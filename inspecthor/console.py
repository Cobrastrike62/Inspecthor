"""Interactive console + CLI entry point.

CONSTRAINT: this is the ONLY layer allowed to print. Parsers, the store, the
engine, and the query layer return typed objects; presentation lives here (and in
reporter.py) via rich. That keeps the library usable from scripts.

CONSTRAINT: the REPL verbs and the CLI subcommands call the SAME functions. Two
code paths for the same behaviour drift, and the one nobody uses interactively is
the one that breaks silently.
"""
from __future__ import annotations

import argparse
import cmd
import os
import shlex
import sys
from datetime import timezone
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from . import __version__, capabilities, reporter
from .engine import Engine, open_evidence
from .interop.attack import AttackDB
from .ioc import IocSweeper
from .models import EventFilter, ParseContext
from .query import parse_time, parse_tz, search, timeline
from .store.store import CaseStore

# Windows console setup: os.system("") flips on ANSI VT processing for legacy
# terminals, and reconfiguring to UTF-8 keeps the block-glyph banner from raising
# UnicodeEncodeError on a cp1252 code page.
if os.name == "nt":  # pragma: no cover - platform-specific
    os.system("")
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


_BANNER_UTF8 = r"""
██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██╗  ██╗ ██████╗ ██████╗
██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ███████║██║   ██║██████╔╝
██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██║██║   ██║██╔══██╗
██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║  ██║
╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"""

_BANNER_ASCII = r"""
 ___ _  _ ___ ___ ___ ___ _____ _  _ ___  ___
|_ _| \| / __| _ \ __/ __|_   _| || / _ \| _ \
 | || .` \__ \  _/ _| (__  | | | __ | (_) |   /
|___|_|\_|___/_| |___\___| |_| |_||_|\___/|_|_\
"""


HELP_YARA_RULES = (
    "extra directory of .yar rules, searched in addition to the bundled set"
)
HELP_SIGMA_RULES = (
    "extra directory of Sigma .yml rules, searched in addition to the bundled set"
)


def _banner() -> str:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return _BANNER_UTF8 if "utf" in enc else _BANNER_ASCII


def _filter_from(args: argparse.Namespace) -> EventFilter:
    """Build an EventFilter from parsed flags, shared by REPL and CLI."""
    start = parse_time(args.since) if getattr(args, "since", None) else None
    end = parse_time(args.until) if getattr(args, "until", None) else None
    return EventFilter(
        start=start, end=end,
        host=getattr(args, "host", None),
        user=getattr(args, "user", None),
        event_type=getattr(args, "type", None),
        source_artifact=getattr(args, "source", None),
        severity=getattr(args, "severity", None),
        tag=getattr(args, "tag", None),
        limit=int(getattr(args, "limit", 0) or 0),
        order="desc" if getattr(args, "desc", False) else "asc",
    )


def _view_parser(prog: str) -> argparse.ArgumentParser:
    """Flags shared by timeline/search/export."""
    parser = argparse.ArgumentParser(prog=prog, add_help=False)
    parser.add_argument("--since", metavar="TIME",
                        help="only events at or after this UTC time, e.g. '2024-03-01' "
                             "or '2024-03-01 09:00:00'")
    parser.add_argument("--until", metavar="TIME",
                        help="only events at or before this UTC time")
    parser.add_argument("--host", metavar="NAME",
                        help="only events from this host (see 'hosts' for what is present)")
    parser.add_argument("--user", metavar="NAME",
                        help="only events for this account (see 'users')")
    parser.add_argument("--type", metavar="EVENT_TYPE",
                        help="only this event type, e.g. logon_failed (see 'types')")
    parser.add_argument("--source", metavar="ARTIFACT",
                        help="only this source artifact; a bare family matches its "
                             "channels, so 'evtx' also matches 'evtx/Security'")
    parser.add_argument("--severity", choices=("high", "med", "info"),
                        help="only events at this triage level")
    parser.add_argument("--tag", metavar="TAG",
                        help="only events carrying this tag, e.g. brute_force_success")
    parser.add_argument("--limit", type=int, default=0, metavar="N",
                        help="stop after N events (default 0, meaning no limit)")
    parser.add_argument("--desc", action="store_true",
                        help="newest first (default is oldest first)")
    return parser


class InspecthorConsole(cmd.Cmd):
    """Interactive REPL. Each command's docstring is its help text."""

    prompt = "inspecthor> "
    intro = None

    def __init__(self, db: str = "inspecthor.db", case: str = "") -> None:
        super().__init__()
        self.console = Console()
        self.db_path = db
        self.store = CaseStore(db, case_name=case)
        self.engine = Engine(self.store)
        self.attack = AttackDB()
        self.evidence_root: Path | None = None

    # ---- lifecycle ----

    def preloop(self) -> None:
        self.console.print(f"[bold red]{_banner()}[/]", highlight=False)
        self.console.print(
            f"  read-only DFIR timeline & artifact analysis  [dim]v{__version__}[/]"
        )
        events = self.store.count_events()
        self.console.print(
            f"  case db: [cyan]{self.db_path}[/]"
            + (f"  [dim]({events} events)[/]" if events else "")
        )
        self.console.print("  type [bold]help[/] to begin, [bold]ingest <path>[/] to start a case\n")

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        self.console.print(
            f"[yellow]unknown command:[/] {line.split()[0]}   (try [bold]help[/])"
        )

    def _args(self, parser: argparse.ArgumentParser, arg: str) -> argparse.Namespace | None:
        """Parse REPL arguments without argparse killing the session on error."""
        try:
            return parser.parse_args(shlex.split(arg))
        except SystemExit:
            return None
        except ValueError as exc:
            self.console.print(f"[red]bad arguments:[/] {exc}")
            return None

    def _filter(self, args: argparse.Namespace) -> EventFilter | None:
        """Build a filter, reporting a bad time value instead of raising.

        A mistyped --since must return the analyst to the prompt; propagating the
        ValueError would end the session over a typo.
        """
        try:
            return _filter_from(args)
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/]")
            return None

    # ---- case ----

    def do_open(self, arg: str) -> None:
        """open <db>  —  switch to another case database."""
        target = arg.strip()
        if not target:
            self.console.print(f"current case db: [cyan]{self.db_path}[/]")
            return
        try:
            new_store = CaseStore(target)
        except Exception as exc:
            self.console.print(f"[red]could not open {target}:[/] {exc}")
            return
        self.store.close()
        self.store = new_store
        self.db_path = target
        self.engine = Engine(self.store)
        self.console.print(
            f"[green]opened[/] {target}  [dim]({self.store.count_events()} events)[/]"
        )

    def do_ingest(self, arg: str) -> None:
        """ingest <path> [--host H] [--year YYYY] [--tz ZONE] [--detect]

        Ingest an evidence folder, a Sherlock .zip (HTB passwords are tried
        automatically), or a single artifact.

        --year  Classic syslog timestamps ("Mar  1 09:15:01") carry no year. Without
                this, the year is inferred from the log file's mtime — which is wrong
                whenever the evidence was repackaged or copied after the fact, as
                Sherlock archives always are. Set it and the guessing stops.
        --tz    Those same lines carry no UTC offset either. Naive times are read in
                this zone before being normalized to UTC, so set it to the host's
                real timezone or the whole Linux timeline sits at the wrong hour
                next to your EVTX events.
        """
        parser = argparse.ArgumentParser(prog="ingest", add_help=False)
        parser.add_argument("path",
                            help="evidence folder, a Sherlock .zip, or a single artifact")
        parser.add_argument("--host", default="", metavar="NAME",
                            help="hostname to label these events with; most Linux logs "
                                 "and loose artifacts do not record one")
        parser.add_argument("--year", type=int, default=None,
                            help="year for classic syslog lines, which carry none "
                                 "(default: inferred from the file's mtime)")
        parser.add_argument("--tz", default="UTC",
                            help="timezone to read tz-naive log times in, e.g. "
                                 "America/Chicago or -06:00 (default: UTC)")
        parser.add_argument("--detect", action="store_true",
                            help="also run YARA over each artifact's bytes while ingesting")
        parser.add_argument("--yara-rules", default=None, metavar="DIR",
                            help=HELP_YARA_RULES)
        args = self._args(parser, arg)
        if args is None:
            return
        self._ingest(args)

    def _ingest(self, args: argparse.Namespace) -> None:
        source = Path(args.path).expanduser()
        root, note = open_evidence(source)
        if note:
            self.console.print(f"[yellow]{note}[/]")
        if not root.exists():
            return
        self.evidence_root = root
        self.console.print(f"[dim]evidence root:[/] {root}")

        try:
            tz = parse_tz(getattr(args, "tz", "UTC") or "UTC")
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/]")
            return

        detectors = []
        if getattr(args, "detect", False):
            from .detect.base import all_detectors
            rule_dirs = (Path(args.yara_rules),) if getattr(args, "yara_rules", None) else ()
            for detector in all_detectors(only_available=True):
                if detector.name == "yara":
                    detector.rule_dirs = rule_dirs
                    detectors.append(detector)
            if not detectors:
                self.console.print(
                    f"[yellow]detection unavailable[/] — {escape(capabilities.hint('yara'))}"
                )

        results = []
        with self.console.status("[cyan]ingesting…[/]"):
            for result in self.engine.ingest(
                root, host=args.host, tz=tz,
                year_hint=args.year, attack=self.attack, detectors=detectors,
            ):
                results.append(result)

        table = reporter.artifacts_table([
            {
                "id": r.artifact_id, "kind": r.kind, "parser": r.parser,
                "status": r.status, "event_count": r.event_count, "path": r.path.name,
            }
            for r in results
        ])
        self.console.print(table)

        parsed = sum(1 for r in results if r.status == "parsed")
        total = sum(r.event_count for r in results)
        self.console.print(
            f"[green]ingested[/] {parsed}/{len(results)} artifacts → "
            f"[bold]{total}[/] events   [dim](total in case: {self.store.count_events()})[/]"
        )
        hints = {r.hint for r in results if r.hint}
        for hint in sorted(hints):
            self.console.print(f"  [yellow]![/] {escape(hint)}")

    def do_artifacts(self, arg: str) -> None:
        """artifacts  —  what was ingested, which parser claimed it, how it went."""
        rows = self.store.get_artifacts()
        if not rows:
            self.console.print("[dim]no artifacts yet — try 'ingest <path>'[/]")
            return
        self.console.print(reporter.artifacts_table(rows))

    # ---- views ----

    def do_timeline(self, arg: str) -> None:
        """timeline [--since T] [--until T] [--host H] [--user U] [--type T]
                   [--source S] [--severity high|med|info] [--tag G]
                   [--limit N] [--desc]

        The super timeline: every artifact's events in one chronological view.
        """
        args = self._args(_view_parser("timeline"), arg)
        if args is None:
            return
        filt = self._filter(args)
        if filt is None:
            return
        rows = timeline(self.store, filt)
        if not rows:
            self.console.print("[dim]no events match[/]")
            return
        table, hidden = reporter.timeline_table(rows)
        self.console.print(table)
        if hidden:
            self.console.print(
                f"[dim]{hidden} more — narrow with filters, or 'export timeline'[/]"
            )

    def do_search(self, arg: str) -> None:
        """search <text> [--regex] [same filters as timeline]

        One query across every artifact at once.
        """
        parser = _view_parser("search")
        parser.add_argument("text",
                            help="text to find in event messages, data fields, and raw records")
        parser.add_argument("--regex", action="store_true",
                            help="treat TEXT as a regular expression instead of a literal")
        args = self._args(parser, arg)
        if args is None:
            return
        filt = self._filter(args)
        if filt is None:
            return
        try:
            rows = search(self.store, args.text, filt, regex=args.regex)
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/]")
            return
        if not rows:
            self.console.print("[dim]no matches[/]")
            return
        table, hidden = reporter.timeline_table(rows, title=f"Matches for {args.text!r}")
        self.console.print(table)
        engine_note = "" if self.store.fts_ok else " [dim](FTS unavailable — literal scan)[/]"
        self.console.print(f"[green]{len(rows)}[/] match(es){engine_note}")
        if hidden:
            self.console.print(f"[dim]{hidden} more not shown[/]")

    def do_hosts(self, arg: str) -> None:
        """hosts  —  distinct hosts and their event counts."""
        self._facet("host")

    def do_users(self, arg: str) -> None:
        """users  —  distinct users and their event counts."""
        self._facet("user")

    def do_types(self, arg: str) -> None:
        """types  —  distinct event types and their counts."""
        self._facet("event_type")

    def _facet(self, column: str) -> None:
        rows = self.store.facets(column)
        if not rows:
            self.console.print(f"[dim]no {column} values recorded[/]")
            return
        from rich.table import Table
        table = Table(title=column, header_style="bold")
        table.add_column(column)
        table.add_column("events", justify="right")
        for value, count in rows:
            table.add_row(Text(str(value)), str(count))
        self.console.print(table)

    # ---- indicators and detections ----

    def do_ioc(self, arg: str) -> None:
        """ioc [sweep|list] [--type T]

        sweep — extract indicators from every event and link them to their source.
        list  — show what has been found (noisy ones dimmed, not hidden).
        """
        parts = shlex.split(arg)
        action = parts[0] if parts else "list"
        kind = None
        if "--type" in parts:
            try:
                kind = parts[parts.index("--type") + 1]
            except IndexError:
                self.console.print("[red]--type needs a value[/]")
                return

        if action == "sweep":
            sweeper = IocSweeper(self.store)
            with self.console.status("[cyan]sweeping for indicators…[/]"):
                counts = sweeper.sweep()
            if not counts:
                self.console.print("[dim]no indicators found[/]")
                return
            summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            self.console.print(f"[green]indicators:[/] {summary}")
            if not sweeper.enriched:
                self.console.print(f"[dim]{escape(capabilities.hint('ioc'))}[/]")
            return

        rows = self.store.get_iocs(kind)
        if not rows:
            self.console.print("[dim]no indicators — run 'ioc sweep' first[/]")
            return
        self.console.print(reporter.iocs_table(rows))

    def do_detect(self, arg: str) -> None:
        """detect [--yara-rules DIR] [--sigma-rules DIR]

        Run the detection overlay: YARA over artifact bytes, Sigma over events.
        """
        parser = argparse.ArgumentParser(prog="detect", add_help=False)
        parser.add_argument("--yara-rules", default=None, metavar="DIR",
                            help=HELP_YARA_RULES)
        parser.add_argument("--sigma-rules", default=None, metavar="DIR",
                            help=HELP_SIGMA_RULES)
        args = self._args(parser, arg)
        if args is None:
            return
        self._detect(args)

    def _detect(self, args: argparse.Namespace) -> None:
        from .detect.sigma_eval import SigmaEval
        from .detect.yara_scan import YaraScan

        ctx = ParseContext(
            evidence_root=self.evidence_root or Path("."), attack=self.attack
        )
        added = 0

        yara_ok, yara_hint = YaraScan().available()
        if yara_ok and self.evidence_root:
            rule_dirs = (Path(args.yara_rules),) if args.yara_rules else ()
            scanner = YaraScan(rule_dirs=rule_dirs)
            with self.console.status("[cyan]running YARA…[/]"):
                for row in self.store.get_artifacts():
                    path = Path(row["path"])
                    if not path.is_file():
                        continue
                    for event in scanner.scan(path, ctx):
                        self.store.add_events_bulk([event], artifact_id=row["id"])
                        self.store.add_finding(
                            "yara", str(event.data.get("rule")), event.severity,
                            event.message, str(event.data.get("strings"))[:500],
                            artifact_id=row["id"], attck=event.attck,
                        )
                        added += 1
        elif not yara_ok:
            self.console.print(f"[yellow]yara unavailable[/] — {escape(yara_hint)}")
        elif not self.evidence_root:
            self.console.print("[yellow]no evidence root known[/] — ingest first for YARA")

        sigma = SigmaEval(
            rule_dirs=(Path(args.sigma_rules),) if args.sigma_rules else ()
        )
        sigma_ok, sigma_hint = sigma.available()
        if sigma_ok:
            with self.console.status("[cyan]evaluating Sigma rules…[/]"):
                for event in sigma.evaluate(self.store, ctx):
                    self.store.add_events_bulk([event])
                    self.store.add_finding(
                        "sigma", str(event.data.get("rule")), event.severity,
                        event.message, f"matched event {event.data.get('matched_event_id')}",
                        attck=event.attck,
                    )
                    added += 1
        else:
            self.console.print(f"[yellow]sigma unavailable[/] — {escape(sigma_hint)}")

        self.store.finalize()
        self.console.print(f"[green]{added}[/] detection(s) recorded")
        for hint in ctx.hints:
            self.console.print(f"  [yellow]![/] {hint}")

    def do_findings(self, arg: str) -> None:
        """findings  —  YARA and Sigma detections, worst first."""
        rows = self.store.get_findings()
        if not rows:
            self.console.print("[dim]no detections — run 'detect'[/]")
            return
        self.console.print(reporter.findings_table(rows))

    # ---- ATT&CK ----

    def do_attck(self, arg: str) -> None:
        """attck [<query>] [--layer FILE]

        With no argument: techniques observed in this case.
        With a query: search the ATT&CK database.
        --layer writes an ATT&CK Navigator layer for the case.
        """
        parts = shlex.split(arg)
        if "--layer" in parts:
            index = parts.index("--layer")
            out = parts[index + 1] if len(parts) > index + 1 else "layer.json"
            from .interop.matrix_interop import write_navigator_layer
            name = self.store.get_meta("case_name") or Path(self.db_path).stem
            written = write_navigator_layer(
                self.store, out, name=name, attack_version=self.attack.version
            )
            self.console.print(f"[green]navigator layer →[/] {written}")
            return

        if parts:
            results = self.attack.search(" ".join(parts))
            if not results:
                self.console.print("[dim]no techniques match[/]")
                return
            from rich.table import Table
            table = Table(title="ATT&CK", header_style="bold", expand=True)
            table.add_column("id", width=11, no_wrap=True)
            table.add_column("name", max_width=36)
            table.add_column("tactics", max_width=28)
            table.add_column("description", overflow="fold")
            for technique in results:
                table.add_row(
                    Text(str(technique.get("id"))), Text(str(technique.get("name"))),
                    Text(", ".join(technique.get("tactics") or [])),
                    Text(str(technique.get("description") or "")[:160]),
                )
            self.console.print(table)
            return

        summary = self.store.attck_summary()
        if not summary:
            self.console.print("[dim]no techniques observed yet[/]")
            return
        from rich.table import Table
        table = Table(title="Techniques observed", header_style="bold", expand=True)
        table.add_column("id", width=11, no_wrap=True)
        table.add_column("name", max_width=40)
        table.add_column("events", justify="right", width=7)
        for technique_id, count in summary:
            table.add_row(technique_id, Text(self.attack.name_of(technique_id)), str(count))
        self.console.print(table)
        self.console.print(
            f"[dim]ATT&CK v{self.attack.version} ({self.attack.origin}: {self.attack.source})[/]"
        )

    # ---- sherlock ----

    def do_sherlock(self, arg: str) -> None:
        """sherlock [<question>] [--readme FILE] [--overview]

        Suggest answers, formatted the way HTB expects. Always verify before
        submitting — these are candidates, not answers.
        """
        parts = shlex.split(arg)
        from .sherlock import answer_question, answer_questions, overview, questions_from_file

        if "--readme" in parts:
            index = parts.index("--readme")
            if len(parts) <= index + 1:
                self.console.print("[red]--readme needs a file[/]")
                return
            questions = questions_from_file(parts[index + 1])
            if not questions:
                self.console.print("[yellow]no questions found in that file[/]")
                return
            self.console.print(f"[green]{len(questions)}[/] question(s) found\n")
            for question, candidates in answer_questions(self.store, questions):
                self.console.print(f"[bold]{question}[/]")
                if candidates:
                    self.console.print(reporter.candidates_table(candidates))
                else:
                    self.console.print("  [dim]no candidate — try a targeted search[/]")
                self.console.print()
            return

        if not parts or "--overview" in parts:
            candidates = overview(self.store)
            if not candidates:
                self.console.print("[dim]nothing to suggest yet — ingest evidence first[/]")
                return
            self.console.print(reporter.candidates_table(candidates))
            return

        candidates = answer_question(self.store, " ".join(parts))
        if not candidates:
            self.console.print(
                "[dim]no candidate for that question — try 'search <keyword>'[/]"
            )
            return
        self.console.print(reporter.candidates_table(candidates))

    # ---- output ----

    def do_report(self, arg: str) -> None:
        """report [FILE.md]  —  write (or print) a markdown case report."""
        target = arg.strip()
        text = reporter.markdown_report(self.store)
        if not target:
            self.console.print(text, highlight=False)
            return
        Path(target).write_text(text, encoding="utf-8")
        self.console.print(f"[green]report →[/] {target}")

    def do_export(self, arg: str) -> None:
        """export <timeline|events|iocs|matrix> [FILE] [--format csv|jsonl|l2tcsv|timesketch]
                  [timeline filters]

        'matrix' writes a .tar.gz that `matrix.py import` accepts.
        """
        parser = _view_parser("export")
        parser.add_argument("what", choices=("timeline", "events", "iocs", "matrix"),
                            help="timeline/events for event rows, iocs for indicators, "
                                 "matrix for a .tar.gz that matrix.py import accepts")
        parser.add_argument("out", nargs="?", default=None, metavar="FILE",
                            help="output path (default is derived from WHAT and --format)")
        parser.add_argument("--format", dest="fmt", default="csv",
                            choices=tuple(reporter.EXPORTERS),
                            help="csv for spreadsheets, jsonl for streaming, l2tcsv for "
                                 "plaso, timesketch for Timesketch import; ignored when "
                                 "WHAT is matrix")
        parser.add_argument("--name", default=None, metavar="NAME",
                            help="case name recorded in the matrix export (default: the "
                                 "case name, else the database filename stem)")
        args = self._args(parser, arg)
        if args is None:
            return

        if args.what == "matrix":
            from .interop.matrix_interop import export_case_targz
            name = args.name or self.store.get_meta("case_name") or Path(self.db_path).stem
            out = args.out or f"{name.lower().replace(' ', '-')}.tar.gz"
            path, case = export_case_targz(self.store, name, out)
            self.console.print(
                f"[green]matrix case →[/] {path}\n"
                f"  [dim]{len(case['techniques'])} techniques, {len(case['iocs'])} iocs, "
                f"{len(case['timeline'])} timeline entries[/]\n"
                f"  [dim]import with: matrix.py import {path}[/]"
            )
            return

        if args.what == "iocs":
            rows = self.store.get_iocs()
            out = args.out or f"iocs.{'jsonl' if args.fmt == 'jsonl' else 'csv'}"
        else:
            filt = self._filter(args)
            if filt is None:
                return
            rows = timeline(self.store, filt)
            suffix = "jsonl" if args.fmt == "jsonl" else "csv"
            out = args.out or f"timeline.{suffix}"

        if not rows:
            self.console.print("[dim]nothing to export[/]")
            return
        try:
            written = reporter.export(rows, out, args.fmt)
        except ValueError as exc:
            self.console.print(f"[red]{exc}[/]")
            return
        self.console.print(f"[green]{len(rows)} row(s) →[/] {written}  [dim]({args.fmt})[/]")

    # ---- introspection ----

    def do_parsers(self, arg: str) -> None:
        """parsers  —  registered parsers and whether their dependencies are present."""
        from .parsers._loader import all_parsers
        from rich.table import Table
        table = Table(title="Parsers", header_style="bold", expand=True)
        table.add_column("name", width=15, no_wrap=True)
        table.add_column("category", width=9, no_wrap=True)
        table.add_column("dep", width=9, no_wrap=True)
        table.add_column("note", overflow="fold")
        for parser in sorted(all_parsers(), key=lambda p: (p.category, p.name)):
            ok, hint = parser.dependency_ok()
            table.add_row(
                parser.name, parser.category,
                "[green]ok[/]" if ok else "[yellow]missing[/]",
                Text(parser.display if ok else hint),
            )
        self.console.print(table)

    def do_tools(self, arg: str) -> None:
        """tools  —  optional capabilities, and how to install what is missing."""
        from rich.table import Table
        table = Table(title="Capabilities", header_style="bold", expand=True)
        table.add_column("capability", width=11, no_wrap=True)
        table.add_column("", width=4, no_wrap=True)
        table.add_column("unlocks", max_width=42)
        table.add_column("install", overflow="fold")
        for name, ok, unlocks, hint in capabilities.status():
            table.add_row(
                name, "[green]yes[/]" if ok else "[yellow]no[/]", Text(unlocks),
                Text("" if ok else hint),
            )
        self.console.print(table)

    def do_info(self, arg: str) -> None:
        """info  —  case summary: counts, database, ATT&CK source."""
        artifacts = self.store.get_artifacts()
        self.console.print(f"case db     : [cyan]{self.db_path}[/]")
        self.console.print(f"case name   : {self.store.get_meta('case_name') or '(unnamed)'}")
        self.console.print(f"artifacts   : {len(artifacts)}")
        self.console.print(f"events      : {self.store.count_events()}")
        self.console.print(f"indicators  : {len(self.store.get_iocs())}")
        self.console.print(f"detections  : {len(self.store.get_findings())}")
        self.console.print(f"fts         : {'yes' if self.store.fts_ok else 'no (literal scan)'}")
        self.console.print(
            f"att&ck      : v{self.attack.version} ({self.attack.origin}) {self.attack.source}"
        )
        if self.evidence_root:
            self.console.print(f"evidence    : {self.evidence_root}")

    # ---- session ----

    def do_exit(self, arg: str) -> bool:
        """exit  —  leave the console."""
        self.store.close()
        return True

    do_quit = do_exit

    def do_EOF(self, arg: str) -> bool:
        """Ctrl-D leaves the console."""
        self.console.print()
        return self.do_exit(arg)


# ---- CLI ----


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspecthor",
        description="read-only forensic timeline and artifact analysis",
        epilog="run with no subcommand for the interactive console",
    )
    parser.add_argument("--db", default="inspecthor.db", metavar="FILE",
                        help="case database to read or create (default inspecthor.db); "
                             "all derived state lives here, never in the evidence")
    parser.add_argument("--case", default="", metavar="NAME",
                        help="case name, recorded in the database and used in reports")
    parser.add_argument("--version", action="version", version=f"inspecthor {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    ingest = sub.add_parser("ingest", help="ingest evidence (folder, zip, or file)")
    ingest.add_argument("path",
                        help="evidence folder, a Sherlock .zip, or a single artifact")
    ingest.add_argument("--host", default="", metavar="NAME",
                        help="hostname to label these events with; most Linux logs and "
                             "loose artifacts do not record one")
    ingest.add_argument("--year", type=int, default=None,
                        help="year for classic syslog lines, which carry none "
                             "(default: inferred from the file's mtime)")
    ingest.add_argument("--tz", default="UTC",
                        help="timezone to read tz-naive log times in, e.g. "
                             "America/Chicago or -06:00 (default: UTC)")
    ingest.add_argument("--detect", action="store_true",
                        help="also run YARA over each artifact's bytes while ingesting")
    ingest.add_argument("--yara-rules", default=None, metavar="DIR",
                        help=HELP_YARA_RULES)

    for name, help_text in (("timeline", "print the super timeline"),
                            ("export", "export events or a matrix case")):
        view = sub.add_parser(name, parents=[_view_parser(name)], help=help_text)
        if name == "export":
            view.add_argument("what", choices=("timeline", "events", "iocs", "matrix"),
                              help="timeline/events for event rows, iocs for indicators, "
                                   "matrix for a .tar.gz that matrix.py import accepts")
            view.add_argument("out", nargs="?", default=None, metavar="FILE",
                              help="output path (default is derived from WHAT and --format)")
            view.add_argument("--format", dest="fmt", default="csv",
                              choices=tuple(reporter.EXPORTERS),
                              help="csv for spreadsheets, jsonl for streaming, l2tcsv for "
                                   "plaso, timesketch for Timesketch import; ignored when "
                                   "WHAT is matrix")
            view.add_argument("--name", default=None, metavar="NAME",
                              help="case name recorded in the matrix export")

    find = sub.add_parser("search", parents=[_view_parser("search")], help="search all events")
    find.add_argument("text",
                      help="text to find in event messages, data fields, and raw records")
    find.add_argument("--regex", action="store_true",
                      help="treat TEXT as a regular expression instead of a literal")

    ioc = sub.add_parser("ioc", help="extract or list indicators")
    ioc.add_argument("action", nargs="?", default="sweep", choices=("sweep", "list"),
                     help="sweep extracts indicators from every event and links them to "
                          "their source; list shows what has been found")
    ioc.add_argument("--type", default=None, metavar="KIND",
                     help="list only this kind: ipv4, ipv6, domain, url, email, md5, "
                          "sha1, sha256")

    detect = sub.add_parser("detect", help="run YARA and Sigma")
    detect.add_argument("--yara-rules", default=None, metavar="DIR",
                        help=HELP_YARA_RULES)
    detect.add_argument("--sigma-rules", default=None, metavar="DIR",
                        help=HELP_SIGMA_RULES)

    sherlock = sub.add_parser("sherlock", help="suggest HTB answers")
    sherlock.add_argument("question", nargs="*", default=[], metavar="WORD",
                          help="the Sherlock question in its own words, e.g. "
                               "\"what is the attacker IP\"")
    sherlock.add_argument("--readme", default=None, metavar="FILE",
                          help="Sherlock task file to pull numbered questions from and "
                               "answer in one pass")
    sherlock.add_argument("--overview", action="store_true",
                          help="answer the standard opening questions (host, timezone, "
                               "attacker IP, first logon, persistence) without being asked")

    report = sub.add_parser("report", help="write a markdown case report")
    report.add_argument("out", nargs="?", default=None, metavar="FILE",
                        help="write the report here instead of printing it to stdout")

    sub.add_parser("artifacts", help="list ingested artifacts")
    sub.add_parser("findings", help="list detections")
    sub.add_parser("parsers", help="list parsers and dependency status")
    sub.add_parser("tools", help="list optional capabilities")
    sub.add_parser("info", help="case summary")

    attck = sub.add_parser("attck", help="ATT&CK search / observed techniques / layer")
    attck.add_argument("query", nargs="*", default=[], metavar="WORD",
                       help="technique id or keyword to look up; omit to list the "
                            "techniques observed in this case")
    attck.add_argument("--layer", default=None, metavar="FILE",
                       help="write an ATT&CK Navigator layer JSON for the case")

    return parser


def _run_subcommand(args: argparse.Namespace) -> None:
    """Dispatch a CLI subcommand through the same console methods the REPL uses."""
    console = InspecthorConsole(args.db, args.case)
    try:
        if args.cmd == "ingest":
            console._ingest(args)
        elif args.cmd == "timeline":
            console.do_timeline(_reflow(args, _view_parser("timeline")))
        elif args.cmd == "search":
            extras = "--regex " if args.regex else ""
            console.do_search(
                f"{shlex.quote(args.text)} {extras}{_reflow(args, _view_parser('search'))}"
            )
        elif args.cmd == "export":
            tail = _reflow(args, _view_parser("export"))
            out = shlex.quote(args.out) if args.out else ""
            name = f"--name {shlex.quote(args.name)} " if args.name else ""
            console.do_export(f"{args.what} {out} --format {args.fmt} {name}{tail}")
        elif args.cmd == "ioc":
            suffix = f" --type {args.type}" if args.type else ""
            console.do_ioc(f"{args.action}{suffix}")
        elif args.cmd == "detect":
            console._detect(args)
        elif args.cmd == "sherlock":
            if args.readme:
                console.do_sherlock(f"--readme {shlex.quote(args.readme)}")
            elif args.overview or not args.question:
                console.do_sherlock("--overview")
            else:
                console.do_sherlock(" ".join(shlex.quote(q) for q in args.question))
        elif args.cmd == "report":
            console.do_report(args.out or "")
        elif args.cmd == "attck":
            if args.layer:
                console.do_attck(f"--layer {shlex.quote(args.layer)}")
            else:
                console.do_attck(" ".join(args.query))
        else:
            getattr(console, f"do_{args.cmd}")("")
    finally:
        console.store.close()


def _reflow(args: argparse.Namespace, _parser: argparse.ArgumentParser) -> str:
    """Rebuild the shared view flags as a string for the do_* methods.

    Slightly indirect, but it guarantees the CLI and the REPL take the identical
    code path rather than two parallel implementations of the same filters.
    """
    parts: list[str] = []
    for flag in ("since", "until", "host", "user", "type", "source", "severity", "tag"):
        value = getattr(args, flag, None)
        if value:
            parts.append(f"--{flag} {shlex.quote(str(value))}")
    if getattr(args, "limit", 0):
        parts.append(f"--limit {int(args.limit)}")
    if getattr(args, "desc", False):
        parts.append("--desc")
    return " ".join(parts)


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if getattr(args, "cmd", None) is None:
            if not sys.stdin.isatty():
                # A non-interactive invocation with no subcommand would hang on
                # input(); say what to do instead.
                print("inspecthor: no subcommand and stdin is not a tty — "
                      "try 'inspecthor --help'", file=sys.stderr)
                raise SystemExit(2)
            InspecthorConsole(args.db, args.case).cmdloop()
        else:
            _run_subcommand(args)
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":  # pragma: no cover
    main()
