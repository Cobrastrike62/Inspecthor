"""Command line.

Four things you can do:

    inspecthor <evidence>          analyze it and tell me what happened
    inspecthor ask "<question>"    answer one question about the last case
    inspecthor find <text>         search everything
    inspecthor timeline            show what happened, in order

The first one is the tool. The other three are for following up on it.

CONSTRAINT: this is the only module that prints. Everything below it returns
objects.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from . import __version__, analyze as analyze_mod, reporter
from .models import EventFilter
from .query import parse_tz, search
from .store.store import CaseStore

# Windows console setup: os.system("") enables ANSI on legacy terminals, and the
# UTF-8 reconfigure keeps the banner glyphs off a cp1252 code page.
if os.name == "nt":  # pragma: no cover - platform-specific
    os.system("")
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


def _console() -> Console:
    return Console(highlight=False)


def _t(value: object) -> Text:
    """Evidence-derived text must never be parsed as rich markup."""
    return Text("" if value is None else str(value))


# ---- finding the case ----


def resolve_case(explicit: str | None) -> Path | None:
    """The case database to work against.

    Defaults to the most recently written ``.db`` in the working directory, so
    the follow-up commands need no flag after an analysis.
    """
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.is_file() else None
    candidates = sorted(
        (p for p in Path.cwd().glob("*.db") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _open_case(console: Console, explicit: str | None) -> CaseStore | None:
    path = resolve_case(explicit)
    if path is None:
        console.print(
            "[red]no case found.[/] Analyze some evidence first:\n"
            "  [bold]inspecthor /path/to/evidence[/]"
        )
        return None
    return CaseStore(str(path))


# ---- the main command ----


def cmd_analyze(args: argparse.Namespace) -> int:
    console = _console()
    try:
        tz = parse_tz(args.tz) if args.tz else None
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        return 2

    rule_dirs = (Path(args.rules),) if args.rules else ()
    console.print(f"[bold]inspecthor[/] [dim]v{__version__}[/]  analyzing [cyan]{args.evidence}[/]\n")

    with console.status("[cyan]starting[/]") as status:
        result = analyze_mod.analyze(
            args.evidence,
            out_dir=args.out,
            case_name=args.name,
            tz=tz,
            host=args.host,
            year=args.year,
            detect=not args.no_detect,
            rule_dirs=rule_dirs,
            progress=lambda msg: status.update(f"[cyan]{msg}[/]"),
        )

    if not result.evidence_root:
        for warning in result.warnings:
            console.print(f"[red]{escape(warning)}[/]")
        return 1

    _render_result(console, result)
    return 0


def _render_result(console: Console, result: analyze_mod.Result) -> None:
    """Tell the story: what it read, what it worked out, what matters, answers."""

    # --- what it read ---
    skipped = result.skipped
    line = f"[green]{result.parsed}[/] artifact(s) parsed, [bold]{result.event_count}[/] events"
    if skipped:
        line += f", [yellow]{len(skipped)}[/] skipped"
    if result.detections:
        line += f", [bold red]{result.detections}[/] detection(s)"
    console.print(line)
    if result.ioc_counts:
        counts = "  ".join(f"{k}={v}" for k, v in sorted(result.ioc_counts.items()))
        console.print(f"[dim]indicators:[/] {counts}")

    # --- what it worked out, and from where ---
    rows = result.context.summary()
    if rows:
        console.print("\n[bold]What the evidence says about itself[/]")
        table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2, 0, 0))
        table.add_column(style="dim", no_wrap=True)
        table.add_column(no_wrap=True)
        table.add_column(style="dim")
        for label, value, source in rows:
            table.add_row(label, _t(value), _t(source))
        console.print(table)

    # --- what matters ---
    notable = result.notable(25)
    if notable:
        console.print("\n[bold]What stands out[/]")
        table, _hidden = reporter.timeline_table(notable, title="")
        console.print(table)
        # A few of each kind are shown rather than 25 of whichever event type is
        # loudest, so state how many notable events there actually are.
        if result.notable_total > len(notable):
            console.print(
                f"[dim]a sample of {len(notable)} kinds shown; "
                f"{result.notable_total} notable events in total — "
                "all of them are in the report[/]"
            )

    # --- answers ---
    if result.answers:
        console.print(
            f"\n[bold]The evidence came with {len(result.questions)} question(s)[/]"
            "  [dim](candidates — verify before submitting)[/]"
        )
        for question, candidates in result.answers:
            console.print(f"\n  [bold]{escape(question)}[/]")
            if not candidates:
                console.print("    [dim]no candidate — try 'inspecthor find <keyword>'[/]")
                continue
            for cand in candidates:
                confident = cand.confidence >= 0.75
                marker = "[bold green]>[/]" if confident else "[dim]·[/]"
                line = Text.assemble(
                    (f"{cand.confidence:.2f}  ", "bold green" if confident else "dim"),
                    (f"{cand.answer}", "bold" if confident else ""),
                    (f"   {cand.label}", "dim"),
                    (f" — {cand.why}", "dim"),
                )
                console.print("   ", marker, line)
    elif result.overview:
        console.print(
            "\n[bold]Opening facts[/]  [dim](candidates — verify before submitting)[/]"
        )
        console.print(reporter.candidates_table(result.overview))

    # --- caveats ---
    for note in result.context.notes:
        console.print(f"\n[yellow]note:[/] {escape(note)}")
    for warning in result.warnings[:6]:
        console.print(f"[yellow]![/] {escape(warning)}")
    for hint in result.hints[:6]:
        console.print(f"[dim]![/] [dim]{escape(hint)}[/]")
    if skipped:
        names = ", ".join(a.path.name for a in skipped[:6])
        console.print(f"[dim]not parsed: {escape(names)}"
                      f"{' …' if len(skipped) > 6 else ''}[/]")

    # --- where things went ---
    console.print(
        f"\n[bold]Saved[/]\n"
        f"  report   [cyan]{result.report_path}[/]\n"
        f"  timeline [cyan]{result.timeline_path}[/]\n"
        f"  case     [cyan]{result.db_path}[/]"
    )
    console.print(
        '\n[dim]Follow up with:  inspecthor ask "when did they first log in?"'
        "   ·   inspecthor find <text>   ·   inspecthor timeline[/]"
    )


# ---- follow-up commands ----


def cmd_ask(args: argparse.Namespace) -> int:
    from .sherlock import answer_question

    console = _console()
    store = _open_case(console, args.case)
    if store is None:
        return 1
    try:
        question = " ".join(args.question)
        candidates = answer_question(store, question)
        if not candidates:
            console.print(
                "[yellow]no candidate for that.[/] Try different words, or "
                f"[bold]inspecthor find <keyword>[/] to look directly."
            )
            return 0
        console.print(reporter.candidates_table(candidates))
        return 0
    finally:
        store.close()


def cmd_find(args: argparse.Namespace) -> int:
    console = _console()
    store = _open_case(console, args.case)
    if store is None:
        return 1
    try:
        rows = search(store, args.text, EventFilter(limit=args.limit), regex=args.regex)
        if not rows:
            console.print(f"[dim]nothing matches {args.text!r}[/]")
            return 0
        table, hidden = reporter.timeline_table(rows, title=f"Matches for {args.text!r}")
        console.print(table)
        console.print(f"[green]{len(rows)}[/] match(es)"
                      + (f"  [dim]+{hidden} more[/]" if hidden else ""))
        return 0
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        return 2
    finally:
        store.close()


def cmd_timeline(args: argparse.Namespace) -> int:
    console = _console()
    store = _open_case(console, args.case)
    if store is None:
        return 1
    try:
        if args.all:
            rows = store.query_events(EventFilter(limit=args.limit))
            title = "Timeline"
        else:
            rows = store.query_events(EventFilter(severity="high", limit=args.limit))
            rows += store.query_events(
                EventFilter(severity="med", limit=max(0, args.limit - len(rows)))
            )
            rows.sort(key=lambda r: (str(r.get("ts")), int(r.get("id", 0))))
            title = "Timeline (notable only — use --all for everything)"
        if not rows:
            console.print("[dim]nothing to show[/]")
            return 0
        table, hidden = reporter.timeline_table(rows, title=title)
        console.print(table)
        if hidden:
            console.print(f"[dim]{hidden} more — see the report or the timeline CSV[/]")
        return 0
    finally:
        store.close()


# ---- parser ----


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspecthor",
        description="Point it at forensic evidence; it tells you what happened.",
        epilog=(
            "examples:\n"
            "  inspecthor sherlock.zip              analyze a Sherlock package\n"
            "  inspecthor /mnt/evidence             analyze a folder\n"
            '  inspecthor ask "attacker IP?"        ask about the last case\n'
            "  inspecthor find 45.33.32.156         search everything\n"
            "  inspecthor timeline --all            the full timeline\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"inspecthor {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    run = sub.add_parser(
        "analyze",
        help="analyze evidence (the default — you can omit the word 'analyze')",
        description="Parse everything, work out the case context, detect, and answer.",
    )
    run.add_argument("evidence", help="a folder, a Sherlock .zip, or a single file")
    run.add_argument("--out", metavar="DIR", default=None,
                     help="where to write the report, timeline and case file "
                          "(default: here)")
    run.add_argument("--name", metavar="NAME", default=None,
                     help="name the case, and the files it writes "
                          "(default: taken from the evidence path)")
    run.add_argument("--no-detect", action="store_true",
                     help="skip the YARA and Sigma pass")
    run.add_argument("--rules", metavar="DIR", default=None,
                     help="your own YARA .yar and Sigma .yml rules, used as well "
                          "as the built-in ones")
    run.add_argument("--tz", metavar="ZONE", default=None,
                     help="override the timezone it worked out, e.g. America/Chicago")
    run.add_argument("--year", type=int, default=None, metavar="YYYY",
                     help="override the year it worked out")
    run.add_argument("--host", metavar="NAME", default=None,
                     help="override the hostname it worked out")
    run.set_defaults(func=cmd_analyze)

    ask = sub.add_parser("ask", help="answer one question about the last case")
    ask.add_argument("question", nargs="+", metavar="WORDS",
                     help='the question, e.g. "what account did they create?"')
    ask.add_argument("--case", metavar="FILE", default=None,
                     help="a specific case file (default: the newest one here)")
    ask.set_defaults(func=cmd_ask)

    find = sub.add_parser("find", help="search every artifact at once")
    find.add_argument("text", help="what to look for")
    find.add_argument("--regex", action="store_true", help="treat it as a regex")
    find.add_argument("--limit", type=int, default=200, metavar="N",
                      help="stop after N matches (default 200)")
    find.add_argument("--case", metavar="FILE", default=None,
                      help="a specific case file (default: the newest one here)")
    find.set_defaults(func=cmd_find)

    tl = sub.add_parser("timeline", help="what happened, in order")
    tl.add_argument("--all", action="store_true",
                    help="every event, not just the notable ones")
    tl.add_argument("--limit", type=int, default=500, metavar="N",
                    help="stop after N events (default 500)")
    tl.add_argument("--case", metavar="FILE", default=None,
                    help="a specific case file (default: the newest one here)")
    tl.set_defaults(func=cmd_timeline)

    return parser


_VERBS = {"analyze", "ask", "find", "timeline"}


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    A bare path is treated as ``analyze <path>``, because typing the verb for the
    thing you do 90% of the time is friction with no upside.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and not argv[0].startswith("-") and argv[0] not in _VERBS:
        argv.insert(0, "analyze")

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
