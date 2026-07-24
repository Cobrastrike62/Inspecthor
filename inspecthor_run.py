#!/usr/bin/env python3
"""Headless one-shot driver: evidence in, case artifacts out.

For the times you do not want a REPL — a fresh analysis VM, a scripted triage
pass, an agent harness. Runs the whole pipeline and leaves a report, a timeline
export, and a case database behind:

    python inspecthor_run.py sherlock.zip
    python inspecthor_run.py /evidence --host WS01 --year 2024 --outdir out/

Unlike the library layers, this is a script, so printing here is fine — but it
still only calls public library functions, so it cannot drift from the console.
"""
from __future__ import annotations

import argparse
import sys
from datetime import timezone
from pathlib import Path

from inspecthor import __version__, reporter
from inspecthor.engine import Engine, open_evidence
from inspecthor.interop.attack import AttackDB
from inspecthor.interop.matrix_interop import export_case_targz
from inspecthor.ioc import IocSweeper
from inspecthor.query import timeline
from inspecthor.sherlock import overview, questions_from_file
from inspecthor.store.store import CaseStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspecthor_run",
        description="one-shot forensic triage: ingest, sweep, detect, report",
    )
    parser.add_argument("evidence", help="folder, .zip (HTB passwords tried), or single file")
    parser.add_argument("--outdir", default=".", help="where to write outputs")
    parser.add_argument("--db", default=None, help="case database path")
    parser.add_argument("--name", default=None, help="case name")
    parser.add_argument("--host", default="", help="host label for this evidence")
    parser.add_argument("--year", type=int, default=None, help="year for syslog with none")
    parser.add_argument("--detect", action="store_true", help="run YARA and Sigma")
    parser.add_argument("--yara-rules", default=None)
    parser.add_argument("--sigma-rules", default=None)
    parser.add_argument("--readme", default=None,
                        help="Sherlock task file to answer questions from")
    parser.add_argument("--matrix", action="store_true",
                        help="also write a .tar.gz that matrix.py import accepts")
    parser.add_argument("--version", action="version", version=f"inspecthor {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    source = Path(args.evidence).expanduser()
    outdir = Path(args.outdir).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)
    name = args.name or source.stem
    db_path = args.db or str(outdir / f"{name}.db")

    root, note = open_evidence(source, outdir / f"{name}_extracted")
    if note:
        print(f"! {note}", file=sys.stderr)
    if not root.exists():
        return 2

    store = CaseStore(db_path, case_name=name)
    attack = AttackDB()
    print(f"inspecthor {__version__} — case '{name}'")
    print(f"  evidence : {root}")
    print(f"  database : {db_path}")
    print(f"  att&ck   : v{attack.version} ({attack.origin})")

    detectors = []
    if args.detect:
        from inspecthor.detect.base import all_detectors
        for detector in all_detectors(only_available=True):
            if detector.name == "yara":
                detector.rule_dirs = (
                    (Path(args.yara_rules),) if args.yara_rules else ()
                )
                detectors.append(detector)

    print("\n-- ingest --")
    parsed = skipped = events = 0
    for result in Engine(store).ingest(
        root, host=args.host, tz=timezone.utc, year_hint=args.year,
        attack=attack, detectors=detectors,
    ):
        events += result.event_count
        if result.status == "parsed":
            parsed += 1
        else:
            skipped += 1
        flag = "ok " if result.status == "parsed" else "-- "
        print(f"  {flag}{result.path.name:34} {result.kind:10} "
              f"{result.parser or '-':14} {result.event_count:>7}")
        if result.hint:
            print(f"       ! {result.hint}")
    print(f"  {parsed} parsed, {skipped} skipped, {events} events")

    print("\n-- indicators --")
    counts = IocSweeper(store).sweep()
    print("  " + ("  ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "(none)"))

    if args.detect:
        print("\n-- detections --")
        from inspecthor.detect.sigma_eval import SigmaEval
        from inspecthor.models import ParseContext
        ctx = ParseContext(evidence_root=root, attack=attack)
        sigma = SigmaEval(
            rule_dirs=(Path(args.sigma_rules),) if args.sigma_rules else ()
        )
        added = 0
        if sigma.available()[0]:
            for event in sigma.evaluate(store, ctx):
                store.add_events_bulk([event])
                store.add_finding("sigma", str(event.data.get("rule")), event.severity,
                                  event.message, attck=event.attck)
                added += 1
        for detector in detectors:
            for row in store.get_artifacts():
                path = Path(row["path"])
                if not path.is_file():
                    continue
                for event in detector.scan(path, ctx):
                    store.add_events_bulk([event], artifact_id=row["id"])
                    store.add_finding(detector.name, str(event.data.get("rule")),
                                      event.severity, event.message,
                                      artifact_id=row["id"], attck=event.attck)
                    added += 1
        store.finalize()
        print(f"  {added} detection(s)")
        for hint in ctx.hints:
            print(f"  ! {hint}")

    print("\n-- outputs --")
    rows = timeline(store)
    for fmt, suffix in (("csv", "csv"), ("jsonl", "jsonl"), ("l2tcsv", "l2t.csv"),
                        ("timesketch", "timesketch.csv")):
        written = reporter.export(rows, outdir / f"{name}-timeline.{suffix}", fmt)
        print(f"  {written}")
    report_path = outdir / f"{name}-report.md"
    report_path.write_text(reporter.markdown_report(store), encoding="utf-8")
    print(f"  {report_path}")

    if args.matrix:
        path, case = export_case_targz(store, name, outdir / f"{name}.tar.gz")
        print(f"  {path}  ({len(case['techniques'])} techniques, "
              f"{len(case['iocs'])} iocs)  -> matrix.py import {path}")

    print("\n-- candidate answers (verify before submitting) --")
    if args.readme:
        from inspecthor.sherlock import answer_questions
        questions = questions_from_file(args.readme)
        if not questions:
            print("  (no questions found in that file)")
        for question, candidates in answer_questions(store, questions):
            print(f"  Q: {question}")
            for cand in candidates:
                print(f"     {cand.confidence:.2f}  {cand.label}: {cand.answer}")
            if not candidates:
                print("     (no candidate)")
    else:
        for cand in overview(store):
            print(f"  {cand.confidence:.2f}  {cand.label}: {cand.answer}"
                  f"   [{cand.source}]")

    store.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        raise SystemExit(130)
