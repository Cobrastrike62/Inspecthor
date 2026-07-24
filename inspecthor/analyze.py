"""The whole analysis, in one call.

``inspecthor <evidence>`` lands here. Everything that used to be a separate
command — parse, derive the case context, run detections, sweep indicators, find
the task file, answer its questions, write the report — happens in sequence
because there is no useful state in between. An analyst who has to run five
commands to see anything is doing the tool's job for it.

CONSTRAINT: silent library. Returns a :class:`Result`; the CLI renders it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timezone, tzinfo
from pathlib import Path
from typing import Callable, Optional

from . import infer, reporter
from .attack import AttackDB
from .engine import Engine, open_evidence
from .infer import Context
from .ioc import IocSweeper
from .models import ArtifactResult, Candidate, EventFilter, ParseContext
from .query import timeline
from .sherlock import answer_questions, overview, questions_from_text
from .store.store import CaseStore

# Files that plausibly hold the investigation questions. HTB ships one with every
# Sherlock; finding it automatically removes the last reason to pass a flag.
_TASK_NAMES = re.compile(
    r"(read ?me|task|question|brief|scenario|instruction|challenge|note)s?\b", re.I
)
_TASK_SUFFIXES = {".txt", ".md", ".rst", ".pdf", ".html", ""}
_MAX_TASK_BYTES = 256 * 1024


@dataclass
class Result:
    """Everything one analysis produced."""

    case_name: str = ""
    db_path: str = ""
    evidence_root: Optional[Path] = None
    context: Context = field(default_factory=Context)
    artifacts: list[ArtifactResult] = field(default_factory=list)
    event_count: int = 0
    ioc_counts: dict = field(default_factory=dict)
    detections: int = 0
    questions: list[str] = field(default_factory=list)
    answers: list[tuple[str, list[Candidate]]] = field(default_factory=list)
    overview: list[Candidate] = field(default_factory=list)
    report_path: str = ""
    timeline_path: str = ""
    notable_events: list[dict] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def parsed(self) -> int:
        return sum(1 for a in self.artifacts if a.status == "parsed")

    @property
    def skipped(self) -> list[ArtifactResult]:
        return [a for a in self.artifacts if a.status != "parsed"]

    def notable(self, limit: int = 40) -> list[dict]:
        """The events worth reading first."""
        return self.notable_events[:limit]


def find_task_file(root: Path) -> tuple[Optional[Path], list[str]]:
    """Locate the investigation questions inside the evidence, if present."""
    if not root.is_dir():
        return None, []
    candidates: list[Path] = []
    for path in sorted(root.rglob("*")):
        try:
            if not path.is_file() or path.stat().st_size > _MAX_TASK_BYTES:
                continue
        except OSError:
            continue
        if path.suffix.lower() not in _TASK_SUFFIXES:
            continue
        if _TASK_NAMES.search(path.stem):
            candidates.append(path)

    # A file that actually contains questions beats one that merely looks like it.
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        questions = questions_from_text(text)
        if questions:
            return path, questions
    return (candidates[0] if candidates else None), []


def _default_case_name(source: Path) -> str:
    stem = source.stem if source.is_file() else source.name
    return re.sub(r"[_\-.]+", " ", stem).strip() or "case"


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "case"


# Stored in meta so a re-run can tell "this is the same evidence" from
# "something unrelated happens to share a folder name".
_META_SOURCE = "evidence_source"
_MAX_SUFFIX = 50


def _existing_source(db_path: Path) -> tuple[bool, str]:
    """``(is_a_case, recorded_source)`` for a file that already exists."""
    import sqlite3
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return False, ""
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key=?", (_META_SOURCE,)
        ).fetchone()
        return True, (row[0] if row and row[0] else "")
    except sqlite3.Error:
        # Exists but is not an inspecthor case (or not even SQLite).
        return False, ""
    finally:
        conn.close()


def resolve_output_slug(out: Path, name: str, source: Path) -> tuple[str, str]:
    """Pick a slug whose files will not clobber an unrelated case.

    Returns ``(slug, note)``.

    Three situations, and the important part is that none of them append to an
    existing case:

    * nothing there — use the name as-is.
    * a case for THIS evidence — reuse the name; :func:`analyze` starts it fresh.
      The database is entirely derived from the evidence, so re-deriving it is
      safe, and it is the only way to avoid silently double-counting every event.
    * a case for DIFFERENT evidence that happens to share a name — leave it alone
      and take the next free suffix. Sherlock packages are full of folders called
      'evidence' and 'artifacts', so this collision is common, and merging two
      unrelated cases would quietly answer questions with the wrong data.
    """
    base = _slugify(name)
    source_key = str(source.resolve())

    for attempt in range(1, _MAX_SUFFIX + 1):
        slug = base if attempt == 1 else f"{base}-{attempt}"
        db_path = out / f"{slug}.db"
        if not db_path.exists():
            note = "" if attempt == 1 else (
                f"{base}.db already holds a different case; using {slug}.db"
            )
            return slug, note
        is_case, recorded = _existing_source(db_path)
        if is_case and recorded == source_key:
            return slug, f"replacing the previous analysis in {slug}.db"
        # Occupied by something else: keep looking.
    return f"{base}-{_MAX_SUFFIX}", (
        f"too many cases named {base}; reusing {base}-{_MAX_SUFFIX}.db"
    )


def analyze(
    source: str | Path,
    out_dir: str | Path | None = None,
    case_name: str | None = None,
    tz: tzinfo | None = None,
    host: str | None = None,
    year: int | None = None,
    detect: bool = True,
    rule_dirs: tuple[Path, ...] = (),
    progress: Callable[[str], None] | None = None,
) -> Result:
    """Analyze an evidence set end to end."""
    step = progress or (lambda _msg: None)
    source = Path(source).expanduser()
    out = Path(out_dir).expanduser() if out_dir else Path.cwd()
    out.mkdir(parents=True, exist_ok=True)

    result = Result(case_name=case_name or _default_case_name(source))
    slug, name_note = resolve_output_slug(out, result.case_name, source)
    result.db_path = str(out / f"{slug}.db")
    if name_note:
        result.warnings.append(name_note)

    # CONSTRAINT: never add to an existing case. Re-running on the same evidence
    # used to insert every event a second time, silently doubling the counts, the
    # indicators and the timeline. The database holds nothing but derived data, so
    # starting clean is both safe and the only correct answer.
    for stale in (
        Path(result.db_path),
        Path(f"{result.db_path}-wal"),
        Path(f"{result.db_path}-shm"),
    ):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            result.warnings.append(f"could not replace {stale.name}: {exc}")

    step("unpacking evidence")
    root, note = open_evidence(source, out / f"{slug}-evidence")
    if note:
        result.warnings.append(note)
    if not root.exists():
        result.warnings.append(f"nothing to analyze at {source}")
        return result
    result.evidence_root = root

    store = CaseStore(result.db_path, case_name=result.case_name)
    # Recorded so a later run can distinguish "same evidence, analyze again" from
    # "different evidence that happens to share a folder name".
    store.set_meta(_META_SOURCE, str(source.resolve()))
    store.set_meta("evidence_root", str(root))
    attack = AttackDB()
    engine = Engine(store)

    try:
        # ---- pass one: everything that dates itself ----
        self_dating, needs_context = engine.plan(root)
        step(f"parsing {len(self_dating)} artifact(s)")
        for artifact in engine.ingest(
            root, attack=attack, paths=self_dating, finalize=False,
            host=host or "", tz=tz or timezone.utc,
        ):
            result.artifacts.append(artifact)
        store.finalize()

        # ---- derive the case context from what pass one found ----
        step("working out the timezone, year and host from the evidence")
        context = infer.derive(store, {"tz": tz, "host": host, "year": year})
        result.context = context

        # ---- pass two: formats that needed that context ----
        if needs_context:
            step(f"parsing {len(needs_context)} time-ambiguous artifact(s)")
            for artifact in engine.ingest(
                root, host=context.host, tz=context.tz, year_hint=context.year,
                attack=attack, paths=needs_context, finalize=False,
            ):
                result.artifacts.append(artifact)
            store.finalize()
            # Pass two can supply the only hostname in a Linux-only evidence set.
            if not context.host:
                found, source_label = infer.host_from_events(store)
                if found:
                    context.host, context.host_source = found, source_label

        result.event_count = store.count_events()

        # ---- detections ----
        if detect:
            step("running detections")
            result.detections = _run_detections(
                store, root, attack, rule_dirs, result
            )

        # ---- indicators ----
        step("extracting indicators")
        result.ioc_counts = IocSweeper(store).sweep()

        # ---- answers ----
        step("looking for the investigation questions")
        task_file, questions = find_task_file(root)
        if questions:
            result.questions = questions
            result.answers = answer_questions(store, questions, limit=3)
        else:
            if task_file is not None:
                result.warnings.append(
                    f"found {task_file.name} but no numbered questions in it"
                )
            result.overview = overview(store)

        # ---- outputs ----
        step("writing the report")
        report_path = out / f"{slug}-report.md"
        report_path.write_text(
            reporter.markdown_report(store, result.case_name), encoding="utf-8"
        )
        result.report_path = str(report_path)

        rows = timeline(store)
        result.timeline_path = reporter.to_csv(rows, out / f"{slug}-timeline.csv")

        result.notable_events = _notable_events(store)
        result.hints = sorted({a.hint for a in result.artifacts if a.hint})
    finally:
        store.close()

    return result


def _run_detections(
    store, root: Path, attack, rule_dirs: tuple[Path, ...], result: Result
) -> int:
    """YARA over artifact bytes, Sigma over normalized events."""
    from .detect.sigma_eval import SigmaEval
    from .detect.yara_scan import YaraScan

    ctx = ParseContext(evidence_root=root, attack=attack)
    added = 0

    scanner = YaraScan(rule_dirs=rule_dirs)
    ok, hint = scanner.available()
    if ok:
        for row in store.get_artifacts():
            path = Path(row["path"])
            if not path.is_file():
                continue
            for event in scanner.scan(path, ctx):
                store.add_events_bulk([event], artifact_id=row["id"])
                store.add_finding(
                    "yara", str(event.data.get("rule")), event.severity,
                    event.message, str(event.data.get("strings"))[:500],
                    artifact_id=row["id"], attck=event.attck,
                )
                added += 1
    elif hint:
        result.warnings.append(f"YARA unavailable — {hint}")

    sigma = SigmaEval(rule_dirs=rule_dirs)
    ok, hint = sigma.available()
    if ok:
        for event in sigma.evaluate(store, ctx):
            store.add_events_bulk([event])
            store.add_finding(
                "sigma", str(event.data.get("rule")), event.severity, event.message,
                f"matched event {event.data.get('matched_event_id')}",
                attck=event.attck,
            )
            added += 1
    elif hint:
        result.warnings.append(f"Sigma unavailable — {hint}")

    store.finalize()
    result.warnings.extend(ctx.hints)
    return added


def _notable_events(store, limit: int = 60) -> list[dict]:
    """High severity first, then medium — what an analyst reads before the rest."""
    rows = store.query_events(EventFilter(severity="high", limit=limit))
    if len(rows) < limit:
        rows += store.query_events(EventFilter(severity="med", limit=limit - len(rows)))
    return rows
