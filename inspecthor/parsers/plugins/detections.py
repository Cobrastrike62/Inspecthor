"""Hayabusa and Chainsaw output — another tool's detections, not raw evidence.

Both run Sigma over Windows event logs and emit a list of hits. Ingesting them
puts someone else's conclusions on the same timeline as the raw artifacts, which
is the point: an analyst who already ran Hayabusa over a collection should see
those hits beside the ``$MFT`` and the prefetch rather than in a second window.

**Their severity is carried across, not recomputed.** Hayabusa's ``Level`` and
Chainsaw's rule level are the rule author's judgement about that specific
detection, and this tool has strictly less information than they did — it has the
one row, they had the rule. Mapping ``critical``/``high`` onto ours and leaving it
alone is the honest move; second-guessing it would be inventing a number.

**They are tagged as third-party detections and never silently promoted to
findings.** A detection is evidence that a rule fired, which is not the same as
evidence that something happened — rules false-positive, and a hit that arrives
pre-labelled ``critical`` would otherwise dominate triage ahead of artifacts the
analyst can actually verify. ``tags`` carries the tool name so they can be
filtered in or out in one query.
"""
from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from ...models import Event, ParseContext
from ..base import Parser, register

_MIN_YEAR, _MAX_YEAR = 1980, 2100
_MAX_HEADER_BYTES = 64 * 1024

# Both tools speak the Sigma level vocabulary. Ours has no 'critical'.
_LEVELS = {
    "crit": "high", "critical": "high", "high": "high",
    "med": "med", "medium": "med",
    "low": "low", "informational": "info", "info": "info", "": "info",
}


@dataclass(frozen=True)
class Shape:
    name: str
    display: str
    must: tuple[str, ...]
    time_col: str
    rule_col: str
    level_col: str
    detail: tuple[str, ...]


SHAPES: tuple[Shape, ...] = (
    Shape(
        name="hayabusa", display="Hayabusa",
        must=("timestamp", "ruletitle", "level"),
        time_col="timestamp", rule_col="ruletitle", level_col="level",
        detail=("computer", "channel", "eventid", "recordid", "details",
                "rulefile", "mitretactics"),
    ),
    Shape(
        name="chainsaw", display="Chainsaw",
        must=("timestamp", "detections", "path"),
        time_col="timestamp", rule_col="detections", level_col="level",
        detail=("path", "event_id", "computer", "channel", "record_id"),
    ),
)


def parse_time(value) -> Optional[datetime]:
    """A detection timestamp. Both tools write ISO-8601, usually with an offset."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    if "." in text:
        head, _, rest = text.partition(".")
        digits = ""
        while rest and rest[0].isdigit():
            digits, rest = digits + rest[0], rest[1:]
        text = f"{head}.{digits[:6]}{rest}"
    # Hayabusa's default profile writes "2025-09-01 08:47:30.123 +00:00".
    text = text.replace(" +", "+").replace(" -", "-", 1) if "+" in text else text
    for attempt in (text, text.replace(" ", "T", 1)):
        try:
            stamp = datetime.fromisoformat(attempt.replace("Z", "+00:00"))
        except ValueError:
            continue
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp if _MIN_YEAR <= stamp.year <= _MAX_YEAR else None
    return None


def map_level(raw: str) -> str:
    """Their vocabulary onto ours. Unknown levels stay 'info' rather than guess."""
    return _LEVELS.get((raw or "").strip().lower(), "info")


def _read_header(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            first = fh.readline(_MAX_HEADER_BYTES)
    except OSError:
        return []
    if not first or "," not in first:
        return []
    try:
        return [c.strip().lower().replace(" ", "") for c in next(csv.reader([first]))]
    except (csv.Error, StopIteration):
        return []


def match_shape(columns: list[str]) -> Optional[Shape]:
    present = set(columns)
    for shape in SHAPES:
        if all(column in present for column in shape.must):
            return shape
    return None


@register
class DetectionCsvParser(Parser):
    """Hayabusa / Chainsaw detection output."""

    name = "detections"
    display = "Third-party detections (Hayabusa, Chainsaw)"
    category = "windows"
    path_globs = ("*.csv",)
    requires = ""
    install_hint = ""

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        if path.suffix.lower() != ".csv":
            return 0.0
        columns = _read_header(path)
        return self.CONF_MAGIC if columns and match_shape(columns) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        columns = _read_header(path)
        shape = match_shape(columns) if columns else None
        if shape is None:
            ctx.hint(f"{path.name}: not a recognised detection export")
            return

        if csv.field_size_limit() < (1 << 24):
            try:
                csv.field_size_limit(1 << 24)
            except OverflowError:
                csv.field_size_limit(sys.maxsize)

        common = dict(source_artifact=f"{self.name}/{shape.name}",
                      artifact_path=str(path), parser=self.name)
        emitted = rows = undated = 0
        earliest = latest = None
        by_level: dict[str, int] = {}

        try:
            handle = path.open("r", encoding="utf-8-sig", errors="replace", newline="")
        except OSError as exc:
            ctx.hint(f"{path.name}: cannot read ({exc})")
            return

        with handle:
            reader = csv.DictReader(handle)
            iterator = iter(reader)
            while True:
                if emitted >= ctx.max_records:
                    ctx.hint(f"{path.name}: stopped at the {ctx.max_records} "
                             f"record cap after {rows:,} rows")
                    break
                try:
                    raw = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    ctx.hint(f"{path.name}: stopped early on a malformed row "
                             f"at {rows:,}")
                    break
                rows += 1
                row = {(k or "").strip().lower().replace(" ", ""): (v or "")
                       for k, v in raw.items() if k is not None}

                when = parse_time(row.get(shape.time_col, ""))
                if when is None:
                    undated += 1
                    continue
                if earliest is None or when < earliest:
                    earliest = when
                if latest is None or when > latest:
                    latest = when

                rule = row.get(shape.rule_col, "").strip() or "detection"
                severity = map_level(row.get(shape.level_col, ""))
                by_level[severity] = by_level.get(severity, 0) + 1

                bits = [f"{c}: {row[c]}" for c in shape.detail
                        if row.get(c, "").strip()]
                details = rule
                if bits:
                    details += " ¦ " + " ¦ ".join(bits[:6])

                emitted += 1
                yield ctx.event(
                    timestamp=when,
                    timestamp_desc=f"{shape.display} detection",
                    event_type="detection",
                    title=f"{shape.display}: {rule}",
                    details=details,
                    message="",
                    data={k: v for k, v in row.items() if v},
                    channel=row.get("channel", ""),
                    event_id=(row.get("eventid") or row.get("event_id") or "") or None,
                    host=row.get("computer", ""),
                    severity=severity,
                    tags=["third_party_detection", shape.name],
                    **common,
                )

        if not rows:
            ctx.hint(f"{path.name}: {shape.display} export had no rows")
            return

        span = ""
        if earliest and latest:
            span = f" ¦ Span: {earliest.date()} to {latest.date()}"
        breakdown = ", ".join(f"{n} {lvl}" for lvl, n in sorted(by_level.items()))
        yield ctx.event(
            timestamp=latest or datetime.now(timezone.utc),
            timestamp_desc=f"{shape.display} summary",
            event_type="artifact_summary",
            title=f"{shape.display} detections ingested",
            details=(f"Rows: {rows:,} ¦ Events: {emitted:,}"
                     f"{' ¦ ' + breakdown if breakdown else ''}{span}"),
            message="",
            data={"tool": shape.name, "rows": rows, "events": emitted,
                  "levels": by_level},
            severity="info",
            **common,
        )
        if undated:
            ctx.hint(f"{path.name}: {undated:,} row(s) carried no usable timestamp")
