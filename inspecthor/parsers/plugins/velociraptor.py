"""Velociraptor offline collector results.

The collector writes a zip whose ``results/`` directory holds one JSON-lines file
per artifact — ``Windows.KapeFiles.Targets.json``,
``Windows.System.Pslist.json`` — alongside an ``uploads/`` tree of collected
files. The uploads are ordinary artifacts and the existing parsers already handle
them once the zip is open; the results are the part that was being read as text.

**There is no fixed schema, and that is the whole design problem.** A Velociraptor
artifact is a VQL query and its columns are whatever the query selected, so no
table of specs can cover them the way the EZTools one does. What *is* stable is
the container: newline-delimited JSON objects under ``results/``, and a small
vocabulary of timestamp column names that the standard artifact library reuses
(``Mtime``, ``Btime``, ``Timestamp``, ``EventTime``, ``_ts``).

So this parser is deliberately generic: find a timestamp by name, keep every
scalar column as ``data``, and name the event after the artifact. An analyst
filtering on ``source_artifact`` gets exactly the Velociraptor artifact name back,
which is the handle they already think in.

**A row with no recognisable timestamp is counted and reported, not dropped
silently.** Plenty of Velociraptor artifacts are inventories with no time at all —
``Pslist`` is a snapshot — and an analyst needs to know the rows were seen and
skipped rather than assume the artifact was empty.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from ...models import Event, ParseContext
from .._pathscore import score_path
from ..base import Parser, register

_MIN_YEAR, _MAX_YEAR = 1980, 2100
_MAX_PROBE_BYTES = 256 * 1024

# Timestamp column names the standard artifact library reuses, most specific
# first. Velociraptor writes RFC3339 strings for these.
_TIME_KEYS = (
    "Timestamp", "timestamp", "EventTime", "event_time", "_ts", "Time",
    "Mtime", "mtime", "Btime", "btime", "Ctime", "ctime", "Atime", "atime",
    "Created", "LastWriteTime", "StartTime", "CreateTime", "TimeGenerated",
)

# Columns that usually hold the path or name a row is about.
_SUBJECT_KEYS = (
    "OSPath", "FullPath", "Path", "_Source", "Name", "Filename", "File",
    "Exe", "CommandLine", "ImagePath",
)

def parse_time(value) -> Optional[datetime]:
    """One Velociraptor timestamp. RFC3339, or epoch seconds."""
    if value is None or value == "" or value is False:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e12:          # milliseconds
            seconds /= 1000.0
        try:
            stamp = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return stamp if _MIN_YEAR <= stamp.year <= _MAX_YEAR else None
    text = str(value).strip()
    if not text or text.startswith("0001-01-01"):
        return None
    try:
        # Go's RFC3339Nano can carry more than 6 fractional digits.
        if "." in text:
            head, _, rest = text.partition(".")
            digits = ""
            while rest and rest[0].isdigit():
                digits, rest = digits + rest[0], rest[1:]
            text = f"{head}.{digits[:6]}{rest}"
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp if _MIN_YEAR <= stamp.year <= _MAX_YEAR else None


def artifact_name(path: Path) -> str:
    """``Windows.System.Pslist.json`` -> ``Windows.System.Pslist``."""
    stem = path.stem
    for suffix in ("_results", "-results"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    return stem or "velociraptor"


def subject_of(row: dict) -> str:
    for key in _SUBJECT_KEYS:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def score_row(subject: str) -> tuple[str, list[str], str]:
    """Defers to the shared path scorer: a Velociraptor row holds a path like any
    other source, and a file that is a finding from the $MFT must be a finding
    here too."""
    return score_path(subject)


def looks_like_results(path: Path) -> bool:
    """Newline-delimited JSON objects, from a Velociraptor results tree.

    The directory is part of the signal: ``results/`` is where the collector puts
    them, and a bare .json elsewhere is far more likely to be something else.
    """
    parts = {p.lower() for p in path.parts}
    in_results = "results" in parts or "uploads" in parts
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline(_MAX_PROBE_BYTES).strip()
            second = fh.readline(_MAX_PROBE_BYTES).strip()
    except OSError:
        return False
    if not first.startswith("{"):
        return False
    try:
        row = json.loads(first)
    except ValueError:
        return False
    if not isinstance(row, dict):
        return False
    # A second object on its own line is what makes it JSONL rather than one
    # pretty-printed document.
    jsonl = bool(second) and second.startswith("{")
    if in_results:
        return True
    # Outside results/, require both JSONL shape and a recognisable timestamp,
    # so this does not claim every JSON file on the system.
    return jsonl and any(key in row for key in _TIME_KEYS)


@register
class VelociraptorParser(Parser):
    """Velociraptor offline collector results (JSON lines)."""

    name = "velociraptor"
    display = "Velociraptor results"
    category = "windows"
    path_globs = ("*.json", "*.jsonl")
    requires = ""
    install_hint = ""

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        if path.suffix.lower() not in (".json", ".jsonl"):
            return 0.0
        return self.CONF_MAGIC if looks_like_results(path) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        artifact = artifact_name(path)
        common = dict(source_artifact=f"{self.name}/{artifact}",
                      artifact_path=str(path), parser=self.name)

        emitted = rows = undated = malformed = 0
        earliest = latest = None

        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            ctx.hint(f"{path.name}: cannot read ({exc})")
            return

        with handle:
            for line in handle:
                if emitted >= ctx.max_records:
                    ctx.hint(f"{path.name}: stopped at the {ctx.max_records} "
                             f"record cap after {rows:,} rows")
                    break
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                rows += 1
                try:
                    row = json.loads(line)
                except ValueError:
                    malformed += 1
                    continue
                if not isinstance(row, dict):
                    malformed += 1
                    continue

                when = None
                for key in _TIME_KEYS:
                    if key in row:
                        when = parse_time(row[key])
                        if when is not None:
                            break
                if when is None:
                    undated += 1
                    continue
                if earliest is None or when < earliest:
                    earliest = when
                if latest is None or when > latest:
                    latest = when

                subject = subject_of(row)
                severity, tags, why = score_row(subject)
                scalars = {k: v for k, v in row.items()
                           if isinstance(v, (str, int, float, bool)) and v != ""}

                bits = [f"{k}: {v}" for k, v in list(scalars.items())[:6]
                        if k not in _TIME_KEYS]
                details = subject or artifact
                if bits:
                    details += " ¦ " + " ¦ ".join(bits)
                if why:
                    details += f" ¦ Why: {why}"

                emitted += 1
                yield ctx.event(
                    timestamp=when,
                    timestamp_desc=f"{artifact} row",
                    event_type="collector_row",
                    title=artifact,
                    details=details,
                    message="",
                    data=scalars,
                    user=str(row.get("User") or row.get("Username") or ""),
                    host=str(row.get("Hostname") or row.get("Fqdn") or ""),
                    severity=severity,
                    tags=tags,
                    **common,
                )

        if not rows:
            ctx.hint(f"{path.name}: no rows in this Velociraptor result")
            return

        span = ""
        if earliest and latest:
            span = f" ¦ Span: {earliest.date()} to {latest.date()}"
        yield ctx.event(
            timestamp=latest or datetime.now(timezone.utc),
            timestamp_desc="Velociraptor artifact summary",
            event_type="artifact_summary",
            title=f"{artifact} ingested",
            details=f"Rows: {rows:,} ¦ Events: {emitted:,}{span}",
            message="",
            data={"artifact": artifact, "rows": rows, "events": emitted},
            severity="info",
            **common,
        )
        if undated:
            ctx.hint(
                f"{path.name}: {undated:,} of {rows:,} row(s) carried no timestamp "
                "— this artifact is an inventory, not a timeline"
            )
        if malformed:
            ctx.hint(f"{path.name}: {malformed:,} line(s) were not JSON objects")
