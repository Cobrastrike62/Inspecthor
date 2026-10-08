"""Plaso / log2timeline output — the l2tcsv and psort JSON-line formats.

Plaso is the other half of the DFIR tooling world: where KAPE collects and EZTools
parses per artifact, ``log2timeline`` builds one super-timeline across all of them.
An analyst who already has a ``.plaso`` processed into CSV should not have to
re-collect to use this tool, and the output is a timeline already, so most of the
work is mapping its vocabulary onto ours.

**l2tcsv splits the timestamp across three columns.** ``date``, ``time`` and
``timezone`` are separate fields, which is why this cannot be another entry in the
EZTools spec table — that table assumes one column is one timestamp. The timezone
column carries a name (``UTC``, ``America/Chicago``) and occasionally an offset.

**``desc`` is the evidence and ``short`` is a truncation of it.** Plaso writes both;
``short`` is a prefix of ``desc`` far more often than not, so storing both doubles
the text with no gain. ``desc`` is kept, ``short`` only when it is genuinely
different.

**The MACB column means the same thing it does in a bodyfile**, so it is reported
the same way rather than invented afresh — an analyst reading a mixed case should
not have to learn two notations for one idea.

CONSTRAINT: a super-timeline is often millions of rows and is nearly all operating
system. Nothing here promotes on volume; severity comes from the path heuristics
shared with the other filesystem parsers, and everything else stays ``info``.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from ...models import Event, ParseContext
from .._pathscore import score_path
from ..base import Parser, register

# The l2tcsv header, in order. Plaso has written this since 2012.
L2T_COLUMNS = (
    "date", "time", "timezone", "macb", "source", "sourcetype", "type", "user",
    "host", "short", "desc", "version", "filename", "inode", "notes", "format",
    "extra",
)

_MIN_YEAR, _MAX_YEAR = 1980, 2100
_MAX_HEADER_BYTES = 64 * 1024

# Timestamp keys psort's JSON lines use, most specific first.
_JSON_TIME_KEYS = (
    "timestamp", "datetime", "timestamp_desc_time", "written_time",
    "creation_time", "modification_time", "access_time", "event_time",
)

_MACB_WORDS = {"m": "Modified", "a": "Accessed", "c": "Changed", "b": "Created"}


def parse_l2t_time(date: str, time_: str, zone: str) -> Optional[datetime]:
    """``10/15/2025`` + ``08:47:30`` + ``UTC`` into one aware datetime.

    Plaso writes US-ordered dates in l2tcsv. The timezone column is a name, and
    naming a zone this tool cannot resolve is not a reason to drop the row — the
    time is still the time, so it falls back to UTC and says nothing, because a
    per-row warning on a million-row timeline is noise.
    """
    date, time_, zone = (date or "").strip(), (time_ or "").strip(), (zone or "").strip()
    if not date or not time_:
        return None
    stamp = None
    for fmt in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            stamp = datetime.strptime(f"{date} {time_}", fmt)
            break
        except ValueError:
            continue
    if stamp is None:
        return None
    if not (_MIN_YEAR <= stamp.year <= _MAX_YEAR):
        return None

    tzinfo = timezone.utc
    if zone and zone.upper() not in ("UTC", "GMT", "Z"):
        if zone.startswith(("+", "-")) and len(zone) >= 5:
            try:
                sign = -1 if zone[0] == "-" else 1
                hours, minutes = int(zone[1:3]), int(zone[3:5].lstrip(":"))
                tzinfo = timezone(sign * timedelta(hours=hours, minutes=minutes))
            except ValueError:
                tzinfo = timezone.utc
        else:
            try:
                from zoneinfo import ZoneInfo
                tzinfo = ZoneInfo(zone)
            except Exception:
                tzinfo = timezone.utc
    return stamp.replace(tzinfo=tzinfo)


def parse_json_time(value) -> Optional[datetime]:
    """A psort JSON timestamp: microseconds since epoch, or an ISO string."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        # Plaso stores microseconds since 1970. Anything that small in seconds
        # would be 1970 itself, which is never a real event time.
        if seconds > 1e11:
            seconds /= 1_000_000.0
        try:
            stamp = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return stamp if _MIN_YEAR <= stamp.year <= _MAX_YEAR else None
    text = str(value).strip()
    if not text:
        return None
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp if _MIN_YEAR <= stamp.year <= _MAX_YEAR else None


def macb_description(macb: str) -> str:
    """``M.C.`` -> ``Modified/Changed``. Same notation as the bodyfile parser."""
    flags = [c for c in (macb or "").lower() if c in _MACB_WORDS]
    return "/".join(_MACB_WORDS[f] for f in flags) or "Timeline entry"


def score_entry(path: str, description: str) -> tuple[str, list[str], str]:
    """``(severity, tags, why)``. A super-timeline is nearly all operating system,
    so this defers entirely to the shared path scorer rather than inventing a
    second set of thresholds that would disagree with the other parsers."""
    return score_path(path)


def _read_header(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            first = fh.readline(_MAX_HEADER_BYTES)
    except OSError:
        return []
    if not first or "," not in first:
        return []
    try:
        return [c.strip().lower() for c in next(csv.reader([first]))]
    except (csv.Error, StopIteration):
        return []


def _looks_like_psort_json(path: Path) -> bool:
    """First line is a JSON object carrying Plaso's own field names."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline(_MAX_HEADER_BYTES).strip()
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
    # data_type is Plaso's own discriminator and appears on every event.
    return "data_type" in row or ("timestamp_desc" in row and "timestamp" in row)


@register
class PlasoParser(Parser):
    """Plaso super-timeline (l2tcsv, or psort JSON lines)."""

    name = "plaso"
    display = "Plaso timeline"
    category = "filesystem"
    path_globs = ("*.csv", "*.json", "*.jsonl")
    requires = ""
    install_hint = ""

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            columns = _read_header(path)
            # The first eleven columns are fixed and in order; matching the set
            # is enough and tolerates the trailing columns plaso has added.
            if columns[:11] == list(L2T_COLUMNS[:11]):
                return self.CONF_MAGIC
            return 0.0
        if suffix in (".json", ".jsonl") and _looks_like_psort_json(path):
            return self.CONF_MAGIC
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        if path.suffix.lower() == ".csv":
            yield from self._parse_l2tcsv(path, ctx)
        else:
            yield from self._parse_json(path, ctx)

    # ---- l2tcsv ----

    def _parse_l2tcsv(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        if csv.field_size_limit() < (1 << 24):
            try:
                csv.field_size_limit(1 << 24)
            except OverflowError:
                csv.field_size_limit(sys.maxsize)

        common = dict(source_artifact=f"{self.name}/l2tcsv",
                      artifact_path=str(path), parser=self.name)
        emitted = rows = undated = 0
        earliest = latest = None

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
                row = {(k or "").strip().lower(): (v or "")
                       for k, v in raw.items() if k is not None}

                when = parse_l2t_time(row.get("date", ""), row.get("time", ""),
                                      row.get("timezone", ""))
                if when is None:
                    undated += 1
                    continue
                if earliest is None or when < earliest:
                    earliest = when
                if latest is None or when > latest:
                    latest = when

                filename = row.get("filename", "").strip()
                description = row.get("desc", "").strip()
                short = row.get("short", "").strip()
                macb = row.get("macb", "").strip()
                source_type = row.get("sourcetype", "").strip() or row.get("source", "")

                severity, tags, why = score_entry(filename, description)
                details = description or short or filename
                bits = []
                if macb:
                    bits.append(f"MACB: {macb}")
                if source_type:
                    bits.append(f"Source: {source_type}")
                if filename:
                    bits.append(f"File: {filename}")
                if why:
                    bits.append(f"Why: {why}")
                if bits:
                    details = f"{details} ¦ " + " ¦ ".join(bits)

                data = {k: v for k, v in row.items() if v}
                # short is a truncation of desc far more often than not.
                if short and description.startswith(short[:40]):
                    data.pop("short", None)

                emitted += 1
                yield ctx.event(
                    timestamp=when,
                    timestamp_desc=macb_description(macb),
                    event_type="timeline_entry",
                    title=(source_type or "Timeline entry"),
                    details=details,
                    message="",
                    data=data,
                    user=row.get("user", ""),
                    host=row.get("host", ""),
                    severity=severity,
                    tags=tags,
                    **common,
                )

        yield from self._summary(ctx, common, "l2tcsv", rows, emitted,
                                 earliest, latest, undated, path)

    # ---- psort JSON lines ----

    def _parse_json(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        common = dict(source_artifact=f"{self.name}/json",
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
                if not line or line in ("[", "]", "{", "}"):
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
                for key in _JSON_TIME_KEYS:
                    when = parse_json_time(row.get(key))
                    if when is not None:
                        break
                if when is None:
                    undated += 1
                    continue
                if earliest is None or when < earliest:
                    earliest = when
                if latest is None or when > latest:
                    latest = when

                filename = str(row.get("filename") or row.get("display_name") or "")
                description = str(row.get("message") or row.get("display_name") or "")
                data_type = str(row.get("data_type") or "")
                severity, tags, why = score_entry(filename, description)

                details = description or filename or data_type
                if why:
                    details += f" ¦ Why: {why}"

                emitted += 1
                yield ctx.event(
                    timestamp=when,
                    timestamp_desc=str(row.get("timestamp_desc") or "Timeline entry"),
                    event_type="timeline_entry",
                    title=data_type or "Timeline entry",
                    details=details,
                    message="",
                    data={k: v for k, v in row.items()
                          if isinstance(v, (str, int, float, bool)) and v != ""},
                    user=str(row.get("username") or ""),
                    host=str(row.get("hostname") or ""),
                    severity=severity,
                    tags=tags,
                    **common,
                )

        if malformed:
            ctx.hint(f"{path.name}: {malformed:,} line(s) were not JSON objects")
        yield from self._summary(ctx, common, "psort JSON", rows, emitted,
                                 earliest, latest, undated, path)

    # ---- shared ----

    @staticmethod
    def _summary(ctx, common, label, rows, emitted, earliest, latest, undated,
                 path) -> Iterator[Event]:
        if not rows:
            ctx.hint(f"{path.name}: {label} export had no rows")
            return
        span = ""
        if earliest and latest:
            span = f" ¦ Span: {earliest.date()} to {latest.date()}"
        yield ctx.event(
            timestamp=latest or datetime.now(timezone.utc),
            timestamp_desc="Plaso timeline summary",
            event_type="artifact_summary",
            title=f"Plaso {label} ingested",
            details=f"Rows: {rows:,} ¦ Events: {emitted:,}{span}",
            message="",
            data={"format": label, "rows": rows, "events": emitted},
            severity="info",
            **common,
        )
        if undated:
            ctx.hint(f"{path.name}: {undated:,} row(s) carried no usable timestamp")
