"""Rendering and export.

Two audiences, two shapes: rich tables for a human reading the terminal, and
machine formats for tools that do timeline analysis better than a terminal can
(Timesketch, plaso, a spreadsheet).

The Timesketch and plaso column contracts are fixed by those tools, so they are
spelled out explicitly here rather than derived — a renamed column silently breaks
an import days later.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from rich.table import Table
from rich.text import Text

# Severity -> rich style. High must be unmissable in a wall of rows.
SEV_STYLE = {"high": "bold red", "med": "yellow", "info": "dim"}
SEV_MARK = {"high": "!!", "med": "!", "info": " "}


def _t(value: Any) -> Text:
    """Wrap an evidence-derived value so rich never parses it as markup.

    CONSTRAINT: every table cell built from evidence goes through here. A command
    line, registry value, or filename containing '[...]' would otherwise be read
    as a style tag — silently swallowing part of the value (and letting the
    contents of the evidence influence terminal rendering).
    """
    return Text("" if value is None else str(value))

# Rows rendered on screen before truncating. A timeline can be 100k rows; a
# terminal is not the right place to page through them, an export is.
SCREEN_ROWS = 200

# plaso's l2tcsv is a fixed 17-column format.
L2TCSV_COLUMNS = (
    "date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user",
    "host", "short", "desc", "version", "filename", "inode", "notes", "format",
    "extra",
)

# Timesketch requires these three; everything else is optional enrichment.
TIMESKETCH_COLUMNS = (
    "message", "datetime", "timestamp_desc", "data_type", "host", "user",
    "source", "tag", "attck", "severity",
)


def _sev(row: dict) -> str:
    return str(row.get("severity") or "info")


def timeline_table(rows: Sequence[dict], title: str = "Timeline") -> tuple[Table, int]:
    """Build a rich timeline table. Returns ``(table, hidden_count)``."""
    table = Table(title=title, header_style="bold", expand=True)
    table.add_column("", width=2, no_wrap=True)
    table.add_column("When (UTC)", width=19, no_wrap=True)
    table.add_column("Host", max_width=14, no_wrap=True)
    table.add_column("User", max_width=16, no_wrap=True)
    table.add_column("Type", max_width=20, no_wrap=True)
    table.add_column("Source", max_width=16, no_wrap=True)
    table.add_column("Message", overflow="fold")

    shown = rows[:SCREEN_ROWS]
    for row in shown:
        severity = _sev(row)
        table.add_row(
            SEV_MARK.get(severity, " "),
            _t(row.get("ts")),
            _t(row.get("host")),
            _t(row.get("user")),
            _t(row.get("event_type")),
            _t(row.get("source_artifact")),
            _t(row.get("message")),
            style=SEV_STYLE.get(severity),
        )
    return table, max(0, len(rows) - len(shown))


def artifacts_table(rows: Sequence[dict]) -> Table:
    table = Table(title="Artifacts", header_style="bold", expand=True)
    for name, width in (
        ("id", 4), ("kind", 10), ("parser", 14), ("status", 11), ("events", 8)
    ):
        table.add_column(name, width=width, no_wrap=True)
    table.add_column("path", overflow="fold")
    status_style = {
        "parsed": None, "error": "red", "unsupported": "yellow", "skipped": "dim",
    }
    for row in rows:
        table.add_row(
            _t(row.get("id", "")), _t(row.get("kind")),
            _t(row.get("parser") or "-"), _t(row.get("status")),
            _t(row.get("event_count") or 0), _t(row.get("path")),
            style=status_style.get(str(row.get("status")), None),
        )
    return table


def iocs_table(rows: Sequence[dict]) -> Table:
    table = Table(title="Indicators", header_style="bold", expand=True)
    table.add_column("type", width=8, no_wrap=True)
    table.add_column("count", width=6, no_wrap=True)
    table.add_column("value", overflow="fold")
    table.add_column("tags", max_width=28, overflow="fold")
    for row in rows:
        tags = row.get("tags") or []
        noisy = any(t in ("private", "allowlisted", "loopback", "reserved") for t in tags)
        table.add_row(
            _t(row.get("type")), _t(row.get("count") or 0),
            _t(row.get("value")), _t(", ".join(tags)),
            style="dim" if noisy else None,
        )
    return table


def findings_table(rows: Sequence[dict]) -> Table:
    table = Table(title="Detections", header_style="bold", expand=True)
    table.add_column("", width=2, no_wrap=True)
    table.add_column("engine", width=9, no_wrap=True)
    table.add_column("rule", max_width=34, overflow="fold")
    table.add_column("ATT&CK", max_width=18, no_wrap=True)
    table.add_column("detail", overflow="fold")
    for row in rows:
        severity = _sev(row)
        table.add_row(
            SEV_MARK.get(severity, " "), _t(row.get("engine")),
            _t(row.get("rule")), _t(", ".join(row.get("attck") or [])),
            _t(row.get("detail") or row.get("title") or ""),
            style=SEV_STYLE.get(severity),
        )
    return table


def candidates_table(candidates: Sequence[Any]) -> Table:
    """Sherlock candidate answers. Framed as candidates, never as answers."""
    table = Table(
        title="Candidate answers — verify before submitting",
        header_style="bold", expand=True,
    )
    table.add_column("conf", width=5, no_wrap=True)
    table.add_column("what", max_width=26, no_wrap=True)
    table.add_column("answer", overflow="fold")
    table.add_column("from", max_width=30, overflow="fold")
    for cand in candidates:
        confidence = float(getattr(cand, "confidence", 0.0))
        style = "bold green" if confidence >= 0.8 else (None if confidence >= 0.5 else "dim")
        table.add_row(
            f"{confidence:.2f}", _t(getattr(cand, "label", "")),
            _t(getattr(cand, "answer", "")),
            _t(f"{getattr(cand, 'source', '')} — {getattr(cand, 'why', '')}".strip(" —")),
            style=style,
        )
    return table


# ---- exporters ----


def _split_ts(ts: str) -> tuple[str, str]:
    """'2024-03-01 12:00:00' -> ('03/01/2024', '12:00:00') for l2tcsv."""
    text = str(ts or "")
    date_part, _, time_part = text.partition(" ")
    try:
        parsed = datetime.strptime(date_part, "%Y-%m-%d")
        return parsed.strftime("%m/%d/%Y"), time_part or "00:00:00"
    except ValueError:
        return date_part, time_part or "00:00:00"


def to_csv(rows: Iterable[dict], path: str | Path) -> str:
    """Native column dump — the format a spreadsheet wants."""
    rows = list(rows)
    path = Path(path)
    columns = (
        "id", "ts", "ts_desc", "host", "user", "event_type", "source_artifact",
        "parser", "event_id", "severity", "message", "data", "tags", "attck",
        "artifact_path",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = dict(row)
            for key in ("data", "tags", "attck"):
                if isinstance(out.get(key), (dict, list)):
                    out[key] = json.dumps(out[key], ensure_ascii=False)
            writer.writerow(out)
    return str(path)


def to_jsonl(rows: Iterable[dict], path: str | Path) -> str:
    """One JSON object per line — streamable, and what the Matrix export reads."""
    path = Path(path)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return str(path)


def to_timesketch_csv(rows: Iterable[dict], path: str | Path) -> str:
    """Timesketch import format.

    ``message``, ``datetime`` and ``timestamp_desc`` are mandatory and must carry
    those exact names; the rest is enrichment Timesketch will index as attributes.
    """
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(TIMESKETCH_COLUMNS))
        writer.writeheader()
        for row in rows:
            tags = row.get("tags") or []
            attck = row.get("attck") or []
            writer.writerow({
                "message": row.get("message") or "",
                # Timesketch parses ISO8601; the store keeps UTC so append the Z.
                "datetime": f"{row.get('ts', '')}".replace(" ", "T") + "Z",
                "timestamp_desc": row.get("ts_desc") or "Event Logged",
                "data_type": row.get("event_type") or "generic",
                "host": row.get("host") or "",
                "user": row.get("user") or "",
                "source": row.get("source_artifact") or "",
                "tag": " ".join(tags) if isinstance(tags, list) else str(tags),
                "attck": " ".join(attck) if isinstance(attck, list) else str(attck),
                "severity": row.get("severity") or "info",
            })
    return str(path)


def to_l2tcsv(rows: Iterable[dict], path: str | Path) -> str:
    """plaso l2tcsv — the 17 fixed columns, in order."""
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(L2TCSV_COLUMNS))
        writer.writeheader()
        for row in rows:
            date_part, time_part = _split_ts(row.get("ts", ""))
            data = row.get("data") or {}
            message = str(row.get("message") or "")
            writer.writerow({
                "date": date_part,
                "time": time_part,
                "timezone": "UTC",
                # MACB only means something for filesystem events; MFT parsers set
                # it in data, everything else gets the empty marker plaso expects.
                "MACB": str(data.get("macb", "....")) if isinstance(data, dict) else "....",
                "source": row.get("parser") or "inspecthor",
                "sourcetype": row.get("source_artifact") or "",
                "type": row.get("ts_desc") or "",
                "user": row.get("user") or "",
                "host": row.get("host") or "",
                "short": message[:80],
                "desc": message,
                "version": "2",
                "filename": row.get("artifact_path") or "",
                "inode": "-",
                "notes": " ".join(row.get("attck") or []),
                "format": row.get("parser") or "",
                "extra": json.dumps(data, ensure_ascii=False, default=str)
                if isinstance(data, (dict, list)) else str(data),
            })
    return str(path)


EXPORTERS = {
    "csv": to_csv,
    "jsonl": to_jsonl,
    "timesketch": to_timesketch_csv,
    "l2tcsv": to_l2tcsv,
}


def export(rows: Iterable[dict], path: str | Path, fmt: str = "csv") -> str:
    """Dispatch to an exporter by name."""
    try:
        func = EXPORTERS[fmt]
    except KeyError:
        raise ValueError(
            f"unknown format {fmt!r} — choose from {', '.join(sorted(EXPORTERS))}"
        ) from None
    return func(rows, path)


# ---- markdown report ----


def markdown_report(store, case_name: str = "", limit: int = 200) -> str:
    """A case writeup: what was ingested, what stood out, what to chase.

    Ordered by what an analyst reads first — the high-severity events and the
    detections, not the 100k-row timeline.
    """
    from .models import EventFilter

    name = case_name or store.get_meta("case_name") or Path(store.db_path).stem
    artifacts = store.get_artifacts()
    parsed = [a for a in artifacts if a.get("status") == "parsed"]
    skipped = [a for a in artifacts if a.get("status") in ("unsupported", "error")]
    total_events = store.count_events()
    high = store.query_events(EventFilter(severity="high", limit=limit))
    findings = store.get_findings()
    iocs = store.get_iocs()
    interesting = [
        i for i in iocs
        if not any(t in ("private", "allowlisted", "loopback", "reserved")
                   for t in (i.get("tags") or []))
    ]
    techniques = store.attck_summary()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    out: list[str] = [
        f"# Case report — {name}",
        "",
        f"Generated {generated} UTC by inspecthor. All times UTC.",
        "",
        "## Summary",
        "",
        f"- Artifacts ingested: **{len(parsed)}** parsed"
        + (f", {len(skipped)} skipped/errored" if skipped else ""),
        f"- Events: **{total_events}**",
        f"- High-severity events: **{len(high)}**",
        f"- Detections: **{len(findings)}**",
        f"- Indicators: **{len(iocs)}** ({len(interesting)} after filtering known-noise)",
        "",
    ]

    if techniques:
        out += ["## ATT&CK techniques observed", "", "| Technique | Events |", "|---|---|"]
        out += [f"| {tid} | {count} |" for tid, count in techniques[:30]]
        out += [""]

    if high:
        out += ["## High-severity timeline", "", "| When (UTC) | Host | User | Type | Message |",
                "|---|---|---|---|---|"]
        for row in high:
            message = str(row.get("message") or "").replace("|", "\\|")
            out.append(
                f"| {row.get('ts','')} | {row.get('host','')} | {row.get('user','')} "
                f"| {row.get('event_type','')} | {message} |"
            )
        out += [""]

    if findings:
        out += ["## Detections", "", "| Engine | Rule | Severity | ATT&CK | Detail |",
                "|---|---|---|---|---|"]
        for row in findings[:limit]:
            detail = str(row.get("detail") or row.get("title") or "").replace("|", "\\|")
            out.append(
                f"| {row.get('engine','')} | {row.get('rule','')} | {row.get('severity','')} "
                f"| {' '.join(row.get('attck') or [])} | {detail[:200]} |"
            )
        out += [""]

    if interesting:
        out += ["## Indicators", "", "| Type | Value | Sightings |", "|---|---|---|"]
        out += [
            f"| {i.get('type','')} | `{i.get('value','')}` | {i.get('count',0)} |"
            for i in interesting[:limit]
        ]
        out += [""]

    out += ["## Artifacts", "", "| Kind | Parser | Status | Events | Path |", "|---|---|---|---|---|"]
    for row in artifacts:
        out.append(
            f"| {row.get('kind','')} | {row.get('parser') or '-'} | {row.get('status','')} "
            f"| {row.get('event_count',0)} | `{row.get('path','')}` |"
        )
    out += [""]

    if skipped:
        out += ["### Not parsed", ""]
        for row in skipped:
            reason = row.get("error") or row.get("hint") or row.get("status")
            out.append(f"- `{row.get('path','')}` — {reason}")
        out += [""]

    return "\n".join(out)
