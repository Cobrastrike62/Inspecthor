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
import re
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from rich.table import Table
from rich.text import Text

from .models import LEVEL_MARK, LEVEL_RANK, LEVEL_STYLE

# Five levels, from the single definition in models so nothing drifts.
SEV_STYLE = LEVEL_STYLE
SEV_MARK = LEVEL_MARK


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
    """Build a rich timeline table. Returns ``(table, hidden_count)``.

    Shows Title and Details rather than event_type and source_artifact. The latter
    two are filter keys, not reading material — 'evtx/Security' adds nothing once
    the channel and event id are visible, and a machine slug is not a sentence.
    """
    table = Table(title=title, header_style="bold", expand=True)
    table.add_column("", width=3, no_wrap=True)
    table.add_column("When (UTC)", width=19, no_wrap=True)
    table.add_column("Host", max_width=13, no_wrap=True)
    table.add_column("User", max_width=14, no_wrap=True)
    table.add_column("Title", max_width=28, overflow="fold")
    table.add_column("ID", width=6, no_wrap=True)
    table.add_column("Details", overflow="fold")

    shown = rows[:SCREEN_ROWS]
    for row in shown:
        severity = _sev(row)
        table.add_row(
            SEV_MARK.get(severity, " "),
            _t(row.get("ts")),
            _t(row.get("host")),
            _t(row.get("user")),
            _t(row.get("title") or _pretty_type(row.get("event_type"))),
            _t(row.get("event_id")),
            _t(row.get("details") or row.get("message")),
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


# The timeline CSV, in reading order. Columns 1-8 are what an analyst scans;
# the rest are for filtering, pivoting and provenance.
#
# The raw `data` JSON column is deliberately absent. It is what made the previous
# file unreadable — a median 126-char and up-to-7,224-char JSON blob per row, in a
# file whose problem was already width, and Excel truncates a cell at 32,767 chars
# anyway. Losslessness lives in two other places: to_jsonl() and the case
# database. `ExtraFields` keeps the CSV scannable without it.
CSV_COLUMNS = (
    "Timestamp", "Level", "Title", "Host", "Channel", "EventID", "User", "Details",
    "Type", "TimestampDesc", "ATTCK", "Tags", "Source", "RecordId", "ExtraFields",
    "ArtifactPath", "Id",
)


def _pretty_type(event_type: object) -> str:
    """'service_installed' -> 'Service installed'. A readable last resort."""
    text = str(event_type or "").replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else "Event"


def _csv_row(row: dict) -> dict:
    """One store row in reading order, with nothing JSON-encoded."""
    attck = row.get("attck") or []
    tags = row.get("tags") or []
    return {
        "Timestamp": row.get("ts") or "",
        "Level": row.get("severity") or "info",
        # Never blank: parsers other than evtx do not set a title, and an
        # empty column in the one place an analyst reads is the bug this
        # whole change exists to fix.
        "Title": row.get("title") or _pretty_type(row.get("event_type")),
        "Host": row.get("host") or "",
        "Channel": row.get("channel") or "",
        "EventID": row.get("event_id") or "",
        "User": row.get("user") or "",
        "Details": row.get("details") or row.get("message") or "",
        "Type": row.get("event_type") or "",
        "TimestampDesc": row.get("ts_desc") or "",
        "ATTCK": " ".join(attck) if isinstance(attck, list) else str(attck),
        "Tags": " ".join(tags) if isinstance(tags, list) else str(tags),
        "Source": row.get("source_artifact") or "",
        "RecordId": row.get("record_id") or "",
        "ExtraFields": row.get("extra_fields") or "",
        "ArtifactPath": row.get("artifact_path") or "",
        "Id": row.get("id") or "",
    }


def to_csv(rows: Iterable[dict], path: str | Path) -> str:
    """The timeline a human opens.

    Streams. The previous version began with ``list(rows)``, which materialized
    every row — at 798k events that is several gigabytes of dicts to write a file
    that is read top-down once.
    """
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for row in rows:
            writer.writerow(_csv_row(row))
    return str(path)


def to_jsonl(rows: Iterable[dict], path: str | Path) -> str:
    """One JSON object per line — streamable, and easy to pipe into jq."""
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
                "message": row.get("message")
                           or " ¦ ".join(p for p in (row.get("title"),
                                                     row.get("details")) if p),
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

    # Artifacts that produced evidence, plus anything that errored. The files nothing
    # could be read from are summarized in "Not parsed" below rather than listed twice:
    # on a UAC collection this table alone was ~1,000 rows of /etc config files, and a
    # 4,467-line report is one nobody opens.
    errored = [a for a in artifacts if a.get("status") == "error"]
    listed = sorted(
        parsed + errored,
        key=lambda a: (-int(a.get("event_count") or 0), str(a.get("path") or "")),
    )
    out += [
        "## Artifacts",
        "",
        f"{len(parsed)} parsed, {len(errored)} errored, "
        f"{len(skipped) - len(errored)} with no parser "
        "(summarized under Not parsed).",
        "",
        "| Kind | Parser | Status | Events | Path |",
        "|---|---|---|---|---|",
    ]
    for row in listed[:limit]:
        out.append(
            f"| {row.get('kind','')} | {row.get('parser') or '-'} | {row.get('status','')} "
            f"| {row.get('event_count',0)} | `{row.get('path','')}` |"
        )
    if len(listed) > limit:
        out.append(
            f"| … | | | | _{len(listed) - limit} more, ordered by event count_ |"
        )
    out += [""]

    if skipped:
        out += _not_parsed_section(skipped)

    return "\n".join(out)


# Files a collector sweeps up that were never evidence and never will be. A UAC run
# produces thousands of these, and listing them individually is how one real report
# became 994 lines of "— unsupported" that buried the four entries that mattered.
_NOT_EVIDENCE = (
    "/etc/alternatives/", "/etc/ssl/certs/", "/usr/share/ca-certificates/",
    "/etc/rc0.d/", "/etc/rc1.d/", "/etc/rc2.d/", "/etc/rc3.d/", "/etc/rc4.d/",
    "/etc/rc5.d/", "/etc/rc6.d/", "/etc/rcs.d/", "/etc/apparmor.d/",
    "/etc/console-setup/", "/etc/dpkg/origins/", "/etc/sgml/", "/etc/newt/",
    "/usr/lib/systemd/system/", "/lib/systemd/system/", "/etc/systemd/system/",
    "/etc/apt/trusted.gpg.d/", "/etc/pam.d/", "/etc/logcheck/", "/etc/terminfo/",
    "/etc/udev/rules.d/", "/etc/init.d/", "/etc/cron.d/", "/etc/ufw/",
)
_NOT_EVIDENCE_SUFFIXES = (
    ".1.gz", ".2.gz", ".3.gz", ".5.gz", ".7.gz", ".8.gz", ".gpg", ".pem", ".crt",
    ".psf.gz", ".acm.gz", ".kmap.gz", ".efi.signed", ".service", ".target",
    ".socket", ".mount", ".rules", ".ttf", ".pyc", ".so",
)


def _is_not_evidence(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    if any(marker in lowered for marker in _NOT_EVIDENCE):
        return True
    if lowered.endswith(_NOT_EVIDENCE_SUFFIXES):
        return True
    # A bare certificate hash link: /etc/ssl/certs/653b494a.0
    return bool(re.fullmatch(r".*/[0-9a-f]{8}\.\d", lowered))


def _not_parsed_section(skipped: list[dict]) -> list[str]:
    """Group what was not parsed, and separate real gaps from collector sweepings.

    An analyst reading this needs one thing from it: *is there evidence here the tool
    could not read?* A flat list of every config file and man page answers that
    question with noise, and a genuine gap — a 13 MB bodyfile, a systemd journal — is
    indistinguishable from a symlink to ``vim``.
    """
    gaps: list[dict] = []
    sweepings: list[dict] = []
    for row in skipped:
        (sweepings if _is_not_evidence(str(row.get("path", ""))) else gaps).append(row)

    out = ["### Not parsed", ""]

    if gaps:
        by_ext: dict[str, list[dict]] = {}
        for row in gaps:
            name = Path(str(row.get("path", ""))).name
            ext = ("." + name.rsplit(".", 1)[1].lower()) if "." in name else "(no extension)"
            by_ext.setdefault(ext, []).append(row)

        out += [
            f"**{len(gaps)} file(s) that may be evidence** — no parser for these yet.",
            "",
            "| Type | Count | Largest | Example |",
            "|---|---|---|---|",
        ]
        for ext, rows in sorted(by_ext.items(), key=lambda kv: -len(kv[1])):
            biggest = max(rows, key=lambda r: int(r.get("size") or 0))
            size = int(biggest.get("size") or 0)
            human = f"{size/1e6:.1f} MB" if size >= 1e6 else f"{size/1e3:.0f} KB"
            out.append(
                f"| `{ext}` | {len(rows)} | {human} | `{Path(str(biggest.get('path',''))).name}` |"
            )
        out += [""]

        # Name the individually large ones: a 13 MB file is worth a parser, and that
        # judgement needs the size in front of the reader.
        notable = sorted(gaps, key=lambda r: -int(r.get("size") or 0))[:8]
        notable = [r for r in notable if int(r.get("size") or 0) > 100_000]
        if notable:
            out += ["Largest unparsed files:", ""]
            for row in notable:
                size = int(row.get("size") or 0)
                reason = row.get("error") or row.get("hint") or row.get("status")
                out.append(
                    f"- `{Path(str(row.get('path',''))).name}` "
                    f"({size/1e6:.1f} MB) — {reason}"
                )
            out += [""]

    if sweepings:
        out += [
            f"**{len(sweepings)} collector sweepings skipped** — symlinks, certificates, "
            "unit files, man pages and other configuration a triage collector picks up "
            "wholesale. Not evidence, and not a coverage gap.",
            "",
        ]

    return out
