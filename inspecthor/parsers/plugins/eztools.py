"""Eric Zimmerman tool output — the CSVs KAPE's modules produce.

KAPE has two halves and this tool only handled one of them. **Targets** collect
raw artifacts; **Modules** run EZTools over them and leave a directory of CSVs.
Most people run both, and on a module run the raw artifacts may not even be kept —
so a collection could arrive fully processed and parse as anonymous text.

**One parser, a table of specs, because the shape is identical and the columns are
not.** Every EZTools CSV is a header row of stable column names plus rows of
values; what differs is which columns exist and which of them are timestamps.
Thirteen near-identical plugin files would be thirteen places to fix the timestamp
parser. A spec is six fields and adding a tool is one entry.

**Claimed on the header, never the filename.** KAPE's naming is configurable and
analysts rename things; ``20250902_PECmd_Output.csv`` and ``prefetch.csv`` are the
same file. Scoring on columns also disentangles the formats that overlap — LECmd
and JLECmd's AutomaticDestinations share 20 columns, and only ``AppId`` and
``DestListVersion`` separate them, so the spec that matches *more* required
columns wins rather than whichever was declared first.

**One event per distinct timestamp, not per column.** The same grouping
``bodyfile.py`` and ``mft.py`` settled on. An MFTECmd ``$MFT`` CSV carries eight
time columns per row; emitting each one turns a 139,000-row export into a million
events, three quarters of them repeats of a file written once.

**EvtxECmd rows are reconstructed into the shape the native EVTX parser emits** —
``event_id``, ``channel``, and the ``Payload`` JSON flattened into ``data`` — so
Sigma matches them. A Sigma rule looks at ``event_id``, ``channel`` and ``data``
keys; a row that keeps its payload as one opaque string is invisible to every rule
in the corpus, which would make the processed collection strictly worse than the
raw one.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from ...models import Event, ParseContext
from .._pathscore import EXEC_EXT, extension_of, score_path
from ..base import Parser, register

# EZTools writes UTC by default, with a variable number of fractional digits and
# occasionally an explicit offset.
_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
)

_MIN_YEAR, _MAX_YEAR = 1980, 2100

# A CSV header longer than this is not an EZTools export.
_MAX_HEADER_BYTES = 64 * 1024

@dataclass(frozen=True)
class Spec:
    """One EZTools CSV format."""

    name: str                              # source_artifact suffix, e.g. "pecmd"
    display: str
    must: tuple[str, ...]                  # lowercased columns that must all exist
    times: tuple[tuple[str, str], ...]     # (column, what that time means)
    event_type: str
    title: str
    # Columns worth showing, in order. Empty values are dropped.
    detail: tuple[str, ...] = ()
    # Column holding the thing the row is *about* — a path, an executable, a key.
    subject: tuple[str, ...] = ()
    # Columns that must NOT be present. Scoring cannot separate a subset: every
    # column LECmd requires also appears in JLECmd's AutomaticDestinations
    # export, so LECmd matches a jump list perfectly and then outscores it on
    # count. Naming the column that proves it is the other format is the only
    # thing that resolves it.
    never: tuple[str, ...] = ()


SPECS: tuple[Spec, ...] = (
    # ---- MFTECmd ----
    Spec(
        name="mftecmd_mft", display="MFTECmd $MFT",
        must=("entrynumber", "parentpath", "filename", "created0x10"),
        times=(("created0x10", "Created ($SI)"),
               ("lastmodified0x10", "Modified ($SI)"),
               ("lastrecordchange0x10", "MFT changed ($SI)"),
               ("lastaccess0x10", "Accessed ($SI)"),
               ("created0x30", "Created ($FN)"),
               ("lastmodified0x30", "Modified ($FN)")),
        event_type="file_timestamp", title="File timestamp",
        detail=("filesize", "inuse", "isdirectory", "hasads", "si<fn"),
        subject=("parentpath", "filename"),
    ),
    Spec(
        name="mftecmd_j", display="MFTECmd $J",
        must=("updatesequencenumber", "updatereasons", "updatetimestamp"),
        times=(("updatetimestamp", "USN record"),),
        event_type="file_change", title="File changed",
        detail=("updatereasons", "fileattributes", "entrynumber"),
        subject=("parentpath", "name"),
    ),
    # ---- PECmd (prefetch) ----
    Spec(
        name="pecmd", display="PECmd (prefetch)",
        must=("executablename", "runcount", "lastrun"),
        times=(("lastrun", "Program executed"),
               ("previousrun0", "Program executed"),
               ("previousrun1", "Program executed"),
               ("previousrun2", "Program executed"),
               ("previousrun3", "Program executed"),
               ("previousrun4", "Program executed"),
               ("previousrun5", "Program executed"),
               ("previousrun6", "Program executed"),
               ("sourcecreated", "Prefetch file created")),
        event_type="process_exec", title="Program executed",
        detail=("runcount", "size", "hash", "volume0name"),
        subject=("executablename",),
    ),
    Spec(
        name="pecmd_timeline", display="PECmd timeline",
        must=("runtime", "executablename"),
        times=(("runtime", "Program executed"),),
        event_type="process_exec", title="Program executed",
        subject=("executablename",),
    ),
    # ---- JLECmd before LECmd: they share 20 columns and AppId is the separator ----
    Spec(
        name="jlecmd_auto", display="JLECmd AutomaticDestinations",
        must=("appid", "destlistversion", "sourcefile"),
        times=(("creationtime", "Jump list entry created"),
               ("lastmodified", "Jump list entry used"),
               ("targetcreated", "Target created"),
               ("targetmodified", "Target modified")),
        event_type="file_opened", title="File opened (jump list)",
        detail=("appiddescription", "interactioncount", "arguments", "machineid"),
        subject=("path", "localpath"),
    ),
    Spec(
        name="jlecmd_custom", display="JLECmd CustomDestinations",
        must=("appid", "entryname", "sourcefile"),
        times=(("targetcreated", "Target created"),
               ("targetmodified", "Target modified"),
               ("targetaccessed", "Target accessed")),
        event_type="file_opened", title="File opened (jump list)",
        detail=("appiddescription", "entryname", "arguments"),
        subject=("localpath", "targetidabsolutepath"),
    ),
    Spec(
        name="lecmd", display="LECmd (LNK)",
        must=("sourcefile", "targetcreated", "localpath", "machineid"),
        times=(("sourcecreated", "Shortcut created"),
               ("sourcemodified", "Shortcut modified"),
               ("targetcreated", "Target created"),
               ("targetmodified", "Target modified"),
               ("targetaccessed", "Target accessed")),
        event_type="file_opened", title="File opened (shortcut)",
        detail=("arguments", "workingdirectory", "machineid", "drivetype",
                "volumelabel", "driveserialnumber"),
        subject=("localpath", "targetidabsolutepath", "relativepath"),
        never=("appid", "destlistversion", "entryname"),
    ),
    # ---- EvtxECmd: handled specially in parse(), see _evtx_event ----
    Spec(
        name="evtxecmd", display="EvtxECmd (event log)",
        must=("eventid", "timecreated", "channel", "provider"),
        times=(("timecreated", "Event Logged"),),
        event_type="windows_event", title="Windows event",
        detail=("mapdescription", "username", "remotehost", "executableinfo"),
        subject=("computer",),
    ),
    # ---- Amcache ----
    Spec(
        name="amcache_files", display="AmcacheParser (file entries)",
        must=("programid", "filekeylastwritetimestamp", "fullpath"),
        times=(("filekeylastwritetimestamp", "Amcache entry written"),
               ("linkdate", "Binary linked")),
        event_type="program_present", title="Program present (Amcache)",
        detail=("sha1", "size", "productname", "version", "binarytype"),
        subject=("fullpath",),
    ),
    Spec(
        name="amcache_programs", display="AmcacheParser (programs)",
        must=("programid", "installdate", "name"),
        times=(("installdate", "Program installed"),
               ("keylastwritetimestamp", "Amcache entry written")),
        event_type="program_installed", title="Program installed",
        detail=("version", "publisher", "installdate", "uninstallkey"),
        subject=("name",),
    ),
    # ---- AppCompatCache / ShimCache ----
    Spec(
        name="appcompatcache", display="AppCompatCacheParser (ShimCache)",
        must=("cacheentryposition", "path", "lastmodifiedtimeutc"),
        times=(("lastmodifiedtimeutc", "Binary last modified"),),
        event_type="program_present", title="Program present (ShimCache)",
        detail=("executed", "cacheentryposition", "controlset", "duplicate"),
        subject=("path",),
    ),
    # ---- Recycle Bin ----
    Spec(
        name="rbcmd", display="RBCmd (recycle bin)",
        must=("sourcename", "filename", "deletedon"),
        times=(("deletedon", "File deleted"),),
        event_type="file_deleted", title="File sent to the recycle bin",
        detail=("filesize", "filetype", "sourcename"),
        subject=("filename",),
    ),
    # ---- Shellbags ----
    Spec(
        name="sbecmd", display="SBECmd (shellbags)",
        must=("bagpath", "absolutepath", "shelltype"),
        times=(("firstinteracted", "Folder first opened"),
               ("lastinteracted", "Folder last opened"),
               ("lastwritetime", "Shellbag key written")),
        event_type="folder_opened", title="Folder opened",
        detail=("shelltype", "mftentry", "value"),
        subject=("absolutepath",),
    ),
    # ---- SRUM ----
    Spec(
        name="srum_network", display="SrumECmd (network usage)",
        must=("timestamp", "bytesreceived", "bytessent"),
        times=(("timestamp", "Network usage recorded"),),
        event_type="network_usage", title="Network usage",
        detail=("bytessent", "bytesreceived", "username", "interfacetype"),
        subject=("exeinfo",),
    ),
    Spec(
        name="srum_appresource", display="SrumECmd (app resource use)",
        must=("timestamp", "foregroundcycletime", "exeinfo"),
        times=(("timestamp", "Application resource use"),),
        event_type="program_usage", title="Application used",
        detail=("username", "foregroundcycletime", "backgroundcycletime"),
        subject=("exeinfo",),
    ),
    # ---- Windows Timeline ----
    Spec(
        name="wxtcmd_activity", display="WxTCmd (Windows Timeline)",
        must=("executable", "displaytext", "starttime"),
        times=(("starttime", "Activity started"),
               ("endtime", "Activity ended"),
               ("lastmodifiedtime", "Activity record written")),
        event_type="program_usage", title="Activity recorded",
        detail=("displaytext", "contentinfo", "duration", "activitytype"),
        subject=("executable",),
    ),
    # ---- RECmd batch ----
    Spec(
        name="recmd", display="RECmd (registry batch)",
        must=("hivepath", "keypath", "lastwritetimestamp"),
        times=(("lastwritetimestamp", "Registry key last write"),),
        event_type="registry_key", title="Registry key",
        detail=("valuename", "valuedata", "description", "category", "hivetype"),
        subject=("keypath",),
    ),
)


def _norm(name: str) -> str:
    return (name or "").strip().lstrip("﻿").lower()


def parse_timestamp(raw: str) -> Optional[datetime]:
    """One EZTools timestamp, or None. UTC unless the value says otherwise."""
    value = (raw or "").strip()
    if not value or value in ("0", "-"):
        return None
    # Trailing 'Z', or an explicit offset: let fromisoformat try first.
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed if _MIN_YEAR <= parsed.year <= _MAX_YEAR else None
    except ValueError:
        pass
    # .NET writes 7 fractional digits; strptime takes at most 6.
    if "." in value:
        head, _, frac = value.partition(".")
        frac = "".join(c for c in frac if c.isdigit())[:6]
        value = f"{head}.{frac}" if frac else head
    for fmt in _TS_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return parsed if _MIN_YEAR <= parsed.year <= _MAX_YEAR else None
    return None


def match_spec(columns: list[str]) -> Optional[tuple[Spec, float]]:
    """Best spec for this header, with a confidence, or None.

    Scored by how many required columns are present so overlapping formats
    separate: LECmd and JLECmd's AutomaticDestinations share most of their
    columns, and only the spec that matches ALL of its own required set wins.
    """
    present = {_norm(c) for c in columns}
    best: Optional[tuple[Spec, float]] = None
    for spec in SPECS:
        if not all(column in present for column in spec.must):
            continue
        if any(column in present for column in spec.never):
            continue
        # Prefer the spec that demanded more, then the one whose optional
        # columns are also present — that is what separates near-identical
        # exports from the same tool family.
        optional = sum(
            1 for column, _desc in spec.times if column in present
        ) + sum(1 for column in spec.detail if column in present)
        score = len(spec.must) * 10 + optional
        if best is None or score > best[1]:
            best = (spec, float(score))
    return best


def _read_header(path: Path) -> list[str]:
    """Column names from the first line, or []."""
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            first = fh.readline(_MAX_HEADER_BYTES)
    except OSError:
        return []
    if not first or "," not in first:
        return []
    try:
        return next(csv.reader([first]))
    except (csv.Error, StopIteration):
        return []


def flatten_payload(raw: str) -> dict:
    """EvtxECmd's Payload JSON into flat ``{name: value}``.

    The payload is the EventData, and Sigma rules address it by the original
    field names — ``Image``, ``CommandLine``, ``TargetUserName``. Keeping it as
    one JSON string would leave every rule in the corpus unable to see it.
    """
    text = (raw or "").strip()
    if not text or text[0] not in "{[":
        return {}
    try:
        loaded = json.loads(text)
    except (ValueError, TypeError):
        return {}

    out: dict = {}

    def walk(node, key: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                # EvtxECmd writes {"#attributes": {"Name": "Image"}, "#text": "..."}
                if k == "#attributes" and isinstance(v, dict) and "Name" in v:
                    continue
                walk(v, str(k))
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict) and "@Name" in item:
                    out.setdefault(str(item["@Name"]), item.get("#text", ""))
                else:
                    walk(item, key)
        elif key and key not in ("#text",):
            out.setdefault(key, node)

    walk(loaded)
    return {k: v for k, v in out.items() if v not in (None, "")}


def group_times(row: dict, spec: Spec) -> list[tuple[datetime, str]]:
    """``[(when, "Created/Modified"), ...]`` — identical values collapsed."""
    by_value: dict[datetime, list[str]] = defaultdict(list)
    for column, meaning in spec.times:
        when = parse_timestamp(row.get(column, ""))
        if when is not None and meaning not in by_value[when]:
            by_value[when].append(meaning)
    out = [(when, "/".join(meanings)) for when, meanings in by_value.items()]
    out.sort(key=lambda item: item[0])
    return out


def subject_of(row: dict, spec: Spec) -> str:
    """The path or name the row is about."""
    parts = [str(row.get(c, "")).strip() for c in spec.subject]
    parts = [p for p in parts if p and p != "-"]
    if not parts:
        return ""
    if len(parts) == 2 and parts[0] and parts[1]:
        left = parts[0].rstrip("\\/")
        return f"{left}\\{parts[1]}" if left else parts[1]
    return parts[0]


def score_row(spec: Spec, subject: str, row: dict) -> tuple[str, list[str], str]:
    """``(severity, tags, why)``.

    Location and shape come from the shared scorer so the same file scores the
    same whether it arrived via ShimCache, Plaso or the $MFT. Only the one
    export-specific signal lives here: a file in the recycle bin was deleted,
    which no path can tell you.
    """
    severity, tags, why = score_path(subject)
    if spec.name == "rbcmd" and severity in ("info", "low") and             extension_of(subject) in EXEC_EXT:
        return "med", ["deleted", "suspicious"], "executable sent to the recycle bin"
    return severity, tags, why


@register
class EZToolsCsvParser(Parser):
    """Eric Zimmerman tool CSV output (what KAPE's modules write)."""

    name = "eztools"
    display = "EZTools CSV (KAPE modules)"
    category = "windows"
    path_globs = ("*.csv",)
    requires = ""
    install_hint = ""

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        """Claimed on the column names, never the filename.

        A .csv alone means nothing — KAPE's copy log is one too. The header has
        to match a known export, and then this must beat generic_text decisively
        or a processed collection reads as anonymous text.
        """
        if path.suffix.lower() != ".csv":
            return 0.0
        columns = _read_header(path)
        if not columns:
            return 0.0
        return self.CONF_MAGIC if match_spec(columns) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        columns = _read_header(path)
        matched = match_spec(columns) if columns else None
        if matched is None:
            ctx.hint(f"{path.name}: not a recognised EZTools export")
            return
        spec, _score = matched

        # These exports run to millions of rows and some carry a whole Payload
        # blob per row; the default limit rejects them mid-file.
        if csv.field_size_limit() < (1 << 24):
            try:
                csv.field_size_limit(1 << 24)
            except OverflowError:                       # 32-bit builds
                csv.field_size_limit(sys.maxsize)

        common = dict(
            source_artifact=f"{self.name}/{spec.name}",
            artifact_path=str(path),
            parser=self.name,
        )

        emitted = 0
        rows = 0
        undated = 0
        malformed = 0
        earliest: Optional[datetime] = None
        latest: Optional[datetime] = None

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
                    ctx.hint(
                        f"{path.name}: stopped at the {ctx.max_records} record cap "
                        f"after {rows:,} rows"
                    )
                    break
                try:
                    raw_row = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    # A malformed line ends the file for csv; what was read stands.
                    malformed += 1
                    break

                rows += 1
                row = {_norm(k): (v if v is not None else "")
                       for k, v in raw_row.items() if k is not None}

                times = group_times(row, spec)
                if not times:
                    undated += 1
                    continue

                subject = subject_of(row, spec)
                detail_bits = [
                    f"{column}: {row[column]}"
                    for column in spec.detail
                    if row.get(column, "").strip() not in ("", "-")
                ]

                if spec.name == "evtxecmd":
                    yield from self._evtx_rows(row, times, common, ctx, detail_bits)
                    emitted += len(times)
                else:
                    severity, tags, why = score_row(spec, subject, row)
                    if why:
                        detail_bits.append(f"Why: {why}")
                    data = {k: v for k, v in row.items() if v not in ("", "-")}
                    data["subject"] = subject
                    for when, meaning in times:
                        details = subject or spec.display
                        if detail_bits:
                            details += " ¦ " + " ¦ ".join(detail_bits[:6])
                        emitted += 1
                        yield ctx.event(
                            timestamp=when,
                            timestamp_desc=meaning,
                            event_type=spec.event_type,
                            title=spec.title,
                            details=details,
                            message="",
                            data=data,
                            severity=severity,
                            tags=tags,
                            **common,
                        )

                for when, _meaning in times:
                    if earliest is None or when < earliest:
                        earliest = when
                    if latest is None or when > latest:
                        latest = when

        if not rows:
            ctx.hint(f"{path.name}: {spec.display} export had no rows")
            return

        span = ""
        if earliest and latest:
            span = f" ¦ Span: {earliest.date()} to {latest.date()}"
        yield ctx.event(
            timestamp=latest or datetime.now(timezone.utc),
            timestamp_desc=f"{spec.display} summary",
            event_type="artifact_summary",
            title=f"{spec.display} ingested",
            details=f"Rows: {rows:,} ¦ Events: {emitted:,}{span}",
            message="",
            data={"export": spec.name, "rows": rows, "events": emitted},
            severity="info",
            **common,
        )
        if undated:
            ctx.hint(f"{path.name}: {undated:,} row(s) carried no usable timestamp")
        if malformed:
            ctx.hint(f"{path.name}: stopped early on a malformed row at {rows:,}")

    def _evtx_rows(self, row: dict, times, common, ctx: ParseContext,
                   detail_bits: list[str]) -> Iterator[Event]:
        """An EvtxECmd row in the shape the native EVTX parser emits.

        Same ``event_id`` / ``channel`` / flattened ``data``, so a Sigma rule
        cannot tell whether the event came from the .evtx or from the CSV.
        """
        payload = flatten_payload(row.get("payload", ""))
        data = {k: v for k, v in row.items()
                if v not in ("", "-") and k != "payload"}
        data.update(payload)

        channel = row.get("channel", "") or ""
        event_id = row.get("eventid", "") or ""
        description = row.get("mapdescription", "").strip()
        title = description or f"Event {event_id}" if event_id else "Windows event"

        details = " ¦ ".join(
            detail_bits[:6]
            or [f"{k}: {v}" for k, v in list(payload.items())[:5]]
        ) or channel

        for when, meaning in times:
            yield ctx.event(
                timestamp=when,
                timestamp_desc=meaning,
                event_type="windows_event",
                title=title,
                details=details,
                message="",
                data=data,
                channel=channel,
                event_id=str(event_id) or None,
                record_id=row.get("eventrecordid") or None,
                user=row.get("username", ""),
                host=row.get("computer", ""),
                severity="info",
                **common,
            )
