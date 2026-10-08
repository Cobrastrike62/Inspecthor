"""$MFT — the NTFS master file table.

Every KAPE triage ships one, and on a targeted MFT+USN collection it *is* the case:
one real collection was 143 MB of ``$MFT``, 35 MB of ``$J`` and nothing else. Before
this parser the image opened, the volume mounted, both artifacts landed in "no parser
for those yet", and the case came out with three events and an empty triage.

**Full paths are the reason to parse an $MFT at all, and they are why this parser
buffers.** A record names its parent by segment number and a child is routinely
written before its parent, so no single streaming pass can resolve
``\\Users\\hclarke\\AppData\\Local\\Temp\\update.exe`` — only a segment->name map
covering the whole table can. Reading the table twice costs a second full pass
(68 s on a 139,533-segment table), so the pass happens once into compact tuples of
ints and strs and paths are resolved from the finished map afterwards. That trades
roughly 40 MB of peak memory on a 143 MB table for the one field that makes every
other field worth reading, and it is the reason this parser does not honour the
streaming habit the rest of ``plugins/`` keeps.

**$SI and $FN are both kept, because the disagreement between them is evidence.**
Windows updates ``$STANDARD_INFORMATION`` through the ordinary API that timestomping
tools call; ``$FILE_NAME`` is maintained by the kernel and is much harder to forge.
A $SI creation time earlier than the $FN creation time is the classic signature, and
whole-second $SI stamps are the second one — ``SetFileTime`` callers usually pass a
value with no sub-second part while real NTFS activity never lands on an exact
second four times running. Both are promoted rather than left for an analyst to spot
by eye across 139,000 rows.

**One event per distinct $SI timestamp, not per record and not per field** — the
grouping ``bodyfile.py`` settled on, for the same reason. A file written once has
identical m/c/b times, so per-field emission triples the timeline with duplicates
while per-record throws away three quarters of what an MFT is for.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from ...capabilities import hint as cap_hint
from ...models import Event, ParseContext
from ..base import Parser, register

# NTFS fixes these. Segment 5 is the volume root; the first 16 are the metadata
# files that describe the filesystem rather than anything a user or an intruder did.
_ROOT_SEGMENT = 5
_FIRST_USER_SEGMENT = 16

# A corrupt or hostile parent chain must not loop forever. Real Windows paths are
# nowhere near this deep.
_MAX_DEPTH = 64

# $FILE_NAME namespaces. A record carries up to four names; the Win32 one is what an
# analyst recognises and the 8.3 alias (FAILOV~1) is never what to report.
_NS_RANK = {1: 0, 3: 0, 0: 1, 2: 2}     # Win32, Win32+DOS, POSIX, DOS

# Timestamps outside this window are unset ($SI defaults to the 1601 NTFS epoch) or
# corrupt, not evidence.
_MIN_YEAR, _MAX_YEAR = 1980, 2100

# Directories that exist to hold transient files. An executable here is worth
# interrupting an analyst for.
_TEMP_STAGING = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
    "\\$recycle.bin\\", "\\perflogs\\",
)

# Writable without admin, but also where a great deal of stock software lives.
# \ProgramData\ alone holds Defender's scan cache, the VC++ redistributable package
# cache and most Start Menu shortcuts; treating it as staging produced 246 'high'
# findings on the first real collection and all but one were Microsoft's own.
# Used only to keep an executable here at 'low' rather than silent.
_USER_WRITABLE = (
    "\\programdata\\", "\\appdata\\roaming\\", "\\appdata\\local\\",
)

# The user Startup folder is close to empty on a stock Windows, so a shortcut or a
# binary appearing in one is worth reporting on its own.
_STARTUP = ("\\start menu\\programs\\startup\\",)

# Persistence too, but populated by Windows itself — ~300 stock scheduled tasks and
# a System32\drivers full of Microsoft .sys files. 547 'med' events on the first
# real collection, none of them a finding. Tagged so they can be filtered for, and
# left at 'low' so they do not fill triage.
_PERSISTENCE_BULK = (
    "\\windows\\system32\\tasks\\", "\\windows\\tasks\\",
    "\\windows\\system32\\drivers\\", "\\windows\\system32\\wbem\\mof\\",
)

_EXEC_EXT = frozenset({
    ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".ps1", ".psm1",
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".jar", ".msi", ".msp", ".lnk", ".pif", ".application",
})

# Extensions that look like a document to a user but sit in front of a real one in a
# double-extension name: invoice.pdf.exe.
_DECOY_EXT = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
    ".jpeg", ".png", ".gif", ".rtf", ".csv", ".zip", ".htm", ".html",
})

# What a lure actually ends in. Narrower than _EXEC_EXT on purpose: .dll, .sys and
# .msi are absent because dotted naming is the .NET convention, and including them
# reported stock Microsoft components — Windows.Data.Pdf.dll read as ".pdf" + ".dll"
# and produced six 'high' findings in \Windows\WinSxS on the first real collection.
_LURE_EXT = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".ps1",
})

# Streams NTFS maintains for itself. $Repair carries $Config/$Corrupt/$Verify and
# $Secure carries $SDS/$SDH/$SII on every volume in existence; reporting those as
# hidden content produced the second-largest block of false positives on the first
# real collection.
_INTERNAL_STREAMS = frozenset({
    # NTFS metadata streams.
    "$config", "$corrupt", "$verify", "$t", "$tops", "$sds", "$sdh", "$sii",
    "$i30", "$o", "$q", "$r", "$j", "$max", "$info", "$data",
    # Streams Windows itself puts on ordinary files. WofCompressedData is the
    # CompactOS/WIM overlay and sits on most of \Windows — it alone accounted for
    # 185,342 'high' events before it was excluded.
    "wofcompresseddata", "zone.identifier", "smartscreen", "encryptable",
    "favicon", "oecustomproperty", "ms-properties",
    "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
})

# How many records must share a $SI-to-$FN skew before it is read as a deployment
# artefact rather than evidence. Counting the SKEW and not the creation value is the
# whole point: every file in an image has its own creation timestamp, so the values
# never collide, but the *distance* between $SI and $FN is the gap between the image
# build and the day it was applied and is therefore identical across the install.
# On the first real collection 136,383 events shared a 1213-day skew and 43,972
# shared 1072 days — two deployment generations, and not one of them a finding.
_BASELINE_MIN = 25
_MICROSECONDS_PER_DAY = 86_400_000_000

_MACB_WORDS = {"m": "Modified", "a": "Accessed", "c": "MFT changed", "b": "Created"}


def _segment_of(reference) -> int:
    """Segment number out of an ``_MFT_SEGMENT_REFERENCE``.

    48 bits split across two fields. Computed here rather than imported because
    dissect has moved ``segment_reference`` between modules across releases.
    """
    return int(reference.SegmentNumberLowPart) | (
        int(reference.SegmentNumberHighPart) << 32
    )


def _usable(when) -> Optional[datetime]:
    """A timestamp worth putting on a timeline, or None."""
    if when is None:
        return None
    try:
        if _MIN_YEAR <= when.year <= _MAX_YEAR:
            return when
    except (AttributeError, ValueError, OverflowError):
        pass
    return None


def _to_us(when: Optional[datetime]) -> Optional[int]:
    """Epoch microseconds. Buffered instead of the datetime — 139k records hold five
    of these each, and an int is a fraction of the size of a datetime object."""
    return None if when is None else int(when.timestamp() * 1_000_000)


def _from_us(value: Optional[int]) -> Optional[datetime]:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)


def best_filename(filenames) -> tuple[str, int, Optional[datetime], int]:
    """``(name, parent_segment, fn_creation, namespace)`` for the name to report.

    Prefers the Win32 name over POSIX over the 8.3 DOS alias. Returns an empty name
    when the record carries no usable $FILE_NAME, which is normal for the metadata
    segments and for records whose attributes live in an $ATTRIBUTE_LIST extension.
    """
    chosen = None
    chosen_rank = 99
    for attribute in filenames:
        try:
            namespace = int(attribute.flags)
            rank = _NS_RANK.get(namespace, 3)
            if rank < chosen_rank:
                chosen, chosen_rank = attribute, rank
        except Exception:
            continue
    if chosen is None:
        return "", -1, None, -1
    try:
        parent = _segment_of(chosen.attribute.attr.ParentDirectory)
    except Exception:
        parent = -1
    return (
        str(chosen.file_name or ""),
        parent,
        _usable(chosen.creation_time),
        int(chosen.flags),
    )


def resolve_path(segment: int, names: dict[int, tuple[str, int]],
                 memo: dict[int, str]) -> str:
    """``\\Users\\bob\\file.txt`` by walking parent segments to the root.

    Iterative rather than recursive: a 139k-segment table with a damaged parent chain
    would otherwise be one malformed record away from a RecursionError.
    """
    chain: list[str] = []
    current = segment
    seen: set[int] = set()
    for _ in range(_MAX_DEPTH):
        if current == _ROOT_SEGMENT or current < 0:
            break
        if current in memo:
            chain.append(memo[current])
            break
        if current in seen:                     # a cycle in a corrupt table
            break
        seen.add(current)
        entry = names.get(current)
        if entry is None:
            chain.append(f"<orphan:{current}>")
            break
        name, parent = entry
        chain.append(name)
        current = parent
    path = "\\".join(reversed(chain))
    resolved = "\\" + path if path and not path.startswith("<") else path
    if segment not in memo and resolved:
        memo[segment] = resolved.lstrip("\\")
    return resolved


def macb_groups(times: dict[str, Optional[datetime]]) -> list[tuple[str, datetime]]:
    """Group the four $SI times by value, in MACB order — ``[("m.cb", dt)]``."""
    by_value: dict[datetime, list[str]] = defaultdict(list)
    for flag in ("m", "a", "c", "b"):
        when = times.get(flag)
        if when is not None:
            by_value[when].append(flag)
    out = [
        ("".join(flag if flag in flags else "." for flag in "macb"), when)
        for when, flags in by_value.items()
    ]
    out.sort(key=lambda item: item[1])
    return out


def timestomp_signals(si: dict[str, Optional[datetime]],
                      fn_creation: Optional[datetime],
                      is_dir: bool, is_baseline: bool) -> list[str]:
    """Why this record looks backdated. Empty when it does not.

    CONSTRAINT: "$SI creation predates $FN creation" on its own is not a finding.
    A Windows installed from an image carries $SI times from the image build and
    $FN times from the day the image was applied, so the condition holds for most
    of the operating system — on the first real collection it flagged 248,164 of
    323,548 events, every one of them ``\\PerfLogs``-grade noise. What separates
    deployment from tampering is that the *skew* is shared: 136,383 events sat
    exactly 1213 days apart and 43,972 exactly 1072, two image generations. The
    caller passes ``is_baseline`` for a record whose skew many others also carry.
    """
    if is_dir or is_baseline:
        return []
    created = si.get("b")
    if not (created and fn_creation) or created >= fn_creation:
        return []
    delta = (fn_creation - created).total_seconds()
    if delta < 3600:
        return []

    # BOTH signals are required. Ordering alone still fires on every installer that
    # preserves a vendor build date — the VMware drivers, MicrosoftEdgeUpdate.exe
    # and a directory of Windows ConstraintIndex files all cleared the skew filter
    # and were nonsense. Sub-second precision is what actually separates them:
    # SetFileTime callers pass whole seconds, and real NTFS activity does not land
    # on an exact second three times running.
    stamps = [t for t in si.values() if t is not None]
    if len(stamps) < 3 or any(t.microsecond for t in stamps):
        return []
    return [
        f"$SI creation predates $FN creation by {_duration(delta)}",
        "all $SI timestamps land on a whole second",
    ]


def _duration(seconds: float) -> str:
    seconds = abs(int(seconds))
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def score_entry(path: str, name: str, in_use: bool, is_dir: bool,
                stomped: bool, ads: tuple[str, ...]) -> tuple[str, list[str], str]:
    """``(severity, tags, why)`` for one MFT record."""
    lowered = path.lower() or name.lower()
    lower_name = name.lower()
    extension = ""
    if "." in lower_name:
        extension = lower_name[lower_name.rindex("."):]
    executable = extension in _EXEC_EXT

    if stomped:
        return "high", ["timestomp", "defense_evasion", "suspicious"], (
            "timestamps disagree between $SI and $FN"
        )

    # Persistence before location, so a shortcut dropped in a Startup folder is
    # reported as persistence rather than buried under "an executable in a
    # writable directory" — which is what happened to the one real finding on the
    # first real collection.
    if any(marker in lowered for marker in _STARTUP):
        if executable:
            return "high", ["persistence", "suspicious"], (
                "executable in a user Startup folder"
            )
        return "med", ["persistence"], "in a user Startup folder"

    # A named data stream is where content hides — but Windows puts plenty there
    # itself, so an unexplained stream only interrupts the analyst when it sits in
    # a directory meant for transient files. Elsewhere it is noted at 'low'.
    real_streams = [s for s in ads if s.lower() not in _INTERNAL_STREAMS]
    ntfs_owned = lower_name.startswith("$") or "\\$extend\\" in lowered
    if real_streams and not is_dir and not ntfs_owned:
        stream_list = ", ".join(real_streams[:3])
        if any(marker in lowered for marker in _TEMP_STAGING):
            return "high", ["ads", "defense_evasion", "suspicious"], (
                f"alternate data stream in a temporary directory: {stream_list}"
            )
        return "low", ["ads"], f"alternate data stream: {stream_list}"

    # invoice.pdf.exe — a real extension hiding behind a decoy one.
    parts = lower_name.split(".")
    if extension in _LURE_EXT and len(parts) >= 3 and f".{parts[-2]}" in _DECOY_EXT:
        return "high", ["double_extension", "suspicious"], (
            f"double extension: .{parts[-2]}{extension}"
        )

    if executable and any(marker in lowered for marker in _TEMP_STAGING):
        return "high", ["unusual_exec_path", "suspicious"], (
            "executable in a temporary directory"
        )

    if executable and not in_use:
        return "med", ["deleted", "suspicious"], "deleted executable"

    if any(marker in lowered for marker in _PERSISTENCE_BULK):
        return "low", ["persistence"], "in a persistence location"

    if executable and any(marker in lowered for marker in _USER_WRITABLE):
        return "low", ["user_writable_exec"], "executable in a user-writable directory"

    if any(marker in lowered for marker in _TEMP_STAGING):
        return "low", ["staging_dir"], "in a temporary directory"

    if not in_use:
        return "low", ["deleted"], "deleted"

    return "info", [], ""


def _macb_desc(macb: str) -> str:
    words = [_MACB_WORDS[flag] for flag in macb if flag != "."]
    return "/".join(words) or "MFT timestamp"


def _title_for(macb: str, is_dir: bool, in_use: bool) -> str:
    kind = "Directory" if is_dir else "File"
    if not in_use:
        kind = f"Deleted {kind.lower()}"
    if macb == "...b":
        return f"{kind} created"
    if macb.startswith("m") and "b" in macb:
        return f"{kind} created and written"
    if macb.startswith("m"):
        return f"{kind} modified"
    if "c" in macb and "m" not in macb:
        return f"{kind} record changed"
    if macb == ".a..":
        return f"{kind} accessed"
    return f"{kind} timestamp"


@register
class MftParser(Parser):
    """NTFS $MFT — filesystem timeline with full paths."""

    name = "mft"
    display = "NTFS $MFT"
    category = "filesystem"
    magic = (b"FILE0", b"BAAD")
    path_globs = ("$mft", "$mft.*", "*.mft", "mft.raw", "$mft_*")
    kinds = ("mft",)
    requires = "dissect.ntfs"
    install_hint = cap_hint("ntfs")

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
            from dissect.ntfs.mft import Mft
        except ImportError:
            ctx.hint(cap_hint("ntfs"))
            return

        common = dict(
            source_artifact=self.name,
            artifact_path=str(path),
            parser=self.name,
        )

        try:
            handle = path.open("rb")
        except OSError as exc:
            ctx.hint(f"{path.name}: cannot read ({exc})")
            return

        names: dict[int, tuple[str, int]] = {}
        rows: list[tuple] = []
        unreadable = 0

        with handle:
            try:
                table = Mft(handle)
                segments = table.segments()
            except Exception as exc:
                ctx.hint(f"{path.name}: not a readable $MFT ({type(exc).__name__})")
                return

            # Guarded at the iterator, not around the body: dissect raises from
            # inside segments() on a table it cannot walk, and that exception would
            # otherwise escape parse() and take the whole case with it.
            iterator = iter(segments)
            while True:
                try:
                    record = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:
                    ctx.hint(
                        f"{path.name}: table ended at segment {len(rows):,} "
                        f"({type(exc).__name__})"
                    )
                    break
                try:
                    segment = int(record.segment)
                    filenames = record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]
                    name, parent, fn_created, _namespace = best_filename(filenames)
                    if name:
                        names[segment] = (name, parent)

                    standard = record.attributes[
                        ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION
                    ]
                    if not standard:
                        continue
                    si = standard[0]
                    times = (
                        _to_us(_usable(si.last_modification_time)),
                        _to_us(_usable(si.last_access_time)),
                        _to_us(_usable(si.last_change_time)),
                        _to_us(_usable(si.creation_time)),
                    )
                    if not any(times):
                        continue

                    streams = tuple(
                        str(stream.name)
                        for stream in record.attributes[ATTRIBUTE_TYPE_CODE.DATA]
                        if getattr(stream, "name", "")
                    )
                    try:
                        size = int(record.size())
                    except Exception:
                        size = 0

                    rows.append((
                        segment, name, record.is_dir(),
                        bool(record.header.Flags & 1), size, times,
                        _to_us(fn_created), streams,
                    ))
                except Exception:
                    # One damaged segment must not end a 139,000-record table.
                    unreadable += 1
                    continue

        if not rows:
            ctx.hint(f"{path.name}: no usable records in the $MFT")
            return

        # Which $SI-to-$FN skews belong to the deployment rather than to anything
        # that happened on this host. Counted over the finished table because a
        # single record cannot tell you it is one of a hundred thousand.
        skew_counts: Counter = Counter()
        for row in rows:
            created_us, fn_created_us = row[5][3], row[6]
            if created_us is not None and fn_created_us is not None:
                if created_us < fn_created_us:
                    skew_counts[
                        (fn_created_us - created_us) // _MICROSECONDS_PER_DAY
                    ] += 1

        memo: dict[int, str] = {}
        emitted = 0
        promoted = 0
        stomped_count = 0
        deleted = 0
        earliest: Optional[datetime] = None
        latest: Optional[datetime] = None

        for segment, name, is_dir, in_use, size, times, fn_us, streams in rows:
            if emitted >= ctx.max_records:
                ctx.hint(
                    f"{path.name}: stopped at the {ctx.max_records} record cap after "
                    f"{len(rows):,} segments"
                )
                break

            si = {
                "m": _from_us(times[0]), "a": _from_us(times[1]),
                "c": _from_us(times[2]), "b": _from_us(times[3]),
            }
            groups = macb_groups(si)
            if not groups:
                continue

            # The metadata segments are the filesystem describing itself. They are
            # kept — $MFT's own record dates the volume — but never promoted.
            is_metadata = segment < _FIRST_USER_SEGMENT
            full_path = resolve_path(segment, names, memo) or name

            is_baseline = False
            if times[3] is not None and fn_us is not None and times[3] < fn_us:
                bucket = (fn_us - times[3]) // _MICROSECONDS_PER_DAY
                is_baseline = skew_counts[bucket] >= _BASELINE_MIN
            signals = [] if is_metadata else timestomp_signals(
                si, _from_us(fn_us), is_dir, is_baseline,
            )
            if signals:
                stomped_count += 1
            if not in_use:
                deleted += 1

            if is_metadata:
                severity, tags, why = "info", ["ntfs_metadata"], ""
            else:
                severity, tags, why = score_entry(
                    full_path, name, in_use, is_dir, bool(signals), streams,
                )
            if signals:
                why = "; ".join(signals)
            if severity != "info":
                promoted += 1

            for macb, when in groups:
                if earliest is None or when < earliest:
                    earliest = when
                if latest is None or when > latest:
                    latest = when

                details = (
                    f"MACB: {macb} ¦ Path: {full_path} ¦ Segment: {segment} ¦ "
                    f"Size: {size:,}"
                )
                if not in_use:
                    details += " ¦ Deleted: yes"
                if streams:
                    details += f" ¦ ADS: {', '.join(streams[:3])}"
                if why:
                    details += f" ¦ Why: {why}"

                data = {
                    "path": full_path,
                    "name": name,
                    "macb": macb,
                    "segment": segment,
                    "size": size,
                    "is_dir": is_dir,
                    "in_use": in_use,
                }
                if streams:
                    data["ads"] = list(streams)
                if signals:
                    data["timestomp"] = signals
                    data["fn_creation"] = (
                        _from_us(fn_us).isoformat() if fn_us else ""
                    )
                if why:
                    data["why"] = why

                emitted += 1
                yield ctx.event(
                    timestamp=when,
                    timestamp_desc=_macb_desc(macb),
                    event_type="file_timestamp",
                    title=_title_for(macb, is_dir, in_use),
                    details=details,
                    message="",
                    data=data,
                    severity=severity,
                    tags=tags,
                    record_id=str(segment),
                    **common,
                )

        span = ""
        if earliest and latest:
            span = f" ¦ Span: {earliest.date()} to {latest.date()}"
        yield ctx.event(
            timestamp=latest or datetime.now(timezone.utc),
            timestamp_desc="$MFT summary",
            event_type="filesystem_timeline",
            title="NTFS $MFT ingested",
            details=(
                f"Segments: {len(rows):,} ¦ Events: {emitted:,} ¦ "
                f"Deleted: {deleted:,} ¦ Timestomped: {stomped_count:,} ¦ "
                f"Notable: {promoted:,}{span}"
            ),
            message="",
            data={
                "segments": len(rows), "events": emitted, "deleted": deleted,
                "timestomped": stomped_count, "notable": promoted,
            },
            severity="info",
            **common,
        )

        if unreadable:
            ctx.hint(f"{path.name}: {unreadable} segment(s) could not be read")
