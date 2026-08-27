"""$UsnJrnl:$J — the NTFS change journal.

The $MFT says what a file looks like now; the journal says what happened to it and in
what order, including to files that no longer exist. On an intrusion that staged a
payload and cleaned up after itself, the ``FILE_CREATE`` and the ``FILE_DELETE`` are
often the only surviving record of the file at all — the MFT segment has already been
reused.

**Only the filename is available, not the directory.** A USN record names its parent
by MFT segment reference, and resolving that to ``\\Users\\hclarke\\Downloads`` needs
the $MFT that the reference points into. dissect will do it when the journal is read
through a live filesystem, but a KAPE collection hands over ``$J`` as a standalone
file, and dissect then renders the path as
``<unavailable_reference_0x18068#1>\\thing.exe``. Emitting that string would put a
placeholder in the Path column of 350,000 timeline rows, so the filename is reported
on its own and the parent segment goes into ``data['parent_segment']``. That field
joins to ``data['segment']`` from ``mft.py`` — when both artifacts are in the case the
analyst can recover the directory, and when only the journal is present nothing
pretends otherwise.

**Every record is emitted, at info unless the change itself is interesting.** A
journal is overwhelmingly Windows servicing itself, and the tool's contract is that
``timeline.csv`` is complete while ``triage.csv`` is ``>= med``. What gets promoted is
narrow: executables appearing and disappearing, renames that change a file into an
executable, and the double-extension pattern. Reason flags arrive combined
(``FILE_DELETE|CLOSE``), so the checks test membership rather than equality.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from ...capabilities import hint as cap_hint
from ...models import Event, ParseContext
from ..base import Parser, register

_EXEC_EXT = frozenset({
    ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".ps1", ".psm1",
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".jar", ".msi", ".msp", ".lnk", ".pif",
})

_DECOY_EXT = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
    ".jpeg", ".png", ".gif", ".rtf", ".csv", ".htm", ".html",
})

# What actually gets dropped. Narrower than _EXEC_EXT on purpose: .dll, .js, .jar,
# .msi and .lnk are created and deleted constantly by Windows servicing, OneDrive
# and Defender, and scoring on the wide set put 6,590 events into triage — the top
# entries being OneDrive's own tutorial .js files and ssshim.dll.
_DROPPER_EXT = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".wsf",
    ".wsh", ".hta", ".ps1", ".psm1",
})

# The lure endings, for the double-extension check. .dll is absent for the same
# reason as in mft.py: dotted naming is the .NET convention.
_LURE_EXT = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".ps1",
})

# Reason flag -> the event_type an analyst filters on. Checked in this order because
# a record usually carries several flags at once and the first is the one that
# describes what happened.
_REASON_EVENT: tuple[tuple[str, str], ...] = (
    ("FILE_DELETE", "file_deleted"),
    ("FILE_CREATE", "file_created"),
    ("RENAME_NEW_NAME", "file_renamed"),
    ("RENAME_OLD_NAME", "file_renamed"),
    ("SECURITY_CHANGE", "file_permissions"),
    ("REPARSE_POINT_CHANGE", "file_reparse"),
    ("STREAM_CHANGE", "file_stream"),
    ("DATA_TRUNCATION", "file_truncated"),
    ("DATA_OVERWRITE", "file_modified"),
    ("DATA_EXTEND", "file_modified"),
    ("BASIC_INFO_CHANGE", "file_metadata"),
)

_REASON_TITLE = {
    "file_deleted": "File deleted",
    "file_created": "File created",
    "file_renamed": "File renamed",
    "file_permissions": "File permissions changed",
    "file_reparse": "Reparse point changed",
    "file_stream": "Alternate data stream changed",
    "file_truncated": "File truncated",
    "file_modified": "File written",
    "file_metadata": "File attributes changed",
    "file_change": "File changed",
}

_MIN_YEAR, _MAX_YEAR = 1980, 2100

# dissect renders an unresolvable parent as this when the journal is read without the
# $MFT it references.
_UNRESOLVED = "<unavailable_reference"


def flag_names(value) -> list[str]:
    """``USN_REASON.FILE_DELETE|CLOSE`` -> ``['FILE_DELETE', 'CLOSE']``.

    Works whether dissect hands back a flag enum or a bare int, because the enum
    type has moved between releases.
    """
    if value is None:
        return []
    text = str(value)
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return [part.strip() for part in text.split("|") if part.strip() and not part.strip().isdigit()]


def event_type_for(reasons: list[str]) -> str:
    for needle, event_type in _REASON_EVENT:
        if needle in reasons:
            return event_type
    return "file_change"


def _extension(name: str) -> str:
    lowered = name.lower()
    return lowered[lowered.rindex("."):] if "." in lowered else ""


def score_record(name: str, reasons: list[str], attributes: list[str]) -> tuple[str, list[str], str]:
    """``(severity, tags, why)`` for one journal record."""
    extension = _extension(name)
    lower = name.lower()

    # invoice.pdf.exe — the decoy extension sits in front of the real one.
    parts = lower.split(".")
    if extension in _LURE_EXT and len(parts) >= 3 and f".{parts[-2]}" in _DECOY_EXT:
        return "high", ["double_extension", "suspicious"], (
            f"double extension: .{parts[-2]}{extension}"
        )

    dropper = extension in _DROPPER_EXT

    # A rename that turns something into an executable is how a staged payload gets
    # armed without an .exe ever being written as one. Rare enough to promote: 66
    # records out of 215,580 on the first real collection.
    if dropper and "RENAME_NEW_NAME" in reasons:
        return "med", ["renamed_to_executable", "suspicious"], (
            "renamed into an executable"
        )

    if dropper and "FILE_DELETE" in reasons:
        return "med", ["deleted", "suspicious"], "executable deleted"

    # Creation is NOT promoted. Windows servicing, OneDrive and Defender create
    # executables constantly, and without the directory — which a standalone $J
    # cannot give us — there is nothing here to tell a payload from an update.
    if dropper and "FILE_CREATE" in reasons:
        return "low", ["dropped_executable"], "executable created"

    if "STREAM_CHANGE" in reasons and lower != "zone.identifier":
        return "low", ["ads"], "alternate data stream changed"

    if extension in _EXEC_EXT:
        return "low", ["executable"], ""

    return "info", [], ""


@register
class UsnJrnlParser(Parser):
    """NTFS change journal ($UsnJrnl:$J)."""

    name = "usnjrnl"
    display = "NTFS USN journal"
    category = "filesystem"
    # No magic: the journal begins with a large sparse region, so the first bytes of
    # a collected $J are zeros. The name is the signal, and collectors are
    # consistent about it.
    path_globs = ("$j", "$usnjrnl*", "*usnjrnl*", "$j.bin", "usnjrnl.bin")
    kinds = ()
    requires = "dissect.ntfs"
    install_hint = cap_hint("ntfs")

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        """``$J`` is unambiguous enough to beat a magic match.

        Nothing else on a Windows system is called this, and the alternative is that
        a 35 MB artifact scores 0.6, ties with generic_text, and gets read as text.
        """
        name = path.name.lower()
        if name in ("$j", "$usnjrnl_$j", "$usnjrnl$j", "$usnjrnl:$j"):
            return self.CONF_MAGIC
        if any(Path(name).match(glob) for glob in self.path_globs):
            return self.CONF_GLOB
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            from dissect.ntfs.usnjrnl import UsnJrnl
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

        emitted = 0
        promoted = 0
        unreadable = 0
        earliest: Optional[datetime] = None
        latest: Optional[datetime] = None
        unresolved_parents = 0

        with handle:
            try:
                journal = UsnJrnl(handle)
                records = journal.records()
            except Exception as exc:
                ctx.hint(
                    f"{path.name}: not a readable USN journal ({type(exc).__name__})"
                )
                return

            # dissect raises from *inside* records() when it meets a page it cannot
            # read, so the iteration itself has to be guarded. A try around the loop
            # body never sees it and the exception escapes parse() — which is exactly
            # what base.py forbids.
            iterator = iter(records)
            while True:
                if emitted >= ctx.max_records:
                    ctx.hint(
                        f"{path.name}: stopped at the {ctx.max_records} record cap"
                    )
                    break
                try:
                    record = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:
                    # There is no resynchronising mid-journal: the generator is spent.
                    # What was read up to here still stands and is still reported.
                    ctx.hint(
                        f"{path.name}: journal ended at record {emitted:,} "
                        f"({type(exc).__name__})"
                    )
                    break
                try:
                    when = record.timestamp
                    if when is None or not (_MIN_YEAR <= when.year <= _MAX_YEAR):
                        continue

                    name = str(record.filename or "")
                    if not name:
                        continue

                    raw = record.record
                    reasons = flag_names(getattr(raw, "Reason", None))
                    attributes = flag_names(getattr(raw, "FileAttributes", None))

                    parent_segment = -1
                    try:
                        reference = raw.ParentFileReferenceNumber
                        parent_segment = int(reference.SegmentNumberLowPart) | (
                            int(reference.SegmentNumberHighPart) << 32
                        )
                    except Exception:
                        pass

                    # Only note the unresolved path once per artifact rather than
                    # per record; it is a property of the collection, not the record.
                    full = str(getattr(record, "full_path", "") or "")
                    if full.startswith(_UNRESOLVED):
                        unresolved_parents += 1
                        full = ""
                except Exception:
                    unreadable += 1
                    continue

                event_type = event_type_for(reasons)
                severity, tags, why = score_record(name, reasons, attributes)
                if severity != "info":
                    promoted += 1

                if earliest is None or when < earliest:
                    earliest = when
                if latest is None or when > latest:
                    latest = when

                reason_text = "|".join(reasons) or "UNKNOWN"
                details = f"File: {name} ¦ Reason: {reason_text}"
                if full:
                    details += f" ¦ Path: {full}"
                elif parent_segment >= 0:
                    details += f" ¦ Parent segment: {parent_segment}"
                if attributes:
                    details += f" ¦ Attributes: {'|'.join(attributes[:4])}"
                if why:
                    details += f" ¦ Why: {why}"

                data = {
                    "name": name,
                    "reasons": reasons,
                    "attributes": attributes,
                    "usn": int(getattr(raw, "Usn", 0) or 0),
                }
                if full:
                    data["path"] = full
                if parent_segment >= 0:
                    data["parent_segment"] = parent_segment
                if why:
                    data["why"] = why

                emitted += 1
                yield ctx.event(
                    timestamp=when,
                    timestamp_desc="USN journal record",
                    event_type=event_type,
                    title=_REASON_TITLE.get(event_type, "File changed"),
                    details=details,
                    message="",
                    data=data,
                    severity=severity,
                    tags=tags,
                    record_id=str(data["usn"]) or None,
                    **common,
                )

        if not emitted:
            ctx.hint(f"{path.name}: no USN records found")
            return

        span = ""
        if earliest and latest:
            span = f" ¦ Span: {earliest.date()} to {latest.date()}"
        yield ctx.event(
            timestamp=latest or datetime.now(timezone.utc),
            timestamp_desc="USN journal summary",
            event_type="filesystem_timeline",
            title="NTFS USN journal ingested",
            details=(
                f"Records: {emitted:,} ¦ Notable: {promoted:,}{span}"
            ),
            message="",
            data={"records": emitted, "notable": promoted},
            severity="info",
            **common,
        )

        if unresolved_parents:
            ctx.hint(
                f"{path.name}: {unresolved_parents:,} record(s) name a parent "
                "directory that is not in this artifact — join data.parent_segment "
                "to the $MFT segment for the full path"
            )
        if unreadable:
            ctx.hint(f"{path.name}: {unreadable} record(s) could not be read")
