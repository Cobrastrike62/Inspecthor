"""Tests for the NTFS USN journal parser.

The journal is the half of a KAPE MFT+USN collection that records what *happened*
rather than what survives, so it is the only evidence of a payload that was staged
and deleted before the collection ran.

Two things here are worth more than the rest. ``test_a_real_page_of_records_parses``
builds actual USN_RECORD_V2 bytes rather than mocking dissect, because the struct
layout and the 4096-byte paging are exactly what a mock would paper over. And the
scoring tests pin the promotions: a journal is overwhelmingly Windows servicing
itself, and the tool's contract is that ``triage.csv`` is ``>= med`` while
``timeline.csv`` is complete.

Reason flags arrive combined — a delete is ``FILE_DELETE|CLOSE``, never
``FILE_DELETE`` on its own — so every check tests membership, not equality.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from inspecthor.models import ParseContext
from inspecthor.parsers.plugins.usnjrnl import (
    UsnJrnlParser, event_type_for, flag_names, score_record,
)

UTC = timezone.utc

# USN reason bits, from the Windows headers.
DATA_EXTEND = 0x00000002
FILE_CREATE = 0x00000100
FILE_DELETE = 0x00000200
RENAME_NEW_NAME = 0x00002000
CLOSE = 0x80000000

FILE_ATTRIBUTE_ARCHIVE = 0x20

_PAGE = 4096
_HEADER = 60                       # USN_RECORD_V2 up to the variable-length name
_FILETIME_EPOCH = 11_644_473_600   # seconds between 1601-01-01 and 1970-01-01


def _filetime(when: datetime) -> int:
    return int((when.timestamp() + _FILETIME_EPOCH) * 10_000_000)


def usn_record(name: str, reason: int, usn: int, when: datetime,
               parent: int = 5, attributes: int = FILE_ATTRIBUTE_ARCHIVE) -> bytes:
    """One USN_RECORD_V2, padded to the 8-byte alignment the format uses."""
    encoded = name.encode("utf-16-le")
    length = _HEADER + len(encoded)
    padded = (length + 7) & ~7
    record = struct.pack(
        "<IHHQQQQIIIIHH",
        padded,          # RecordLength
        2, 0,            # Major/MinorVersion
        0x1000,          # FileReferenceNumber
        parent,          # ParentFileReferenceNumber
        usn,             # Usn
        _filetime(when),
        reason,
        0,               # SourceInfo
        0,               # SecurityId
        attributes,
        len(encoded),    # FileNameLength
        _HEADER,         # FileNameOffset
    )
    return record + encoded + b"\x00" * (padded - length)


def journal_page(records: list[bytes]) -> bytes:
    """One 4096-byte journal page. Trailing zeros end the page, as on disk."""
    body = b"".join(records)
    assert len(body) <= _PAGE, "test records must fit one page"
    return body + b"\x00" * (_PAGE - len(body))


# ---- flags -------------------------------------------------------------------


def test_combined_reason_flags_split_into_names():
    assert flag_names("USN_REASON.FILE_DELETE|CLOSE") == ["FILE_DELETE", "CLOSE"]


def test_a_single_flag_splits():
    assert flag_names("USN_REASON.FILE_CREATE") == ["FILE_CREATE"]


def test_absent_flags_are_not_an_error():
    assert flag_names(None) == []


# ---- reason to event type ----------------------------------------------------


def test_a_delete_outranks_the_close_it_arrives_with():
    """Every delete is FILE_DELETE|CLOSE. If CLOSE wins the record reads as a
    generic change and the deletion disappears from the timeline."""
    assert event_type_for(["FILE_DELETE", "CLOSE"]) == "file_deleted"


def test_a_create_is_a_create():
    assert event_type_for(["FILE_CREATE"]) == "file_created"


def test_a_write_is_a_modification():
    assert event_type_for(["DATA_EXTEND", "CLOSE"]) == "file_modified"


def test_an_unrecognised_reason_still_gets_a_type():
    assert event_type_for(["SOMETHING_NEW"]) == "file_change"


# ---- scoring -----------------------------------------------------------------


def test_a_lure_filename_is_high():
    severity, tags, why = score_record(
        "invoice.pdf.exe", ["FILE_CREATE"], ["ARCHIVE"])
    assert severity == "high"
    assert "double_extension" in tags
    assert ".pdf.exe" in why


def test_a_deleted_executable_is_promoted():
    severity, tags, _why = score_record(
        "beacon.exe", ["FILE_DELETE", "CLOSE"], ["ARCHIVE"])
    assert severity == "med"
    assert "deleted" in tags


def test_a_created_executable_is_recorded_but_not_promoted():
    """Windows servicing, OneDrive and Defender create executables constantly, and
    a standalone $J has no directory to tell an update from a payload. Promoting
    this put 6,590 events into triage."""
    severity, tags, _why = score_record(
        "update.exe", ["FILE_CREATE"], ["ARCHIVE"])
    assert severity == "low"
    assert "dropped_executable" in tags


def test_a_created_dll_is_not_promoted():
    """ssshim.dll appeared 136 times and OneDrive's tutorial .js files 46 each."""
    for name in ("ssshim.dll", "FRE_Tutorial_Intro.js", "OneDrive.exe"):
        severity, _tags, _why = score_record(name, ["FILE_CREATE"], ["ARCHIVE"])
        assert severity in ("info", "low"), name


def test_a_deleted_dll_is_not_promoted():
    """Servicing deletes DLLs in bulk; only the narrower dropper set promotes."""
    severity, _tags, _why = score_record(
        "ssshim.dll", ["FILE_DELETE", "CLOSE"], ["ARCHIVE"])
    assert severity in ("info", "low")


def test_a_rename_into_an_executable_is_promoted():
    """Staging a payload as .tmp and renaming it is how the .exe never gets
    written to disk as an .exe."""
    severity, tags, _why = score_record(
        "payload.exe", ["RENAME_NEW_NAME"], ["ARCHIVE"])
    assert severity == "med"
    assert "renamed_to_executable" in tags


def test_an_ordinary_document_write_stays_at_info():
    """A journal is mostly this. If it promotes, triage is worthless."""
    severity, tags, _why = score_record(
        "notes.docx", ["DATA_EXTEND", "CLOSE"], ["ARCHIVE"])
    assert severity == "info"
    assert tags == []


def test_a_servicing_write_stays_at_info():
    severity, _tags, _why = score_record(
        "esp-locale-cy-gb-3dfd0fca3d74fee0.js.gz",
        ["FILE_DELETE", "CLOSE"], ["ARCHIVE"])
    assert severity == "info"


# ---- selection ---------------------------------------------------------------


def test_the_journal_is_claimed_by_name():
    """$J has no magic — it opens with a sparse region — and at 0.6 it would tie
    with generic_text and get read as text."""
    parser = UsnJrnlParser()
    assert parser.sniff(Path("/C/$Extend/$J"), b"\x00" * 512, "binary") == parser.CONF_MAGIC


def test_the_collector_naming_variants_are_claimed():
    parser = UsnJrnlParser()
    for name in ("$UsnJrnl_$J", "$J"):
        assert parser.sniff(Path(f"/x/{name}"), b"\x00" * 8, "binary") > 0


def test_unrelated_files_are_not_claimed():
    assert UsnJrnlParser().sniff(Path("/x/notes.txt"), b"hello", "text") == 0.0


# ---- end to end --------------------------------------------------------------


def test_a_real_page_of_records_parses(tmp_path: Path):
    """Real USN_RECORD_V2 bytes through dissect, not a mock of it."""
    pytest.importorskip("dissect.ntfs")

    created = datetime(2025, 9, 1, 8, 47, 30, tzinfo=UTC)
    deleted = datetime(2025, 9, 1, 8, 49, 15, tzinfo=UTC)
    page = journal_page([
        usn_record("invoice.pdf.exe", FILE_CREATE, 0x1000, created, parent=98408),
        usn_record("invoice.pdf.exe", FILE_DELETE | CLOSE, 0x1080, deleted, parent=98408),
        usn_record("notes.docx", DATA_EXTEND | CLOSE, 0x1100, created, parent=77),
    ])
    path = tmp_path / "$J"
    path.write_bytes(page)

    ctx = ParseContext(evidence_root=tmp_path)
    events = list(UsnJrnlParser().parse(path, ctx))
    records = [e for e in events if e.event_type != "filesystem_timeline"]

    assert len(records) == 3, [e.details for e in events]

    by_name = {e.data["name"]: e for e in records if e.event_type == "file_created"}
    lure = by_name["invoice.pdf.exe"]
    assert lure.severity == "high"
    assert lure.ts_iso() == "2025-09-01 08:47:30"
    assert lure.data["parent_segment"] == 98408
    assert "FILE_CREATE" in lure.data["reasons"]

    removal = [e for e in records if e.event_type == "file_deleted"][0]
    assert removal.data["reasons"] == ["FILE_DELETE", "CLOSE"]
    assert removal.title == "File deleted"

    ordinary = [e for e in records if e.data["name"] == "notes.docx"][0]
    assert ordinary.severity == "info"


def test_the_summary_reports_what_was_ingested(tmp_path: Path):
    pytest.importorskip("dissect.ntfs")
    page = journal_page([
        usn_record("a.txt", DATA_EXTEND, 0x1000, datetime(2025, 9, 1, tzinfo=UTC)),
    ])
    path = tmp_path / "$J"
    path.write_bytes(page)

    events = list(UsnJrnlParser().parse(path, ParseContext(evidence_root=tmp_path)))
    summary = [e for e in events if e.event_type == "filesystem_timeline"]
    assert len(summary) == 1
    assert "Records: 1" in summary[0].details


def test_an_unreadable_file_degrades_instead_of_raising(tmp_path: Path):
    """CONSTRAINT from base.py: parse() never lets one bad artifact abort a case."""
    path = tmp_path / "$J"
    path.write_bytes(b"not a journal")
    ctx = ParseContext(evidence_root=tmp_path)
    events = list(UsnJrnlParser().parse(path, ctx))
    assert events == []
    assert ctx.hints
