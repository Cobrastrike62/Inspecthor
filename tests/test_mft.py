"""Tests for the NTFS $MFT parser.

Numbers here come from a real KAPE collection's ``C/$MFT`` — 139,533 segments,
323,548 events. The parser was correct on its first run and useless: 248,164 of
those events came back ``high``, because "$SI creation predates $FN creation" is
true for most of an operating system deployed from an image.

**These tests exist to protect the tuning, not the plumbing.** Every suppression
below was a real block of false positives on that collection, and every one of them
would come back the moment someone loosens the rule that killed it. The three that
mattered, in the order they were found:

* ``WofCompressedData`` — the CompactOS overlay stream, on most of ``\\Windows``.
  185,342 events.
* a *shared* $SI-to-$FN skew — one image generation, 136,383 events at 1213 days
  and 43,972 at 1072.
* installers that preserve a vendor build date — VMware's drivers and
  ``MicrosoftEdgeUpdate.exe`` cleared the skew filter because only a dozen files
  share their gap.

The last of those is why ordering and whole-second precision are both required, and
``test_a_genuinely_stomped_file_is_still_caught`` is what stops that pair being
tightened into a rule that can never fire at all.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from inspecthor.parsers.plugins.mft import (
    MftParser, best_filename, macb_groups, resolve_path, score_entry,
    timestomp_signals,
)

UTC = timezone.utc


def _dt(year=2025, month=9, day=1, hour=8, minute=0, second=0, micro=0):
    return datetime(year, month, day, hour, minute, second, micro, tzinfo=UTC)


def _fn(name: str, namespace: int, parent: int = 5, created=None):
    """A stand-in for a dissect $FILE_NAME attribute."""
    return SimpleNamespace(
        file_name=name,
        flags=namespace,
        creation_time=created or _dt(),
        attribute=SimpleNamespace(
            attr=SimpleNamespace(
                ParentDirectory=SimpleNamespace(
                    SegmentNumberLowPart=parent, SegmentNumberHighPart=0,
                )
            )
        ),
    )


# ---- names -------------------------------------------------------------------


def test_the_win32_name_wins_over_the_dos_alias():
    """A record carries both. FAILOV~1 is never what to report."""
    name, parent, _created, namespace = best_filename([
        _fn("FAILOV~1", 2, parent=91),
        _fn("FailoverSignalAggregator", 1, parent=91),
    ])
    assert name == "FailoverSignalAggregator"
    assert namespace == 1
    assert parent == 91


def test_the_dos_alias_is_used_when_it_is_the_only_name():
    name, _parent, _created, _ns = best_filename([_fn("MICROS~1.PF", 2)])
    assert name == "MICROS~1.PF"


def test_a_record_with_no_filename_is_not_an_error():
    assert best_filename([]) == ("", -1, None, -1)


# ---- paths -------------------------------------------------------------------


def test_a_path_is_built_by_walking_parents_to_the_root():
    names = {5: (".", 5), 20: ("Windows", 5), 30: ("System32", 20), 40: ("cmd.exe", 30)}
    assert resolve_path(40, names, {}) == "\\Windows\\System32\\cmd.exe"


def test_a_missing_parent_is_reported_rather_than_guessed():
    """The collection is a subset of a volume; parents legitimately go missing."""
    names = {40: ("thing.exe", 999)}
    assert "orphan" in resolve_path(40, names, {})


def test_a_parent_cycle_terminates():
    """A corrupt table must not hang the parser or blow the stack."""
    names = {10: ("a", 11), 11: ("b", 10)}
    assert resolve_path(10, names, {})          # returns something, does not hang


# ---- MACB grouping -----------------------------------------------------------


def test_identical_timestamps_collapse_into_one_event():
    """A file written once has the same m, c and b time. Three events would be
    three copies of one fact."""
    when = _dt(hour=9)
    groups = macb_groups({"m": when, "a": None, "c": when, "b": when})
    assert groups == [("m.cb", when)]


def test_distinct_timestamps_stay_separate():
    groups = macb_groups({
        "m": _dt(hour=9), "a": _dt(hour=10), "c": _dt(hour=9), "b": _dt(hour=9),
    })
    assert [macb for macb, _ in groups] == ["m.cb", ".a.."]


# ---- timestomping ------------------------------------------------------------


def test_a_genuinely_stomped_file_is_still_caught():
    """The rule must not be tightened into one that can never fire.

    Backdated by a year, every $SI stamp on a whole second, skew unique to this
    record. That is the signature, and it has to survive every suppression below.
    """
    stomped = _dt(2024, 1, 1, 3, 0, 0, micro=0)
    signals = timestomp_signals(
        {"m": stomped, "a": stomped, "c": stomped, "b": stomped},
        fn_creation=_dt(2025, 9, 1),
        is_dir=False, is_baseline=False,
    )
    assert signals
    assert "predates" in signals[0]
    assert "whole second" in signals[1]


def test_an_installer_that_preserves_a_build_date_is_not_a_finding():
    """VMware's drivers and MicrosoftEdgeUpdate.exe. $SI is older than $FN because
    the installer kept the vendor's timestamp — but it has sub-second precision, so
    nothing called SetFileTime on it."""
    old = _dt(2023, 10, 3, 7, 31, 22, micro=413_000)
    assert timestomp_signals(
        {"m": old, "a": old, "c": old, "b": old},
        fn_creation=_dt(2025, 9, 1), is_dir=False, is_baseline=False,
    ) == []


def test_a_shared_deployment_skew_is_not_a_finding():
    """136,383 events sat exactly 1213 days apart. One image, not 136,383 attacks."""
    old = _dt(2022, 5, 7, 5, 24, 50, micro=0)
    assert timestomp_signals(
        {"m": old, "a": old, "c": old, "b": old},
        fn_creation=_dt(2025, 9, 1), is_dir=False, is_baseline=True,
    ) == []


def test_directories_are_not_checked():
    """\\PerfLogs and \\$Recycle.Bin, every time."""
    old = _dt(2022, 5, 7, 5, 24, 50, micro=0)
    assert timestomp_signals(
        {"m": old, "a": old, "c": old, "b": old},
        fn_creation=_dt(2025, 9, 1), is_dir=True, is_baseline=False,
    ) == []


def test_a_forward_ordering_is_not_a_finding():
    """$SI after $FN is ordinary activity: the file was written after it was named."""
    assert timestomp_signals(
        {"b": _dt(2025, 9, 2), "m": _dt(2025, 9, 2)},
        fn_creation=_dt(2025, 9, 1), is_dir=False, is_baseline=False,
    ) == []


def test_a_sub_hour_gap_is_not_a_finding():
    created = _dt(hour=8, minute=0, micro=0)
    assert timestomp_signals(
        {"m": created, "a": created, "c": created, "b": created},
        fn_creation=_dt(hour=8, minute=5), is_dir=False, is_baseline=False,
    ) == []


# ---- alternate data streams --------------------------------------------------


def test_the_compactos_stream_is_not_a_finding():
    """WofCompressedData sits on most of \\Windows. It was 185,342 'high' events."""
    severity, tags, _why = score_entry(
        "\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System.ni.dll",
        "System.ni.dll", in_use=True, is_dir=False, stomped=False,
        ads=("WofCompressedData",),
    )
    assert severity == "info"
    assert "ads" not in tags


def test_mark_of_the_web_is_not_a_finding():
    severity, _tags, _why = score_entry(
        "\\Users\\bob\\Downloads\\report.pdf", "report.pdf",
        in_use=True, is_dir=False, stomped=False, ads=("Zone.Identifier",),
    )
    assert severity == "info"


def test_ntfs_own_streams_are_not_a_finding():
    """$Repair carries $Config/$Corrupt/$Verify on every volume in existence."""
    severity, _tags, _why = score_entry(
        "\\$Extend\\$RmMetadata\\$Repair", "$Repair",
        in_use=True, is_dir=False, stomped=False,
        ads=("$Config", "$Corrupt", "$Verify"),
    )
    assert severity == "info"


def test_an_unexplained_stream_in_a_user_directory_is_high():
    severity, tags, why = score_entry(
        "\\Users\\bob\\AppData\\Local\\Temp\\notes.txt", "notes.txt",
        in_use=True, is_dir=False, stomped=False, ads=("payload",),
    )
    assert severity == "high"
    assert "ads" in tags
    assert "payload" in why


def test_an_unexplained_stream_elsewhere_is_only_noted():
    """Worth recording, not worth interrupting the analyst for."""
    severity, tags, _why = score_entry(
        "\\Program Files\\Vendor\\app.dat", "app.dat",
        in_use=True, is_dir=False, stomped=False, ads=("custom",),
    )
    assert severity == "low"
    assert "ads" in tags


# ---- double extensions -------------------------------------------------------


def test_a_lure_is_high():
    severity, tags, why = score_entry(
        "\\Users\\bob\\Downloads\\invoice.pdf.exe", "invoice.pdf.exe",
        in_use=True, is_dir=False, stomped=False, ads=(),
    )
    assert severity == "high"
    assert "double_extension" in tags
    assert ".pdf.exe" in why


def test_a_dotted_dotnet_assembly_is_not_a_lure():
    """Windows.Data.Pdf.dll is a stock Microsoft component. Reading it as
    '.pdf' + '.dll' produced six 'high' findings in \\Windows\\WinSxS."""
    severity, tags, _why = score_entry(
        "\\Windows\\WinSxS\\amd64_microsoft-windows-data-pdf\\Windows.Data.Pdf.dll",
        "Windows.Data.Pdf.dll", in_use=True, is_dir=False, stomped=False, ads=(),
    )
    assert "double_extension" not in tags
    assert severity != "high"


# ---- paths and state ---------------------------------------------------------


def test_an_executable_in_a_temp_directory_is_high():
    severity, tags, _why = score_entry(
        "\\Users\\bob\\AppData\\Local\\Temp\\update.exe", "update.exe",
        in_use=True, is_dir=False, stomped=False, ads=(),
    )
    assert severity == "high"
    assert "unusual_exec_path" in tags


def test_a_startup_folder_shortcut_is_reported_as_persistence():
    """The one real finding on the first real collection, and it was mislabelled
    'an executable in a writable directory' because the location check ran first."""
    severity, tags, why = score_entry(
        "\\Users\\susan\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"
        "\\Programs\\Startup\\Display Settings.lnk", "Display Settings.lnk",
        in_use=True, is_dir=False, stomped=False, ads=(),
    )
    assert severity == "high"
    assert "persistence" in tags
    assert "Startup" in why


def test_stock_software_in_programdata_is_not_promoted():
    """\\ProgramData\\ holds Defender's scan cache, the VC++ package cache and most
    Start Menu shortcuts. Treating it as staging produced 246 'high' findings and
    all but one were Microsoft's own."""
    for path, name in (
        ("\\ProgramData\\Microsoft\\Windows Defender\\Scans\\MsMpEngCP.exe",
         "MsMpEngCP.exe"),
        ("\\ProgramData\\Package Cache\\{410c0ee1}\\VC_redist.x86.exe",
         "VC_redist.x86.exe"),
        ("\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\WinRAR"
         "\\WinRAR.lnk", "WinRAR.lnk"),
    ):
        severity, _tags, _why = score_entry(
            path, name, in_use=True, is_dir=False, stomped=False, ads=())
        assert severity == "low", path


def test_the_stock_scheduled_tasks_are_not_promoted():
    """Windows ships around 300 of these — 547 'med' events, none a finding."""
    severity, tags, _why = score_entry(
        "\\Windows\\System32\\Tasks\\Microsoft\\Windows\\RetailDemo\\CleanupTask",
        "CleanupTask", in_use=True, is_dir=False, stomped=False, ads=(),
    )
    assert severity == "low"
    assert "persistence" in tags        # still filterable, just not in triage


def test_a_deleted_executable_is_promoted():
    severity, tags, _why = score_entry(
        "\\Windows\\System32\\svchost.exe", "svchost.exe",
        in_use=False, is_dir=False, stomped=False, ads=(),
    )
    assert severity == "med"
    assert "deleted" in tags


def test_an_ordinary_system_file_stays_at_info():
    """The contract is that triage.csv is '>= med'. If this ever promotes, triage
    becomes the timeline."""
    severity, tags, _why = score_entry(
        "\\Windows\\System32\\kernel32.dll", "kernel32.dll",
        in_use=True, is_dir=False, stomped=False, ads=(),
    )
    assert severity == "info"
    assert tags == []


def test_a_stomped_record_outranks_everything_else():
    severity, tags, _why = score_entry(
        "\\Windows\\System32\\kernel32.dll", "kernel32.dll",
        in_use=True, is_dir=False, stomped=True, ads=(),
    )
    assert severity == "high"
    assert "timestomp" in tags


# ---- selection ---------------------------------------------------------------


def test_the_parser_claims_an_mft_by_its_magic():
    from pathlib import Path
    parser = MftParser()
    assert parser.sniff(Path("/C/$MFT"), b"FILE0\x00\x03\x00", "mft") == parser.CONF_MAGIC


def test_the_parser_claims_a_corrupt_record_too():
    """BAAD is a damaged record. It is still an $MFT and still evidence."""
    from pathlib import Path
    parser = MftParser()
    assert parser.sniff(Path("/x/$MFT"), b"BAAD\x00\x00", "") == parser.CONF_MAGIC


def test_the_parser_does_not_claim_unrelated_binaries():
    from pathlib import Path
    assert MftParser().sniff(Path("/x/app.exe"), b"MZ\x90\x00", "pe") == 0.0
