"""Tests for rarity scoring — the part that does not need to know what an attack is.

Every other signal in this tool encodes an attack somebody already described, and the
path scorer was tuned against one intrusion whose answer was known in advance. These
tests are built the other way round: the fixtures describe a *host*, not an attack, and
the assertion is that the odd thing stands out from that host's own history.

The confirmed chain is used only to check the signal points the right way. Nothing here
looks at a filename, a path or a command string — swap ``node.exe`` for anything else
and the assertions hold, which is the whole claim being made.
"""
from __future__ import annotations

import pytest

from inspecthor import rarity
from inspecthor.models import LEVEL_RANK

DAY = 86_400_000_000        # microseconds
SEC = 1_000_000


def _proc(image: str, parent: str, ts: str, epoch: int, severity: str = "info",
          event_id: int = 1) -> dict:
    return {
        "id": event_id,
        "ts": ts,
        "ts_epoch": epoch,
        "severity": severity,
        "event_type": "process_created",
        "tags": [],
        "data": {"new_process_name": image, "parent_process_name": parent},
    }


def _busy_host() -> list[dict]:
    """Eight months of ordinary workstation behaviour.

    Launches are spread across each day on purpose. The first version of this fixture
    put all twelve Chrome starts one microsecond apart, which made ``explorer.exe``
    register as a spawn burst and quietly turned the baseline into an anomaly — the
    detector was right and the fixture was not.
    """
    rows: list[dict] = []
    eid = 0
    base = 1_700_000_000_000_000
    for day in range(240):
        stamp = f"2026-0{1 + day % 9}-{1 + day % 28:02d} 09:00:00"
        for slot in range(12):
            eid += 1
            rows.append(_proc(r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                              r"C:\Windows\explorer.exe", stamp,
                              base + day * DAY + slot * 1800 * SEC, event_id=eid))
        for slot in range(3):
            eid += 1
            rows.append(_proc(r"C:\Windows\System32\svchost.exe",
                              r"C:\Windows\System32\services.exe", stamp,
                              base + day * DAY + slot * 7200 * SEC, event_id=eid))
    return rows


# ---- binary rarity -----------------------------------------------------------


def test_a_binary_seen_once_is_rare_and_chrome_is_not():
    rows = _busy_host()
    rows.append(_proc(r"C:\Users\kimv\AppData\Local\x\node.exe",
                      r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "2026-07-27 16:56:17", 1_800_000_000_000_000, event_id=99_001))
    stats, _pairs, _bursts = rarity.profile(rows)
    assert stats["node.exe"].rare
    assert not stats["chrome.exe"].rare
    assert not stats["svchost.exe"].rare


def test_rarity_is_keyed_on_the_basename_not_the_full_path():
    """A dropper that copies itself to a fresh directory each run would otherwise
    look novel every single time, and the signal would be worthless."""
    rows = _busy_host()
    for i in range(30):
        rows.append(_proc(rf"C:\Users\kimv\AppData\Local\dir{i}\payload.exe",
                          r"C:\Windows\explorer.exe", "2026-07-27 16:56:17",
                          1_800_000_000_000_000 + i, event_id=90_000 + i))
    stats, _pairs, _bursts = rarity.profile(rows)
    assert stats["payload.exe"].runs == 30
    assert not stats["payload.exe"].rare, "30 runs is not rare, wherever they ran from"


# ---- parent/child pair rarity ------------------------------------------------


def test_a_first_ever_parent_child_edge_is_detected():
    """The strongest of the three signals: normal software has a stable process
    tree, and this is what would have caught the confirmed incident cold."""
    rows = _busy_host()
    rows.append(_proc(r"C:\Users\kimv\AppData\Local\x\node.exe",
                      r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "2026-07-27 16:56:17", 1_800_000_000_000_000, event_id=99_001))
    stats, pairs, bursts = rarity.profile(rows)
    assert pairs[("powershell.exe", "node.exe")] == 1
    assert pairs[("explorer.exe", "chrome.exe")] > 100

    burst_parents = {p: n for p, _a, n in bursts}
    level, tags, reasons = rarity.score_row(
        rows[-1], stats, pairs, burst_parents,
    )
    assert "rare_parent_child" in tags
    assert LEVEL_RANK[level] > LEVEL_RANK["info"]
    assert any("powershell.exe -> node.exe" in r for r in reasons), reasons


def test_a_common_parent_child_edge_is_not_promoted():
    rows = _busy_host()
    stats, pairs, bursts = rarity.profile(rows)
    level, tags, _reasons = rarity.score_row(
        rows[0], stats, pairs, {p: n for p, _a, n in bursts},
    )
    assert level == "info"
    assert not tags


# ---- burst structure ---------------------------------------------------------


def test_a_burst_from_a_routine_parent_is_not_promoted():
    """The measurement that forced the rare-parent qualifier: an absolute child-count
    threshold promoted 19,817 of 24,475 process events on a real host — 81% — and
    caught none of the intrusion. services.exe started 142 children in a minute,
    msiexec.exe 143, Acrobat's renderer 23, and the tag cascaded to every child."""
    rows = _busy_host()
    base = 1_800_000_000_000_000
    for i in range(30):
        rows.append(_proc(r"C:\Windows\System32\msiexec.exe",
                          r"C:\Windows\System32\services.exe",
                          "2026-07-21 18:24:35", base + i * SEC, event_id=96_000 + i))
    stats, pairs, bursts = rarity.profile(rows)
    parents = {p: n for p, _a, n in bursts}
    assert "services.exe" not in parents, (
        "services.exe spawns children on 240 days; bursting is simply what it does"
    )

    promoted = 0
    for row in rows:
        _level, tags, _reasons = rarity.score_row(row, stats, pairs, parents)
        if "spawn_burst" in tags:
            promoted += 1
    assert promoted == 0, f"{promoted} events promoted off a routine parent's fan-out"


def test_a_spawn_burst_is_detected_whatever_the_commands_are():
    """NitSSMjZ.exe started 20 cmd.exe in 8 seconds. The rate is the signal; the
    commands are the part an adversary can change for free."""
    rows = _busy_host()
    base = 1_800_000_000_000_000
    for i in range(20):
        rows.append(_proc(r"C:\Windows\System32\cmd.exe",
                          r"C:\Users\kimv\AppData\Local\x\NitSSMjZ.exe",
                          "2026-07-27 16:56:21", base + i * (SEC // 2),
                          event_id=95_000 + i))
    stats, pairs, bursts = rarity.profile(rows)
    parents = {p: n for p, _a, n in bursts}
    assert "nitssmjz.exe" in parents
    assert parents["nitssmjz.exe"] >= 20

    # And it must actually score, because the parent is one this host barely runs.
    _level, tags, reasons = rarity.score_row(rows[-1], stats, pairs, parents)
    assert "spawn_burst" in tags, reasons


def test_a_burst_straddling_the_window_boundary_is_still_one_burst():
    """A fixed bucket would split a sweep in half and let both halves fall under
    the threshold, so the window slides."""
    rows = []
    base = 1_800_000_000_000_000 + 55 * SEC
    for i in range(12):
        rows.append(_proc(r"C:\Windows\System32\cmd.exe", r"C:\tmp\sweeper.exe",
                          "2026-07-27 16:56:21", base + i * SEC, event_id=i + 1))
    _stats, _pairs, bursts = rarity.profile(rows)
    assert bursts and bursts[0][2] >= rarity.BURST_MIN_CHILDREN


def test_a_boot_time_parent_is_judged_on_fanout_not_its_own_execution_count():
    """services.exe and svchost.exe start once at boot, so by execution count they
    are the rarest binaries on the host while being its most prolific parents. An
    earlier qualifier used execution count and let 750 events through."""
    rows = _busy_host()
    stats, _pairs, bursts = rarity.profile(rows)
    # Never seen as an image at all — the trap.
    assert "services.exe" not in stats
    assert "services.exe" not in {p for p, _a, _n in bursts}


def test_steady_activity_over_hours_is_not_a_burst():
    rows = []
    base = 1_800_000_000_000_000
    for i in range(40):
        rows.append(_proc(r"C:\Windows\System32\svchost.exe",
                          r"C:\Windows\System32\services.exe",
                          "2026-07-27 09:00:00", base + i * 600 * SEC, event_id=i + 1))
    _stats, _pairs, bursts = rarity.profile(rows)
    assert not bursts, bursts


# ---- the deliberate limitation ----------------------------------------------


def test_rarity_alone_cannot_reach_high():
    """The measured reason this is a multiplier and not an alarm: the first version
    of the path scorer produced ~300 false positives from one workstation's
    installer history, and every one of those is also rare and bursty. Rarity lifts
    something into view; it does not get to declare an intrusion."""
    rows = []
    base = 1_800_000_000_000_000
    for i in range(15):
        rows.append(_proc(
            rf"C:\Windows\Temp\{{GUID{i}}}\_isF830.exe",
            r"C:\Windows\SysWOW64\msiexec.exe", "2026-03-04 11:00:00",
            base + i * SEC, event_id=i + 1))
    stats, pairs, bursts = rarity.profile(rows)
    parents = {p: n for p, _a, n in bursts}
    for row in rows:
        level, _tags, _reasons = rarity.score_row(row, stats, pairs, parents)
        assert LEVEL_RANK[level] <= LEVEL_RANK[rarity.RARITY_MAX_LEVEL], level


def test_rarity_promotes_by_one_level_from_wherever_it_started():
    rows = _busy_host()
    odd = _proc(r"C:\Users\kimv\AppData\Local\x\node.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "2026-07-27 16:56:17", 1_800_000_000_000_000, severity="low",
                event_id=99_001)
    rows.append(odd)
    stats, pairs, bursts = rarity.profile(rows)
    level, _tags, _reasons = rarity.score_row(
        odd, stats, pairs, {p: n for p, _a, n in bursts},
    )
    assert level == "med", level


def test_a_curated_high_is_never_lowered_by_rarity():
    rows = _busy_host()
    common = dict(rows[0])
    common["severity"] = "high"
    stats, pairs, bursts = rarity.profile(rows)
    level, _tags, _reasons = rarity.score_row(
        common, stats, pairs, {p: n for p, _a, n in bursts},
    )
    assert level == "high"


# ---- plumbing ----------------------------------------------------------------


def test_score_row_handles_json_encoded_rows_from_the_store():
    """iter_events may hand back data/tags as JSON text rather than objects."""
    import json

    rows = _busy_host()
    raw = {
        "id": 1, "ts": "2026-07-27 16:56:17", "ts_epoch": 1_800_000_000_000_000,
        "severity": "info", "tags": "[]",
        "data": json.dumps({"new_process_name": r"C:\x\node.exe",
                            "parent_process_name": r"C:\y\powershell.exe"}),
    }
    # In the baseline, as apply() always has it: the pass profiles the same rows it
    # scores, so a row scored against a baseline it is absent from is not a real case.
    rows.append(raw)
    stats, pairs, bursts = rarity.profile(rows)
    level, tags, reasons = rarity.score_row(
        raw, stats, pairs, {p: n for p, _a, n in bursts},
    )
    assert reasons and tags
    assert LEVEL_RANK[level] > LEVEL_RANK["info"]


def test_a_binary_absent_from_the_baseline_is_the_most_anomalous_answer():
    """Scoring against another host's baseline is a meaningful question, and
    'never seen here' should not fall through as 'nothing to report'."""
    stats, pairs, _bursts = rarity.profile(_busy_host())
    level, tags, reasons = rarity.score_row(
        _proc(r"C:\x\unknown.exe", r"C:\Windows\explorer.exe",
              "2026-07-27 16:56:17", 1_800_000_000_000_000),
        stats, pairs, {},
    )
    assert "rare_binary" in tags
    assert any("baseline" in r for r in reasons), reasons
    assert LEVEL_RANK[level] > LEVEL_RANK["info"]


def test_no_process_events_is_not_an_error():
    stats, pairs, bursts = rarity.profile([])
    assert stats == {} and pairs == {} and bursts == []
    assert rarity.describe(rarity.Findings()) == []


def test_rows_without_an_image_are_skipped():
    stats, _pairs, _bursts = rarity.profile([
        {"id": 1, "ts": "2026-07-27 00:00:00", "ts_epoch": 1, "data": {}},
    ])
    assert stats == {}
