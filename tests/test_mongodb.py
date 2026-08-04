"""Tests for the MongoDB log parser and text-log source labelling.

Both exist because of one Sherlock the tool could not answer. The record shapes here
are copied verbatim from a real 22 MB ``mongod.log`` (MongoDB 8.0.16), including the
irregular whitespace mongod emits after ``"s":`` and ``"c":``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from inspecthor.models import EventFilter
from inspecthor.parsers.plugins.generic_text import source_label
from inspecthor.parsers.plugins.mongodb_log import MongoDBLogParser
from inspecthor.store.store import CaseStore

# Verbatim from the real log, including mongod's alignment padding.
STARTUP = (
    '{"t":{"$date":"2025-12-29T05:16:58.104+00:00"},"s":"I",  "c":"CONTROL",  '
    '"id":4615611, "ctx":"initandlisten","msg":"MongoDB starting","attr":'
    '{"pid":2009,"port":27017,"dbPath":"/var/lib/mongodb","architecture":"64-bit",'
    '"host":"mongodbsync"}}'
)
LISTEN = (
    '{"t":{"$date":"2025-12-29T05:16:59.222+00:00"},"s":"I",  "c":"NETWORK",  '
    '"id":23015,   "ctx":"listener","msg":"Listening on","attr":'
    '{"address":"0.0.0.0:27017"}}'
)
NO_AUTH = (
    '{"t":{"$date":"2025-12-29T05:16:59.300+00:00"},"s":"W",  "c":"CONTROL",  '
    '"id":22120,   "ctx":"initandlisten","msg":"Access control is not enabled for '
    'the database. Read and write access to data and configuration is unrestricted"}'
)


def _conn(second: int, ip: str = "65.0.76.43", port: int = 35340) -> str:
    return json.dumps({
        "t": {"$date": f"2025-12-29T05:25:{second:02d}.743+00:00"},
        "s": "I", "c": "NETWORK", "id": 22943, "ctx": "listener",
        "msg": "Connection accepted",
        "attr": {"remote": f"{ip}:{port}", "connectionId": port, "connectionCount": 1},
    })


def _write(tmp_path: Path, lines: list[str], name: str = "mongod.log") -> Path:
    log = tmp_path / name
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return log


def _parse(path: Path, ctx=None):
    from inspecthor.models import ParseContext
    ctx = ctx or ParseContext(evidence_root=path.parent)
    return list(MongoDBLogParser().parse(path, ctx)), ctx


# ---- recognition -------------------------------------------------------------


def test_claimed_by_content_not_only_by_name(tmp_path: Path):
    """Collectors rename things; a rotated log must still be claimed."""
    log = _write(tmp_path, [STARTUP], name="mongod.log.2025-12-29")
    header = log.read_bytes()[:600]
    assert MongoDBLogParser().sniff(log, header) >= MongoDBLogParser.CONF_GLOB


def test_not_claimed_for_unrelated_json(tmp_path: Path):
    other = tmp_path / "package.json"
    other.write_text('{"name":"thing","version":"1.0.0"}\n', encoding="utf-8")
    assert MongoDBLogParser().sniff(other, other.read_bytes()) == 0.0


# ---- the records that answer questions ---------------------------------------


def test_startup_record_yields_version_port_and_host(tmp_path: Path):
    events, _ = _parse(_write(tmp_path, [STARTUP]))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "service_start"
    assert event.data["port"] == "27017"
    assert event.host == "mongodbsync"
    assert "dbPath" in event.details


def test_bind_address_is_captured(tmp_path: Path):
    """'Listening on 0.0.0.0:27017' is the exposure, and it is one line."""
    events, _ = _parse(_write(tmp_path, [STARTUP, LISTEN]))
    listen = [e for e in events if e.event_type == "db_listen"]
    assert listen and "0.0.0.0:27017" in listen[0].details


def test_access_control_disabled_is_high_and_hinted(tmp_path: Path):
    """The whole vulnerability in the measured case, and mongod says it outright."""
    events, ctx = _parse(_write(tmp_path, [STARTUP, NO_AUTH]))
    warn = [e for e in events if e.event_type == "db_no_auth"]
    assert warn, [e.event_type for e in events]
    assert warn[0].severity == "high"
    assert any("access control is disabled" in h.lower() for h in ctx.hints), ctx.hints


def test_connection_records_carry_the_source_ip(tmp_path: Path):
    events, _ = _parse(_write(tmp_path, [_conn(52)]))
    assert events[0].data["source_ip"] == "65.0.76.43"


# ---- the flood, which is the actual finding ----------------------------------


def test_a_connection_flood_becomes_one_high_event(tmp_path: Path):
    """37,630 connections from one address in 75s was the finding; no single
    connection was. Rating each one individually buries it under its own evidence."""
    lines = [STARTUP] + [_conn(52 + (i % 8), port=40000 + i) for i in range(400)]
    events, _ = _parse(_write(tmp_path, lines))

    floods = [e for e in events if e.event_type == "db_connection_flood"]
    assert len(floods) == 1
    flood = floods[0]
    assert flood.severity == "high"
    assert flood.data["source_ip"] == "65.0.76.43"
    assert flood.data["connections"] == 400
    assert "T1046" in flood.attck
    assert "connection_flood" in flood.tags
    assert flood.data["why"]

    # The individual connections stay at info, or the flood is invisible in a sea of
    # its own components.
    conns = [e for e in events if e.event_type == "db_connection"]
    assert conns and all(e.severity == "info" for e in conns)


def test_ordinary_connection_volume_is_not_a_flood(tmp_path: Path):
    events, _ = _parse(_write(tmp_path, [STARTUP] + [_conn(52, port=1000 + i)
                                                     for i in range(20)]))
    assert not [e for e in events if e.event_type == "db_connection_flood"]


def test_two_sources_are_judged_independently(tmp_path: Path):
    lines = [STARTUP]
    lines += [_conn(52 + (i % 5), ip="65.0.76.43", port=40000 + i) for i in range(300)]
    lines += [_conn(52 + (i % 5), ip="10.0.0.9", port=50000 + i) for i in range(5)]
    events, _ = _parse(_write(tmp_path, lines))
    floods = {e.data["source_ip"] for e in events
              if e.event_type == "db_connection_flood"}
    assert floods == {"65.0.76.43"}


# ---- robustness --------------------------------------------------------------


def test_malformed_lines_are_counted_not_fatal(tmp_path: Path):
    events, ctx = _parse(_write(tmp_path, [STARTUP, "not json at all", "{broken",
                                           LISTEN]))
    assert len(events) == 2
    assert any("not valid JSON" in h for h in ctx.hints), ctx.hints


def test_an_empty_log_yields_nothing_and_does_not_raise(tmp_path: Path):
    events, _ = _parse(_write(tmp_path, []))
    assert events == []


def test_every_event_has_a_title_and_details(tmp_path: Path):
    """The v0.5.0 guarantee has to hold for new parsers too."""
    events, _ = _parse(_write(tmp_path, [STARTUP, LISTEN, NO_AUTH, _conn(52)]))
    assert events
    for event in events:
        assert event.title.strip(), event
        assert event.details.strip(), event


# ---- source labelling: "the logs don't specify their source" -----------------


@pytest.mark.parametrize("path,expected", [
    ("/ev/uac/[root]/var/log/mongodb/mongod.log", "text/mongodb"),
    ("/ev/uac/[root]/var/log/apt/history.log", "text/apt"),
    ("/ev/uac/[root]/var/log/amazon/ssm/errors.log", "text/amazon-ssm"),
    ("/ev/uac/[root]/var/log/cloud-init.log", "text/cloud-init"),
    ("/ev/uac/[root]/var/log/dpkg.log", "text/dpkg"),
    ("/ev/uac/[root]/var/log/kern.log", "text/kernel"),
    ("/ev/uac/live_response/process/ps.txt", "text/uac-live-response/process"),
    ("/ev/uac/live_response/network/netstat.txt", "text/uac-live-response/network"),
])
def test_log_sources_are_named(path, expected):
    assert source_label(Path(path)) == expected


def test_an_unknown_log_still_names_its_file():
    """A shared 'generic_text' bucket was the complaint; the filename beats it."""
    label = source_label(Path("/ev/uac/[root]/opt/vendor/weird-service.log"))
    assert label == "text/weird-service.log"
    assert label != "text/generic_text"


def test_two_different_logs_are_distinguishable():
    a = source_label(Path("/x/var/log/mongodb/mongod.log"))
    b = source_label(Path("/x/var/log/apt/history.log"))
    assert a != b


def test_sigma_text_routing_matches_the_new_source_prefix():
    """source_artifact is now 'text/<label>', and the router keys on the part before
    the first '/'. Spelling the token 'generic_text' would route text rules to a
    bucket no event lands in — which reads as a clean host."""
    from inspecthor.detect.sigma_eval import _TEXT_CATEGORIES, _rule_scope

    for sources in _TEXT_CATEGORIES.values():
        assert "generic_text" not in sources
    verdict, eids, tokens = _rule_scope(
        {"logsource": {"category": "webserver"}, "detection": {}}
    )
    assert verdict == "text"
    assert "text" in tokens
    assert source_label(Path("/x/var/log/mongodb/mongod.log")).split("/", 1)[0] == "text"


# ---- end to end --------------------------------------------------------------


def test_mongodb_log_beats_generic_text_in_selection(tmp_path: Path):
    """The specialist has to win, or 22 MB of structured JSON stays anonymous text."""
    from inspecthor.engine import sniff
    from inspecthor.parsers._loader import select_parser

    log = _write(tmp_path, [STARTUP, LISTEN, NO_AUTH, _conn(52)])
    header = log.read_bytes()[:512]
    chosen, _unavailable = select_parser(log, header, sniff(log).kind)
    assert chosen is not None and chosen.name == "mongodb", chosen


def test_startup_advice_is_not_a_finding(tmp_path: Path):
    """mongod emits its tuning advice at W. Mapping W to 'med' put 37 rows of
    housekeeping into the triage file of a real case."""
    advice = json.dumps({
        "t": {"$date": "2025-12-29T05:11:48.000+00:00"},
        "s": "W", "c": "CONTROL", "id": 22178, "ctx": "initandlisten",
        "msg": "For customers running the current memory allocator, we suggest "
               "setting the contents of sysfsFile to 0",
        "attr": {"allocator": "tcmalloc-google", "currentValue": "never"},
    })
    events, _ = _parse(_write(tmp_path, [advice]))
    assert events[0].severity == "info", events[0].title
    assert events[0].event_type == "db_tuning_advice"


def test_access_control_warning_outranks_the_severity_letter(tmp_path: Path):
    """Both are 'W'. One is housekeeping; the other is the vulnerability."""
    events, _ = _parse(_write(tmp_path, [NO_AUTH]))
    assert events[0].severity == "high"


def test_the_flood_answers_the_attacker_ip_question(tmp_path: Path):
    """SSH background noise outranked the real attacker on a real Sherlock, because
    the answer rule only knew about logon events."""
    from inspecthor.analyze import analyze
    from inspecthor.sherlock import answer_question

    root = tmp_path / "ev"
    log_dir = root / "var" / "log" / "mongodb"
    log_dir.mkdir(parents=True)
    _write(log_dir, [STARTUP, LISTEN, NO_AUTH]
           + [_conn(52 + (i % 8), port=40000 + i) for i in range(300)])

    result = analyze(root, out_dir=tmp_path / "out", detect=False)
    store = CaseStore(result.db_path)
    try:
        answers = [c.answer for c in
                   answer_question(store, "What is the attacker's IP address?")]
        assert answers and answers[0] == "65.0.76.43", answers

        when = [c.answer for c in
                answer_question(store, "When did the attacker first connect?")]
        assert when and when[0].startswith("2025-12-29"), when

        count = [c.answer for c in
                 answer_question(store, "How many connections were made?")]
        assert count and count[0] == "300", count

        host = [c.answer for c in answer_question(store, "What is the hostname?")]
        assert "mongodbsync" in host, host
    finally:
        store.close()


def test_mongodb_log_runs_end_to_end_through_analyze(tmp_path: Path):
    """A folder holding a mongod.log must produce the flood finding, not text rows."""
    from inspecthor.analyze import analyze

    root = tmp_path / "ev"
    log_dir = root / "var" / "log" / "mongodb"
    log_dir.mkdir(parents=True)
    lines = [STARTUP, LISTEN, NO_AUTH]
    lines += [_conn(52 + (i % 8), port=40000 + i) for i in range(300)]
    _write(log_dir, lines)

    result = analyze(root, out_dir=tmp_path / "out", detect=False)
    store = CaseStore(result.db_path)
    try:
        floods = list(store.query_events(
            EventFilter(event_type="db_connection_flood")))
        assert len(floods) == 1
        assert floods[0]["severity"] == "high"
        assert "65.0.76.43" in floods[0]["details"]

        no_auth = list(store.query_events(EventFilter(event_type="db_no_auth")))
        assert no_auth, "the disabled-access-control warning must survive ingest"
    finally:
        store.close()
