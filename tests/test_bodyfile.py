"""Tests for the mactime bodyfile parser.

Lines here are copied from a real UAC collection's 13 MB ``bodyfile/bodyfile.txt``.
It mattered on that case because mongod does not log queries: the connection log proved
37,630 connections happened and could not say what was read, and filesystem timestamps
were the only remaining evidence.

The volume decisions are what these tests mostly protect. A bodyfile is ~145,000
entries; getting the event-per-entry ratio wrong either loses three quarters of the
timestamps or quadruples the timeline with duplicates.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from inspecthor.models import LEVEL_RANK, ParseContext
from inspecthor.parsers.plugins.bodyfile import (
    BodyfileParser, macb_groups, parse_line, score_entry,
)

# Verbatim first two lines of the real file.
REAL = [
    "0|/|2|drwxr-xr-x|0|0|4096|1766986864|1766984648|1766984648|1761127364",
    "0|/dev|1|drwxr-xr-x|0|0|3240|1766985094|1766984650|1766984650|1766984637",
]


def _parse(tmp_path: Path, lines: list[str], name: str = "bodyfile.txt"):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ctx = ParseContext(evidence_root=tmp_path)
    return list(BodyfileParser().parse(path, ctx)), ctx


def _files(events):
    return [e for e in events if e.event_type == "file_timestamp"]


# ---- format ------------------------------------------------------------------


def test_the_real_first_lines_parse():
    for line in REAL:
        record = parse_line(line)
        assert record is not None, line
        assert record["name"].startswith("/")
        assert record["mode"].startswith("d")


def test_a_name_containing_pipes_still_parses():
    """Linux filenames may contain '|'. Splitting from the left corrupts the row."""
    line = ("0|/tmp/weird|name|with|pipes.txt|262147|-rw-r--r--|1000|1000|12"
            "|1766986864|1766984648|1766984648|1761127364")
    record = parse_line(line)
    assert record is not None
    assert record["name"] == "/tmp/weird|name|with|pipes.txt"
    assert record["mode"] == "-rw-r--r--"
    assert record["uid"] == "1000"


@pytest.mark.parametrize("line", [
    "", "#comment", "not a bodyfile line", "0|/too|few|fields",
])
def test_non_records_are_rejected(line):
    assert parse_line(line) is None


def test_placeholder_epochs_are_dropped_not_dated_to_1970():
    """crtime 0 is 'the filesystem never recorded this', not 1970-01-01."""
    record = parse_line("0|/etc/hosts|1|-rw-r--r--|0|0|10|1766986864|1766984648|1766984648|0")
    assert record is not None
    assert record["times"]["b"] is None
    assert record["times"]["m"] is not None


# ---- MACB grouping: the volume decision --------------------------------------


def test_identical_times_collapse_to_one_event():
    """A file written once has identical m, c and b. Three events for it would triple
    the timeline for no information."""
    when = datetime(2025, 12, 29, 5, 16, tzinfo=timezone.utc)
    groups = macb_groups({"m": when, "a": when, "c": when, "b": when})
    assert groups == [("macb", when)]


def test_distinct_times_produce_distinct_events_in_order():
    created = datetime(2025, 1, 1, tzinfo=timezone.utc)
    modified = datetime(2025, 12, 29, tzinfo=timezone.utc)
    groups = macb_groups({"m": modified, "a": modified, "c": modified, "b": created})
    assert groups == [("...b", created), ("mac.", modified)]


def test_a_file_modified_long_after_creation_keeps_both(tmp_path: Path):
    """The interesting case, and the one an event-per-file design loses."""
    line = ("0|/usr/bin/legit|9|-rwxr-xr-x|0|0|100"
            "|1766986864|1766986864|1766986864|1600000000")
    events, _ = _parse(tmp_path, [line])
    stamps = sorted(e.timestamp for e in _files(events))
    assert len(stamps) == 2
    # 1600000000 is 2020-09-13; 1766986864 is 2025-12-29.
    assert stamps[0].year == 2020 and stamps[1].year == 2025
    assert (stamps[1] - stamps[0]).days > 1800


def test_event_count_stays_near_two_per_entry(tmp_path: Path):
    """Guards the ratio: per-field would be 4x with three quarters duplicates."""
    lines = [
        f"0|/usr/share/doc/pkg{i}/README|{i}|-rw-r--r--|0|0|100"
        f"|17669868{i:02d}|17669848{i:02d}|17669848{i:02d}|16000000{i:02d}"
        for i in range(50)
    ]
    events, _ = _parse(tmp_path, lines)
    rows = _files(events)
    assert 50 <= len(rows) <= 150, len(rows)


def test_macb_notation_and_description_are_readable(tmp_path: Path):
    events, _ = _parse(tmp_path, [REAL[0]])
    rows = _files(events)
    assert rows
    assert any("MACB:" in e.details for e in rows)
    assert any("Created" in e.timestamp_desc or "Modified" in e.timestamp_desc
               for e in rows)


# ---- scoring -----------------------------------------------------------------


def test_executable_in_tmp_is_high():
    severity, tags, why = score_entry("/tmp/.x/miner", "-rwxr-xr-x", "1000")
    assert severity == "high"
    assert "unusual_exec_path" in tags
    assert why


def test_suid_outside_the_usual_locations_is_high():
    severity, tags, why = score_entry("/home/kimv/.local/sh", "-rwsr-xr-x", "0")
    assert severity == "high"
    assert "suid" in tags
    assert "SUID" in why


def test_suid_in_usr_bin_is_expected():
    """sudo, passwd, ping are all SUID and all normal."""
    severity, _tags, _why = score_entry("/usr/bin/sudo", "-rwsr-xr-x", "0")
    assert LEVEL_RANK[severity] <= LEVEL_RANK["low"]


@pytest.mark.parametrize("path", [
    "/root/.ssh/authorized_keys", "/etc/shadow", "/etc/sudoers",
    "/etc/cron.d/backdoor", "/etc/ld.so.preload", "/etc/systemd/system/evil.service",
])
def test_sensitive_paths_are_promoted(path):
    severity, _tags, _why = score_entry(path, "-rw-r--r--", "0")
    assert LEVEL_RANK[severity] >= LEVEL_RANK["med"], path


def test_shell_history_is_promoted():
    severity, tags, _why = score_entry("/home/mongoadmin/.bash_history",
                                       "-rw-------", "1001")
    assert severity == "med"
    assert "credential_path" in tags


@pytest.mark.parametrize("path", [
    "/usr/share/doc/bash/README", "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/var/lib/dpkg/status", "/etc/hostname",
])
def test_ordinary_system_files_stay_info(path):
    """A bodyfile is mostly the operating system. Promoting it would be the same
    failure as rating every connection in a flood."""
    severity, _tags, _why = score_entry(path, "-rw-r--r--", "0")
    assert severity == "info", path


# ---- false positives the real 99,137-entry bodyfile produced ------------------


@pytest.mark.parametrize("path,mode", [
    ("/var/spool/mail", "lrwxrwxrwx"),
    ("/etc/localtime", "lrwxrwxrwx"),
])
def test_symlinks_are_not_executables(path, mode):
    """A symlink is always lrwxrwxrwx, so a mode-only check called every one of them
    an executable. '/var/spool/mail -> ../mail' was flagged high."""
    severity, _tags, _why = score_entry(path, mode, "0")
    assert LEVEL_RANK[severity] < LEVEL_RANK["high"], (path, severity)


def test_unix_sockets_are_not_executables():
    """'/tmp/mongodb-27017.sock' is srwxrwxrwx and was flagged high."""
    severity, _tags, _why = score_entry("/tmp/mongodb-27017.sock", "srwxrwxrwx", "111")
    assert LEVEL_RANK[severity] < LEVEL_RANK["high"]


@pytest.mark.parametrize("path", [
    "/snap/core22/2133/etc/sudoers",
    "/snap/core22/2133/etc/systemd/system/sshd.service",
    "/snap/core22/2133/etc/sudoers.d/README",
    "/snap/core22/2133/var/spool/mail",
    "/var/lib/snapd/snaps/core22_2133.snap",
    "/var/lib/docker/overlay2/abc/diff/etc/shadow",
])
def test_read_only_image_mounts_are_not_findings(path):
    """A snap carries a complete /etc inside it. These produced 18 of 22 'med'
    findings on the real collection, every one of them noise — and they cannot have
    been modified in place, because the mount is read-only."""
    severity, _tags, _why = score_entry(path, "-rw-r--r--", "0")
    assert severity == "info", path


def test_the_real_host_sudoers_is_still_a_finding():
    """The image-mount exemption must not swallow the real one."""
    severity, _tags, _why = score_entry("/etc/sudoers", "-r--r-----", "0")
    assert LEVEL_RANK[severity] >= LEVEL_RANK["med"]


def test_credential_names_outside_a_home_are_not_findings():
    """'/usr/share/doc/git/contrib/credential/netrc/test.netrc' is documentation."""
    severity, _tags, _why = score_entry(
        "/usr/share/doc/git/contrib/credential/netrc/test.netrc", "-rw-r--r--", "0",
    )
    assert severity == "info"


def test_credential_names_inside_a_home_are_findings():
    severity, tags, _why = score_entry("/home/kimv/.netrc", "-rw-------", "1000")
    assert severity == "med"
    assert "credential_path" in tags


# ---- completeness and bounds --------------------------------------------------


def test_everything_is_emitted_not_filtered(tmp_path: Path):
    """timeline.csv is complete by contract; filtering here would break that."""
    lines = REAL + [
        "0|/usr/share/doc/x/README|9|-rw-r--r--|0|0|10|1766986864|1766984648|1766984648|0",
    ]
    events, _ = _parse(tmp_path, lines)
    paths = {e.data["path"] for e in _files(events)}
    assert paths == {"/", "/dev", "/usr/share/doc/x/README"}


def test_a_summary_event_states_the_counts(tmp_path: Path):
    events, _ = _parse(tmp_path, REAL)
    summary = [e for e in events if e.event_type == "filesystem_timeline"]
    assert len(summary) == 1
    assert "Entries: 2" in summary[0].details
    assert "Span:" in summary[0].details


def test_the_record_cap_is_reported_not_silent(tmp_path: Path):
    lines = [
        f"0|/f{i}|{i}|-rw-r--r--|0|0|1|17669868{i:02d}|17669848{i:02d}"
        f"|17669848{i:02d}|16000000{i:02d}"
        for i in range(40)
    ]
    path = tmp_path / "bodyfile.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ctx = ParseContext(evidence_root=tmp_path, max_records=10)
    events = list(BodyfileParser().parse(path, ctx))
    assert len(_files(events)) <= 12
    assert any("cap" in h for h in ctx.hints), ctx.hints


def test_malformed_lines_are_counted_not_fatal(tmp_path: Path):
    events, ctx = _parse(tmp_path, [REAL[0], "garbage", "also|not|a|record", REAL[1]])
    assert len(_files(events)) >= 2
    assert any("not bodyfile records" in h for h in ctx.hints), ctx.hints


def test_every_event_has_a_title_and_details(tmp_path: Path):
    events, _ = _parse(tmp_path, REAL)
    for event in events:
        assert event.title.strip(), event
        assert event.details.strip(), event


# ---- recognition -------------------------------------------------------------


def test_claimed_by_content_under_any_name(tmp_path: Path):
    path = tmp_path / "collected-timeline.dat"
    path.write_text("\n".join(REAL) + "\n", encoding="utf-8")
    assert BodyfileParser().sniff(path, path.read_bytes()) == BodyfileParser.CONF_MAGIC


def test_not_claimed_for_other_pipe_delimited_text(tmp_path: Path):
    path = tmp_path / "table.txt"
    path.write_text("a|b|c|d|e|f|g|h|i|j|k\n", encoding="utf-8")
    assert BodyfileParser().sniff(path, path.read_bytes()) == 0.0


def test_bodyfile_wins_over_generic_text(tmp_path: Path):
    from inspecthor.engine import sniff
    from inspecthor.parsers._loader import select_parser

    path = tmp_path / "bodyfile.txt"
    path.write_text("\n".join(REAL) + "\n", encoding="utf-8")
    chosen, _unavailable = select_parser(path, path.read_bytes()[:512], sniff(path).kind)
    assert chosen is not None and chosen.name == "bodyfile", chosen
