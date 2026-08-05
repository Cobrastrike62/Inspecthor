"""A parser must never claim a file it cannot actually parse.

This is a structural guard, not a feature test, and it exists because the mistake it
catches has now happened three times in three different places:

* ``Image`` did not map to ``new_process_name``, so 1,299 Sigma process rules loaded,
  evaluated and reported nothing
* the Sigma text-category tokens said ``generic_text`` after ``source_artifact`` became
  ``text/<label>``, routing every webserver and database rule to an empty bucket
* ``linux_config`` claimed ``.bash_history`` at 0.75, beating the generic text parser at
  0.2, then had no handler for it and emitted one content-free ``info`` row — displacing
  a fallback that would have stored a searchable 16 KB preview

Every instance had the same signature: **no error, no warning, and output that reads as
"nothing here".** That is the worst failure mode a forensic tool has, because absence of
evidence and absence of parsing are indistinguishable to the analyst.

The rule asserted here: for a file that is evidence, whichever parser wins must produce
either real events or searchable raw text. A bare posture row is not enough.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from inspecthor.engine import sniff
from inspecthor.models import ParseContext
from inspecthor.parsers._loader import select_parser

# Real evidence filenames with plausible content. Each is something an analyst would be
# angry to find missing.
EVIDENCE: tuple[tuple[str, str, str], ...] = (
    (
        "home/mongoadmin/.bash_history",
        "mongosh --host 127.0.0.1\nshow dbs\nmongodump --out /tmp/x\nhistory -c\n",
        "mongodump",
    ),
    (
        "home/ubuntu/.bash_history",
        "sudo systemctl restart mongod\nexit\n",
        "systemctl",
    ),
    (
        "home/mongoadmin/.python_history",
        "import pymongo\npymongo.MongoClient('mongodb://10.0.0.9:27017')\n",
        "pymongo",
    ),
    (
        "home/mongoadmin/.mysql_history",
        "select * from users;\n",
        "select",
    ),
    (
        "home/mongoadmin/.dbshell",
        'db.users.find({})\ndb.adminCommand("listDatabases")\n',
        "listDatabases",
    ),
    (
        "root/.ssh/authorized_keys",
        "ssh-rsa AAAAB3NzaC1yc2EAAAxxxxxxxxxxxxxx attacker@vps\n",
        "attacker@vps",
    ),
    (
        "etc/mongod.conf",
        "net:\n  bindIp: 0.0.0.0\n#security:\n",
        "0.0.0.0",
    ),
    (
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/tmp:/bin/bash\n",
        "backdoor",
    ),
    (
        "etc/hosts",
        "127.0.0.1 localhost\n10.0.0.9 evil.internal\n",
        "evil.internal",
    ),
    (
        "etc/fstab",
        "/dev/sda1 / ext4 defaults 0 1\n",
        "ext4",
    ),
    (
        "etc/resolv.conf",
        "nameserver 10.0.0.53\n",
        "10.0.0.53",
    ),
    (
        "home/mongoadmin/.netrc",
        "machine ftp.evil.test login bob password hunter2\n",
        "ftp.evil.test",
    ),
    (
        "var/log/auth.log",
        "2025-12-29T05:07:41+00:00 h sshd[1]: Accepted password for ubuntu from "
        "119.73.124.129 port 1 ssh2\n",
        "119.73.124.129",
    ),
)


def _write(tmp_path: Path, rel: str, content: str) -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize("rel,content,needle", EVIDENCE, ids=[e[0] for e in EVIDENCE])
def test_evidence_is_never_silently_swallowed(tmp_path: Path, rel, content, needle):
    """Whoever claims the file must leave its content findable."""
    path = _write(tmp_path, rel, content)
    header = path.read_bytes()[:512]
    parser, _unavailable = select_parser(path, header, sniff(path).kind)
    assert parser is not None, f"nothing claimed {rel}"

    ctx = ParseContext(evidence_root=tmp_path)
    events = list(parser.parse(path, ctx))
    assert events, f"{parser.name} claimed {rel} and produced no events"

    # The content has to be reachable. FTS indexes message, extra_fields and raw, so
    # the needle must appear in at least one of those or in details.
    haystack = " ".join(
        " ".join(filter(None, [e.message, e.details, e.extra_fields, e.raw or ""]))
        for e in events
    )
    assert needle in haystack, (
        f"{parser.name} claimed {rel} but {needle!r} is not searchable; "
        f"produced {len(events)} event(s): "
        f"{[(e.event_type, e.title) for e in events][:3]}"
    )


@pytest.mark.parametrize("rel,content,_needle", EVIDENCE, ids=[e[0] for e in EVIDENCE])
def test_a_claiming_parser_beats_the_generic_fallback_on_value(
    tmp_path: Path, rel, content, _needle,
):
    """A specialist must not produce *less* than the fallback it displaced.

    The .bash_history regression passed every test I had written, because I only tested
    the files I had written handlers for. This compares against the alternative.
    """
    from inspecthor.parsers.plugins.generic_text import GenericText

    path = _write(tmp_path, rel, content)
    header = path.read_bytes()[:512]
    winner, _unavailable = select_parser(path, header, sniff(path).kind)
    assert winner is not None

    ctx = ParseContext(evidence_root=tmp_path)
    winner_events = list(winner.parse(path, ctx))

    if winner.name == "generic_text":
        return
    fallback = GenericText()
    if fallback.sniff(path, header, sniff(path).kind) <= 0:
        return
    fallback_events = list(fallback.parse(path, ParseContext(evidence_root=tmp_path)))

    def value(events) -> int:
        return sum(len(e.details or "") + len(e.raw or "") + len(e.message or "")
                   for e in events)

    assert value(winner_events) >= value(fallback_events) * 0.5, (
        f"{winner.name} retains less content than generic_text would for {rel}"
    )


def test_linux_config_declines_what_it_cannot_handle(tmp_path: Path):
    """The specific bug: sniff() claimed everything is_evidence_config recognized."""
    from inspecthor.parsers.plugins.linux_config import LinuxConfigParser

    parser = LinuxConfigParser()
    handled = _write(tmp_path, "etc/mongod.conf", "net:\n  bindIp: 0.0.0.0\n")
    unhandled = _write(tmp_path, "home/x/.bash_history", "whoami\nmongodump\n")

    assert parser.sniff(handled, handled.read_bytes()) > 0
    assert parser.sniff(unhandled, unhandled.read_bytes()) == 0.0, (
        "linux_config must not claim a file it has no handler for"
    )


def test_shell_history_outranks_the_config_parser(tmp_path: Path):
    """A history file is a command log, not configuration."""
    path = _write(tmp_path, "home/mongoadmin/.bash_history", "mongodump --out /tmp/x\n")
    winner, _ = select_parser(path, path.read_bytes(), sniff(path).kind)
    assert winner is not None and winner.name == "shell_history", winner
