"""Shell and client history files — what someone actually typed.

The most direct evidence there is of what an intruder did, and reported missing on a
real case: *"this log was extremely important in seeing what commands the attacker
ran"*.

It was missing for a reason worth recording. ``.bash_history`` was in the config
parser's evidence list, so that parser claimed it at 0.75 and beat the generic text
fallback at 0.2 — then had no handler for it, fell through to a ``key: value`` reader
that found nothing, and emitted one ``info`` row saying ``.bash_history configuration —
12 line(s)``. The generic parser it displaced would at least have stored a 16 KB
FTS-indexed preview, so ``find mongodump`` would have hit. **A parser that claims a
file and produces nothing is worse than no parser.**

Formats, all of which appear in the wild:

- bash, plain — one command per line, no times
- bash with ``HISTTIMEFORMAT`` — a ``#<epoch>`` line before each command
- zsh extended — ``: <epoch>:<elapsed>;command``
- mongosh / mysql / psql / python REPL histories — plain lines

**Order is evidence even without timestamps.** History files are chronological, so every
event carries its line number and untimed entries are placed in sequence rather than
collapsed onto one mtime. An analyst reading ``mongodump`` three lines after ``mongosh``
learns something the set of commands alone does not tell them.

Severity scores the **command**, not the file. A history full of ``ls`` and ``cd`` is not
a finding; ``mongodump`` against a remote host is.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from ...models import Event, ParseContext
from ..base import Parser, register

_MAX_COMMAND = 800
_MAX_LINES = 20_000

# Filenames that are command histories. Matched on the basename, dot or not.
_HISTORY_NAMES = frozenset({
    ".bash_history", "bash_history", ".sh_history", ".zsh_history", "zsh_history",
    ".ksh_history", ".history", ".zhistory", ".local_history",
    ".mysql_history", ".psql_history", ".sqlite_history", ".dbshell",
    ".rediscli_history", ".mongorc_history", "mongosh_repl_history",
    ".python_history", ".node_repl_history", ".irb_history", ".php_history",
    ".lesshst", ".viminfo",
})

# zsh extended history: ': 1766986864:0;command'
_ZSH = re.compile(r"^:\s*(\d{9,11}):\d+;(.*)$")
# bash HISTTIMEFORMAT marker line
_BASH_TS = re.compile(r"^#(\d{9,11})\s*$")

_MIN_EPOCH = 315_532_800
_MAX_EPOCH = 4_102_444_800


def _epoch(raw: str) -> datetime | None:
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        return None
    if not _MIN_EPOCH <= seconds <= _MAX_EPOCH:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


# What the command does. Ordered: the first match wins, so the most serious reading of
# a line is the one reported.
_COMMAND_RULES: tuple[tuple[re.Pattern, str, str, tuple[str, ...], str], ...] = (
    # (pattern, severity, label, attck, why)
    (re.compile(r"\b(?:curl|wget)\b[^|;&]*[|]\s*(?:ba)?sh\b", re.I), "high",
     "Download piped straight into a shell", ("T1059.004", "T1105"),
     "remote content executed without ever touching disk"),
    (re.compile(r"\b(?:bash|sh)\s+-i\s*>&\s*/dev/tcp/|/dev/(?:tcp|udp)/", re.I), "high",
     "Reverse shell", ("T1059.004",), "shell redirected to a network socket"),
    (re.compile(r"\bnc\b[^\n]*\s-[a-z]*e\b|\bncat\b[^\n]*--exec|\bsocat\b[^\n]*exec", re.I),
     "high", "Netcat/socat with command execution", ("T1059.004",),
     "listener or client wired to a shell"),
    (re.compile(r"\bmongodump\b|\bmongoexport\b|\bmysqldump\b|\bpg_dump(?:all)?\b", re.I),
     "high", "Database dump", ("T1005", "T1030"),
     "bulk export of database contents"),
    (re.compile(r"\b(?:cat|less|more|cp|scp|vi|nano)\b[^\n]*/etc/(?:shadow|gshadow)\b",
                re.I), "high", "Password hash file read", ("T1003.008",),
     "/etc/shadow accessed directly"),
    (re.compile(r"\bhistory\s+-c\b|\bshred\b|\brm\b[^\n]*(?:/var/log|\.bash_history)"
                r"|>\s*[~/][^\n]*\.bash_history|\btruncate\b[^\n]*/var/log", re.I),
     "high", "History or log destruction", ("T1070.003", "T1070.002"),
     "anti-forensics: evidence being removed"),
    (re.compile(r"\bchmod\b\s+[ugoa]*\+s|\bchmod\b\s+[24]\d{3}\b", re.I), "high",
     "SUID bit set", ("T1548.001",), "a binary made to run as its owner"),
    (re.compile(r"\bbase64\b[^\n]*-d|\becho\b[^\n]*[|]\s*base64\s+-d", re.I), "high",
     "Base64 decoded for execution", ("T1140",), "encoded payload being unpacked"),

    (re.compile(r"\b(?:useradd|adduser|usermod)\b", re.I), "med",
     "Account created or modified", ("T1136.001",), "account management from a shell"),
    (re.compile(r"\bpasswd\b\s+\S|\bchpasswd\b", re.I), "med", "Password changed",
     ("T1098",), ""),
    (re.compile(r"authorized_keys", re.I), "med", "SSH authorized_keys touched",
     ("T1098.004",), "passwordless persistent access"),
    (re.compile(r"\bcrontab\b\s+-|\bsystemctl\b\s+(?:enable|link)\b|\.service\b", re.I),
     "med", "Persistence mechanism touched", ("T1053.003", "T1543.002"), ""),
    (re.compile(r"\b(?:curl|wget)\b", re.I), "med", "Remote file fetched",
     ("T1105",), "content downloaded from the network"),
    (re.compile(r"\bmongosh?\b|\bmysql\b|\bpsql\b|\bredis-cli\b", re.I), "med",
     "Database client used", ("T1005",), ""),
    (re.compile(r"\bsudo\b\s+(?:su|-i|-s)\b|\bsu\b\s+-?\s*root\b", re.I), "med",
     "Escalated to root", ("T1548.003",), ""),
    (re.compile(r"\biptables\b|\bufw\b\s+(?:disable|allow)|\bsetenforce\s+0\b", re.I),
     "med", "Host firewall or SELinux changed", ("T1562.004",), ""),

    (re.compile(r"\bwhoami\b|\bid\b\s*$|\buname\b|\bhostname(?:ctl)?\b|\blsb_release\b",
                re.I), "low", "Host discovery", ("T1082",), ""),
    (re.compile(r"\bnetstat\b|\bss\b\s+-|\bip\s+a(?:ddr)?\b|\bifconfig\b|\barp\b", re.I),
     "low", "Network discovery", ("T1016",), ""),
    (re.compile(r"\bps\b\s+(?:aux|-ef)|\btop\b|\blsof\b", re.I), "low",
     "Process discovery", ("T1057",), ""),
    (re.compile(r"\bfind\b[^\n]*-perm|\bgetcap\b", re.I), "low",
     "Privilege discovery", ("T1083",), ""),
)


def classify(command: str) -> tuple[str, str, list[str], str]:
    """(severity, label, attck, why) for one command line."""
    for pattern, severity, label, attck, why in _COMMAND_RULES:
        if pattern.search(command):
            return severity, label, list(attck), why
    return "info", "Command", [], ""


def read_history(lines: list[str]) -> list[tuple[int, datetime | None, str]]:
    """(line_number, timestamp_or_None, command) in file order.

    Handles bash plain, bash with ``HISTTIMEFORMAT``, and zsh extended history in one
    pass, because a single collection routinely holds more than one shell's file.
    """
    out: list[tuple[int, datetime | None, str]] = []
    pending: datetime | None = None
    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n").rstrip("\r")
        if not line.strip():
            continue

        marker = _BASH_TS.match(line)
        if marker:
            pending = _epoch(marker.group(1))
            continue

        zsh = _ZSH.match(line)
        if zsh:
            out.append((number, _epoch(zsh.group(1)), zsh.group(2).strip()[:_MAX_COMMAND]))
            pending = None
            continue

        # A '#' line that is not a timestamp is a comment someone typed; keep it, it is
        # still what they entered.
        out.append((number, pending, line.strip()[:_MAX_COMMAND]))
        pending = None
    return out


@register
class ShellHistoryParser(Parser):
    """Shell and database-client command histories."""

    name = "shell_history"
    display = "Shell/client history"
    category = "linux"
    # Above linux_config's 0.75: a history file is a command log, not configuration.
    CONF_NAME = 0.85
    requires = ""
    install_hint = ""

    path_globs = tuple(sorted(_HISTORY_NAMES))

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        return self.CONF_NAME if path.name.lower() in _HISTORY_NAMES else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = [line for _i, line in zip(range(_MAX_LINES), handle)]
        except OSError as exc:
            ctx.hint(f"{path.name}: cannot read ({exc})")
            return

        commands = read_history(lines)
        if not commands:
            return

        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        owner = _owner(path)
        shell = path.name.lower().lstrip(".").replace("_history", "")
        common = dict(
            source_artifact=f"history/{shell}",
            artifact_path=str(path),
            parser=self.name,
            user=owner,
        )

        # Untimed entries: keep file order visible by spacing them one second apart
        # ending at mtime, so the timeline reads in the order they were typed. The
        # timestamp_desc says plainly that the ordering is real and the clock is not.
        untimed = sum(1 for _n, when, _c in commands if when is None)
        step = 0

        for number, when, command in commands:
            if when is None:
                step += 1
                stamp = mtime - timedelta(seconds=(untimed - step))
                desc = f"History order (line {number}; file mtime, not the run time)"
            else:
                stamp = when
                desc = "Command run"

            severity, label, attck, why = classify(command)
            data = {
                "command": command,
                "line": number,
                "shell": shell,
                "history_file": str(path),
            }
            if owner:
                data["account"] = owner
            if why:
                data["why"] = why

            yield ctx.event(
                timestamp=stamp,
                timestamp_desc=desc,
                event_type="shell_command",
                title=label if label != "Command" else f"Command typed by {owner or '?'}",
                details=f"Cmd: {command}" + (f" ¦ User: {owner}" if owner else "")
                        + f" ¦ Line: {number}",
                message="",
                data=data,
                severity=severity,
                attck=attck,
                tags=["shell_history"] + (["suspicious"] if severity in ("high", "crit")
                                          else []),
                raw=command,
                **common,
            )

        if untimed:
            ctx.hint(
                f"{path.name}: {untimed} command(s) had no timestamp "
                "(HISTTIMEFORMAT was not set) — order is preserved, times are not"
            )


def _owner(path: Path) -> str:
    """'/…/[root]/home/mongoadmin/.bash_history' -> 'mongoadmin'."""
    parts = [p for p in str(path).replace("\\", "/").split("/") if p]
    for index, part in enumerate(parts):
        if part == "home" and index + 1 < len(parts):
            return parts[index + 1]
    # /root/.bash_history, including under a collector's [root] prefix
    for index, part in enumerate(parts[:-1]):
        if part == "root" and parts[index + 1].startswith("."):
            return "root"
    return ""
