"""Linux auth.log / secure / syslog.

Pure stdlib, so this parser works on any install — which matters because a
stdlib-only checkout must still be able to solve a Linux Sherlock.

Beyond normalizing lines, this correlates the SSH brute-force story: repeated
failures from an address followed by a success for one of the same accounts is
the single most common Sherlock answer chain, and it is only visible if the
parser remembers what it has already seen.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models import Event, ParseContext
from .._textio import read_lines
from ..base import Parser, register

# sshd / sudo / useradd shapes. Named groups keep the emit sites readable.
_RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F:.]+)"
)
_RE_ACCEPT = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F:.]+)"
)
_RE_INVALID = re.compile(r"Invalid user (?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F:.]+)")
_RE_NEWUSER = re.compile(r"new user: name=(?P<user>[^,]+)")
_RE_NEWGROUP = re.compile(r"new group: name=(?P<group>[^,]+)")
_RE_SUDO = re.compile(
    r"sudo:\s+(?P<user>[^\s]+).*?(?:COMMAND=|COMMAND\s*=\s*)(?P<cmd>.+)$"
)
_RE_SUDO_FAIL = re.compile(r"sudo:.*authentication failure.*?user=(?P<user>[^\s]+)")
_RE_SESSION_OPEN = re.compile(
    r"session opened for user (?P<user>[^\s(]+)"
)
_RE_KEY_ACCEPT = re.compile(r"Accepted publickey for (?P<user>[^\s]+)")

# Classic syslog: "Mar  1 12:00:00 host sshd[123]: ..."  (no year, no offset)
_RE_TS_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
# rsyslog ISO: "2024-03-01T12:00:00.123456+00:00 host ..." (authoritative)
_RE_TS_ISO = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
)
_RE_HOST = re.compile(r"^(?:\S+\s+){3}(?P<host>[A-Za-z0-9._-]+)\s")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Commands that, run through sudo or a shell, are worth flagging on sight.
_SUSPICIOUS = (
    (re.compile(r"\b(?:wget|curl)\b.*\b(?:https?|ftp)://", re.I), "T1105", "med"),
    (re.compile(r"\bnc\b\s+(?:-\w+\s+)*[\d.]+\s+\d+", re.I), "T1059.004", "high"),
    (re.compile(r"/dev/tcp/", re.I), "T1059.004", "high"),
    (re.compile(r"\bbase64\b\s+-d", re.I), "T1027", "med"),
    (re.compile(r"\bchattr\b|\bshred\b|\bhistory\s+-c", re.I), "T1070.003", "high"),
    (re.compile(r"\bchmod\b\s+[47]777|\bchmod\b\s+\+s", re.I), "T1222.002", "med"),
    (re.compile(r"\b(?:crontab|systemctl\s+enable)\b", re.I), "T1053.003", "med"),
    (re.compile(r"\buseradd\b|\badduser\b", re.I), "T1136.001", "high"),
)


def _classic_year(month: int, mtime: datetime | None, hint: int | None) -> int:
    """Best-effort year for a syslog line that carries none.

    An explicit hint wins. Otherwise anchor on the file's mtime: entries whose
    month is *later* than the mtime month cannot belong to the mtime year, so
    they fall in the previous one. That is what makes a log spanning New Year
    (December lines in a file last written in January) land correctly.
    """
    if hint:
        return hint
    if mtime is None:
        return datetime.now().year
    return mtime.year - 1 if month > mtime.month else mtime.year


def _line_time(
    line: str, mtime: datetime | None, hint: int | None
) -> tuple[datetime | None, bool]:
    """Return ``(timestamp_or_None, tz_was_explicit)``."""
    match = _RE_TS_ISO.match(line)
    if match:
        raw = match.group("iso").replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
            return parsed, parsed.tzinfo is not None
        except ValueError:
            pass
    match = _RE_TS_CLASSIC.match(line)
    if match:
        month = _MONTHS[match.group("mon")]
        hour, minute, second = (int(p) for p in match.group("time").split(":"))
        try:
            return datetime(
                _classic_year(month, mtime, hint), month, int(match.group("day")),
                hour, minute, second,
            ), False
        except ValueError:
            return None, False
    return None, False


@register
class LinuxSyslog(Parser):
    """auth.log / secure / syslog, including rotated and compressed copies."""

    name = "linux_syslog"
    display = "Linux auth/syslog"
    category = "linux"
    kinds = ("syslog",)
    path_globs = (
        "auth.log*", "secure*", "syslog*", "messages*",
        "*.log", "*.log.gz", "*.log.bz2", "*.log.xz",
    )
    requires = ""            # pure stdlib
    install_hint = ""
    # Classic syslog carries neither year nor UTC offset, so this parser runs in
    # the second ingest pass, after the engine has derived both from the registry
    # and from artifacts that do record absolute time.
    needs_time_context = True

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        """Content beats filename here: collected evidence is full of renamed
        logs, and 'auth.log' shaped content is unmistakable."""
        text = header[:512].decode("utf-8", "replace").lower()
        if any(tok in text for tok in ("sshd[", "sudo:", "systemd[", "cron[", "kernel:")):
            return 0.85
        name = path.name.lower()
        if name.startswith(("auth.log", "secure", "syslog", "messages")):
            return 0.7
        if kind == "syslog":
            return 0.65
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            mtime = None

        # ip -> {count, users, first_seen}
        failures: dict[str, dict] = {}
        host_seen = ""
        emitted = 0
        naive_seen = False

        for line in read_lines(path, ctx.max_bytes):
            if emitted >= ctx.max_records:
                ctx.hint(f"{path.name}: stopped at the {ctx.max_records} record cap")
                return
            timestamp, tz_explicit = _line_time(line, mtime, ctx.year_hint)
            if timestamp is None:
                continue
            if not tz_explicit:
                naive_seen = True
            # "Mar  1 12:00:00 web01 sshd[...]" -> host is the 4th field
            if not host_seen:
                match = _RE_HOST.match(line)
                if match:
                    host_seen = match.group("host")
            host = ctx.host or host_seen
            # Naive lines were interpreted in ctx.tz; say so, because an analyst
            # comparing against a UTC EVTX timeline needs to know which times
            # were inferred.
            suffix = "" if tz_explicit else f" (tz assumed {ctx.tz})"

            try:
                for event in self._events_for(
                    line, timestamp, host, suffix, failures, ctx, path
                ):
                    emitted += 1
                    yield event
            except Exception:
                # One malformed line never aborts a log.
                continue

        if naive_seen and not ctx.year_hint:
            ctx.hint(
                f"{path.name}: syslog lines carry no year; inferred from file mtime "
                "(pass a year hint if the evidence was collected later)"
            )

    def _events_for(
        self,
        line: str,
        timestamp: datetime,
        host: str,
        suffix: str,
        failures: dict[str, dict],
        ctx: ParseContext,
        path: Path,
    ) -> Iterator[Event]:
        """Emit the Events implied by one log line."""
        common = dict(
            source_artifact=self.name, artifact_path=str(path), parser=self.name,
            host=host, raw=line[:2000],
        )

        match = _RE_FAILED.search(line)
        if match:
            ip, user = match.group("ip"), match.group("user")
            record = failures.setdefault(ip, {"count": 0, "users": set(), "first": timestamp})
            record["count"] += 1
            record["users"].add(user)
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"SSH auth attempt{suffix}",
                event_type="ssh_failed_login", user=user,
                data={"source_ip": ip, "attempt": record["count"]},
                attck=["T1110.001"], severity="info",
                message=f"Failed SSH password for {user} from {ip}", **common,
            )
            return

        match = _RE_ACCEPT.search(line)
        if match:
            ip, user, method = match.group("ip"), match.group("user"), match.group("method")
            record = failures.get(ip)
            # A publickey success after failures is normal (agent tried keys
            # first); only a password success following failures for the SAME
            # account is evidence the brute force worked.
            cracked = bool(
                record and user in record["users"] and method.lower() != "publickey"
            )
            yield ctx.event(
                timestamp=timestamp,
                timestamp_desc=f"SSH logon{suffix}",
                event_type="ssh_login_success", user=user,
                data={
                    "source_ip": ip, "method": method,
                    "prior_failures": record["count"] if record else 0,
                },
                attck=["T1078"] + (["T1110.001"] if cracked else []),
                severity="high" if cracked else "info",
                tags=["brute_force_success"] if cracked else [],
                message=(
                    f"Brute-force SUCCESS: {user} from {ip} via {method} "
                    f"after {record['count']} failures"
                    if cracked else
                    f"SSH login: {user} from {ip} via {method}"
                ),
                **common,
            )
            return

        match = _RE_INVALID.search(line)
        if match:
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"SSH auth attempt{suffix}",
                event_type="ssh_invalid_user", user=match.group("user"),
                data={"source_ip": match.group("ip")},
                attck=["T1110.001", "T1087.001"], severity="info",
                message=(
                    f"SSH attempt for nonexistent user {match.group('user')} "
                    f"from {match.group('ip')}"
                ),
                **common,
            )
            return

        match = _RE_NEWUSER.search(line)
        if match:
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"Account created{suffix}",
                event_type="account_created", user=match.group("user").strip(),
                attck=["T1136.001"], severity="high",
                message=f"Local account created: {match.group('user').strip()}",
                **common,
            )
            return

        match = _RE_NEWGROUP.search(line)
        if match:
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"Group created{suffix}",
                event_type="group_created",
                data={"group": match.group("group").strip()},
                attck=["T1136"], severity="info",
                message=f"Local group created: {match.group('group').strip()}",
                **common,
            )
            return

        match = _RE_SUDO.search(line)
        if match:
            cmd = match.group("cmd").strip()
            attck = ["T1548.003"]
            severity = "info"
            for pattern, technique, sev in _SUSPICIOUS:
                if pattern.search(cmd):
                    attck.append(technique)
                    severity = sev if sev == "high" else max(severity, sev, key=_sev_rank)
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"Privilege escalation{suffix}",
                event_type="sudo_command", user=match.group("user"),
                data={"cmd": cmd[:500]}, attck=attck, severity=severity,
                message=f"sudo: {match.group('user')} ran {cmd[:120]}",
                **common,
            )
            return

        match = _RE_SUDO_FAIL.search(line)
        if match:
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"sudo failure{suffix}",
                event_type="sudo_failed", user=match.group("user"),
                attck=["T1548.003"], severity="info",
                message=f"sudo authentication failure for {match.group('user')}",
                **common,
            )
            return

        match = _RE_SESSION_OPEN.search(line)
        if match:
            yield ctx.event(
                timestamp=timestamp, timestamp_desc=f"Session opened{suffix}",
                event_type="session_open", user=match.group("user"),
                attck=["T1078"], severity="info",
                message=f"Session opened for {match.group('user')}",
                **common,
            )


_SEV_ORDER = {"info": 0, "med": 1, "high": 2}


def _sev_rank(value: str) -> int:
    return _SEV_ORDER.get(value, 0)
