"""Linux configuration and account files, read as evidence.

Written because a real case was answered entirely from a config file the tool never
opened. MongoDB accepted unauthenticated connections from any address, and both halves
of that were in ``/etc/mongod.conf``::

    net:
      bindIp: 0.0.0.0        # every interface
    #security:               # authorization never enabled

An analyst reading that file knows immediately. The tool had 22 MB of connection logs
and no idea why the connections were allowed.

**Comments are parsed, not skipped.** For ``mongod.conf`` the finding *is* a commented
line: ``#security:`` and an absent ``security:`` look identical to a normal config
reader, and both mean unauthenticated. A parser that strips comments cannot tell a
deliberately disabled control from one that was never configured, and the difference
matters when you are writing up how a host was exposed.

**Every file produces a posture event even when nothing is wrong.** Otherwise "no
finding" and "the file was never collected" look the same in a timeline, and an analyst
cannot tell whether they checked something or missed it.

Severity here is about exposure, not certainty. A UID 0 account that is not root, a
password field that is empty, a NOPASSWD sudoers rule and an SSH key in a service
account's home are each enough on their own; a bind address of ``0.0.0.0`` is only
serious once nothing is authenticating.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ...evidence import is_evidence_config
from ...models import Event, ParseContext
from ..base import Parser, register

_MAX_LINES = 20_000
_MAX_VALUE = 400

# Shells that mean a human can log in. A service account with one of these is worth a
# look; nologin/false is the expected state.
_REAL_SHELLS = (
    "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh",
    "/bin/dash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish",
)
_NO_LOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")

# Commands in a cron job or shell profile that mean "fetch and run something".
_FETCH_EXEC = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|socat|base64|python3?\s+-c|perl\s+-e|"
    r"bash\s+-i|sh\s+-i|/dev/tcp/|openssl\s+s_client)\b", re.I
)


def _clean(value: str) -> str:
    return value.strip().strip('"').strip("'")[:_MAX_VALUE]


def _read(path: Path, ctx: ParseContext) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = []
            for index, line in enumerate(handle):
                if index >= _MAX_LINES:
                    ctx.hint(f"{path.name}: stopped at {_MAX_LINES} lines")
                    break
                lines.append(line.rstrip("\n"))
            return lines
    except OSError as exc:
        ctx.hint(f"{path.name}: cannot read ({exc})")
        return []


def _mtime(path: Path) -> datetime:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# YAML-subset reader: enough for mongod.conf, netplan and daemon.json-style files
# ---------------------------------------------------------------------------

def read_indented_config(lines: list[str]) -> tuple[dict[str, str], set[str]]:
    """Return ``(settings, commented_keys)`` from an indented ``key: value`` file.

    Deliberately not a YAML parser: core inspecthor is stdlib plus rich, and these
    files use one construct. Keys are dotted paths — ``net.bindIp``,
    ``security.authorization``.

    ``commented_keys`` holds dotted paths that appear only behind a ``#``. That set is
    the point of the function: ``#security:`` is how a real host had authentication
    disabled, and it is invisible to anything that treats comments as whitespace.
    """
    settings: dict[str, str] = {}
    commented: set[str] = set()
    # (indent, key) for the active path
    stack: list[tuple[int, str]] = []
    comment_stack: list[tuple[int, str]] = []

    for raw in lines:
        if not raw.strip():
            continue
        is_comment = raw.lstrip().startswith("#")
        text = raw.lstrip("\t ")
        indent = len(raw) - len(text)
        if is_comment:
            text = text.lstrip("#").strip()
            if not text or ":" not in text:
                continue
        stripped = text.strip()
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.split("#", 1)[0].strip() if not is_comment else value.strip()
        if not key or " " in key:
            continue

        target = comment_stack if is_comment else stack
        while target and target[-1][0] >= indent:
            target.pop()
        path = ".".join([k for _i, k in target] + [key])
        target.append((indent, key))

        if is_comment:
            commented.add(path)
        elif value:
            settings[path] = _clean(value)
        else:
            settings.setdefault(path, "")
    return settings, commented


# ---------------------------------------------------------------------------
# per-file handlers
# ---------------------------------------------------------------------------

def _finding(title: str, details: str, severity: str, event_type: str,
             why: str = "", attck: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "title": title, "details": details, "severity": severity,
        "event_type": event_type, "why": why or title, "attck": list(attck),
    }


def inspect_service_config(name: str, lines: list[str]) -> list[dict]:
    """mongod.conf and friends: what is it listening on, and is anything checked?"""
    settings, commented = read_indented_config(lines)
    out: list[dict] = []

    bind = settings.get("net.bindIp", "") or settings.get("net.bindIpAll", "")
    port = settings.get("net.port", "")
    auth = (settings.get("security.authorization", "")
            or settings.get("security.authenticationMechanisms", ""))
    auth_on = auth.lower() in ("enabled", "on", "true", "yes")
    key_file = settings.get("security.keyFile", "")
    security_commented = any(k == "security" or k.startswith("security.")
                             for k in commented)

    exposed = bind in ("0.0.0.0", "::", "::,0.0.0.0", "0.0.0.0,::") or bind == "*"
    detail = " ¦ ".join(filter(None, [
        f"bindIp: {bind}" if bind else "",
        f"port: {port}" if port else "",
        f"authorization: {auth or 'not set'}",
        "security block: commented out" if security_commented else "",
        f"keyFile: {key_file}" if key_file else "",
    ]))

    if exposed and not (auth_on or key_file):
        out.append(_finding(
            "Service listens on every interface with NO authentication",
            detail, "crit", "config_exposed_service",
            why=(f"bindIp {bind} reaches every interface and authorization is "
                 + ("commented out" if security_commented else "not enabled")),
            attck=("T1190",),
        ))
    elif not (auth_on or key_file):
        out.append(_finding(
            "Service authentication is not enabled", detail, "high",
            "config_no_auth",
            why="no security.authorization and no keyFile",
            attck=("T1078",),
        ))
    elif exposed:
        out.append(_finding(
            "Service listens on every interface", detail, "med",
            "config_bind_all", why=f"bindIp {bind}", attck=("T1190",),
        ))
    else:
        out.append(_finding(
            f"{name} configuration", detail or "no notable settings", "low",
            "config_posture",
        ))
    return out


_SSHD_RISKS: tuple[tuple[str, str, str, str], ...] = (
    ("permitrootlogin", "yes", "high", "root may log in over SSH"),
    ("permitrootlogin", "prohibit-password", "low", "root may log in with a key"),
    ("permitemptypasswords", "yes", "crit", "empty passwords accepted over SSH"),
    ("passwordauthentication", "yes", "low", "password authentication is enabled"),
    ("gssapiauthentication", "yes", "low", "GSSAPI authentication is enabled"),
    ("permittunnel", "yes", "med", "SSH tunnelling is permitted"),
    ("allowtcpforwarding", "yes", "low", "TCP forwarding is permitted"),
    ("x11forwarding", "yes", "low", "X11 forwarding is permitted"),
)


def inspect_sshd_config(lines: list[str]) -> list[dict]:
    settings: dict[str, str] = {}
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            settings.setdefault(parts[0].lower(), _clean(parts[1]))

    out: list[dict] = []
    for key, risky_value, severity, why in _SSHD_RISKS:
        value = settings.get(key, "")
        if value and value.lower() == risky_value:
            out.append(_finding(
                f"sshd: {key} {value}", f"{key}: {value}", severity,
                "config_sshd_risk", why=why, attck=("T1021.004",),
            ))

    # The pair is worse than either alone: a remotely guessable root password.
    if (settings.get("permitrootlogin", "").lower() == "yes"
            and settings.get("passwordauthentication", "").lower() == "yes"):
        out.append(_finding(
            "sshd: root login permitted WITH password authentication",
            "PermitRootLogin: yes ¦ PasswordAuthentication: yes", "crit",
            "config_sshd_risk",
            why="root is remotely reachable with a guessable password",
            attck=("T1110", "T1021.004"),
        ))

    detail = " ¦ ".join(f"{k}: {v}" for k, v in list(settings.items())[:10])
    out.append(_finding("sshd configuration", detail or "defaults only", "low",
                        "config_posture"))
    return out


def inspect_passwd(lines: list[str]) -> list[dict]:
    out: list[dict] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = raw.split(":")
        if len(fields) < 7:
            continue
        name, _pw, uid, gid, _gecos, home, shell = fields[:7]
        detail = (f"user: {name} ¦ uid: {uid} ¦ gid: {gid} ¦ home: {home} ¦ "
                  f"shell: {shell}")
        if uid == "0" and name != "root":
            out.append(_finding(
                f"Second UID 0 account: {name}", detail, "crit",
                "config_uid0_account",
                why=f"{name} has uid 0, which is root-equivalent",
                attck=("T1136.001", "T1078.003"),
            ))
        elif shell in _REAL_SHELLS and _looks_like_service_account(name, uid):
            out.append(_finding(
                f"Service account with a login shell: {name}", detail, "med",
                "config_service_shell",
                why=f"{name} (uid {uid}) has {shell} rather than nologin",
                attck=("T1136.001",),
            ))
    return out


_SERVICE_NAMES = ("daemon", "bin", "sys", "games", "man", "lp", "mail", "news",
                  "uucp", "proxy", "backup", "list", "irc", "gnats", "nobody",
                  "systemd", "syslog", "messagebus", "mongodb", "mysql", "postgres",
                  "redis", "www-data", "sshd", "ftp", "nginx", "apache")


def _looks_like_service_account(name: str, uid: str) -> bool:
    try:
        numeric = int(uid)
    except ValueError:
        return False
    if name in _SERVICE_NAMES:
        return True
    # Debian/Ubuntu system range, excluding root.
    return 0 < numeric < 1000


def inspect_shadow(lines: list[str]) -> list[dict]:
    out: list[dict] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = raw.split(":")
        if len(fields) < 2:
            continue
        name, digest = fields[0], fields[1]
        if digest == "":
            out.append(_finding(
                f"Account with NO password: {name}",
                f"user: {name} ¦ password field: empty", "crit",
                "config_empty_password",
                why=f"{name} can authenticate with no password at all",
                attck=("T1078.003",),
            ))
        elif digest in ("!", "*", "!!", "!*"):
            continue          # locked, which is the safe state
        elif digest.startswith("$1$"):
            out.append(_finding(
                f"Account using MD5 password hashing: {name}",
                f"user: {name} ¦ hash: $1$ (MD5-crypt)", "med",
                "config_weak_hash",
                why="MD5-crypt is trivially crackable",
                attck=("T1110.002",),
            ))
    return out


def inspect_sudoers(lines: list[str], where: str) -> list[dict]:
    out: list[dict] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("Defaults"):
            continue
        if "NOPASSWD" in stripped.upper():
            severity = "high" if re.search(r"ALL\s*$", stripped) else "med"
            out.append(_finding(
                "Passwordless sudo rule", f"{where}: {stripped[:200]}", severity,
                "config_nopasswd_sudo",
                why="this rule grants sudo without re-authenticating",
                attck=("T1548.003",),
            ))
        elif re.search(r"=\s*\(\s*ALL\s*(:\s*ALL\s*)?\)\s*ALL", stripped):
            out.append(_finding(
                "Full sudo rule", f"{where}: {stripped[:200]}", "low",
                "config_sudo_rule", why="grants full sudo",
            ))
    return out


def inspect_authorized_keys(lines: list[str], path: Path) -> list[dict]:
    out: list[dict] = []
    owner = _home_owner(path)
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        key_type = parts[0] if parts[0].startswith(("ssh-", "ecdsa-", "sk-")) else "?"
        comment = " ".join(parts[2:])[:120] if len(parts) > 2 else "(no comment)"
        fingerprint_source = parts[1] if key_type != "?" else parts[0]
        severity = "high" if owner in ("root", *_SERVICE_NAMES) else "med"
        out.append(_finding(
            f"SSH authorized key for {owner or 'unknown user'}",
            f"user: {owner or '?'} ¦ type: {key_type} ¦ comment: {comment} ¦ "
            f"key: …{fingerprint_source[-24:]}",
            severity, "config_ssh_key",
            why=("an authorized key is passwordless persistent access"
                 + (f" to {owner}" if owner else "")),
            attck=("T1098.004",),
        ))
    return out


def _home_owner(path: Path) -> str:
    """'/root/.ssh/authorized_keys' -> 'root'; '/home/x/.ssh/...' -> 'x'."""
    parts = [p for p in str(path).replace("\\", "/").split("/") if p]
    for index, part in enumerate(parts):
        if part == "home" and index + 1 < len(parts):
            return parts[index + 1]
        if part == "root":
            return "root"
    return ""


def inspect_cron(lines: list[str], where: str) -> list[dict]:
    out: list[dict] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" in stripped.split()[0:1]:
            continue
        if not re.match(r"^[\d*/,\-]+\s", stripped) and not stripped.startswith("@"):
            continue
        match = _FETCH_EXEC.search(stripped)
        if match:
            out.append(_finding(
                "Scheduled job fetches or executes remote content",
                f"{where}: {stripped[:220]}", "high", "config_cron_fetch",
                why=f"cron job uses {match.group(1)}",
                attck=("T1053.003", "T1105"),
            ))
        else:
            out.append(_finding(
                "Scheduled job", f"{where}: {stripped[:220]}", "low",
                "config_cron_job", attck=("T1053.003",),
            ))
    return out


def inspect_preload(lines: list[str]) -> list[dict]:
    """``/etc/ld.so.preload`` is almost never legitimately populated."""
    entries = [line.strip() for line in lines
               if line.strip() and not line.strip().startswith("#")]
    if not entries:
        return []
    return [_finding(
        "ld.so.preload is populated",
        "libraries: " + ", ".join(entries[:6]), "crit", "config_ld_preload",
        why="every process on the host loads these libraries first",
        attck=("T1574.006",),
    )]


@register
class LinuxConfigParser(Parser):
    """Security-relevant Linux configuration and account files."""

    name = "linux_config"
    display = "Linux config/accounts"
    category = "linux"
    # Above generic_text (0.2) so the specialist wins, below a magic-byte match.
    CONF_PATH = 0.75
    requires = ""
    install_hint = ""

    path_globs = (
        "passwd", "shadow", "group", "gshadow", "sudoers", "crontab",
        "sshd_config", "authorized_keys", "authorized_keys2",
        "mongod.conf", "mongodb.conf", "redis.conf", "my.cnf", "pg_hba.conf",
        "ld.so.preload", "hosts.allow", "hosts.deny",
    )

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        return self.CONF_PATH if is_evidence_config(path) else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        lines = _read(path, ctx)
        if not lines:
            return

        posix = str(path).replace("\\", "/").lower()
        name = path.name.lower()
        where = path.name

        if name in ("mongod.conf", "mongodb.conf", "redis.conf", "postgresql.conf"):
            findings = inspect_service_config(path.name, lines)
        elif name in ("sshd_config",):
            findings = inspect_sshd_config(lines)
        elif name == "passwd":
            findings = inspect_passwd(lines)
        elif name == "shadow":
            findings = inspect_shadow(lines)
        elif name == "sudoers" or "/sudoers.d/" in posix:
            findings = inspect_sudoers(lines, where)
        elif name.startswith("authorized_keys"):
            findings = inspect_authorized_keys(lines, path)
        elif name == "crontab" or "/cron." in posix or "/spool/cron/" in posix:
            findings = inspect_cron(lines, where)
        elif name == "ld.so.preload":
            findings = inspect_preload(lines)
        else:
            settings, commented = read_indented_config(lines)
            detail = " ¦ ".join(f"{k}: {v}" for k, v in list(settings.items())[:10])
            findings = [_finding(
                f"{path.name} configuration", detail or f"{len(lines)} line(s)",
                "info", "config_posture",
            )]

        # A file with nothing wrong still has to appear, or "checked and clean" and
        # "never collected" are indistinguishable in the timeline.
        if not findings:
            findings = [_finding(
                f"{path.name} — nothing notable",
                f"{len(lines)} line(s) read, no risky settings found", "info",
                "config_posture",
            )]

        # A config finding is a STATE, not an event: the file describes how the host was
        # configured, not when anything happened. mtime is the only time available and
        # it is unreliable — extracting a collection resets it, which on a real case put
        # every config finding at the extraction date instead of inside the incident
        # window. Labelled explicitly so nobody reads it as the time of a change.
        when = _mtime(path)
        for finding in findings:
            yield ctx.event(
                timestamp=when,
                timestamp_desc="Config file mtime (not the time of the change)",
                event_type=finding["event_type"],
                title=finding["title"],
                details=finding["details"],
                message="",
                severity=finding["severity"],
                attck=finding["attck"],
                data={
                    "config_file": str(path),
                    "why": finding["why"],
                },
                tags=["config"] if finding["severity"] in ("info", "low")
                else ["config", "suspicious"],
                source_artifact=f"config/{path.name}",
                artifact_path=str(path),
                parser=self.name,
            )
