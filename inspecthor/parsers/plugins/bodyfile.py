"""Sleuth Kit / mactime bodyfile — the filesystem timeline.

UAC and most Linux triage collectors ship one. On the held-out case it was 13 MB and
completely unparsed, which mattered because mongod does not log queries: the connection
log proved 37,630 connections happened and could not say what was read. Filesystem
timestamps on ``/var/lib/mongodb`` are the only remaining evidence of that.

Eleven pipe-separated fields, Unix epoch seconds, ``0`` where a hash was not computed::

    MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    0|/etc/passwd|131081|-rw-r--r--|0|0|1876|1766986864|1766984648|1766984648|1761127364

**One event per distinct timestamp, not per file and not per field.** Per file loses
three of the four times, which is most of why a bodyfile exists — a file modified long
after it was created is the interesting case. Per field emits four events for every
entry, and on a 145,000-entry bodyfile that is 580,000 rows of which three quarters are
duplicates, because a file written once has identical m/c/b times. Grouping by distinct
value gives mactime's own MACB notation (``..cb``, ``m...``) and lands at roughly 2 per
entry.

**Everything is emitted, and almost all of it at ``info``.** A bodyfile is mostly the
operating system, and the tool's contract is that ``timeline.csv`` is complete while
``triage.csv`` is ``>= med``. Filtering here would break the first half of that. What
gets promoted is narrow: executables in world-writable directories, SUID binaries
outside the places SUID belongs, and files in the paths an intruder actually uses.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ...models import Event, ParseContext
from ..base import Parser, register

_FIELDS = 11
_MAX_NAME = 400

# Timestamps outside this range are corrupt or a placeholder, not evidence. Epoch 0
# appears constantly for files whose birth time the filesystem never recorded.
_MIN_EPOCH = 315_532_800          # 1980-01-01
_MAX_EPOCH = 4_102_444_800        # 2100-01-01

# Directories any user can write to. An executable appearing here is the classic Linux
# staging pattern.
_WORLD_WRITABLE = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/spool/", "/var/crash/",
)

# Where SUID binaries legitimately live. Anywhere else is worth a look.
_SUID_EXPECTED = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/",
    "/lib/", "/opt/",
)

# Paths where a change is worth noticing regardless of mode.
_SENSITIVE = (
    "/root/.ssh/", "/.ssh/authorized_keys", "/etc/passwd", "/etc/shadow",
    "/etc/sudoers", "/etc/cron", "/etc/systemd/system/", "/etc/ld.so.preload",
    "/etc/rc.local", "/var/spool/cron/",
)

# Shell histories and credential caches: read or truncated during most intrusions.
_HISTORY = (
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".dbshell",
    ".netrc", ".git-credentials", ".aws/credentials", ".ssh/id_rsa", ".ssh/id_ed25519",
)

# Read-only image mounts. A snap or flatpak carries a complete /etc inside it, so
# /snap/core22/2133/etc/sudoers is a base-image file that cannot be modified in place —
# it produced 18 of 22 'med' findings on a real collection, every one of them noise.
_IMAGE_MOUNTS = (
    "/snap/", "/var/lib/snapd/snaps/", "/var/lib/flatpak/", "/var/lib/docker/overlay",
    "/var/lib/containerd/", "/nix/store/", "/usr/lib/modules/",
)


def _epoch(value: str) -> datetime | None:
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return None
    if not _MIN_EPOCH <= seconds <= _MAX_EPOCH:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def parse_line(line: str) -> dict | None:
    """One bodyfile row into a dict, or None if it is not one.

    Names legitimately contain ``|`` on Linux, so the split is bounded from the right:
    the last nine fields are fixed, whatever the name holds.
    """
    if not line or line.startswith("#"):
        return None
    parts = line.rstrip("\n").split("|")
    if len(parts) < _FIELDS:
        return None
    if len(parts) > _FIELDS:
        # md5 | name-containing-pipes | the 9 fixed trailing fields
        head, tail = parts[0], parts[-9:]
        name = "|".join(parts[1:-9])
        parts = [head, name, *tail]

    digest, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = parts[:11]
    if not name:
        return None
    return {
        "md5": digest if digest and digest != "0" else "",
        "name": name[:_MAX_NAME],
        "inode": inode,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "size": size,
        "times": {
            "a": _epoch(atime), "m": _epoch(mtime),
            "c": _epoch(ctime), "b": _epoch(crtime),
        },
    }


def macb_groups(times: dict[str, datetime | None]) -> list[tuple[str, datetime]]:
    """Group the four times by value, in mactime's MACB order.

    A file written once has identical m, c and b times; emitting three events for it
    would triple the timeline for no information. Returns e.g. ``[("m.c b", dt)]``.
    """
    by_value: dict[datetime, list[str]] = defaultdict(list)
    for flag in ("m", "a", "c", "b"):
        when = times.get(flag)
        if when is not None:
            by_value[when].append(flag)
    out = []
    for when, flags in by_value.items():
        macb = "".join(flag if flag in flags else "." for flag in "macb")
        out.append((macb, when))
    out.sort(key=lambda item: item[1])
    return out


def score_entry(name: str, mode: str, uid: str) -> tuple[str, list[str], str]:
    """(severity, tags, why) for one filesystem entry."""
    lowered = name.replace("\\", "/").lower()

    # Inside a read-only image mount nothing an intruder did is visible, and the
    # contents look exactly like host configuration.
    if any(marker in lowered for marker in _IMAGE_MOUNTS):
        return "info", [], ""

    # Only a regular file can be an executable. Symlinks are always lrwxrwxrwx and
    # sockets srwxrwxrwx, so a mode-only check flagged '/var/spool/mail -> ../mail' and
    # '/tmp/mongodb-27017.sock' as executables in world-writable directories.
    is_regular = mode.startswith("-")
    is_dir = mode.startswith("d")
    executable = is_regular and "x" in mode[1:10]
    suid = is_regular and "s" in mode[1:4]
    sgid = is_regular and "s" in mode[4:7]

    if suid and not any(lowered.startswith(p) or p in lowered for p in _SUID_EXPECTED):
        return "high", ["suid", "suspicious"], (
            f"SUID binary outside the usual locations ({mode})"
        )
    if executable and any(marker in lowered for marker in _WORLD_WRITABLE):
        return "high", ["unusual_exec_path", "suspicious"], (
            "executable in a world-writable directory"
        )
    if any(marker in lowered for marker in _SENSITIVE):
        return "med", ["sensitive_path"], "change to a security-relevant path"
    # In a home directory only: '/usr/share/doc/git/contrib/credential/netrc/test.netrc'
    # is documentation, and matching on the name alone flagged it.
    if (lowered.startswith(("/home/", "/root/")) or "/home/" in lowered) and any(
        lowered.endswith(marker) or f"/{marker}" in lowered for marker in _HISTORY
    ):
        return "med", ["credential_path"], "shell history or credential file"
    if suid or sgid:
        return "low", ["suid"], f"SUID/SGID binary ({mode})"
    if any(marker in lowered for marker in _WORLD_WRITABLE):
        return "low", ["world_writable"], "in a world-writable directory"
    if uid not in ("0", "") and lowered.startswith(("/home/", "/root/")):
        return "low", ["user_file"], ""
    return "info", [], ""


@register
class BodyfileParser(Parser):
    """Sleuth Kit / mactime bodyfile."""

    name = "bodyfile"
    display = "Filesystem timeline (bodyfile)"
    category = "filesystem"
    path_globs = ("bodyfile.txt", "bodyfile", "*.body", "mactime.body")
    requires = ""
    install_hint = ""

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        # Content first: collectors name this file several ways, and the format is
        # unmistakable — 11 pipe-separated fields whose last four are epoch seconds.
        first = header.split(b"\n", 1)[0]
        if first.count(b"|") >= 10:
            parsed = parse_line(first.decode("utf-8", "replace"))
            if parsed and any(v is not None for v in parsed["times"].values()):
                return self.CONF_MAGIC
        name = path.name.lower()
        if any(Path(name).match(g) for g in self.path_globs):
            return self.CONF_GLOB
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        common = dict(
            source_artifact=self.name,
            artifact_path=str(path),
            parser=self.name,
        )

        entries = 0
        emitted = 0
        malformed = 0
        promoted = 0
        earliest: datetime | None = None
        latest: datetime | None = None

        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            ctx.hint(f"{path.name}: cannot read ({exc})")
            return

        with handle:
            for raw in handle:
                if emitted >= ctx.max_records:
                    ctx.hint(
                        f"{path.name}: stopped at the {ctx.max_records} record cap "
                        f"after {entries:,} filesystem entries"
                    )
                    break
                record = parse_line(raw)
                if record is None:
                    if raw.strip():
                        malformed += 1
                    continue
                entries += 1

                groups = macb_groups(record["times"])
                if not groups:
                    continue

                severity, tags, why = score_entry(
                    record["name"], record["mode"], record["uid"],
                )
                if severity != "info":
                    promoted += 1

                for macb, when in groups:
                    if earliest is None or when < earliest:
                        earliest = when
                    if latest is None or when > latest:
                        latest = when

                    details = (
                        f"MACB: {macb} ¦ Path: {record['name']} ¦ "
                        f"Mode: {record['mode']} ¦ UID: {record['uid']} ¦ "
                        f"Size: {record['size']}"
                    )
                    if record["md5"]:
                        details += f" ¦ MD5: {record['md5']}"

                    data = {
                        "path": record["name"],
                        "macb": macb,
                        "mode": record["mode"],
                        "uid": record["uid"],
                        "gid": record["gid"],
                        "size": record["size"],
                        "inode": record["inode"],
                    }
                    if record["md5"]:
                        data["md5"] = record["md5"]
                    if why:
                        data["why"] = why

                    emitted += 1
                    yield ctx.event(
                        timestamp=when,
                        timestamp_desc=_macb_desc(macb),
                        event_type="file_timestamp",
                        title=_title_for(macb, record["mode"]),
                        details=details,
                        message="",
                        data=data,
                        severity=severity,
                        tags=tags,
                        **common,
                    )

        if entries:
            span = ""
            if earliest and latest:
                span = (f" ¦ Span: {earliest.date()} to {latest.date()}")
            yield ctx.event(
                timestamp=latest or datetime.now(timezone.utc),
                timestamp_desc="Bodyfile summary",
                event_type="filesystem_timeline",
                title="Filesystem timeline ingested",
                details=(f"Entries: {entries:,} ¦ Events: {emitted:,} ¦ "
                         f"Notable: {promoted:,}{span}"),
                message="",
                data={"entries": entries, "events": emitted, "notable": promoted},
                severity="info",
                **common,
            )
        if malformed:
            ctx.hint(f"{path.name}: {malformed} line(s) were not bodyfile records")


_MACB_WORDS = {"m": "Modified", "a": "Accessed", "c": "Changed", "b": "Created"}


def _macb_desc(macb: str) -> str:
    """'m.cb' -> 'Modified/Changed/Created'. What the timestamp actually means."""
    words = [_MACB_WORDS[flag] for flag in macb if flag != "."]
    return "/".join(words) or "File timestamp"


def _title_for(macb: str, mode: str) -> str:
    kind = "Directory" if mode.startswith("d") else (
        "Symlink" if mode.startswith("l") else "File")
    if macb == "...b":
        return f"{kind} created"
    if macb.startswith("m") and "b" in macb:
        return f"{kind} created and written"
    if macb.startswith("m"):
        return f"{kind} modified"
    if "c" in macb and "m" not in macb:
        return f"{kind} metadata changed"
    if macb == ".a.." :
        return f"{kind} accessed"
    return f"{kind} timestamp"
