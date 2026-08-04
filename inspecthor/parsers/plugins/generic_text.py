"""Fallback parser for text evidence no specialist claims.

CONSTRAINT: this parser must always be available (pure stdlib) and must always
sit at the lowest confidence, so any specialist beats it. It exists so that an
unrecognized log still lands in the timeline and the search index instead of
being silently skipped — an unparsed file is an invisible file.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...evidence import is_collector_noise
from ...models import Event, ParseContext
from .._textio import read_lines
from ..base import Parser, register

# Timestamp shapes common in application and web logs, most specific first.
_TS_PATTERNS = (
    # 2024-03-01T12:00:00(.123)(+00:00|Z)  /  2024-03-01 12:00:00
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"),
     "iso"),
    # 01/Mar/2024:12:00:00 +0000   (Apache/nginx combined)
    (re.compile(r"(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)"), "clf"),
    # 2024/03/01 12:00:00
    (re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"), "slash"),
)

# Content preview cap for a file with no timestamps at all: enough to search and
# sweep for indicators, bounded so a huge blob cannot bloat one row.
_PREVIEW_BYTES = 16 * 1024
_MAX_LINE = 2000


def _parse_ts(text: str, kind: str) -> datetime | None:
    try:
        if kind == "iso":
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        if kind == "clf":
            cleaned = text.strip()
            fmt = "%d/%b/%Y:%H:%M:%S %z" if ("+" in cleaned or "-" in cleaned[12:]) else "%d/%b/%Y:%H:%M:%S"
            return datetime.strptime(cleaned, fmt)
        if kind == "slash":
            return datetime.strptime(text, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    return None


def _line_ts(line: str) -> datetime | None:
    for pattern, kind in _TS_PATTERNS:
        match = pattern.search(line)
        if match:
            parsed = _parse_ts(match.group(1), kind)
            if parsed is not None:
                return parsed
    return None


# A UAC or /var/log collection is dozens of unrelated logs, and reporting all of them
# as "generic_text" makes the timeline unusable: mongod.log, apt/history.log,
# cloud-init.log and amazon-ssm-agent.log arrive indistinguishable, so a row gives no
# clue which service produced it. Reported directly — "the logs don't specify their
# source so it's hard to tell what's what".
#
# Matched on the collected path, longest first, because the same basename appears under
# several services and the directory is what disambiguates.
_LOG_SOURCES: tuple[tuple[str, str], ...] = (
    ("/var/log/mongodb/", "mongodb"),
    ("/var/log/postgresql/", "postgresql"),
    ("/var/log/mysql/", "mysql"),
    ("/var/log/redis/", "redis"),
    ("/var/log/nginx/", "nginx"),
    ("/var/log/apache2/", "apache"),
    ("/var/log/httpd/", "apache"),
    ("/var/log/amazon/ssm/", "amazon-ssm"),
    ("/var/log/amazon/", "amazon"),
    ("/var/log/unattended-upgrades/", "unattended-upgrades"),
    ("/var/log/landscape/", "landscape"),
    ("/var/log/sysstat/", "sysstat"),
    ("/var/log/apt/", "apt"),
    ("/var/log/audit/", "auditd"),
    ("/var/log/samba/", "samba"),
    ("/var/log/lxd/", "lxd"),
    ("/lxd/logs/", "lxd"),
    ("/var/log/journal/", "systemd-journal"),
    ("/live_response/process", "uac-live-response/process"),
    ("/live_response/network", "uac-live-response/network"),
    ("/live_response/packages", "uac-live-response/packages"),
    ("/live_response/containers", "uac-live-response/containers"),
    ("/live_response/hardware", "uac-live-response/hardware"),
    ("/live_response/storage", "uac-live-response/storage"),
    ("/live_response/system", "uac-live-response/system"),
    ("/live_response/", "uac-live-response"),
    ("/hash_executables/", "uac-hashes"),
)

# Distinctive filenames, used when the directory says nothing.
_LOG_STEMS: dict[str, str] = {
    "cloud-init.log": "cloud-init",
    "cloud-init-output.log": "cloud-init",
    "dpkg.log": "dpkg",
    "alternatives.log": "dpkg-alternatives",
    "kern.log": "kernel",
    "dmesg": "kernel",
    "apport.log": "apport",
    "ufw.log": "ufw",
    "fail2ban.log": "fail2ban",
    "mongod.log": "mongodb",
    "boot.log": "boot",
}


def source_label(path: Path) -> str:
    """A source_artifact that names the log, not just its format.

    Returns e.g. ``text/mongodb``, ``text/apt``, ``text/auth.log``. Prefixed with
    ``text/`` so it is still obvious which parser produced the row, and so existing
    filters on the parser name keep working.
    """
    posix = str(path).replace("\\", "/").lower()
    for marker, label in _LOG_SOURCES:
        if marker in posix:
            return f"text/{label}"
    named = _LOG_STEMS.get(path.name.lower())
    if named:
        return f"text/{named}"
    # Fall back to the filename itself: still far more use than one shared bucket.
    stem = path.name or "text"
    return f"text/{stem[:40]}"


@register
class GenericText(Parser):
    """Timestamped lines become events; untimestamped files become one
    searchable event anchored at the file's mtime."""

    name = "generic_text"
    display = "Generic text/log"
    category = "generic"
    kinds = ("text", "syslog")
    requires = ""
    install_hint = ""

    # Deliberately below every specialist (see the module CONSTRAINT).
    CONF_KIND = 0.2

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        # A triage collector takes the whole of /etc. On one real UAC collection this
        # parser claimed ~3,000 files — AppArmor abstractions, XML schemas, systemd
        # units — and turned each into a one-event row, which is where 80,554 'info'
        # events and a 109 MB case file came from. Declining them registers the file as
        # unsupported, so it is still counted and reported, just not in the timeline.
        if is_collector_noise(path):
            return 0.0
        if kind in ("text", "syslog"):
            return self.CONF_KIND
        # Printable-ratio heuristic for anything the engine could not label.
        if not header:
            return 0.0
        if b"\x00" in header[:512]:
            return 0.0
        sample = header[:512]
        printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
        return 0.15 if printable / max(len(sample), 1) > 0.85 else 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            mtime = datetime.now()

        common = dict(
            source_artifact=source_label(path), artifact_path=str(path),
            parser=self.name,
        )

        emitted = 0
        preview: list[str] = []
        preview_bytes = 0

        for line in read_lines(path, ctx.max_bytes):
            if not line.strip():
                continue
            if emitted >= ctx.max_records:
                ctx.hint(f"{path.name}: stopped at the {ctx.max_records} record cap")
                break
            timestamp = _line_ts(line)
            if timestamp is None:
                if preview_bytes < _PREVIEW_BYTES:
                    preview.append(line[:_MAX_LINE])
                    preview_bytes += len(line)
                continue
            emitted += 1
            yield ctx.event(
                timestamp=timestamp,
                timestamp_desc="Log line time",
                event_type="log_line",
                message=line[:500],
                raw=line[:_MAX_LINE],
                **common,
            )

        # Nothing timestamped: keep the file reachable by search and the IOC sweep
        # rather than dropping it from the case entirely.
        if emitted == 0 and preview:
            yield ctx.event(
                timestamp=mtime,
                timestamp_desc="Artifact mtime (no timestamps in content)",
                event_type="text_artifact",
                message=f"{path.name}: {len(preview)} lines, no parseable timestamps",
                data={"lines": len(preview)},
                raw="\n".join(preview)[:_PREVIEW_BYTES],
                **common,
            )
