"""Shared data model.

CONSTRAINT: ``Event`` is the only currency between parsers and the rest of the
tool. Parsers know nothing about SQLite, the console, or each other; they yield
Events. That is what makes a cross-artifact timeline and a single search index
possible, and why adding an artifact type never touches the engine.

This module imports nothing from the store, engine, or parsers so every layer can
depend on it without a cycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .attack import AttackDB

# Severity is a closed set; the console colours on it and triage sorts by it.
#
# Five levels, worst first. The addition of 'crit' and 'low' is deliberately
# additive — 'high', 'med' and 'info' keep their exact spellings so every existing
# filter and test keeps working. The extra resolution is what makes 800k events
# tractable, under one rule:
#
#     low  = recognized and routine
#     info = noise, or not recognized at all
#
# That keeps 'info' honest: an event with no template is 'info' and can never be
# promoted, so count(level > info) is a free measure of how much the tool actually
# understood. 'crit' is reserved and small — log cleared, Defender disabled — and
# is never reached by a heuristic.
SEVERITIES = ("crit", "high", "med", "low", "info")
LEVEL_RANK = {"crit": 4, "high": 3, "med": 2, "low": 1, "info": 0}
LEVEL_MARK = {"crit": "!!!", "high": "!!", "med": "!", "low": "·", "info": " "}
LEVEL_STYLE = {
    "crit": "bold white on red", "high": "bold red", "med": "yellow",
    "low": None, "info": "dim",
}


def level_rank(level: str) -> int:
    return LEVEL_RANK.get(str(level or "info"), 0)


def to_utc(value: datetime, assume: tzinfo = timezone.utc) -> datetime:
    """Return a tz-aware UTC datetime.

    A naive datetime is interpreted in ``assume`` (the case timezone) rather than
    silently treated as UTC — log formats like classic syslog carry no offset, and
    guessing UTC would shift every event by the host's real offset.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=assume)
    return value.astimezone(timezone.utc)


@dataclass
class Event:
    """One thing that happened, normalized out of one artifact.

    CONSTRAINT: ``timestamp`` is ALWAYS tz-aware. An artifact with no meaningful
    internal time uses its own mtime with a ``timestamp_desc`` saying so — the
    timeline never holds a null time, because a null would sort unpredictably and
    silently drop out of range filters.
    """

    timestamp: datetime                 # tz-aware, UTC-canonical -> timeline sort key
    timestamp_desc: str                 # 'Event Logged'|'Last Run'|'Registry key last write'|...
    message: str                        # one-line summary -> timeline display + primary FTS target
    event_type: str = "generic"         # 'logon'|'process_exec'|'service_installed'|'registry_write'|...
    source_artifact: str = ""           # logical label, usually parser.name ('evtx/Security'|'linux_syslog')
    artifact_path: str = ""             # provenance; joins to artifacts.path
    host: str = ""                      # multi-host cases; filter + correlation
    user: str = ""                      # filter + correlation
    data: dict = field(default_factory=dict)          # parser-specific fields -> JSON column
    tags: list[str] = field(default_factory=list)     # 'lateral_movement'|'suspicious'|... (Timesketch tag)
    attck: list[str] = field(default_factory=list)    # validated MITRE ids e.g. ['T1021.001']
    severity: str = "info"              # 'high'|'med'|'info'
    event_id: Optional[str] = None      # native id: Windows EventID, syslog msgid; nullable
    parser: str = ""                    # producing parser.name
    artifact_sha256: str = ""           # sha256 of the SOURCE FILE (chain of custody)
    raw: Optional[str] = None           # optional bounded raw record (fidelity, FTS)
    # Display fields. `title` is the human sentence ("Logon succeeded"), `details`
    # the labelled one-line field summary; together they replace a message that
    # used to read "windows event" for 418k rows. `channel` and `record_id` were
    # buried in data or not captured — an analyst filters on the channel, and the
    # record id is the only way a report can point at the exact source record.
    title: str = ""
    details: str = ""
    extra_fields: str = ""              # fields the template did not consume
    channel: str = ""
    record_id: Optional[str] = None

    def utc(self) -> datetime:
        """UTC view of the timestamp, whatever offset it was built with."""
        return self.timestamp.astimezone(timezone.utc)

    def ts_iso(self) -> str:
        """UTC ISO8601 to second precision — the store's sortable text form."""
        return self.utc().strftime("%Y-%m-%d %H:%M:%S")

    def ts_epoch_us(self) -> int:
        """Epoch microseconds — precise sort key and range bound."""
        return int(self.utc().timestamp() * 1_000_000)


@dataclass
class ParseContext:
    """Case-wide facts handed to every ``parse()`` call.

    Parsers stay pure and global-free: everything environmental (assumed
    timezone, host label, caps, the ATT&CK validator) arrives here. It also
    carries the degrade channel — a parser that cannot run says so via
    :meth:`hint` instead of printing or raising.
    """

    evidence_root: Path
    host: str = ""                      # best-known host label for this evidence set
    tz: tzinfo = timezone.utc           # assumed tz for tz-NAIVE log lines
    year_hint: Optional[int] = None     # classic syslog carries no year
    artifact_sha256: str = ""           # precomputed by the engine per file
    attack: Optional["AttackDB"] = None  # technique-id validator; None = skip validation
    max_records: int = 2_000_000        # per-artifact event cap (a pathological file cannot hang a case)
    max_bytes: int = 64 * 1024 * 1024   # per-artifact text read cap
    _hints: list[str] = field(default_factory=list)

    def hint(self, msg: str) -> None:
        """Record a degradation note (missing dependency, cap hit, unparsable
        section). Deduped. The console renders these; the library never prints."""
        if msg and msg not in self._hints:
            self._hints.append(msg)

    @property
    def hints(self) -> list[str]:
        return list(self._hints)

    def valid_attck(self, ids: Iterable[str] | None) -> list[str]:
        """Keep only technique IDs that exist in the bundled ATT&CK DB.

        CONSTRAINT: never surface or persist an ATT&CK id the DB does not know.
        A typo or a retired id would show up in reports and exports as a
        technique that does not exist, so it is dropped here rather than at
        render time.
        """
        if not ids:
            return []
        if self.attack is None:
            # No DB loaded (unit tests, minimal install): normalize but do not invent.
            out, seen = [], set()
            for i in ids:
                t = str(i).strip().upper()
                if t and t not in seen:
                    seen.add(t)
                    out.append(t)
            return out
        return self.attack.valid(ids)

    def event(
        self,
        *,
        timestamp: datetime,
        timestamp_desc: str,
        message: str,
        event_type: str = "generic",
        data: dict | None = None,
        user: str = "",
        host: str = "",
        attck: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        severity: str = "info",
        event_id: str | None = None,
        source_artifact: str = "",
        artifact_path: str = "",
        parser: str = "",
        raw: str | None = None,
        title: str = "",
        details: str = "",
        extra_fields: str = "",
        channel: str = "",
        record_id: str | None = None,
    ) -> Event:
        """Build an Event with the case invariants already applied.

        Parsers may construct ``Event`` directly, but going through here gets
        UTC normalization, the host default, and ATT&CK validation for free —
        which is why every bundled parser uses it.
        """
        # A caller that supplies title+details need not repeat itself in message:
        # the searchable text is exactly those two joined.
        if not message and (title or details):
            message = " ¦ ".join(p for p in (title, details) if p)
        return Event(
            timestamp=to_utc(timestamp, self.tz),
            timestamp_desc=timestamp_desc,
            message=message,
            event_type=event_type,
            source_artifact=source_artifact,
            artifact_path=artifact_path,
            host=host or self.host,
            user=user,
            data=dict(data or {}),
            tags=list(tags or ()),
            attck=self.valid_attck(attck),
            severity=severity if severity in SEVERITIES else "info",
            event_id=event_id,
            parser=parser,
            artifact_sha256=self.artifact_sha256,
            raw=raw,
            title=title,
            details=details,
            extra_fields=extra_fields,
            channel=channel,
            record_id=record_id,
        )


@dataclass
class EventFilter:
    """Declarative timeline/search filter. ``query.py`` turns it into
    parameterized SQL — never string interpolation."""

    start: Optional[datetime] = None
    end: Optional[datetime] = None
    host: Optional[str] = None
    user: Optional[str] = None
    event_type: Optional[str] = None
    source_artifact: Optional[str] = None
    parser: Optional[str] = None
    severity: Optional[str] = None      # exact match: 'crit'|'high'|'med'|'low'|'info'
    # A floor rather than an exact match. Exists because triage means "everything
    # at least this serious", and an exact-match filter cannot express that.
    min_severity: Optional[str] = None
    tag: Optional[str] = None
    limit: int = 0                      # 0 = unbounded
    order: str = "asc"                  # 'asc'|'desc' by (ts_epoch, id)


@dataclass
class Fingerprint:
    """What sniffing one file concluded."""

    path: Path
    kind: str = "unknown"               # 'evtx'|'registry'|'mft'|'sqlite'|'pcap'|'syslog'|'text'|'binary'|...
    sha256: str = ""
    size: int = 0
    mtime: Optional[datetime] = None
    confidence: float = 0.0             # 1.0 magic hit, ~0.85 text heuristic, 0.0 unreadable


@dataclass
class ArtifactResult:
    """Per-file outcome of ingest, for the console to render. The engine returns
    these instead of printing."""

    path: Path
    kind: str = "unknown"
    parser: str = ""
    status: str = "pending"             # 'parsed'|'error'|'unsupported'|'skipped'
    event_count: int = 0
    error: str = ""
    hint: str = ""                      # e.g. "would parse with evtx — pip install ..."
    artifact_id: Optional[int] = None


@dataclass
class Candidate:
    """A proposed answer to a Sherlock question, formatted the way HTB expects.

    Never auto-submitted — the console frames these as candidates to verify,
    because a confidently wrong answer costs more than no answer.
    """

    answer: str
    label: str
    confidence: float                   # 0..1
    source: str = ""                    # source_artifact it came from
    why: str = ""                       # short provenance, e.g. "logon_failed @ 2024-01-02 03:04:05"
    event_id: Optional[int] = None       # events.id row it came from
    extra: Any = None
