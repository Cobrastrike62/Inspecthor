"""MongoDB server log (``mongod.log``), the structured JSON format of 4.4 and later.

Written because a real Sherlock could not be answered without it. The collection held
22 MB of clean, one-object-per-line JSON — timestamps, severity, component, and the
remote address of every connection — and the tool read all of it as anonymous text.
Every question was about MongoDB and nothing in the timeline said which rows were
MongoDB's.

One record per line::

    {"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"s":"I","c":"NETWORK",
     "id":22943,"ctx":"listener","msg":"Connection accepted",
     "attr":{"remote":"65.0.76.43:35340","connectionId":1,"connectionCount":1}}

**The hard part is severity, not parsing.** On the measured log 75,260 of 75,597
records were ``Connection accepted`` / ``Connection ended``, and the finding was not any
one of them — it was that 37,630 arrived from a single address in 75 seconds. So
connections are emitted at ``info`` for timeline completeness, and the flood itself
becomes one ``high`` event per source. Rating each connection individually would bury
the finding under its own evidence, which is the failure this tool has already made
once at the ``high`` tier.

Note what is *not* here, because an analyst needs to know the difference between "no
evidence" and "not logged": mongod does not log queries by default, so what an intruder
read is absent. And with ``security.authorization`` disabled there are no ``ACCESS``
records at all — not because nothing authenticated, but because nothing had to.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from ...models import LEVEL_RANK, Event, ParseContext
from ..base import Parser, register

# mongod severities. F and E are the server's own failures; a compromise usually shows
# up as W or I, so these map conservatively and the interesting verdicts come from the
# message rules below.
#
# W maps to 'low', not 'med'. Measured: mongod emits its startup advice at W — tcmalloc
# tuning, transparent hugepage settings, deprecated parameter names — and on the real
# log that put 37 rows of housekeeping into the triage file. The verdicts worth reading
# come from the message rules below, which can raise a specific W (access control
# disabled) to 'high' without dragging every other W up with it.
_SEVERITY = {"F": "high", "E": "high", "W": "low", "I": "info", "D1": "info",
             "D2": "info", "D3": "info", "D4": "info", "D5": "info"}

# mongod's own startup tuning advice. Recognized so it is explicitly 'info' rather
# than merely un-promoted, and so nobody later "fixes" it back up to med.
_STARTUP_ADVICE = (
    "we suggest setting", "for customers running the current memory allocator",
    "use of deprecated server parameter", "deprecated", "vm.max_map_count",
    "soft rlimits", "transparent hugepage",
)

# Messages worth naming. Anything not listed keeps the component as its title, which is
# still far better than an untyped text line.
_TITLES: dict[str, tuple[str, str, str]] = {
    # msg -> (title, event_type, severity floor)
    "Connection accepted": ("Connection accepted", "db_connection", "info"),
    "Connection ended": ("Connection ended", "db_connection", "info"),
    "MongoDB starting": ("MongoDB server starting", "service_start", "low"),
    "Listening on": ("Listening on", "db_listen", "low"),
    "Build Info": ("Build info", "software_version", "info"),
    "Operating System": ("Host operating system", "system_info", "info"),
    "Access control is not enabled for the database":
        ("ACCESS CONTROL DISABLED — no authentication required", "db_no_auth", "high"),
    "Authentication failed": ("Authentication failed", "db_auth_failed", "med"),
    "Authentication succeeded": ("Authentication succeeded", "db_auth_success", "low"),
    "Successfully authenticated as principal":
        ("Authenticated", "db_auth_success", "low"),
    "Failed to authenticate": ("Authentication failed", "db_auth_failed", "med"),
    "createUser": ("Database user created", "db_user_created", "high"),
    "dropDatabase": ("Database dropped", "db_dropped", "high"),
    "dropCollection": ("Collection dropped", "db_dropped", "high"),
    "Index build: done building": ("Index build finished", "db_index", "info"),
    "Shutting down": ("MongoDB shutting down", "service_stop", "low"),
    "Received signal": ("Signal received", "service_signal", "low"),
}

# A connection flood: this many from one address inside this window.
_FLOOD_MIN = 200
_FLOOD_WINDOW = timedelta(minutes=10)

_MAX_LINE = 64_000          # a slow-query log line can be enormous
_ATTR_CHARS = 700           # bounded, like every other parser's field capture


def _parse_ts(record: dict) -> datetime | None:
    raw = record.get("t")
    if isinstance(raw, dict):
        raw = raw.get("$date")
    if not isinstance(raw, str) or not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _flatten(attr: Any, prefix: str = "") -> dict[str, str]:
    """One level of useful flattening — mongod nests uuid/buildInfo several deep."""
    out: dict[str, str] = {}
    if isinstance(attr, dict):
        for key, value in attr.items():
            name = f"{prefix}{key}"
            if isinstance(value, (dict, list)):
                text = json.dumps(value, separators=(",", ":"))[:_ATTR_CHARS]
            else:
                text = str(value)
            out[name] = text[:_ATTR_CHARS]
    elif attr not in (None, ""):
        out[prefix or "attr"] = str(attr)[:_ATTR_CHARS]
    return out


def _title_for(msg: str) -> tuple[str, str, str]:
    if msg in _TITLES:
        return _TITLES[msg]
    lowered = msg.lower()
    for needle, spec in _TITLES.items():
        if needle.lower() in lowered:
            return spec
    return (msg[:120] or "MongoDB event", "db_event", "info")


@register
class MongoDBLogParser(Parser):
    """MongoDB server log in the 4.4+ structured JSON format."""

    name = "mongodb"
    display = "MongoDB server log"
    category = "database"
    path_globs = ("mongod.log", "mongod.log.*", "mongodb.log", "mongos.log")
    requires = ""
    install_hint = ""

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        # Content, not just the name: UAC and KAPE both rename things, and a rotated
        # mongod.log.2025-12-29 should still be claimed.
        if header[:1] == b"{" and b'"$date"' in header[:400] and b'"ctx"' in header[:400]:
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
            timestamp_desc="Logged",
        )

        # source address -> [timestamps], for the flood summary emitted at the end.
        connections: dict[str, list[datetime]] = defaultdict(list)
        host = ""
        malformed = 0
        emitted = 0
        auth_enabled: bool | None = None

        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            ctx.hint(f"{path.name}: cannot read ({exc})")
            return

        with handle:
            for raw_line in handle:
                if emitted >= ctx.max_records:
                    ctx.hint(f"{path.name}: stopped at the {ctx.max_records} record cap")
                    break
                line = raw_line.strip()
                if not line or line[0] != "{":
                    if line:
                        malformed += 1
                    continue
                if len(line) > _MAX_LINE:
                    line = line[:_MAX_LINE]
                try:
                    record = json.loads(line)
                except ValueError:
                    malformed += 1
                    continue
                if not isinstance(record, dict):
                    malformed += 1
                    continue

                timestamp = _parse_ts(record)
                if timestamp is None:
                    malformed += 1
                    continue

                msg = str(record.get("msg") or "")
                component = str(record.get("c") or "").strip()
                severity_letter = str(record.get("s") or "I").strip()
                attr = _flatten(record.get("attr"))

                title, event_type, floor = _title_for(msg)
                severity = _SEVERITY.get(severity_letter, "info")
                if LEVEL_RANK.get(floor, 0) > LEVEL_RANK.get(severity, 0):
                    severity = floor
                lowered_msg = msg.lower()
                if any(needle in lowered_msg for needle in _STARTUP_ADVICE):
                    severity, event_type = "info", "db_tuning_advice"

                if msg == "MongoDB starting":
                    host = attr.get("host", "") or host
                if "Access control is not enabled" in msg:
                    auth_enabled = False

                remote = attr.get("remote", "")
                if msg == "Connection accepted" and remote:
                    connections[remote.rsplit(":", 1)[0]].append(timestamp)

                details = " ¦ ".join(
                    f"{k}: {v}" for k, v in list(attr.items())[:10]
                ) or f"component: {component or '-'}"

                data: dict[str, Any] = {
                    "component": component,
                    "mongo_id": record.get("id"),
                    "ctx": record.get("ctx"),
                    "msg": msg,
                    **attr,
                }
                if remote:
                    data["source_ip"] = remote.rsplit(":", 1)[0]

                emitted += 1
                yield ctx.event(
                    timestamp=timestamp,
                    event_type=event_type,
                    title=f"{title}" if not component else f"{title} [{component}]",
                    details=details,
                    message="",
                    data=data,
                    host=host,
                    severity=severity,
                    channel=f"mongodb/{component}" if component else "mongodb",
                    **common,
                )

        # One event per flooding source. The individual connections above are the
        # evidence; this is the finding.
        for source_ip, stamps in connections.items():
            if len(stamps) < _FLOOD_MIN:
                continue
            stamps.sort()
            span = stamps[-1] - stamps[0]
            if span > _FLOOD_WINDOW:
                continue
            seconds = max(span.total_seconds(), 1.0)
            yield ctx.event(
                timestamp=stamps[0],
                event_type="db_connection_flood",
                title="Connection flood from a single address",
                details=(
                    f"SrcIP: {source_ip} ¦ Connections: {len(stamps):,} ¦ "
                    f"Window: {seconds:.0f}s ¦ Rate: {len(stamps)/seconds:.0f}/s ¦ "
                    f"First: {stamps[0].isoformat()} ¦ Last: {stamps[-1].isoformat()}"
                ),
                message="",
                data={
                    "source_ip": source_ip,
                    "connections": len(stamps),
                    "window_seconds": round(seconds, 1),
                    "rate_per_second": round(len(stamps) / seconds, 1),
                    "why": (
                        f"{len(stamps):,} connections from one address in "
                        f"{seconds:.0f}s"
                    ),
                },
                host=host,
                severity="high",
                attck=["T1046"],
                tags=["connection_flood", "suspicious"],
                channel="mongodb/NETWORK",
                **common,
            )

        if auth_enabled is False:
            ctx.hint(
                f"{path.name}: MongoDB logged that access control is disabled — "
                "connections in this log are unauthenticated"
            )
        if malformed:
            ctx.hint(f"{path.name}: {malformed} line(s) were not valid JSON records")
