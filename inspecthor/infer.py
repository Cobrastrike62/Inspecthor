"""Work out the case's context from the evidence instead of asking for it.

Three facts decide whether a Linux timeline lines up with a Windows one: the
host's timezone, the year, and the hostname. Classic syslog records none of them.

But the same evidence set usually does. The registry stores
``TimeZoneInformation`` and ``ComputerName``; event logs carry absolute UTC
timestamps that pin down which year "Mar  1" means. So the tool derives all three
and only falls back to asking when the evidence genuinely cannot say.

CONSTRAINT: every inference reports where it came from. A derived timezone that
silently shifts a timeline is worse than a wrong one you can see, so
:class:`Context` carries a human-readable source for each value and the CLI prints
it. Nothing here is invisible.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Optional

# Windows records the offset as minutes to ADD to local time to reach UTC.
_RE_OFFSET = re.compile(r"UTC([+-])(\d{2}):(\d{2})")

# Registry TimeZoneKeyName values mapped to their standard-time UTC offset in
# minutes (Eastern = -300, i.e. UTC-05:00). These are UTC offsets, NOT Windows
# bias values, which carry the opposite sign. The numeric ActiveTimeBias is
# preferred when present; this table is the fallback when only the name survives.
#
# Standard time only: DST is not applied, so a summer timestamp can be an hour
# out. The registry's ActiveTimeBias reflects the live setting and is why it wins.
_WINDOWS_ZONES: dict[str, int] = {
    "utc": 0,
    "gmt standard time": 0,
    "greenwich standard time": 0,
    "w. europe standard time": 60,
    "central europe standard time": 60,
    "central european standard time": 60,
    "romance standard time": 60,
    "e. europe standard time": 120,
    "gtb standard time": 120,
    "israel standard time": 120,
    "south africa standard time": 120,
    "russian standard time": 180,
    "arab standard time": 180,
    "arabic standard time": 180,
    "iran standard time": 210,
    "arabian standard time": 240,
    "india standard time": 330,
    "central asia standard time": 360,
    "se asia standard time": 420,
    "china standard time": 480,
    "singapore standard time": 480,
    "w. australia standard time": 480,
    "tokyo standard time": 540,
    "korea standard time": 540,
    "aus eastern standard time": 600,
    "new zealand standard time": 720,
    "hawaiian standard time": -600,
    "alaskan standard time": -540,
    "pacific standard time": -480,
    "us mountain standard time": -420,
    "mountain standard time": -420,
    "central standard time": -360,
    "canada central standard time": -360,
    "eastern standard time": -300,
    "us eastern standard time": -300,
    "atlantic standard time": -240,
    "sa western standard time": -240,
    "e. south america standard time": -180,
    "argentina standard time": -180,
}


@dataclass
class Context:
    """What the evidence says about itself."""

    tz: tzinfo = timezone.utc
    tz_source: str = "default (no timezone evidence found)"
    host: str = ""
    host_source: str = ""
    year: Optional[int] = None
    year_source: str = ""
    # Absolute time window seen in artifacts that carry real timestamps.
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    notes: list[str] = field(default_factory=list)

    def summary(self) -> list[tuple[str, str, str]]:
        """``[(label, value, source)]`` for display."""
        rows = [
            ("timezone", _tz_label(self.tz), self.tz_source),
        ]
        if self.host:
            rows.append(("host", self.host, self.host_source))
        if self.year:
            rows.append(("year", str(self.year), self.year_source))
        if self.first_seen and self.last_seen:
            rows.append((
                "activity",
                f"{self.first_seen:%Y-%m-%d %H:%M} to {self.last_seen:%Y-%m-%d %H:%M} UTC",
                "from artifacts with absolute timestamps",
            ))
        return rows


def _tz_label(tz: tzinfo) -> str:
    offset = tz.utcoffset(None)
    if offset in (None, timedelta(0)):
        return "UTC"
    total = int(offset.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"UTC{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def _tz_from_utc_offset(offset_minutes: int) -> tzinfo:
    """Build a timezone from a real UTC offset in minutes (Eastern = -300).

    Deliberately NOT the same as Windows' ActiveTimeBias, which is the number of
    minutes to ADD to local time to reach UTC and therefore has the opposite sign.
    Conflating the two put Eastern at UTC+5 instead of UTC-5 — a ten-hour error
    that would have quietly slid an entire Linux timeline.
    """
    return timezone(timedelta(minutes=offset_minutes))


def timezone_from_events(store) -> tuple[Optional[tzinfo], str]:
    """Registry-derived timezone, or ``(None, "")``.

    Prefers the numeric bias over the zone name: the bias is what Windows
    actually applied, and the name can be stale after a zone change.
    """
    from .models import EventFilter

    rows = store.query_events(EventFilter(event_type="system_timezone"))
    named: tuple[Optional[tzinfo], str] = (None, "")
    biases: dict[str, str] = {}

    for row in rows:
        data = row.get("data") or {}
        name = str(data.get("name") or "").lower()
        value = str(data.get("value") or "")
        offset_text = str(data.get("utc_offset") or "")

        if name in ("activetimebias", "bias") and offset_text:
            biases[name] = offset_text

        if name == "timezonekeyname" and value:
            key = value.strip().rstrip("\x00").lower()
            if key in _WINDOWS_ZONES:
                named = (
                    _tz_from_utc_offset(_WINDOWS_ZONES[key]),
                    f"registry TimeZoneKeyName ({value.strip()})",
                )

    # ActiveTimeBias, then Bias — collected first rather than taken from whichever
    # row the store returned first. Both live in the same key and on a real host
    # they read UTC-05:00 and UTC-06:00: ActiveTimeBias includes the DST shift in
    # force when the evidence was collected, Bias does not. Returning Bias under
    # the label "registry ActiveTimeBias" put every inferred syslog timestamp an
    # hour out and misnamed the source string that exists to catch exactly that.
    for name in ("activetimebias", "bias"):
        offset_text = biases.get(name)
        if not offset_text:
            continue
        match = _RE_OFFSET.match(offset_text)
        if not match:
            continue
        sign = 1 if match.group(1) == "+" else -1
        minutes = int(match.group(2)) * 60 + int(match.group(3))
        label = ("ActiveTimeBias" if name == "activetimebias"
                 else "Bias, standard time with no DST adjustment")
        return (
            timezone(sign * timedelta(minutes=minutes)),
            f"registry {label} ({offset_text})",
        )
    return named


def host_from_events(store) -> tuple[str, str]:
    """Hostname from the registry, else the most common host on real events."""
    from .models import EventFilter

    for row in store.query_events(EventFilter(event_type="computer_name")):
        data = row.get("data") or {}
        # Only the value actually named ComputerName. The key also carries a
        # (Default) value, which on a real collection held 'mnmsrvc' — and because
        # it sorted first, every run reported that as the hostname of the machine.
        if str(data.get("name") or "").lower() != "computername":
            continue
        value = str(data.get("value") or "").strip().rstrip("\x00")
        if value:
            return value, "registry ComputerName"

    weighted: Counter[str] = Counter()
    for host, count in store.facets("host"):
        if str(host).strip():
            weighted[str(host)] += int(count)
    if weighted:
        host, _count = weighted.most_common(1)[0]
        return host, "most common host field in parsed events"
    return "", ""


def year_from_events(store) -> tuple[Optional[int], str, Optional[datetime], Optional[datetime]]:
    """Anchor year from artifacts that carry absolute timestamps.

    Returns ``(year, source, first_seen, last_seen)``.

    The anchor is the LATEST absolute event, not the earliest: incident evidence
    is collected at or after the activity, so the newest real timestamp is the
    closest thing to "now" the evidence contains. That is strictly better than a
    file's mtime, which reflects when the archive was packaged.

    Artifacts whose parser needed a year hint are excluded, or the inference would
    feed on its own output.
    """
    def _parse(value: object) -> Optional[datetime]:
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except (TypeError, ValueError):
            return None

    # Events anchored to a file's mtime, and detection hits stamped at scan time,
    # record when the TOOL ran — not when anything happened. Including them would
    # stretch the activity window to today and could anchor the year to now.
    strong = store.conn.execute(
        "SELECT MIN(ts) AS lo, MAX(ts) AS hi, COUNT(*) AS n FROM events "
        "WHERE parser NOT IN ('linux_syslog', 'yara', 'sigma') "
        "AND IFNULL(ts_desc,'') NOT LIKE '%mtime%' AND ts IS NOT NULL"
    ).fetchone()
    if strong and strong["n"] and strong["hi"]:
        first, last = _parse(strong["lo"]), _parse(strong["hi"])
        if last is not None:
            return (
                last.year,
                "latest event in artifacts with absolute timestamps",
                first, last,
            )

    # Nothing recorded real time. Fall back to mtimes and say so, because a year
    # taken from a repackaged archive is a guess the analyst needs to see.
    loose = store.conn.execute(
        "SELECT MIN(ts) AS lo, MAX(ts) AS hi, COUNT(*) AS n FROM events "
        "WHERE parser NOT IN ('linux_syslog', 'yara', 'sigma') AND ts IS NOT NULL"
    ).fetchone()
    if not loose or not loose["n"] or not loose["hi"]:
        return None, "", None, None
    first, last = _parse(loose["lo"]), _parse(loose["hi"])
    if last is None:
        return None, "", first, last
    return (
        last.year,
        "artifact modification times (nothing recorded an absolute timestamp)",
        first, last,
    )


def derive(store, overrides: dict | None = None) -> Context:
    """Build the case Context from what has been parsed so far.

    ``overrides`` (tz / host / year) always win and are labelled as explicit, so
    an analyst who knows better is never argued with.
    """
    overrides = overrides or {}
    ctx = Context()

    year, year_source, first, last = year_from_events(store)
    ctx.first_seen, ctx.last_seen = first, last
    if year:
        ctx.year, ctx.year_source = year, year_source

    tz, tz_source = timezone_from_events(store)
    if tz is not None:
        ctx.tz, ctx.tz_source = tz, tz_source

    host, host_source = host_from_events(store)
    if host:
        ctx.host, ctx.host_source = host, host_source

    if overrides.get("tz") is not None:
        ctx.tz, ctx.tz_source = overrides["tz"], "you passed --tz"
    if overrides.get("host"):
        ctx.host, ctx.host_source = overrides["host"], "you passed --host"
    if overrides.get("year"):
        ctx.year, ctx.year_source = int(overrides["year"]), "you passed --year"

    if ctx.year is None:
        ctx.notes.append(
            "No artifact carried an absolute timestamp, so the year for classic "
            "syslog lines falls back to each file's modification time. Pass "
            "--year if that is wrong."
        )
    if tz is None and overrides.get("tz") is None:
        ctx.notes.append(
            "No registry timezone found, so tz-naive log times are read as UTC. "
            "Pass --tz if the host was not on UTC."
        )
    return ctx
