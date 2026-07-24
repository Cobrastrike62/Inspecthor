"""Timeline and search queries over the case store.

CONSTRAINT: every value reaches SQLite as a bound parameter. Filter values come
from evidence (usernames, hostnames, paths found inside artifacts), so string
interpolation here would be an injection path from the evidence itself.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

from .models import EventFilter, to_utc

# Accepted --from/--to spellings, loosest last. Bare dates mean midnight UTC.
_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d",
)


def parse_time(text: str, assume: tzinfo = timezone.utc) -> datetime:
    """Parse a user-supplied timestamp into tz-aware UTC.

    Raises ValueError with the accepted formats listed, because a silently
    mis-parsed time window is worse than a rejected one.
    """
    raw = (text or "").strip().replace("Z", "")
    if not raw:
        raise ValueError("empty timestamp")
    for fmt in _TIME_FORMATS:
        try:
            return to_utc(datetime.strptime(raw, fmt), assume)
        except ValueError:
            continue
    try:
        return to_utc(datetime.fromisoformat(raw), assume)
    except ValueError:
        pass
    raise ValueError(
        f"unrecognized time {text!r} — try 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'"
    )


def parse_tz(name: str) -> tzinfo:
    """Resolve a timezone name or fixed offset for tz-naive log lines.

    Accepts an IANA name ('America/Chicago'), 'UTC', or a fixed offset
    ('+05:00', '-0600').

    Raises ValueError on anything unrecognized rather than falling back to UTC:
    silently ignoring the timezone the analyst asked for would shift every naive
    event by the host's real offset while looking like it worked.
    """
    raw = (name or "").strip()
    if not raw or raw.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc

    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", raw)
    if match:
        sign = 1 if match.group(1) == "+" else -1
        offset = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
        if offset > timedelta(hours=24):
            raise ValueError(f"offset out of range: {name!r}")
        return timezone(sign * offset)

    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:  # pragma: no cover - Python < 3.9
        raise ValueError(f"named timezones unavailable on this interpreter: {name!r}") from None
    try:
        return ZoneInfo(raw)
    except ZoneInfoNotFoundError:
        # On a bare Windows interpreter the IANA database is a separate package;
        # say so instead of quietly using the wrong offset.
        raise ValueError(
            f"unknown timezone {name!r} — use an IANA name like 'America/Chicago', "
            "'UTC', or an offset like '-06:00' (on Windows you may need: pip install tzdata)"
        ) from None
    except (ValueError, OSError):
        raise ValueError(f"unknown timezone {name!r}") from None


def _epoch_us(value: datetime) -> int:
    return int(value.astimezone(timezone.utc).timestamp() * 1_000_000)


def build_where(filt: EventFilter) -> tuple[str, list[Any]]:
    """Compose an AND-joined WHERE clause and its bound parameters.

    Returns ``("", [])`` when nothing is filtered, otherwise a fragment starting
    with " WHERE " so callers can concatenate it directly.
    """
    clauses: list[str] = []
    params: list[Any] = []

    if filt.start is not None:
        clauses.append("ts_epoch >= ?")
        params.append(_epoch_us(filt.start))
    if filt.end is not None:
        clauses.append("ts_epoch <= ?")
        params.append(_epoch_us(filt.end))

    # Exact-match facets.
    for column, value in (
        ("host", filt.host),
        ("user", filt.user),
        ("event_type", filt.event_type),
        ("parser", filt.parser),
        ("severity", filt.severity),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)

    # source_artifact is a prefixed label ('evtx/Security'), so a bare 'evtx'
    # should match the whole family rather than nothing.
    if filt.source_artifact:
        clauses.append("(source_artifact = ? OR source_artifact LIKE ?)")
        params.extend([filt.source_artifact, f"{filt.source_artifact}/%"])

    # tags is a JSON array; a quoted substring match avoids 'rdp' hitting 'rdp_x'.
    if filt.tag:
        clauses.append("tags LIKE ?")
        params.append(f'%"{filt.tag}"%')

    if not clauses:
        return "", []
    return " WHERE " + " AND ".join(clauses), params


def timeline(store, filt: EventFilter | None = None) -> list[dict]:
    """Events in chronological order, subject to the filter."""
    return store.query_events(filt or EventFilter())


def search(
    store,
    text: str,
    filt: EventFilter | None = None,
    regex: bool = False,
) -> list[dict]:
    """Search event text across every artifact at once.

    ``regex=True`` pulls the filtered candidate set and applies a Python pattern
    over message/data/raw — SQLite has no regex operator by default, and shipping
    a custom function would still prevent index use.
    """
    filt = filt or EventFilter()
    if not regex:
        return store.search_events(text, filt)

    try:
        pattern = re.compile(text, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"bad regex {text!r}: {exc}") from exc

    limit = int(filt.limit) if filt.limit else 500
    out: list[dict] = []
    for row in store.query_events(EventFilter(
        start=filt.start, end=filt.end, host=filt.host, user=filt.user,
        event_type=filt.event_type, source_artifact=filt.source_artifact,
        parser=filt.parser, severity=filt.severity, tag=filt.tag,
        limit=0, order=filt.order,
    )):
        haystack = "\n".join(
            str(part) for part in (row.get("message"), row.get("data"), row.get("raw")) if part
        )
        if pattern.search(haystack):
            out.append(row)
            if len(out) >= limit:
                break
    return out
