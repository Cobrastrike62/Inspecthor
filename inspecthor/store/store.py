"""Per-case SQLite evidence store.

CONSTRAINT: this layer never prints. It returns rows as dicts and counts as ints;
the console decides how to show them.

The performance shape that matters: a single EVTX can yield 100k+ events, so
inserts go through executemany in batches against a bare table, and every
secondary index plus the FTS index is built once in :meth:`finalize`.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Iterable, Iterator, Optional

from ..models import Event, EventFilter, level_rank

SCHEMA_VERSION = "1"

# Rows inserted per transaction during bulk load. Large enough to amortize the
# statement overhead, small enough that a huge artifact does not build an
# unbounded in-memory list.
BULK_BATCH = 5000

_EVENT_COLS = (
    "ts", "ts_epoch", "ts_desc", "host", "user", "event_type", "source_artifact",
    "artifact_id", "artifact_path", "parser", "event_id", "severity", "sev_rank",
    "message", "title", "details", "extra_fields", "channel", "record_id",
    "data", "tags", "attck", "raw",
)

# Built after bulk load, not at schema time (see schema.sql CONSTRAINT).
_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_events_sort     ON events(ts_epoch, id)",
    "CREATE INDEX IF NOT EXISTS idx_events_host     ON events(host)",
    "CREATE INDEX IF NOT EXISTS idx_events_user     ON events(user)",
    "CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_source   ON events(source_artifact)",
    "CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_eid      ON events(event_id)",
    # Makes the triage export a range scan rather than a table scan.
    "CREATE INDEX IF NOT EXISTS idx_events_sevrank  ON events(sev_rank, ts_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_events_channel  ON events(channel)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_hits_ioc    ON ioc_hits(ioc_id)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_hits_event  ON ioc_hits(event_id)",
)

# Deliberately NOT indexing `data`: it is a JSON re-encoding of the same text
# already covered by message (title + details) and extra_fields, and on an 800k
# event case that duplicate cost 336 MB of index for no extra searchable content.
_FTS_CREATE = """
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    message, extra_fields, raw, content='events', content_rowid='id',
    tokenize='unicode61'
)
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _jdump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _jload(value: Any, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return fallback


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Decode the JSON columns so callers get real dicts/lists, not strings."""
    out = dict(row)
    if "data" in out:
        out["data"] = _jload(out.get("data"), {})
    if "tags" in out:
        out["tags"] = _jload(out.get("tags"), [])
    if "attck" in out:
        out["attck"] = _jload(out.get("attck"), [])
    return out


class CaseStore:
    """The evidence database for one case."""

    def __init__(self, db_path: str = "inspecthor.db", case_name: str = "") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._tune()
        self._init_schema()
        self.fts_ok = self._probe_fts()
        if case_name:
            self.set_meta("case_name", case_name)

    # ---- setup ----

    def _tune(self) -> None:
        """Pragmas that make bulk ingest tolerable. WAL also means a reader (a
        second console) does not block the writer mid-ingest."""
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA temp_store=MEMORY",
            "PRAGMA cache_size=-65536",   # ~64 MiB
            "PRAGMA foreign_keys=ON",
        ):
            try:
                self.conn.execute(pragma)
            except sqlite3.DatabaseError:
                # A read-only filesystem or an odd SQLite build should not be fatal;
                # ingest will just be slower.
                continue

    def _init_schema(self) -> None:
        ddl = files("inspecthor.store").joinpath("schema.sql").read_text(encoding="utf-8")
        self.conn.executescript(ddl)
        self.conn.commit()
        if self.get_meta("schema_version") is None:
            self.set_meta("schema_version", SCHEMA_VERSION)
            self.set_meta("created", _now())

    def _probe_fts(self) -> bool:
        """FTS5 is compiled in on most builds but not guaranteed. Probe once and
        remember; search() falls back to a bounded LIKE scan when absent."""
        try:
            self.conn.execute(_FTS_CREATE)
            self.conn.commit()
            return True
        except sqlite3.DatabaseError:
            return False

    # ---- meta ----

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    # ---- artifacts ----

    def add_artifact(
        self,
        path: str,
        sha256: str = "",
        kind: str = "",
        size: int = 0,
        mtime: str = "",
    ) -> int:
        """Register an artifact, returning its id. Re-registering the same
        (path, sha256) returns the existing id so a re-ingest is idempotent."""
        cur = self.conn.execute(
            "INSERT INTO artifacts(path, sha256, kind, size, mtime, status, first_seen) "
            "VALUES(?,?,?,?,?,'pending',?) ON CONFLICT(path, sha256) DO NOTHING",
            (path, sha256, kind, size, mtime, _now()),
        )
        self.conn.commit()
        if cur.lastrowid and cur.rowcount:
            return int(cur.lastrowid)
        row = self.conn.execute(
            "SELECT id FROM artifacts WHERE path=? AND sha256=?", (path, sha256)
        ).fetchone()
        return int(row["id"])

    def set_artifact_status(
        self,
        artifact_id: int,
        status: str,
        parser: str | None = None,
        event_count: int | None = None,
        error: str | None = None,
        hint: str | None = None,
    ) -> None:
        sets, params = ["status=?"], [status]
        for col, val in (
            ("parser", parser), ("event_count", event_count),
            ("error", error), ("hint", hint),
        ):
            if val is not None:
                sets.append(f"{col}=?")
                params.append(val)
        params.append(artifact_id)
        self.conn.execute(f"UPDATE artifacts SET {', '.join(sets)} WHERE id=?", params)
        self.conn.commit()

    def get_artifacts(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM artifacts ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ---- events ----

    def add_events_bulk(
        self,
        events: Iterable[Event],
        artifact_id: int | None = None,
        batch: int = BULK_BATCH,
        max_events: int = 0,
    ) -> int:
        """Stream Events into the store. Returns the number inserted.

        Consumes an iterator lazily, so a generator parser never materializes a
        whole EVTX in memory. ``max_events`` > 0 stops early (cap enforcement).
        """
        sql = (
            f"INSERT INTO events({', '.join(_EVENT_COLS)}) "
            f"VALUES({', '.join('?' * len(_EVENT_COLS))})"
        )
        total = 0
        chunk: list[tuple] = []
        for ev in events:
            chunk.append((
                ev.ts_iso(), ev.ts_epoch_us(), ev.timestamp_desc, ev.host, ev.user,
                ev.event_type, ev.source_artifact, artifact_id, ev.artifact_path,
                ev.parser, ev.event_id, ev.severity, level_rank(ev.severity),
                ev.message, ev.title, ev.details, ev.extra_fields, ev.channel,
                ev.record_id,
                _jdump(ev.data), _jdump(ev.tags), _jdump(ev.attck), ev.raw,
            ))
            if len(chunk) >= batch:
                self.conn.executemany(sql, chunk)
                self.conn.commit()
                total += len(chunk)
                chunk.clear()
                if max_events and total >= max_events:
                    return total
        if chunk:
            self.conn.executemany(sql, chunk)
            self.conn.commit()
            total += len(chunk)
        return total

    def finalize(self) -> None:
        """Build indexes and the FTS index after ingest. Idempotent."""
        for stmt in _INDEXES:
            try:
                self.conn.execute(stmt)
            except sqlite3.DatabaseError:
                continue
        if self.fts_ok:
            try:
                self.conn.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
            except sqlite3.DatabaseError:
                self.fts_ok = False
        try:
            self.conn.execute("ANALYZE")
        except sqlite3.DatabaseError:
            pass
        self.conn.commit()

    def count_events(self, filt: EventFilter | None = None) -> int:
        """Row count, optionally filtered — so a view can state what it hid."""
        from ..query import build_where

        where, params = build_where(filt) if filt else ("", [])
        return int(
            self.conn.execute(
                f"SELECT COUNT(*) AS n FROM events{where}", params
            ).fetchone()["n"]
        )

    def query_events(self, filt: EventFilter | None = None) -> list[dict]:
        """Filtered, ordered events. Delegates WHERE building to query.py."""
        from ..query import build_where     # local import: avoids a module cycle

        filt = filt or EventFilter()
        where, params = build_where(filt)
        order = "DESC" if str(filt.order).lower() == "desc" else "ASC"
        sql = f"SELECT * FROM events{where} ORDER BY ts_epoch {order}, id {order}"
        if filt.limit:
            sql += " LIMIT ?"
            params = [*params, int(filt.limit)]
        return [_row_to_dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def search_events(self, text: str, filt: EventFilter | None = None) -> list[dict]:
        """Full-text search over message/data/raw, narrowed by the same filters.

        Uses FTS5 when available. The LIKE fallback is bounded by the filter's
        limit because it cannot use an index and would otherwise scan everything.
        """
        from ..query import build_where

        filt = filt or EventFilter()
        where, params = build_where(filt)
        limit = int(filt.limit) if filt.limit else 500

        if self.fts_ok and text.strip():
            # The filter columns live only on `events`, so the bare names from
            # build_where still resolve unambiguously inside the join.
            clause = where.strip()
            if clause.upper().startswith("WHERE"):
                clause = clause[len("WHERE"):].strip()
            sql = (
                "SELECT e.* FROM events_fts f JOIN events e ON e.id = f.rowid "
                "WHERE events_fts MATCH ?"
            )
            fts_params: list[Any] = [text]
            if clause:
                sql += f" AND {clause}"
                fts_params.extend(params)
            sql += " ORDER BY e.ts_epoch ASC, e.id ASC LIMIT ?"
            fts_params.append(limit)
            try:
                rows = self.conn.execute(sql, fts_params).fetchall()
                return [_row_to_dict(r) for r in rows]
            except sqlite3.DatabaseError:
                # A malformed MATCH expression (bare punctuation, unbalanced quote)
                # should degrade to a literal search, not fail the command.
                pass

        like = f"%{text}%"
        joiner = " AND" if where else " WHERE"
        sql = (
            f"SELECT * FROM events{where}{joiner} "
            "(message LIKE ? OR IFNULL(extra_fields,'') LIKE ? "
            "OR IFNULL(raw,'') LIKE ?) "
            "ORDER BY ts_epoch ASC, id ASC LIMIT ?"
        )
        return [
            _row_to_dict(r)
            for r in self.conn.execute(sql, [*params, like, like, like, limit]).fetchall()
        ]

    def iter_events(
        self, chunk: int = 5000, filt: EventFilter | None = None
    ) -> Iterator[dict]:
        """Stream events in id order, without holding them all in memory.

        The export path depends on this: materializing 800k dicts to write a file
        that is read top-down once costs gigabytes of RSS for nothing.
        """
        from ..query import build_where

        where, params = build_where(filt) if filt else ("", [])
        joiner = " AND" if where else " WHERE"
        last = 0
        while True:
            rows = self.conn.execute(
                f"SELECT * FROM events{where}{joiner} id > ? ORDER BY id LIMIT ?",
                [*params, last, chunk],
            ).fetchall()
            if not rows:
                return
            for r in rows:
                yield _row_to_dict(r)
            last = int(rows[-1]["id"])

    def facets(self, column: str) -> list[tuple[str, int]]:
        """Distinct values and counts for a column (host/user/event_type/...)."""
        allowed = {
            "host", "user", "event_type", "source_artifact", "parser", "severity",
            "event_id", "channel", "title",
        }
        if column not in allowed:
            raise ValueError(f"not a facetable column: {column}")
        rows = self.conn.execute(
            f"SELECT {column} AS v, COUNT(*) AS n FROM events "
            f"WHERE IFNULL({column},'') <> '' GROUP BY {column} ORDER BY n DESC"
        ).fetchall()
        return [(r["v"], int(r["n"])) for r in rows]

    def attck_summary(self) -> list[tuple[str, int]]:
        """Observed technique ids with counts, decoded from the JSON column."""
        tally: dict[str, int] = {}
        rows = self.conn.execute(
            "SELECT attck FROM events WHERE IFNULL(attck,'[]') NOT IN ('', '[]')"
        ).fetchall()
        for r in rows:
            for tid in _jload(r["attck"], []):
                tally[tid] = tally.get(tid, 0) + 1
        return sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))

    def apply_rarity(self, updates: list[tuple[int, str, list[str], str]]) -> int:
        """Write back rarity promotions: (event id, level, merged tags, merged why).

        A post-ingest UPDATE rather than a parse-time decision, because "has this host
        ever done this before" cannot be answered until the whole host has been read.

        The caller supplies already-merged tags and reasons. Merging here in SQL was
        the first attempt and was wrong: ``json_patch`` replaces arrays rather than
        appending to them, so it silently discarded the path scorer's tags. The caller
        holds the row anyway, so it can merge in Python where the semantics are plain.
        """
        from ..models import level_rank

        payload = [
            (level, level_rank(level), json.dumps(tags), why[:600], event_id)
            for event_id, level, tags, why in updates
        ]
        self.conn.executemany(
            """
            UPDATE events SET
                severity = ?,
                sev_rank = ?,
                tags     = ?,
                data     = json_set(COALESCE(data, '{}'), '$.why', ?)
            WHERE id = ?
            """,
            payload,
        )
        self.conn.commit()
        return len(payload)

    def level_counts(self) -> dict[str, int]:
        """Events per level, so a filtered view can always state what it hid."""
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS n FROM events GROUP BY severity"
        ).fetchall()
        return {str(r["severity"] or "info"): int(r["n"]) for r in rows}

    def coverage(self, limit: int = 6) -> list[dict]:
        """Per-channel recognition: how much was interpreted vs merely transcribed.

        An analyst needs to know the difference. A channel at 3% templated is not
        a quiet channel — it is a channel this tool cannot read yet, and treating
        those as equivalent is how a gap in coverage gets mistaken for a gap in
        activity.
        """
        rows = self.conn.execute(
            "SELECT IFNULL(NULLIF(channel,''), source_artifact) AS chan, "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN tags LIKE '%\"auto_fields\"%' THEN 1 ELSE 0 END) AS auto "
            "FROM events WHERE parser = 'evtx' "
            "GROUP BY chan ORDER BY total DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for row in rows:
            total = int(row["total"])
            auto = int(row["auto"] or 0)
            out.append({
                "channel": row["chan"] or "(unknown)",
                "total": total,
                "auto": auto,
                "templated_pct": (100.0 * (total - auto) / total) if total else 0.0,
            })
        return out

    def top_unrecognized(self, limit: int = 8) -> list[dict]:
        """The ids worth writing a template for next, by volume."""
        rows = self.conn.execute(
            "SELECT event_id, IFNULL(NULLIF(channel,''),'?') AS chan, "
            "json_extract(data, '$.provider') AS provider, COUNT(*) AS n "
            "FROM events WHERE parser='evtx' AND tags LIKE '%\"auto_fields\"%' "
            "GROUP BY provider, event_id ORDER BY n DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {"event_id": r["event_id"], "provider": r["provider"] or "?",
             "channel": r["chan"], "count": int(r["n"])}
            for r in rows
        ]

    # ---- iocs ----

    def add_ioc(
        self,
        type_: str,
        value: str,
        defanged: str | None = None,
        tags: Iterable[str] | None = None,
        note: str = "",
    ) -> int:
        """Upsert an indicator, incrementing its sighting count."""
        self.conn.execute(
            "INSERT INTO iocs(type, value, defanged, tags, count, note, first_seen) "
            "VALUES(?,?,?,?,1,?,?) "
            "ON CONFLICT(type, value) DO UPDATE SET count = count + 1",
            (type_, value, defanged, _jdump(list(tags or ())), note, _now()),
        )
        row = self.conn.execute(
            "SELECT id FROM iocs WHERE type=? AND value=?", (type_, value)
        ).fetchone()
        return int(row["id"])

    def link_ioc(
        self, ioc_id: int, event_id: int | None = None, artifact_id: int | None = None
    ) -> None:
        self.conn.execute(
            "INSERT INTO ioc_hits(ioc_id, event_id, artifact_id) VALUES(?,?,?)",
            (ioc_id, event_id, artifact_id),
        )

    def get_iocs(self, type_: str | None = None) -> list[dict]:
        if type_:
            rows = self.conn.execute(
                "SELECT * FROM iocs WHERE type=? ORDER BY count DESC, value", (type_,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM iocs ORDER BY count DESC, type, value"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["tags"] = _jload(d.get("tags"), [])
            out.append(d)
        return out

    # ---- findings ----

    def add_finding(
        self,
        engine: str,
        rule: str,
        severity: str = "med",
        title: str = "",
        detail: str = "",
        event_id: int | None = None,
        artifact_id: int | None = None,
        attck: Iterable[str] | None = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings(engine, rule, severity, title, detail, attck, "
            "event_id, artifact_id, created) VALUES(?,?,?,?,?,?,?,?,?)",
            (engine, rule, severity, title, detail, _jdump(list(attck or ())),
             event_id, artifact_id, _now()),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def get_findings(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY "
            "CASE severity WHEN 'crit' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'med' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["attck"] = _jload(d.get("attck"), [])
            out.append(d)
        return out

    # ---- lifecycle ----

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()

    def __enter__(self) -> "CaseStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
