-- inspecthor case store. One SQLite DB per case.
--
-- CONSTRAINT: events.ts is ALWAYS UTC ISO8601 zero-padded, so a lexical sort
-- equals a chronological sort. ts_epoch (microseconds) carries sub-second
-- precision; (ts_epoch, id) is the canonical timeline sort key. events.id is
-- monotonic per ingest, which is what makes "the FIRST such event" answerable.
--
-- CONSTRAINT: secondary indexes and the FTS index are NOT created here. They are
-- built by CaseStore.finalize() after bulk load, because maintaining them across
-- a 100k-row executemany dominates the insert cost.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,     -- 'schema_version'|'case_name'|'evidence_root'|'tool_version'|'created'
    value TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY,
    path        TEXT NOT NULL,
    sha256      TEXT,
    kind        TEXT,           -- sniffed: 'evtx'|'registry'|'mft'|'sqlite'|'pcap'|'syslog'|'text'|...
    size        INTEGER,
    mtime       TEXT,
    parser      TEXT,
    status      TEXT,           -- 'pending'|'parsed'|'error'|'unsupported'|'skipped'
    event_count INTEGER DEFAULT 0,
    error       TEXT,
    hint        TEXT,           -- degradation note, e.g. missing optional dependency
    first_seen  TEXT,
    UNIQUE(path, sha256)        -- re-ingesting the same evidence is idempotent
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL,   -- UTC ISO8601 (see CONSTRAINT above)
    ts_epoch        INTEGER,         -- epoch microseconds
    ts_desc         TEXT,            -- 'Event Logged'|'Last Run'|'Creation'|...
    host            TEXT,
    user            TEXT,
    event_type      TEXT,            -- 'logon'|'process_exec'|'registry_write'|...
    source_artifact TEXT,            -- 'evtx/Security'|'linux_syslog'|'registry'
    artifact_id     INTEGER REFERENCES artifacts(id),
    artifact_path   TEXT,
    parser          TEXT,
    event_id        TEXT,            -- native id (Windows EventID / syslog msgid)
    severity        TEXT DEFAULT 'info',   -- 'crit'|'high'|'med'|'low'|'info'
    -- Denormalized so a "level >= med" filter can use an index. At 800k rows a
    -- CASE expression over severity means a full scan on every triage query.
    sev_rank        INTEGER DEFAULT 0,
    message         TEXT,            -- one-line summary
    title           TEXT,            -- human sentence: 'Logon succeeded'
    details         TEXT,            -- 'Label: value ¦ Label: value'
    extra_fields    TEXT,            -- fields the Details template did not consume
    channel         TEXT,            -- Windows channel; the discriminator analysts filter on
    record_id       TEXT,            -- EventRecordID: points at the exact source record
    data            TEXT,            -- JSON: parser-specific fields
    tags            TEXT,            -- JSON list[str]
    attck           TEXT,            -- JSON list[str] of validated MITRE ids
    raw             TEXT             -- optional bounded raw record
);

CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY,
    type       TEXT NOT NULL,   -- 'ipv4'|'ipv6'|'domain'|'url'|'email'|'md5'|'sha1'|'sha256'
    value      TEXT NOT NULL,   -- refanged canonical form
    defanged   TEXT,            -- original defanged form when that is how it appeared
    tags       TEXT,            -- JSON list: ['private'|'allowlisted'|...]
    count      INTEGER DEFAULT 0,
    note       TEXT,
    first_seen TEXT,
    UNIQUE(type, value)
);

-- Which events/artifacts an indicator was seen in. Keeps "where did this IP come
-- from" a join rather than a re-scan.
CREATE TABLE IF NOT EXISTS ioc_hits (
    ioc_id      INTEGER REFERENCES iocs(id),
    event_id    INTEGER REFERENCES events(id),
    artifact_id INTEGER REFERENCES artifacts(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    engine      TEXT,           -- 'yara'|'sigma'|'heuristic'
    rule        TEXT,
    severity    TEXT DEFAULT 'med',   -- 'high'|'med'|'info'
    title       TEXT,
    detail      TEXT,
    attck       TEXT,           -- JSON list[str]
    event_id    INTEGER REFERENCES events(id),
    artifact_id INTEGER REFERENCES artifacts(id),
    created     TEXT
);
