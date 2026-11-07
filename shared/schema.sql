-- Shadow Profile data model (Phase 0).
-- One SQLite file, encrypted with SQLCipher. The recorder writes `requests`;
-- the analyzer fills the rest. The Electron app never opens this file
-- directly: it asks the analyzer over IPC (see shared/PROTOCOL.md).
--
-- Times are integer milliseconds since the Unix epoch, UTC.
-- JSON columns hold UTF-8 JSON text.

PRAGMA foreign_keys = ON;

-- Key/value settings. Known keys (see shared/db.py SETTINGS_KEYS):
--   install_at, last_opened_at, tracking_mode ('blocklist' | 'allowlist'),
--   zero_network ('0' | '1'), gpc ('0' | '1'), recorder_heartbeat_at,
--   recorder_status (JSON: mode, ca status, last error), schema_version
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Per-app and per-domain capture rules. The recorder reloads these within
-- seconds without a restart.
CREATE TABLE IF NOT EXISTS app_rules (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('app', 'domain', 'action')),
    match       TEXT NOT NULL,          -- app path/name, or a domain
    -- app/domain: track | metadata_only | dont_track
    -- action (phase 6, per domain, applies across apps): block | strip
    rule        TEXT NOT NULL CHECK (rule IN ('track', 'metadata_only', 'dont_track', 'block', 'strip')),
    source      TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'auto')),
                                        -- 'auto': set by the recorder (e.g. certificate pinning)
    updated_at  INTEGER NOT NULL,
    UNIQUE (kind, match)
);

-- One row per captured request. Written only by the recorder.
-- Never contains Cookie / Set-Cookie / Authorization values, passwords or
-- search queries (see recorder/sanitize.py).
CREATE TABLE IF NOT EXISTS requests (
    id              INTEGER PRIMARY KEY,
    captured_at     INTEGER NOT NULL,
    app_name        TEXT,
    app_path        TEXT,
    page_site       TEXT,               -- site of the page that caused it (from Referer/Origin)
    page_url        TEXT,               -- sanitized page URL
    dest_domain     TEXT NOT NULL,
    method          TEXT,
    url             TEXT,               -- sanitized; NULL when metadata_only
    status          INTEGER,
    headers         TEXT,               -- JSON {name: value}; credentials removed
    cookies         TEXT,               -- JSON {name: hmac}; never raw values
    body            BLOB,               -- <= 64 KB; deleted after analysis
    body_truncated  INTEGER NOT NULL DEFAULT 0,
    size_bytes      INTEGER,            -- request + response size on the wire
    flags           TEXT,               -- JSON list of capture-time flags
    metadata_only   INTEGER NOT NULL DEFAULT 0,
    analyzed        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_requests_captured ON requests (captured_at);
CREATE INDEX IF NOT EXISTS idx_requests_unanalyzed ON requests (analyzed) WHERE analyzed = 0;
CREATE INDEX IF NOT EXISTS idx_requests_dest ON requests (dest_domain);
CREATE INDEX IF NOT EXISTS idx_requests_app ON requests (app_path);

CREATE TABLE IF NOT EXISTS findings (
    request_id  INTEGER PRIMARY KEY REFERENCES requests (id) ON DELETE CASCADE,
    company     TEXT,
    category    TEXT,
    flags       TEXT,                   -- JSON: ids, page_url, fingerprinting, hashed_email, replay
    topic       TEXT,                   -- IAB category of the page or app
    summary     TEXT
);

-- Topic per page or app, keyed by an HMAC of the page so addresses aren't kept.
CREATE TABLE IF NOT EXISTS topic_cache (
    key         TEXT PRIMARY KEY,
    topic       TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

-- Every sighting of a tracking ID (keyed hash only), across all history, so
-- cross-site IDs and cookie syncing are caught even if first seen last week.
CREATE TABLE IF NOT EXISTS id_sightings (
    hmac        TEXT NOT NULL,
    company     TEXT NOT NULL,
    context     TEXT NOT NULL,          -- page site or app name
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (hmac, company, context)
);

-- Breakage probe results per registrable domain (original plan, stretch).
CREATE TABLE IF NOT EXISTS breakage (
    domain      TEXT PRIMARY KEY,
    result      TEXT NOT NULL CHECK (result IN ('works', 'breaks')),
    page_site   TEXT,
    probed_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scores (
    request_id  INTEGER PRIMARY KEY REFERENCES requests (id) ON DELETE CASCADE,
    score       INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    tier        TEXT NOT NULL,
    breakdown   TEXT NOT NULL           -- JSON [{signal, points}]
);

CREATE TABLE IF NOT EXISTS companies (
    name            TEXT PRIMARY KEY,
    policy_summary  TEXT,
    is_data_broker  INTEGER,
    opt_out_url     TEXT,
    news            TEXT,               -- JSON
    sources         TEXT,               -- JSON list of URLs
    researched_at   INTEGER,
    from_snapshot   INTEGER NOT NULL DEFAULT 0
);

-- "What left this device": hash-chained, append-only.
CREATE TABLE IF NOT EXISTS ledger (
    id          INTEGER PRIMARY KEY,
    sent_at     INTEGER NOT NULL,
    destination TEXT NOT NULL,
    payload     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY,
    company     TEXT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('block', 'strip', 'opt-out', 'letter')),
    taken_at    INTEGER NOT NULL
);
