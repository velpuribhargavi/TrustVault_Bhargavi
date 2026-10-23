-- TrustVault database schema (SQLite).
-- Applied by scripts/init_db.py and by the app on start-up. Idempotent.

-- (foreign_keys is switched on per connection in db.connect)
-- Schema version 3: every grant expires (grants.expires_at NOT NULL), documents
-- carry an access_version that invalidates share links, anonymous share links
-- are gone (links are now signed, 5-minute, for one named person - not stored).
PRAGMA user_version = 3;

-- ---------------------------------------------------------------------------
-- Users and sessions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name        TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    is_external         INTEGER NOT NULL DEFAULT 0 CHECK (is_external IN (0, 1)),
    failed_logins       INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    created_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    deleted_at          TEXT            -- set when an admin deletes the account (final; row kept for the audit trail)
);

-- Server-side sessions. Only the SHA-256 of the token is stored, so a copy of
-- the database does not give anyone a usable session.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- ---------------------------------------------------------------------------
-- Documents, versions and encrypted blobs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id                 TEXT PRIMARY KEY,
    owner_id           TEXT NOT NULL REFERENCES users(id),
    name               TEXT NOT NULL,
    category           TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    current_version_id TEXT,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    deleted_at         TEXT,           -- set while the document is in the trash
    deleted_by         TEXT,
    purged_at          TEXT,           -- set once the content has been crypto-shredded
    -- Signed share links carry the access_version they were issued under. Any
    -- reduction of access (revoke, lower a level, "revoke all links", trash)
    -- increments it, so every outstanding link dies on its next use.
    access_version     INTEGER NOT NULL DEFAULT 1 CHECK (access_version >= 1)
);
CREATE INDEX IF NOT EXISTS idx_documents_owner   ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents(created_at);
CREATE INDEX IF NOT EXISTS idx_documents_cat     ON documents(category);

CREATE TABLE IF NOT EXISTS document_versions (
    id                TEXT PRIMARY KEY,
    document_id       TEXT NOT NULL REFERENCES documents(id),
    version_no        INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    extension         TEXT NOT NULL,
    mime_type         TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL,
    sha256            TEXT NOT NULL,       -- hash of the plaintext, verified on every download
    blob_id           TEXT NOT NULL UNIQUE,
    wrapped_key       BLOB,                -- per-file key wrapped by the master key; NULL after crypto-shred
    uploaded_by       TEXT NOT NULL REFERENCES users(id),
    created_at        TEXT NOT NULL,
    UNIQUE (document_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_versions_doc ON document_versions(document_id);

-- ---------------------------------------------------------------------------
-- Permissions: one row per (document, named person). Revoking deletes the row,
-- so there is no "revoked" flag that a query could forget to check.
--   view     = open it in the browser (watermarked render); never the file itself
--   download = view + download the original file
--   edit     = download + upload new versions + change name/category/description
-- Every grant has an expiry (default 30 minutes, see config.py). An expired
-- row stays so the owner can see it and extend it; the access check ignores it.
-- expiry_logged_at records that the 'access.expired' audit event was written.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grants (
    id          TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    permission  TEXT NOT NULL CHECK (permission IN ('view', 'download', 'edit')),
    granted_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    expiry_logged_at TEXT,
    source      TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'suggestion')),
    UNIQUE (document_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_grants_doc  ON grants(document_id);
-- Finds grants that ran out but whose expiry is not yet in the audit trail.
CREATE INDEX IF NOT EXISTS idx_grants_unlogged_expiry ON grants(expires_at) WHERE expiry_logged_at IS NULL;

-- Access suggestions. A suggestion never grants anything by itself; it is
-- only a record of what was proposed and what the owner decided.
CREATE TABLE IF NOT EXISTS suggestions (
    id                TEXT PRIMARY KEY,
    document_id       TEXT NOT NULL REFERENCES documents(id),
    owner_id          TEXT NOT NULL REFERENCES users(id),
    suggested_user_id TEXT NOT NULL REFERENCES users(id),
    permission        TEXT NOT NULL CHECK (permission = 'view'),
    score             REAL NOT NULL,
    reasons           TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'dismissed')),
    created_at        TEXT NOT NULL,
    decided_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_suggestions_doc ON suggestions(document_id);

-- ---------------------------------------------------------------------------
-- Audit trail: append-only, HMAC hash-chained.
--   entry_hash = HMAC-SHA256(audit_key, canonical(entry fields + prev_hash))
-- Editing, deleting or re-ordering any row breaks the chain; truncating the
-- tail is caught by the external anchor file. The triggers below stop the
-- application (and casual SQL) from changing history at all.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    seq            INTEGER PRIMARY KEY,
    ts             TEXT NOT NULL,
    actor_id       TEXT,
    actor_name     TEXT,
    action         TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error', 'info')),
    document_id    TEXT,
    target_user_id TEXT,
    ip             TEXT,
    user_agent     TEXT,
    details        TEXT NOT NULL DEFAULT '{}',
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_doc     ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
