-- cordon store, schema V1.
--
-- Migrations are versioned via SQLite's `user_version` (managed by
-- rusqlite_migration). Never edit this file once it has shipped; add a new
-- V2__*.sql for later changes (e.g. Phase 3 identity granularity, tool-groups).
-- Connection pragmas (foreign_keys, journal_mode) are set on open, not here,
-- because PRAGMA foreign_keys is a no-op inside a migration transaction.

-- Zones: traversable-but-never-owned roots; the first subtree level inside is
-- claimable. (Distinct from OS/OCI "containers" — these are just directory roots
-- under which TOFU ownership is established, e.g. ~, ~/.config.)
CREATE TABLE zones (
    path TEXT PRIMARY KEY
) WITHOUT ROWID;

-- A named identity set (tool-group). Auto-seeded with the creator on TOFU,
-- expandable via `cordon claim <subtree> --add <id>`.
CREATE TABLE owners (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

-- The exe paths that belong to an owner group (Phase 0 granularity = path).
CREATE TABLE owner_identities (
    owner_id INTEGER NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    exe      TEXT NOT NULL,
    PRIMARY KEY (owner_id, exe)
) WITHOUT ROWID;

-- An owned subtree: everything under `path` is gated to the owner group.
CREATE TABLE subtrees (
    path       TEXT PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;

-- Explicit rules (highest precedence). identity_exe '*' matches any caller.
CREATE TABLE rules (
    id           INTEGER PRIMARY KEY,
    identity_exe TEXT NOT NULL,
    path_prefix  TEXT NOT NULL,
    mode         TEXT NOT NULL,            -- 'r' | 'w' | 'rw'
    allow        INTEGER NOT NULL,         -- 1 = allow, 0 = deny
    expires_at   INTEGER                   -- NULL = permanent, else unix secs
);

CREATE INDEX idx_subtrees_owner ON subtrees(owner_id);
CREATE INDEX idx_owner_identities_exe ON owner_identities(exe);
