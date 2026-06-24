//! The ownership + rules store, backed by SQLite with versioned migrations.
//!
//! In production this file is **root-owned and not user-writable** — otherwise a
//! scraper could write itself in as owner (DESIGN §5). It is mutated only by the
//! daemon, on behalf of the privileged `cordon` CLI over IPC. All access goes
//! through `Connection`, which uses interior mutability, so every method takes
//! `&self`; the daemon serializes concurrent callers behind a single `Mutex`.

use crate::identity::Caller;
use crate::paths::{self, normalize};
use crate::{Error, Result};
use rusqlite::{Connection, OptionalExtension, params};
use rusqlite_migration::{M, Migrations};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Ordered schema migrations. Append-only: later phases push V2, V3, … and must
/// never edit a shipped migration. `to_latest` advances `user_version`.
static MIGRATIONS: LazyLock<Migrations<'static>> =
    LazyLock::new(|| Migrations::new(vec![M::up(include_str!("sql/V1__init.sql"))]));

/// A row from `subtrees`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subtree {
    pub path: PathBuf,
    pub owner_id: i64,
    pub created_at: i64,
}

/// A row from `rules`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: i64,
    pub identity_exe: String,
    pub path_prefix: PathBuf,
    pub mode: String,
    pub allow: bool,
    pub expires_at: Option<i64>,
}

/// An owner group with its identities and owned subtrees, for `status`/`owners`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerDetail {
    pub id: i64,
    pub name: String,
    pub identities: Vec<PathBuf>,
    pub subtrees: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
pub struct Counts {
    pub zones: i64,
    pub owners: i64,
    pub subtrees: i64,
    pub rules: i64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if absent) the store at `path`, migrating to the latest
    /// schema.
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        Self::init(Connection::open(path)?)
    }

    /// An ephemeral in-memory store — used by unit tests.
    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Store> {
        // WAL persists in the DB header (harmless no-op for :memory:); set before
        // migrations so they run under it.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        MIGRATIONS.to_latest(&mut conn)?;
        // foreign_keys is per-connection and cannot be toggled inside a txn, so
        // enable it after migrations complete.
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Store { conn })
    }

    // ---- zones --------------------------------------------------------------

    pub fn add_zone(&self, path: &Path) -> Result<()> {
        let p = normalize(path);
        self.conn.execute(
            "INSERT OR IGNORE INTO zones(path) VALUES (?1)",
            params![path_str(&p)?],
        )?;
        Ok(())
    }

    pub fn zones(&self) -> Result<Vec<PathBuf>> {
        let mut stmt = self.conn.prepare("SELECT path FROM zones ORDER BY path")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().map(PathBuf::from).collect())
    }

    /// Seed the default zone roots, but only into an empty table (idempotent
    /// across restarts; never clobbers a curated set). Returns whether it seeded.
    pub fn seed_zones(&self, defaults: &[PathBuf]) -> Result<bool> {
        if !self.zones()?.is_empty() {
            return Ok(false);
        }
        for z in defaults {
            self.add_zone(z)?;
        }
        Ok(true)
    }

    // ---- owners / identities ------------------------------------------------

    /// Create an owner group seeded with one identity, or return the existing
    /// group of that name (adding the identity to it).
    pub fn ensure_owner(&self, name: &str, seed_exe: &Path) -> Result<i64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO owners(name) VALUES (?1)",
            params![name],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM owners WHERE name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        self.add_identity(id, seed_exe)?;
        Ok(id)
    }

    pub fn add_identity(&self, owner_id: i64, exe: &Path) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO owner_identities(owner_id, exe) VALUES (?1, ?2)",
            params![owner_id, path_str(exe)?],
        )?;
        Ok(())
    }

    pub fn owner_identities(&self, owner_id: i64) -> Result<Vec<PathBuf>> {
        let mut stmt = self
            .conn
            .prepare("SELECT exe FROM owner_identities WHERE owner_id = ?1 ORDER BY exe")?;
        let rows = stmt
            .query_map(params![owner_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().map(PathBuf::from).collect())
    }

    // ---- subtrees -----------------------------------------------------------

    /// Record `subtree` as owned by `owner_id`. Idempotent on the path.
    pub fn claim_subtree(&self, subtree: &Path, owner_id: i64, now: i64) -> Result<()> {
        let p = normalize(subtree);
        self.conn.execute(
            "INSERT OR REPLACE INTO subtrees(path, owner_id, created_at) VALUES (?1, ?2, ?3)",
            params![path_str(&p)?, owner_id, now],
        )?;
        Ok(())
    }

    /// The owned subtree that most specifically covers `path` — the
    /// longest-prefix match among all owned subtrees, or `None`.
    pub fn owning_subtree(&self, path: &Path) -> Result<Option<Subtree>> {
        let target = normalize(path);
        let mut best: Option<Subtree> = None;
        for row in self.subtrees()? {
            if paths::is_within(&target, &row.path)
                && best
                    .as_ref()
                    .is_none_or(|b| paths::depth(&row.path) > paths::depth(&b.path))
            {
                best = Some(row);
            }
        }
        Ok(best)
    }

    pub fn disown_subtree(&self, subtree: &Path) -> Result<bool> {
        let p = normalize(subtree);
        let n = self.conn.execute(
            "DELETE FROM subtrees WHERE path = ?1",
            params![path_str(&p)?],
        )?;
        Ok(n > 0)
    }

    pub fn subtrees(&self) -> Result<Vec<Subtree>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, owner_id, created_at FROM subtrees ORDER BY path")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Subtree {
                    path: PathBuf::from(r.get::<_, String>(0)?),
                    owner_id: r.get(1)?,
                    created_at: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The owner that owns the subtree exactly at `subtree`, if any.
    pub fn owner_of_subtree(&self, subtree: &Path) -> Result<Option<i64>> {
        let p = normalize(subtree);
        let id = self
            .conn
            .query_row(
                "SELECT owner_id FROM subtrees WHERE path = ?1",
                params![path_str(&p)?],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        Ok(id)
    }

    // ---- rules --------------------------------------------------------------

    pub fn add_rule(
        &self,
        identity_exe: &str,
        path_prefix: &Path,
        mode: &str,
        allow: bool,
        expires_at: Option<i64>,
    ) -> Result<i64> {
        let p = normalize(path_prefix);
        self.conn.execute(
            "INSERT INTO rules(identity_exe, path_prefix, mode, allow, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![identity_exe, path_str(&p)?, mode, allow as i64, expires_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn remove_rule(&self, id: i64) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    pub fn rules(&self) -> Result<Vec<Rule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, identity_exe, path_prefix, mode, allow, expires_at FROM rules ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], row_to_rule)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The most specific explicit rule that matches this access, or `None`.
    /// A rule matches when: its identity is `*` or in the caller's identity
    /// chain; its prefix covers the path; its mode covers the op; and it is not
    /// expired. Most specific = longest prefix; on a tie, **deny wins** so a
    /// revocation can't be shadowed by a same-scope allow.
    pub fn matching_rule(
        &self,
        path: &Path,
        caller: &Caller,
        op: crate::event::Op,
        now: i64,
    ) -> Result<Option<Rule>> {
        let target = normalize(path);
        let chain: Vec<&Path> = caller.identity_chain().collect();
        let mut best: Option<Rule> = None;
        for rule in self.rules()? {
            if rule.expires_at.is_some_and(|exp| exp <= now) {
                continue;
            }
            if !op.covered_by_mode(&rule.mode) {
                continue;
            }
            let identity_ok = rule.identity_exe == "*"
                || chain
                    .iter()
                    .any(|p| p.as_os_str() == rule.identity_exe.as_str());
            if !identity_ok {
                continue;
            }
            if !paths::is_within(&target, &rule.path_prefix) {
                continue;
            }
            best = Some(pick_more_specific(best, rule));
        }
        Ok(best)
    }

    // ---- aggregate views ----------------------------------------------------

    pub fn owners_detailed(&self) -> Result<Vec<OwnerDetail>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name FROM owners ORDER BY name")?;
        let owners = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let all_subtrees = self.subtrees()?;
        let mut out = Vec::with_capacity(owners.len());
        for (id, name) in owners {
            let subtrees = all_subtrees
                .iter()
                .filter(|s| s.owner_id == id)
                .map(|s| s.path.clone())
                .collect();
            out.push(OwnerDetail {
                id,
                name,
                identities: self.owner_identities(id)?,
                subtrees,
            });
        }
        Ok(out)
    }

    pub fn counts(&self) -> Result<Counts> {
        Ok(Counts {
            zones: self.scalar("SELECT COUNT(*) FROM zones")?,
            owners: self.scalar("SELECT COUNT(*) FROM owners")?,
            subtrees: self.scalar("SELECT COUNT(*) FROM subtrees")?,
            rules: self.scalar("SELECT COUNT(*) FROM rules")?,
        })
    }

    fn scalar(&self, sql: &str) -> Result<i64> {
        Ok(self.conn.query_row(sql, [], |r| r.get(0))?)
    }
}

fn row_to_rule(r: &rusqlite::Row) -> rusqlite::Result<Rule> {
    Ok(Rule {
        id: r.get(0)?,
        identity_exe: r.get(1)?,
        path_prefix: PathBuf::from(r.get::<_, String>(2)?),
        mode: r.get(3)?,
        allow: r.get::<_, i64>(4)? != 0,
        expires_at: r.get(5)?,
    })
}

/// Keep the more specific of two rules (longer prefix wins; deny breaks a tie).
fn pick_more_specific(best: Option<Rule>, candidate: Rule) -> Rule {
    match best {
        None => candidate,
        Some(b) => {
            let (bd, cd) = (
                paths::depth(&b.path_prefix),
                paths::depth(&candidate.path_prefix),
            );
            if cd > bd || (cd == bd && !candidate.allow) {
                candidate
            } else {
                b
            }
        }
    }
}

/// Paths are stored as UTF-8; reject the (vanishingly rare) non-UTF-8 path
/// rather than silently lossy-converting it into a mismatching key.
fn path_str(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| Error::msg(format!("non-UTF-8 path: {}", p.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_valid() {
        // rusqlite_migration's own consistency check (V-numbering, parseable SQL).
        assert!(MIGRATIONS.validate().is_ok());
    }

    #[test]
    fn longest_prefix_owner_wins() {
        let s = Store::open_in_memory().unwrap();
        let o1 = s.ensure_owner("a", Path::new("/bin/a")).unwrap();
        let o2 = s.ensure_owner("b", Path::new("/bin/b")).unwrap();
        s.claim_subtree(Path::new("/home/u/.config/x"), o1, 0)
            .unwrap();
        s.claim_subtree(Path::new("/home/u/.config/x/y"), o2, 0)
            .unwrap();
        let got = s
            .owning_subtree(Path::new("/home/u/.config/x/y/secret"))
            .unwrap()
            .unwrap();
        assert_eq!(got.owner_id, o2);
        let got = s
            .owning_subtree(Path::new("/home/u/.config/x/other"))
            .unwrap()
            .unwrap();
        assert_eq!(got.owner_id, o1);
    }
}
