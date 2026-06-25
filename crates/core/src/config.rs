//! Operational configuration.
//!
//! cordon's settings split in two:
//! - **Bootstrap / operational** — `mode`, `backend`, and the `socket`/`store`
//!   paths plus the initial `zones` seed — live in an optional **TOML config
//!   file** (this module). They're needed before, or independent of, the store.
//! - **Dynamic policy** — zones (after the first-run seed), owners, rules — live
//!   in the SQLite store, mutated at runtime via the `cordon` CLI over IPC.
//!
//! Precedence is **CLI flag > config file > built-in default**. String values in
//! the file may interpolate `${ENV}` (e.g. `socket = "${XDG_RUNTIME_DIR}/cordon.sock"`).
//! The file is optional; absent ⇒ all defaults.

use crate::backend::BackendKind;
use crate::{Error, Result};
use serde::Deserialize;
use std::env;
use std::path::{Path, PathBuf};

/// Whether the enforcement backend actually blocks (`Enforce`) or only logs what
/// it *would* block (`Audit`) while allowing everything — for previewing the
/// blast radius of an ownership decision before it bites.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Enforce,
    Audit,
}

impl Mode {
    /// True in enforce mode (the backend writes real denials).
    pub fn enforces(self) -> bool {
        matches!(self, Mode::Enforce)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Audit => "audit",
        }
    }
}

impl std::str::FromStr for Mode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Mode> {
        match s {
            "enforce" => Ok(Mode::Enforce),
            "audit" => Ok(Mode::Audit),
            other => Err(Error::msg(format!(
                "invalid mode '{other}' (expected 'enforce' or 'audit')"
            ))),
        }
    }
}

/// Fully-resolved operational config (file + defaults). The daemon applies CLI
/// overrides on top of this.
#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    pub backend: BackendKind,
    pub socket: PathBuf,
    pub store: PathBuf,
    /// Zone roots seeded into a fresh store (first run only; thereafter managed
    /// via `cordon zone …`).
    pub zones: Vec<PathBuf>,
    /// `bpf-lsm` backend: the compiled eBPF object to load at runtime (built by
    /// `just build-ebpf`). Ignored by the other backends.
    pub bpf_object: PathBuf,
    /// `bpf-lsm` backend: the bpffs directory to pin the program + maps under, so
    /// enforcement survives the daemon dying (fail-safe, DESIGN §4).
    pub bpf_pin_dir: PathBuf,
}

/// The raw, all-optional TOML shape. Unknown keys are rejected so typos fail loud.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    mode: Option<String>,
    backend: Option<String>,
    socket: Option<String>,
    store: Option<String>,
    zones: Option<Vec<String>>,
    bpf_object: Option<String>,
    bpf_pin_dir: Option<String>,
}

impl Config {
    /// Load config from `path` (else `$CORDON_CONFIG`, else the default
    /// location), interpolating `${ENV}` and filling unset fields with defaults.
    /// A missing file is fine — you get all defaults.
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let path = path
            .map(PathBuf::from)
            .or_else(|| env::var_os("CORDON_CONFIG").map(PathBuf::from))
            .unwrap_or_else(default_config_path);
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<ConfigFile>(&text)
                .map_err(|e| Error::msg(format!("config {}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigFile::default(),
            Err(e) => return Err(Error::msg(format!("config {}: {e}", path.display()))),
        };
        Config::resolve(file)
    }

    fn resolve(f: ConfigFile) -> Result<Config> {
        Ok(Config {
            mode: match f.mode {
                Some(s) => interpolate(&s)?.parse()?,
                None => Mode::default(),
            },
            backend: match f.backend {
                Some(s) => interpolate(&s)?.parse()?,
                None => BackendKind::default(),
            },
            socket: match f.socket {
                Some(s) => PathBuf::from(interpolate(&s)?),
                None => default_socket(),
            },
            store: match f.store {
                Some(s) => PathBuf::from(interpolate(&s)?),
                None => default_store(),
            },
            zones: match f.zones {
                Some(list) => list
                    .iter()
                    .map(|s| interpolate(s).map(PathBuf::from))
                    .collect::<Result<_>>()?,
                None => default_zones(),
            },
            bpf_object: match f.bpf_object {
                Some(s) => PathBuf::from(interpolate(&s)?),
                None => default_bpf_object(),
            },
            bpf_pin_dir: match f.bpf_pin_dir {
                Some(s) => PathBuf::from(interpolate(&s)?),
                None => default_bpf_pin_dir(),
            },
        })
    }
}

/// Expand `${VAR}` references from the environment. Errors on an unterminated
/// `${` or an unset variable — misconfiguration should fail loudly, not silently
/// produce an empty path.
fn interpolate(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| Error::msg(format!("unterminated ${{...}} in config value: {s:?}")))?;
        let var = &after[..end];
        let val = env::var(var)
            .map_err(|_| Error::msg(format!("config references unset env var ${{{var}}}")))?;
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

// ---- defaults ---------------------------------------------------------------

/// Effective uid, via a direct libc symbol so the core pulls in no extra crate.
pub fn euid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

pub fn is_root() -> bool {
    euid() == 0
}

fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Default config-file location: `/etc/cordon/config.toml` (root) or
/// `$XDG_CONFIG_HOME/cordon/config.toml` (user).
fn default_config_path() -> PathBuf {
    if is_root() {
        return PathBuf::from("/etc/cordon/config.toml");
    }
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"));
    base.join("cordon/config.toml")
}

fn default_socket() -> PathBuf {
    if is_root() {
        return PathBuf::from("/run/cordon.sock");
    }
    if let Some(rt) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("cordon.sock");
    }
    env::temp_dir().join(format!("cordon-{}.sock", euid()))
}

fn default_store() -> PathBuf {
    if is_root() {
        return PathBuf::from("/var/lib/cordon/cordon.db");
    }
    let base = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"));
    base.join("cordon/cordon.db")
}

/// Default eBPF object location: where production packaging installs it. In dev,
/// point `bpf_object` at the `just build-ebpf` output (`target/bpf/cordon.bpf.o`).
fn default_bpf_object() -> PathBuf {
    PathBuf::from("/usr/lib/cordon/cordon.bpf.o")
}

/// Default bpffs pin directory for the `bpf-lsm` backend's fail-safe pinning.
fn default_bpf_pin_dir() -> PathBuf {
    PathBuf::from("/sys/fs/bpf/cordon")
}

fn default_zones() -> Vec<PathBuf> {
    let h = home();
    vec![
        h.clone(),
        h.join(".config"),
        h.join(".local/share"),
        h.join(".cache"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolate_expands_env() {
        // SAFETY: single-threaded test.
        unsafe { env::set_var("CORDON_TEST_X", "/tmp/x") };
        assert_eq!(
            interpolate("${CORDON_TEST_X}/cordon.sock").unwrap(),
            "/tmp/x/cordon.sock"
        );
        assert_eq!(interpolate("no vars here").unwrap(), "no vars here");
        assert!(interpolate("${CORDON_TEST_UNSET_ZZZ}").is_err());
        assert!(interpolate("${unterminated").is_err());
    }

    #[test]
    fn mode_parses() {
        assert_eq!("audit".parse::<Mode>().unwrap(), Mode::Audit);
        assert_eq!("enforce".parse::<Mode>().unwrap(), Mode::Enforce);
        assert!("nope".parse::<Mode>().is_err());
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load(Some(Path::new("/nonexistent/cordon/config.toml"))).unwrap();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert_eq!(cfg.backend, BackendKind::Mock);
    }
}
