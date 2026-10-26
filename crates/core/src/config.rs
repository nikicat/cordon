//! Operational configuration — the bootstrap settings the daemon needs before (or
//! independent of) the policy: the `backend`, the `socket` path, and the `bpf-lsm`
//! object/pin/`policy` paths. The *enforcement* settings — the rules and their per-rule
//! `policy` — live in the **text policy file** (`policy`), not here (DESIGN §15.8).
//!
//! Precedence is **CLI flag > config file > built-in default**. String values in the
//! file may interpolate `${ENV}` (e.g. `socket = "${XDG_RUNTIME_DIR}/cordon.sock"`).
//! The file is optional; absent ⇒ all defaults.

use crate::backend::BackendKind;
use crate::{Context, Error, Result};
use serde::Deserialize;
use std::env;
use std::path::{Path, PathBuf};

/// Fully-resolved operational config (file + defaults). The daemon applies CLI
/// overrides on top of this.
#[derive(Clone, Debug)]
pub struct Config {
    pub backend: BackendKind,
    pub socket: SocketPath,
    /// The roots where autolearn may propose rules (DESIGN §15.9). Accepted, but nothing
    /// enforces from it.
    pub zones: Vec<PathBuf>,
    /// `bpf-lsm` backend: the compiled eBPF object to load at runtime (built by
    /// `just build-ebpf`).
    pub bpf_object: PathBuf,
    /// `bpf-lsm` backend: the bpffs directory the LSM links are pinned under (the
    /// daemon's `PinDir::pin_links`; DESIGN §4).
    pub bpf_pin_dir: PathBuf,
    /// The root-owned text policy (the flat rule model, DESIGN §15.8) — a single file,
    /// or a conf.d directory of `*.toml` fragments
    /// ([`read_sources`](crate::policy::read_sources)). The `bpf-lsm` backend compiles it
    /// at startup and seeds the maps from it.
    pub policy: PathBuf,
}

/// The raw, all-optional TOML shape. Unknown keys are rejected so typos fail loud.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    backend: Option<String>,
    socket: Option<String>,
    zones: Option<Vec<String>>,
    bpf_object: Option<String>,
    bpf_pin_dir: Option<String>,
    policy: Option<String>,
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
                .with_context(|| format!("config {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigFile::default(),
            Err(e) => return Err(Error::msg(format!("config {}: {e}", path.display()))),
        };
        Config::resolve(file)
    }

    fn resolve(f: ConfigFile) -> Result<Config> {
        Ok(Config {
            backend: match f.backend {
                Some(s) => interpolate(&s)?.parse()?,
                None => BackendKind::default(),
            },
            socket: match f.socket {
                Some(s) => SocketPath::Configured(PathBuf::from(interpolate(&s)?)),
                None => SocketPath::Default(default_socket()),
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
            policy: match f.policy {
                Some(s) => PathBuf::from(interpolate(&s)?),
                None => default_policy(),
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

/// Where the **system** daemon listens — the one a packaged `cordond` binds and every
/// unprivileged client ultimately falls back to.
pub const SYSTEM_SOCKET: &str = "/run/cordon.sock";

fn default_socket() -> PathBuf {
    if is_root() {
        return PathBuf::from(SYSTEM_SOCKET);
    }
    if let Some(rt) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("cordon.sock");
    }
    env::temp_dir().join(format!("cordon-{}.sock", euid()))
}

/// The daemon socket path *and where it came from*. The provenance decides whether a
/// client may fall back to the system daemon ([`SocketPath::for_client`]), so it travels
/// with the path rather than beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketPath {
    /// An explicit `socket =` in the config file, or a `--socket` flag.
    Configured(PathBuf),
    /// The built-in per-euid default ([`default_socket`]).
    Default(PathBuf),
}

impl SocketPath {
    /// The path itself — what the daemon binds.
    pub fn path(&self) -> &Path {
        match self {
            SocketPath::Configured(p) | SocketPath::Default(p) => p,
        }
    }

    /// Returns the socket a **client** should talk to.
    ///
    /// [`default_socket`] resolves by euid, so an unprivileged `cordon` would otherwise
    /// look for a *per-user* daemon that almost never exists and never reach the system
    /// one (`cordon bless list` from a user account is the case this guards). A default
    /// with nothing listening therefore falls back to [`SYSTEM_SOCKET`]; a configured path
    /// never does, so a typo is reported as written instead of silently redirected.
    pub fn for_client(self, exists: impl Fn(&Path) -> bool) -> PathBuf {
        match self {
            SocketPath::Configured(p) => p,
            // Root's default already *is* the system socket, and it is legitimately
            // absent while the daemon is down — the connect error names it, which is the
            // diagnostic we want.
            SocketPath::Default(p) if p == Path::new(SYSTEM_SOCKET) || exists(&p) => p,
            SocketPath::Default(_) => PathBuf::from(SYSTEM_SOCKET),
        }
    }
}

impl From<SocketPath> for PathBuf {
    fn from(s: SocketPath) -> PathBuf {
        match s {
            SocketPath::Configured(p) | SocketPath::Default(p) => p,
        }
    }
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

/// Default text-policy location (root-owned). User-mode dev points it elsewhere via
/// config.
fn default_policy() -> PathBuf {
    if is_root() {
        return PathBuf::from("/etc/cordon/policy.toml");
    }
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"));
    base.join("cordon/policy.toml")
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
    fn missing_file_yields_defaults() {
        let cfg = Config::load(Some(Path::new("/nonexistent/cordon/config.toml"))).unwrap();
        assert_eq!(cfg.backend, BackendKind::BpfLsm);
        assert!(matches!(cfg.socket, SocketPath::Default(_)));
    }

    #[test]
    fn client_socket_falls_back_to_the_system_daemon() {
        let user = PathBuf::from("/run/user/1000/cordon.sock");
        let system = PathBuf::from(SYSTEM_SOCKET);
        let missing = |_: &Path| false;
        let present = |_: &Path| true;

        // The per-user default with no daemon there ⇒ the system daemon.
        let d = SocketPath::Default(user.clone());
        assert_eq!(d.for_client(missing), system);
        // …but a per-user daemon that *is* listening wins.
        let d = SocketPath::Default(user.clone());
        assert_eq!(d.for_client(present), user);
        // An explicit `socket =` is never redirected, even when absent.
        let c = SocketPath::Configured(user.clone());
        assert_eq!(c.for_client(missing), user);
        // Root's default is already the system socket: no existence check needed.
        let d = SocketPath::Default(system.clone());
        assert_eq!(d.for_client(missing), system);
    }
}
