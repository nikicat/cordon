//! Operational configuration, meaning the settings the daemon needs before, or apart
//! from, the policy. The rules themselves live in the text policy file that `policy`
//! names, not here (DESIGN §15.8).
//!
//! A CLI flag overrides the config file, and the config file overrides the built-in
//! default. String values in the file may interpolate `${ENV}`, as in
//! `socket = "${XDG_RUNTIME_DIR}/cordon.sock"`. The file is optional, and without it
//! every setting takes its default.

use crate::backend::BackendKind;
use crate::{Context, Error, Result, Uid};
use serde::Deserialize;
use std::env;
use std::path::{Path, PathBuf};

/// The operational config after the file is merged with the defaults. The daemon applies
/// its CLI overrides on top of it.
#[derive(Clone, Debug)]
pub struct Config {
    pub backend: BackendKind,
    pub socket: SocketPath,
    /// The roots under which autolearn may propose rules (DESIGN §15.9). The setting is
    /// accepted, but nothing enforces from it.
    pub zones: Vec<PathBuf>,
    /// The compiled eBPF object that the `bpf-lsm` backend loads at runtime, as
    /// `just build-ebpf` builds it.
    pub bpf_object: PathBuf,
    /// The bpffs directory under which the `bpf-lsm` backend pins its LSM links (the
    /// daemon's `PinDir::pin_links`, DESIGN §4).
    pub bpf_pin_dir: PathBuf,
    /// The root-owned text policy (the flat rule model, DESIGN §15.8). It is a single
    /// file or a conf.d directory of `*.toml` fragments
    /// ([`PolicyRoot`](crate::policy::PolicyRoot)). The `bpf-lsm` backend compiles it
    /// at startup and seeds its maps from it.
    pub policy: PathBuf,
}

/// The config file as written, with every key optional. Unknown keys are rejected so
/// that a typo fails loudly.
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
    /// Returns the config read from `path`, or from `$CORDON_CONFIG` when `path` is
    /// `None`, or else from the default location. Unset fields take their defaults, and a
    /// missing file yields all defaults. Errors when the file cannot be read or parsed,
    /// when a value fails to interpolate, or when it names an unknown backend.
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

/// Returns `s` with each `${VAR}` replaced by that variable's value from the environment.
/// Errors when a `${` is unterminated or names an unset variable, so that a
/// misconfiguration fails loudly instead of yielding an empty path.
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

/// Returns the effective uid of this process.
pub fn euid() -> Uid {
    // A direct libc symbol, so that the core pulls in no extra crate.
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    Uid(unsafe { geteuid() })
}

pub fn is_root() -> bool {
    euid() == Uid::ROOT
}

fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Returns cordon's config directory, which is `/etc/cordon` for root and
/// `$XDG_CONFIG_HOME/cordon` for anyone else.
fn config_dir() -> PathBuf {
    if is_root() {
        return PathBuf::from("/etc/cordon");
    }
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"));
    base.join("cordon")
}

/// Returns the default config file path, `config.toml` in [`config_dir`].
fn default_config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// The socket that the system daemon listens on. A packaged `cordond` binds it, and an
/// unprivileged client falls back to it ([`SocketPath::for_client`]).
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

/// The daemon socket path, together with where it came from. The origin decides whether
/// a client may fall back to the system daemon ([`SocketPath::for_client`]), so it
/// travels with the path rather than beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketPath {
    /// An explicit `socket =` in the config file, or a `--socket` flag.
    Configured(PathBuf),
    /// The built-in per-euid default ([`default_socket`]).
    Default(PathBuf),
}

impl SocketPath {
    /// Returns the path, which is what the daemon binds.
    pub fn path(&self) -> &Path {
        match self {
            SocketPath::Configured(p) | SocketPath::Default(p) => p,
        }
    }

    /// Returns the socket that a client should connect to.
    ///
    /// A default path that `exists` does not find falls back to [`SYSTEM_SOCKET`]. The
    /// default resolves by euid, so without the fallback an unprivileged client would
    /// look for a per-user daemon that almost never runs. A configured path is returned
    /// as written, so that a typo is reported instead of silently redirected.
    pub fn for_client(self, exists: impl Fn(&Path) -> bool) -> PathBuf {
        match self {
            SocketPath::Configured(p) => p,
            // Root's default already *is* the system socket, and it is legitimately
            // absent while the daemon is down. The connect error then names it, which is
            // the diagnostic we want.
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

/// Returns the path where packaging installs the eBPF object. A development setup points
/// `bpf_object` at the `just build-ebpf` output (`target/bpf/cordon.bpf.o`) instead.
fn default_bpf_object() -> PathBuf {
    PathBuf::from("/usr/lib/cordon/cordon.bpf.o")
}

/// Returns the default bpffs directory where the `bpf-lsm` backend pins its links, so
/// that enforcement fails safe.
fn default_bpf_pin_dir() -> PathBuf {
    PathBuf::from("/sys/fs/bpf/cordon")
}

/// Returns the default text policy path, `policy.toml` in [`config_dir`]. For root that
/// is the root-owned `/etc/cordon/policy.toml`.
fn default_policy() -> PathBuf {
    config_dir().join("policy.toml")
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
