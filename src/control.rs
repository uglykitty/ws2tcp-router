use std::{
    collections::BTreeMap,
    fmt::Write as _,
    ops::Deref,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

// The proxied connections that are open right now, listed by the control socket.
static SESSIONS: Mutex<BTreeMap<u64, Arc<Session>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct Session {
    id: u64,
    peer: String,
    user: String,
    user_agent: String,
    protocol: &'static str,
    upstream: String,
    started: Instant,
    // Payload bytes: `sent` goes from the client to the upstream, `received` the other way.
    sent: AtomicU64,
    received: AtomicU64,
}

impl Session {
    pub fn add_sent(&self, bytes: usize) {
        self.sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn add_received(&self, bytes: usize) {
        self.received.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Keeps a connection listed while it is open.
pub struct SessionGuard(Arc<Session>);

impl Deref for SessionGuard {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.0
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        sessions().remove(&self.0.id);
    }
}

pub fn register(
    peer: &impl std::fmt::Display,
    user: &str,
    user_agent: &str,
    protocol: &'static str,
    upstream: &str,
) -> SessionGuard {
    let session = Arc::new(Session {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        peer: peer.to_string(),
        user: user.to_owned(),
        user_agent: user_agent.to_owned(),
        protocol,
        upstream: upstream.to_owned(),
        started: Instant::now(),
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
    });
    sessions().insert(session.id, Arc::clone(&session));
    SessionGuard(session)
}

fn sessions() -> std::sync::MutexGuard<'static, BTreeMap<u64, Arc<Session>>> {
    SESSIONS.lock().expect("sessions mutex poisoned")
}

/// Renders the open connections as a table, oldest first.
pub fn render_sessions() -> String {
    let sessions: Vec<Arc<Session>> = sessions().values().cloned().collect();
    let mut out = format!("{} active connection(s)\n", sessions.len());
    if sessions.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "{:>6} {:<24} {:<12} {:<5} {:<28} {:>9} {:>10} {:>10}  UA",
        "ID", "PEER", "USER", "PROTO", "UPSTREAM", "AGE", "SENT", "RECEIVED"
    );
    for session in sessions {
        let _ = writeln!(
            out,
            "{:>6} {:<24} {:<12} {:<5} {:<28} {:>9} {:>10} {:>10}  {}",
            session.id,
            session.peer,
            session.user,
            session.protocol,
            session.upstream,
            format_age(session.started.elapsed().as_secs()),
            format_bytes(session.sent.load(Ordering::Relaxed)),
            format_bytes(session.received.load(Ordering::Relaxed)),
            session.user_agent,
        );
    }
    out
}

fn format_age(secs: u64) -> String {
    let (hours, minutes, seconds) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes}B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1}{}", UNITS[unit])
}

const DEFAULT_SOCKET_NAME: &str = "ws2tcp-router.sock";

/// Where the control socket goes when `--control-socket` is not given: the user's runtime
/// directory from the XDG Base Directory specification, where other tools look for it.
#[cfg(unix)]
pub fn default_path() -> Option<std::path::PathBuf> {
    default_path_in(std::env::var_os("XDG_RUNTIME_DIR"))
}

#[cfg(not(unix))]
pub fn default_path() -> Option<std::path::PathBuf> {
    None
}

// The specification says a relative `XDG_RUNTIME_DIR` is invalid, and defines no fallback.
#[cfg(unix)]
fn default_path_in(runtime_dir: Option<std::ffi::OsString>) -> Option<std::path::PathBuf> {
    let dir = std::path::PathBuf::from(runtime_dir?);
    dir.is_absolute().then(|| dir.join(DEFAULT_SOCKET_NAME))
}

#[cfg(unix)]
pub use unix::{serve, status};

#[cfg(unix)]
mod unix {
    use std::{
        fs,
        os::unix::{fs::FileTypeExt, fs::PermissionsExt},
        path::{Path, PathBuf},
    };

    use anyhow::{Context, Result, bail};
    use std::os::unix::net::UnixStream;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    use tracing::{info, warn};

    use super::{default_path, render_sessions};

    /// Prints what the control socket of a running service reports (`ws2tcp-router status`).
    pub async fn status(path: Option<PathBuf>) -> Result<()> {
        let path = path.or_else(default_path).context(
            "no control socket path: set XDG_RUNTIME_DIR or pass --control-socket <PATH>",
        )?;
        let mut stream = tokio::net::UnixStream::connect(&path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to control socket {}; is the service running?",
                    path.display()
                )
            })?;
        let mut listing = Vec::new();
        stream
            .read_to_end(&mut listing)
            .await
            .context("failed to read from control socket")?;
        std::io::Write::write_all(&mut std::io::stdout(), &listing)
            .context("failed to write to standard output")
    }

    /// Listens on a Unix socket and writes the open connections to every client that connects,
    /// then closes it. Read them with, for example, `socat - UNIX-CONNECT:<path>`.
    pub fn serve(path: PathBuf) -> Result<()> {
        remove_stale_socket(&path)?;
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("failed to bind control socket {}", path.display()))?;
        // Only the owner may read the connection list.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict control socket {}", path.display()))?;
        info!(path = %path.display(), "control socket is listening");

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let _ = stream.write_all(render_sessions().as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(err) => warn!(error = %err, "control socket accept failed"),
                }
            }
        });
        Ok(())
    }

    // A socket file left by an earlier run would make `bind` fail; anything else at the path, and
    // a socket another instance is still listening on, is not ours to delete.
    fn remove_stale_socket(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                if UnixStream::connect(path).is_ok() {
                    bail!(
                        "control socket {} is in use by another instance",
                        path.display()
                    );
                }
                fs::remove_file(path)
                    .with_context(|| format!("failed to remove old socket {}", path.display()))
            }
            Ok(_) => bail!(
                "control socket path {} exists and is not a socket",
                path.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
        }
    }
}

#[cfg(not(unix))]
pub async fn status(_path: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("the status command is only supported on Unix platforms")
}

#[cfg(not(unix))]
pub fn serve(_path: std::path::PathBuf) -> anyhow::Result<()> {
    anyhow::bail!("--control-socket is only supported on Unix platforms")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_open_sessions_until_dropped() {
        let guard = register(
            &"203.0.113.7:4000",
            "alice",
            "probe/1.0",
            "tcp",
            "db.internal:5432",
        );
        guard.add_sent(2048);
        guard.add_received(10);

        let listing = render_sessions();
        assert!(listing.contains("203.0.113.7:4000"), "{listing}");
        assert!(listing.contains("alice"), "{listing}");
        assert!(listing.contains("db.internal:5432"), "{listing}");
        assert!(listing.contains("2.0KiB"), "{listing}");
        assert!(listing.contains("probe/1.0"), "{listing}");

        drop(guard);
        assert!(!render_sessions().contains("203.0.113.7:4000"));
    }

    #[cfg(unix)]
    #[test]
    fn default_path_follows_xdg_runtime_dir() {
        assert_eq!(
            default_path_in(Some("/run/user/1000".into())),
            Some("/run/user/1000/ws2tcp-router.sock".into())
        );
        assert_eq!(default_path_in(Some("run/user".into())), None);
        assert_eq!(default_path_in(Some("".into())), None);
        assert_eq!(default_path_in(None), None);
    }

    #[test]
    fn formats_age_and_bytes() {
        assert_eq!(format_age(5), "5s");
        assert_eq!(format_age(65), "1m05s");
        assert_eq!(format_age(3_725), "1h02m05s");
        assert_eq!(format_bytes(1023), "1023B");
        assert_eq!(format_bytes(1536), "1.5KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0MiB");
    }
}
