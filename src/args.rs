use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, ValueEnum};
use serde::Deserialize;

const DEFAULT_BIND: &str = "::";
const DEFAULT_PORT: u16 = 80;
const DEFAULT_TLS_PORT: u16 = 443;
const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct Args {
    pub bind: String,
    pub service_mode: ServiceMode,
    pub port: u16,
    pub tls_port: u16,
    pub ipv6_only: bool,
    pub buffer_size: usize,
    pub basic_auth: Vec<String>,
    pub basic_auth_file: Option<PathBuf>,
    pub anonymous_target: Vec<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub auto_self_signed_cert: bool,
    pub log_file: Option<PathBuf>,
    pub log_level: Option<String>,
}

impl Args {
    pub fn parse() -> Result<Self> {
        Self::try_parse_from(std::env::args_os())
    }

    #[cfg(test)]
    fn try_parse_from<I, T>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = CliArgs::try_parse_from(args)?;
        Self::from_cli(cli)
    }

    #[cfg(not(test))]
    fn try_parse_from<I, T>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = CliArgs::parse_from(args);
        Self::from_cli(cli)
    }

    fn from_cli(cli: CliArgs) -> Result<Self> {
        let config = match &cli.config {
            Some(path) => ConfigArgs::read(path)?,
            None => ConfigArgs::default(),
        };

        let cli_file_tls = cli.tls_cert.is_some() || cli.tls_key.is_some();
        let (tls_cert, tls_key, auto_self_signed_cert) = if cli.auto_self_signed_cert {
            (None, None, true)
        } else if cli.no_auto_self_signed_cert || cli_file_tls {
            (
                cli.tls_cert.or(config.tls_cert),
                cli.tls_key.or(config.tls_key),
                false,
            )
        } else {
            (
                config.tls_cert,
                config.tls_key,
                config.auto_self_signed_cert.unwrap_or(false),
            )
        };

        let service_mode = cli.service_mode.or(config.service_mode).unwrap_or_default();
        let port = cli.port.or(config.port).unwrap_or(DEFAULT_PORT);
        let tls_port = cli.tls_port.or(config.tls_port).unwrap_or(DEFAULT_TLS_PORT);

        let args = Self {
            bind: cli
                .bind
                .or(config.bind)
                .unwrap_or_else(|| DEFAULT_BIND.to_owned()),
            service_mode,
            port,
            tls_port,
            ipv6_only: if cli.ipv6_only {
                true
            } else if cli.no_ipv6_only {
                false
            } else {
                config.ipv6_only.unwrap_or(false)
            },
            buffer_size: cli
                .buffer_size
                .or(config.buffer_size)
                .unwrap_or(DEFAULT_BUFFER_SIZE),
            basic_auth: if cli.basic_auth.is_empty() {
                config.basic_auth.unwrap_or_default()
            } else {
                cli.basic_auth
            },
            basic_auth_file: cli.basic_auth_file.or(config.basic_auth_file),
            anonymous_target: if cli.anonymous_target.is_empty() {
                config.anonymous_target.unwrap_or_default()
            } else {
                cli.anonymous_target
            },
            tls_cert,
            tls_key,
            auto_self_signed_cert,
            log_file: cli.log_file.or(config.log_file),
            log_level: cli.log_level.or(config.log_level),
        };

        args.validate()?;
        Ok(args)
    }

    fn validate(&self) -> Result<()> {
        if self.buffer_size == 0 {
            bail!("--buffer-size must be greater than 0");
        }

        for target in &self.anonymous_target {
            crate::target::parse_target_addr(target)
                .with_context(|| format!("invalid anonymous target {target:?}"))?;
        }

        if self.tls_cert.is_some() != self.tls_key.is_some() {
            bail!("--tls-cert and --tls-key must be configured together");
        }

        if self.auto_self_signed_cert && self.tls_cert.is_some() {
            bail!("--auto-self-signed-cert cannot be used with --tls-cert or --tls-key");
        }

        if self.service_mode.includes_wss() && !self.has_tls_config() {
            bail!("wss service mode requires --tls-cert and --tls-key, or --auto-self-signed-cert");
        }

        if self.service_mode == ServiceMode::Both && self.port == self.tls_port {
            bail!("--port and --tls-port must be different when --service-mode both is used");
        }

        Ok(())
    }

    pub fn has_tls_config(&self) -> bool {
        self.auto_self_signed_cert || (self.tls_cert.is_some() && self.tls_key.is_some())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceMode {
    #[default]
    WsOnly,
    WssOnly,
    Both,
}

impl ServiceMode {
    pub fn includes_ws(self) -> bool {
        matches!(self, Self::WsOnly | Self::Both)
    }

    pub fn includes_wss(self) -> bool {
        matches!(self, Self::WssOnly | Self::Both)
    }
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Forward WebSocket connections to TCP upstreams"
)]
struct CliArgs {
    /// Load options from a TOML configuration file.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Address to bind the WebSocket server to.
    #[arg(long)]
    bind: Option<String>,

    /// Service mode to run.
    #[arg(long, value_enum)]
    service_mode: Option<ServiceMode>,

    /// Port to bind the WS server to.
    #[arg(long)]
    port: Option<u16>,

    /// Port to bind the WSS server to.
    #[arg(long)]
    tls_port: Option<u16>,

    /// Only accept IPv6 connections when binding an IPv6 address.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_ipv6_only")]
    ipv6_only: bool,

    /// Accept both IPv4 and IPv6 connections when binding an IPv6 address.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "ipv6_only")]
    no_ipv6_only: bool,

    /// Maximum TCP read buffer size in bytes.
    #[arg(long)]
    buffer_size: Option<usize>,

    /// Require HTTP Basic authentication for WebSocket handshakes. Can be repeated.
    #[arg(long, value_name = "USER:PASS")]
    basic_auth: Vec<String>,

    /// Load HTTP Basic authentication credentials from a line-based USER:PASS file.
    #[arg(long, value_name = "PATH")]
    basic_auth_file: Option<PathBuf>,

    /// Allow anonymous access to this upstream target even when Basic authentication is enabled.
    #[arg(long, value_name = "HOST:PORT")]
    anonymous_target: Vec<String>,

    /// PEM-encoded TLS certificate chain for serving WSS.
    #[arg(long, value_name = "PATH")]
    tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS private key for serving WSS.
    #[arg(long, value_name = "PATH")]
    tls_key: Option<PathBuf>,

    /// Generate an in-memory 10-year self-signed certificate for serving WSS.
    #[arg(
        long,
        conflicts_with_all = ["no_auto_self_signed_cert", "tls_cert", "tls_key"]
    )]
    auto_self_signed_cert: bool,

    /// Disable automatic self-signed certificate generation from a config file.
    #[arg(long, conflicts_with = "auto_self_signed_cert")]
    no_auto_self_signed_cert: bool,

    /// Append logs to this file instead of standard error.
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// Logging filter, overriding RUST_LOG. Example: ws2tcp_router=debug
    #[arg(long, value_name = "FILTER")]
    log_level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ConfigArgs {
    bind: Option<String>,
    service_mode: Option<ServiceMode>,
    port: Option<u16>,
    tls_port: Option<u16>,
    ipv6_only: Option<bool>,
    buffer_size: Option<usize>,
    basic_auth: Option<Vec<String>>,
    basic_auth_file: Option<PathBuf>,
    anonymous_target: Option<Vec<String>>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    auto_self_signed_cert: Option<bool>,
    log_file: Option<PathBuf>,
    log_level: Option<String>,
}

impl ConfigArgs {
    fn read(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn parse(args: &[&str]) -> Args {
        let args = std::iter::once("ws2tcp-router")
            .chain(args.iter().copied())
            .map(OsString::from);
        Args::try_parse_from(args).unwrap()
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ws2tcp-router-{name}-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        path
    }

    #[test]
    fn uses_defaults_without_config_or_cli_values() {
        let args = parse(&[]);

        assert_eq!(args.bind, DEFAULT_BIND);
        assert_eq!(args.service_mode, ServiceMode::WsOnly);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.tls_port, DEFAULT_TLS_PORT);
        assert!(!args.ipv6_only);
        assert_eq!(args.buffer_size, DEFAULT_BUFFER_SIZE);
        assert!(args.basic_auth.is_empty());
        assert!(args.anonymous_target.is_empty());
        assert!(args.tls_cert.is_none());
        assert!(args.tls_key.is_none());
        assert!(!args.auto_self_signed_cert);
    }

    #[test]
    fn reads_values_from_config_file() {
        let path = temp_path("config");
        fs::write(
            &path,
            r#"
bind = "127.0.0.1"
service-mode = "wss-only"
port = 8080
tls-port = 8443
ipv6-only = true
buffer-size = 4096
basic-auth = ["alice:secret"]
basic-auth-file = "./users.txt"
anonymous-target = ["ocs.wangguofang.net:8443"]
tls-cert = "./cert.pem"
tls-key = "./key.pem"
auto-self-signed-cert = false
log-file = "./router.log"
log-level = "ws2tcp_router=debug"
"#,
        )
        .unwrap();

        let args = parse(&["--config", path.to_str().unwrap()]);
        fs::remove_file(path).unwrap();

        assert_eq!(args.bind, "127.0.0.1");
        assert_eq!(args.service_mode, ServiceMode::WssOnly);
        assert_eq!(args.port, 8080);
        assert_eq!(args.tls_port, 8443);
        assert!(args.ipv6_only);
        assert_eq!(args.buffer_size, 4096);
        assert_eq!(args.basic_auth, vec!["alice:secret"]);
        assert_eq!(args.basic_auth_file, Some(PathBuf::from("./users.txt")));
        assert_eq!(args.anonymous_target, vec!["ocs.wangguofang.net:8443"]);
        assert_eq!(args.tls_cert, Some(PathBuf::from("./cert.pem")));
        assert_eq!(args.tls_key, Some(PathBuf::from("./key.pem")));
        assert!(!args.auto_self_signed_cert);
        assert_eq!(args.log_file, Some(PathBuf::from("./router.log")));
        assert_eq!(args.log_level, Some("ws2tcp_router=debug".to_owned()));
    }

    #[test]
    fn cli_values_override_config_file_values() {
        let path = temp_path("override");
        fs::write(
            &path,
            r#"
bind = "127.0.0.1"
port = 8001
service-mode = "ws-only"
ipv6-only = true
buffer-size = 4096
basic-auth = ["alice:secret"]
anonymous-target = ["config.example:443"]
tls-cert = "./config-cert.pem"
tls-key = "./config-key.pem"
"#,
        )
        .unwrap();

        let args = parse(&[
            "--config",
            path.to_str().unwrap(),
            "--bind",
            "0.0.0.0",
            "--service-mode",
            "wss-only",
            "--port",
            "9000",
            "--tls-port",
            "9443",
            "--no-ipv6-only",
            "--buffer-size",
            "8192",
            "--basic-auth",
            "bob:secret",
            "--anonymous-target",
            "cli.example:443",
            "--tls-cert",
            "./cli-cert.pem",
            "--tls-key",
            "./cli-key.pem",
        ]);
        fs::remove_file(path).unwrap();

        assert_eq!(args.bind, "0.0.0.0");
        assert_eq!(args.service_mode, ServiceMode::WssOnly);
        assert_eq!(args.port, 9000);
        assert_eq!(args.tls_port, 9443);
        assert!(!args.ipv6_only);
        assert_eq!(args.buffer_size, 8192);
        assert_eq!(args.basic_auth, vec!["bob:secret"]);
        assert_eq!(args.anonymous_target, vec!["cli.example:443"]);
        assert_eq!(args.tls_cert, Some(PathBuf::from("./cli-cert.pem")));
        assert_eq!(args.tls_key, Some(PathBuf::from("./cli-key.pem")));
    }

    #[test]
    fn rejects_partial_tls_config_after_merge() {
        let path = temp_path("partial-tls");
        fs::write(&path, r#"tls-cert = "./cert.pem""#).unwrap();

        let args = std::iter::once("ws2tcp-router")
            .chain(["--config", path.to_str().unwrap()])
            .map(OsString::from);
        let result = Args::try_parse_from(args);
        fs::remove_file(path).unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn enables_auto_self_signed_cert_from_cli() {
        let args = parse(&["--auto-self-signed-cert"]);

        assert!(args.auto_self_signed_cert);
        assert!(args.tls_cert.is_none());
        assert!(args.tls_key.is_none());
    }

    #[test]
    fn rejects_auto_self_signed_cert_with_file_tls() {
        let args = std::iter::once("ws2tcp-router")
            .chain([
                "--auto-self-signed-cert",
                "--tls-cert",
                "./cert.pem",
                "--tls-key",
                "./key.pem",
            ])
            .map(OsString::from);
        let result = Args::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn cli_auto_self_signed_cert_overrides_config_file_tls() {
        let path = temp_path("auto-overrides-file-tls");
        fs::write(
            &path,
            r#"
tls-cert = "./config-cert.pem"
tls-key = "./config-key.pem"
"#,
        )
        .unwrap();

        let args = parse(&[
            "--config",
            path.to_str().unwrap(),
            "--auto-self-signed-cert",
        ]);
        fs::remove_file(path).unwrap();

        assert!(args.auto_self_signed_cert);
        assert!(args.tls_cert.is_none());
        assert!(args.tls_key.is_none());
    }

    #[test]
    fn cli_file_tls_overrides_config_auto_self_signed_cert() {
        let path = temp_path("file-tls-overrides-auto");
        fs::write(&path, r#"auto-self-signed-cert = true"#).unwrap();

        let args = parse(&[
            "--config",
            path.to_str().unwrap(),
            "--tls-cert",
            "./cli-cert.pem",
            "--tls-key",
            "./cli-key.pem",
        ]);
        fs::remove_file(path).unwrap();

        assert!(!args.auto_self_signed_cert);
        assert_eq!(args.tls_cert, Some(PathBuf::from("./cli-cert.pem")));
        assert_eq!(args.tls_key, Some(PathBuf::from("./cli-key.pem")));
    }

    #[test]
    fn cli_no_auto_self_signed_cert_overrides_config_auto_self_signed_cert() {
        let path = temp_path("no-auto");
        fs::write(&path, r#"auto-self-signed-cert = true"#).unwrap();

        let args = parse(&[
            "--config",
            path.to_str().unwrap(),
            "--no-auto-self-signed-cert",
        ]);
        fs::remove_file(path).unwrap();

        assert!(!args.auto_self_signed_cert);
        assert!(args.tls_cert.is_none());
        assert!(args.tls_key.is_none());
    }

    #[test]
    fn port_sets_ws_port() {
        let args = parse(&["--port", "8080"]);

        assert_eq!(args.port, 8080);
        assert_eq!(args.tls_port, DEFAULT_TLS_PORT);
    }

    #[test]
    fn rejects_wss_mode_without_tls_config() {
        let args = std::iter::once("ws2tcp-router")
            .chain(["--service-mode", "wss-only"])
            .map(OsString::from);
        let result = Args::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn accepts_both_mode_with_auto_self_signed_cert() {
        let args = parse(&["--service-mode", "both", "--auto-self-signed-cert"]);

        assert_eq!(args.service_mode, ServiceMode::Both);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.tls_port, DEFAULT_TLS_PORT);
    }

    #[test]
    fn rejects_both_mode_with_same_ports() {
        let args = std::iter::once("ws2tcp-router")
            .chain([
                "--service-mode",
                "both",
                "--auto-self-signed-cert",
                "--port",
                "8443",
                "--tls-port",
                "8443",
            ])
            .map(OsString::from);
        let result = Args::try_parse_from(args);

        assert!(result.is_err());
    }
}
