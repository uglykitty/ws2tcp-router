use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Forward WebSocket connections to TCP upstreams"
)]
pub struct Args {
    /// Address to bind the WebSocket server to.
    #[arg(long, default_value = "::")]
    pub bind: String,

    /// Port to bind the WebSocket server to.
    #[arg(long, default_value_t = 8000)]
    pub port: u16,

    /// Only accept IPv6 connections when binding an IPv6 address.
    #[arg(long)]
    pub ipv6_only: bool,

    /// Maximum TCP read buffer size in bytes.
    #[arg(long, default_value_t = 16 * 1024)]
    pub buffer_size: usize,

    /// Require HTTP Basic authentication for WebSocket handshakes. Can be repeated.
    #[arg(long, value_name = "USER:PASS")]
    pub basic_auth: Vec<String>,

    /// Load HTTP Basic authentication credentials from a line-based USER:PASS file.
    #[arg(long, value_name = "PATH")]
    pub basic_auth_file: Option<PathBuf>,

    /// PEM-encoded TLS certificate chain for serving WSS.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS private key for serving WSS.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// Append logs to this file instead of standard error.
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Logging filter, overriding RUST_LOG. Example: ws2tcp_router=debug
    #[arg(long, value_name = "FILTER")]
    pub log_level: Option<String>,
}
