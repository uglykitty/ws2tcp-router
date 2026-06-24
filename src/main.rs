use std::{future::pending, sync::Arc};

use anyhow::{Context, Result};
use tracing::{info, warn};

mod args;
mod auth;
mod listener;
mod logging;
mod proxy;
mod target;
mod tls;

use args::Args;
use auth::build_auth_config;
use listener::{bind_listener, resolve_bind_addr};
use logging::init_logging;
use proxy::handle_connection;
use tls::build_tls_config;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse()?;
    let _log_guard = init_logging(&args)?;

    let auth = build_auth_config(&args)?.map(Arc::new);
    let tls_config = if args.service_mode.includes_wss() {
        build_tls_config(&args)?
    } else {
        None
    };

    if args.service_mode.includes_ws() {
        let bind_addr = resolve_bind_addr(&args.bind, args.port)?;
        let listener = bind_listener(bind_addr, args.ipv6_only).await?;
        info!(basic_auth = auth.is_some(), "listening on ws://{bind_addr}");
        tokio::spawn(serve_listener(
            "ws",
            listener,
            args.buffer_size,
            auth.clone(),
            None,
        ));
    }

    if args.service_mode.includes_wss() {
        let bind_addr = resolve_bind_addr(&args.bind, args.tls_port)?;
        let listener = bind_listener(bind_addr, args.ipv6_only).await?;
        let tls_config = tls_config.expect("validated wss service mode requires tls config");
        info!(
            basic_auth = auth.is_some(),
            "listening on wss://{bind_addr}"
        );
        tokio::spawn(serve_listener(
            "wss",
            listener,
            args.buffer_size,
            auth.clone(),
            Some(tls_config),
        ));
    }

    pending::<()>().await;
    Ok(())
}

async fn serve_listener(
    scheme: &'static str,
    listener: TcpListener,
    buffer_size: usize,
    auth: Option<Arc<auth::AuthConfig>>,
    tls_config: Option<Arc<ServerConfig>>,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .with_context(|| format!("{scheme} accept failed"))?;
        let auth = auth.clone();
        let tls_config = tls_config.clone();

        tokio::spawn(async move {
            let result = handle_accepted_stream(stream, peer_addr, buffer_size, auth, tls_config)
                .await
                .with_context(|| format!("{scheme} connection failed"));

            if let Err(err) = result {
                warn!(%peer_addr, error = %format_args!("{err:#}"), "connection closed with error");
            }
        });
    }
}

async fn handle_accepted_stream(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    buffer_size: usize,
    auth: Option<Arc<auth::AuthConfig>>,
    tls_config: Option<Arc<ServerConfig>>,
) -> Result<()> {
    match tls_config {
        Some(config) => {
            let acceptor = TlsAcceptor::from(config);
            let stream = acceptor
                .accept(stream)
                .await
                .context("tls handshake failed")?;
            handle_connection(stream, peer_addr, buffer_size, auth).await
        }
        None => handle_connection(stream, peer_addr, buffer_size, auth).await,
    }
}
