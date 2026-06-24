use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
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
use tokio_rustls::TlsAcceptor;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _log_guard = init_logging(&args)?;

    if args.buffer_size == 0 {
        bail!("--buffer-size must be greater than 0");
    }

    let auth = build_auth_config(&args)?.map(Arc::new);
    let tls_config = build_tls_config(&args)?;
    let bind_addr = resolve_bind_addr(&args.bind, args.port)?;
    let listener = bind_listener(bind_addr, args.ipv6_only).await?;
    let scheme = if tls_config.is_some() { "wss" } else { "ws" };

    info!(
        basic_auth = auth.is_some(),
        tls = tls_config.is_some(),
        "listening on {scheme}://{bind_addr}"
    );

    loop {
        let (stream, peer_addr) = listener.accept().await.context("accept failed")?;
        let buffer_size = args.buffer_size;
        let auth = auth.clone();
        let tls_config = tls_config.clone();

        tokio::spawn(async move {
            let result = match tls_config {
                Some(config) => {
                    let acceptor = TlsAcceptor::from(config);
                    match acceptor.accept(stream).await {
                        Ok(stream) => handle_connection(stream, peer_addr, buffer_size, auth).await,
                        Err(err) => Err(err).context("tls handshake failed"),
                    }
                }
                None => handle_connection(stream, peer_addr, buffer_size, auth).await,
            };

            if let Err(err) = result {
                warn!(%peer_addr, error = %format_args!("{err:#}"), "connection closed with error");
            }
        });
    }
}
