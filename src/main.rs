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

use args::Args;
use auth::build_auth_config;
use listener::{bind_listener, resolve_bind_addr};
use logging::init_logging;
use proxy::handle_connection;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _log_guard = init_logging(&args)?;

    if args.buffer_size == 0 {
        bail!("--buffer-size must be greater than 0");
    }

    let auth = build_auth_config(&args)?.map(Arc::new);
    let bind_addr = resolve_bind_addr(&args.bind, args.port)?;
    let listener = bind_listener(bind_addr, args.ipv6_only).await?;

    info!(basic_auth = auth.is_some(), "listening on ws://{bind_addr}");

    loop {
        let (stream, peer_addr) = listener.accept().await.context("accept failed")?;
        let buffer_size = args.buffer_size;
        let auth = auth.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr, buffer_size, auth).await {
                warn!(%peer_addr, error = %format_args!("{err:#}"), "connection closed with error");
            }
        });
    }
}
