use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result, anyhow, bail};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

pub fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve bind address {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("bind address {host}:{port} did not resolve"))
}

pub async fn bind_listener(bind_addr: SocketAddr, ipv6_only: bool) -> Result<TcpListener> {
    match bind_addr.ip() {
        IpAddr::V4(_) => {
            if ipv6_only {
                bail!("--ipv6-only requires an IPv6 bind address");
            }

            TcpListener::bind(bind_addr)
                .await
                .with_context(|| format!("failed to bind {bind_addr}"))
        }
        IpAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
                .context("failed to create IPv6 TCP socket")?;
            socket
                .set_only_v6(ipv6_only)
                .context("failed to set IPV6_V6ONLY")?;
            socket
                .bind(&bind_addr.into())
                .with_context(|| format!("failed to bind {bind_addr}"))?;
            socket.listen(1024).context("failed to listen")?;
            socket
                .set_nonblocking(true)
                .context("failed to set listener nonblocking")?;

            TcpListener::from_std(socket.into()).context("failed to create tokio listener")
        }
    }
}
