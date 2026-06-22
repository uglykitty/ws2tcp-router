use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};
use tracing::{debug, info, warn};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Forward WebSocket connections to TCP upstreams"
)]
struct Args {
    /// Address to bind the WebSocket server to.
    #[arg(long, default_value = "::")]
    bind: String,

    /// Port to bind the WebSocket server to.
    #[arg(long, default_value_t = 22345)]
    port: u16,

    /// Only accept IPv6 connections when binding an IPv6 address.
    #[arg(long)]
    ipv6_only: bool,

    /// Maximum TCP read buffer size in bytes.
    #[arg(long, default_value_t = 16 * 1024)]
    buffer_size: usize,
}

#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
}

impl Target {
    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ws2tcp_router=info".into()),
        )
        .init();

    let args = Args::parse();
    if args.buffer_size == 0 {
        bail!("--buffer-size must be greater than 0");
    }

    let bind_addr = resolve_bind_addr(&args.bind, args.port)?;
    let listener = bind_listener(bind_addr, args.ipv6_only).await?;

    info!("listening on ws://{bind_addr}");

    loop {
        let (stream, peer_addr) = listener.accept().await.context("accept failed")?;
        let buffer_size = args.buffer_size;

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr, buffer_size).await {
                warn!(%peer_addr, error = ?err, "connection closed with error");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    buffer_size: usize,
) -> Result<()> {
    let requested_target = Arc::new(Mutex::new(None));
    let target_slot = Arc::clone(&requested_target);

    #[allow(clippy::result_large_err)]
    let websocket = accept_hdr_async(stream, move |request: &Request, response: Response| {
        capture_requested_target(request, response, &target_slot, peer_addr)
    })
    .await
    .context("websocket handshake failed")?;

    let target = requested_target
        .lock()
        .expect("target mutex poisoned")
        .clone()
        .ok_or_else(|| anyhow!("websocket request target was not captured"))?;

    info!(%peer_addr, upstream = %target.addr(), "proxying websocket to tcp");

    let tcp = TcpStream::connect(target.addr())
        .await
        .with_context(|| format!("failed to connect upstream {}", target.addr()))?;

    proxy(websocket, tcp, buffer_size).await
}

#[allow(clippy::result_large_err)]
fn capture_requested_target(
    request: &Request,
    response: Response,
    target_slot: &Arc<Mutex<Option<Target>>>,
    peer_addr: SocketAddr,
) -> std::result::Result<Response, ErrorResponse> {
    match parse_target(request.uri().path()) {
        Ok(target) => {
            *target_slot.lock().expect("target mutex poisoned") = Some(target);
            Ok(response)
        }
        Err(err) => {
            warn!(
                %peer_addr,
                path = %request.uri().path(),
                error = %err,
                "rejecting websocket request"
            );
            Err(ErrorResponse::new(Some(
                "path must be /tcp:<host>:<port>, with IPv6 hosts formatted as [host]:port"
                    .to_owned(),
            )))
        }
    }
}

async fn proxy(
    websocket: tokio_tungstenite::WebSocketStream<TcpStream>,
    tcp: TcpStream,
    buffer_size: usize,
) -> Result<()> {
    let (mut ws_writer, mut ws_reader) = websocket.split();
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let mut tcp_buffer = vec![0_u8; buffer_size];

    loop {
        tokio::select! {
            message = ws_reader.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        tcp_writer.write_all(&bytes).await.context("write websocket binary frame to tcp failed")?;
                    }
                    Some(Ok(Message::Text(text))) => {
                        tcp_writer.write_all(text.as_bytes()).await.context("write websocket text frame to tcp failed")?;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        ws_writer.send(Message::Pong(payload)).await.context("send websocket pong failed")?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        debug!(?frame, "websocket closed");
                        tcp_writer.shutdown().await.context("shutdown tcp writer failed")?;
                        break;
                    }
                    Some(Err(err)) => return Err(err).context("read websocket frame failed"),
                    None => {
                        tcp_writer.shutdown().await.context("shutdown tcp writer failed")?;
                        break;
                    }
                }
            }
            read_result = tcp_reader.read(&mut tcp_buffer) => {
                let n = read_result.context("read tcp failed")?;
                if n == 0 {
                    let _ = ws_writer.send(Message::Close(None)).await;
                    break;
                }

                ws_writer
                    .send(Message::Binary(tcp_buffer[..n].to_vec().into()))
                    .await
                    .context("send tcp bytes to websocket failed")?;
            }
        }
    }

    Ok(())
}

fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve bind address {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("bind address {host}:{port} did not resolve"))
}

async fn bind_listener(bind_addr: SocketAddr, ipv6_only: bool) -> Result<TcpListener> {
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

fn parse_target(path: &str) -> Result<Target> {
    let target = path
        .strip_prefix("/tcp:")
        .ok_or_else(|| anyhow!("path must start with /tcp:"))?;

    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("IPv6 target must be formatted as [host]:port"))?;
        if host.is_empty() {
            bail!("target host is empty");
        }
        (format!("[{host}]"), port)
    } else {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("target must be formatted as host:port"))?;
        if host.contains(':') {
            bail!("IPv6 target must be enclosed in brackets");
        }
        (host.to_owned(), port)
    };

    if host.is_empty() {
        bail!("target host is empty");
    }

    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid target port {port:?}"))?;

    Ok(Target { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_from_path() {
        let target = parse_target("/tcp:116.63.8.64:12345").unwrap();
        assert_eq!(target.host, "116.63.8.64");
        assert_eq!(target.port, 12345);
    }

    #[test]
    fn parse_bracketed_ipv6_target_from_path() {
        let target = parse_target("/tcp:[2001:db8::1]:443").unwrap();
        assert_eq!(target.host, "[2001:db8::1]");
        assert_eq!(target.port, 443);
        assert_eq!(target.addr(), "[2001:db8::1]:443");
    }

    #[test]
    fn rejects_invalid_path() {
        assert!(parse_target("/http:116.63.8.64:12345").is_err());
        assert!(parse_target("/tcp:116.63.8.64").is_err());
        assert!(parse_target("/tcp::12345").is_err());
        assert!(parse_target("/tcp:2001:db8::1:443").is_err());
        assert!(parse_target("/tcp:[]:443").is_err());
        assert!(parse_target("/tcp:[2001:db8::1]443").is_err());
        assert!(parse_target("/tcp:116.63.8.64:not-a-port").is_err());
    }
}
