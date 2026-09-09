use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};
use tracing::{debug, info, warn};

use crate::{
    auth::{AuthConfig, authorize_request},
    target::{Protocol, Target, parse_target},
};

// Large enough for the maximum possible UDP payload (65507 bytes over IPv4/IPv6).
const UDP_DATAGRAM_BUFFER: usize = 65536;

pub async fn handle_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    buffer_size: usize,
    auth: Option<Arc<AuthConfig>>,
    udp_idle_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let requested_target = Arc::new(Mutex::new(None));
    let target_slot = Arc::clone(&requested_target);
    let authenticated_user = Arc::new(Mutex::new(None));
    let auth_user_slot = Arc::clone(&authenticated_user);

    #[allow(clippy::result_large_err)]
    let websocket = accept_hdr_async(stream, move |request: &Request, response: Response| {
        let auth_user = authorize_request(request, auth.as_deref(), peer_addr)?;
        *auth_user_slot.lock().expect("auth user mutex poisoned") = Some(auth_user.clone());
        capture_requested_target(request, response, &target_slot, peer_addr, &auth_user)
    })
    .await
    .context("websocket handshake failed")?;

    let target = requested_target
        .lock()
        .expect("target mutex poisoned")
        .clone()
        .ok_or_else(|| anyhow!("websocket request target was not captured"))?;
    let auth_user = authenticated_user
        .lock()
        .expect("auth user mutex poisoned")
        .clone()
        .ok_or_else(|| anyhow!("websocket auth user was not captured"))?;

    match target.protocol() {
        Protocol::Tcp => {
            info!(%peer_addr, auth_user = %auth_user, upstream = %target.addr(), "proxying websocket to tcp");

            let tcp = TcpStream::connect(target.addr())
                .await
                .with_context(|| format!("failed to connect upstream {}", target.addr()))?;

            proxy_tcp(websocket, tcp, buffer_size).await
        }
        Protocol::Udp => {
            info!(%peer_addr, auth_user = %auth_user, upstream = %target.addr(), "proxying websocket to udp");

            let udp = connect_udp(&target.addr())
                .await
                .with_context(|| format!("failed to connect upstream {}", target.addr()))?;

            proxy_udp(websocket, udp, udp_idle_timeout).await
        }
    }
}

async fn connect_udp(target_addr: &str) -> Result<UdpSocket> {
    let mut addrs = tokio::net::lookup_host(target_addr)
        .await
        .with_context(|| format!("failed to resolve udp target {target_addr}"))?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow!("udp target {target_addr} did not resolve"))?;

    let local_bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(local_bind)
        .await
        .with_context(|| format!("failed to bind local udp socket for {target_addr}"))?;
    socket
        .connect(addr)
        .await
        .with_context(|| format!("failed to connect udp socket to {target_addr}"))?;

    Ok(socket)
}

#[allow(clippy::result_large_err)]
fn capture_requested_target(
    request: &Request,
    response: Response,
    target_slot: &Arc<Mutex<Option<Target>>>,
    peer_addr: SocketAddr,
    auth_user: &str,
) -> std::result::Result<Response, ErrorResponse> {
    match parse_target(request.uri().path()) {
        Ok(target) => {
            *target_slot.lock().expect("target mutex poisoned") = Some(target);
            Ok(response)
        }
        Err(err) => {
            warn!(
                %peer_addr,
                auth_user = %auth_user,
                path = %request.uri().path(),
                error = %err,
                "rejecting websocket request"
            );
            Err(ErrorResponse::new(Some(
                "path must be /tcp:<host>:<port> or /udp:<host>:<port>, with IPv6 hosts formatted as [host]:port"
                    .to_owned(),
            )))
        }
    }
}

async fn proxy_tcp<S>(
    websocket: WebSocketStream<S>,
    tcp: TcpStream,
    buffer_size: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

async fn proxy_udp<S>(
    websocket: WebSocketStream<S>,
    udp: UdpSocket,
    idle_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ws_writer, mut ws_reader) = websocket.split();
    let mut udp_buffer = vec![0_u8; UDP_DATAGRAM_BUFFER];

    loop {
        tokio::select! {
            message = timeout(idle_timeout, ws_reader.next()) => {
                let Ok(message) = message else {
                    debug!("udp session idle timeout reached, closing");
                    let _ = ws_writer.send(Message::Close(None)).await;
                    break;
                };

                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        udp.send(&bytes).await.context("send websocket binary frame to udp failed")?;
                    }
                    Some(Ok(Message::Text(text))) => {
                        udp.send(text.as_bytes()).await.context("send websocket text frame to udp failed")?;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        ws_writer.send(Message::Pong(payload)).await.context("send websocket pong failed")?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        debug!(?frame, "websocket closed");
                        break;
                    }
                    Some(Err(err)) => return Err(err).context("read websocket frame failed"),
                    None => break,
                }
            }
            read_result = timeout(idle_timeout, udp.recv(&mut udp_buffer)) => {
                let Ok(read_result) = read_result else {
                    debug!("udp session idle timeout reached, closing");
                    let _ = ws_writer.send(Message::Close(None)).await;
                    break;
                };

                let n = read_result.context("read udp datagram failed")?;
                ws_writer
                    .send(Message::Binary(udp_buffer[..n].to_vec().into()))
                    .await
                    .context("send udp datagram to websocket failed")?;
            }
        }
    }

    Ok(())
}
