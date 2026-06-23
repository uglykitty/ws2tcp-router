use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};
use tracing::{debug, info, warn};

use crate::{
    auth::{AuthConfig, authorize_request},
    target::{Target, parse_target},
};

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    buffer_size: usize,
    auth: Option<Arc<AuthConfig>>,
) -> Result<()> {
    let requested_target = Arc::new(Mutex::new(None));
    let target_slot = Arc::clone(&requested_target);

    #[allow(clippy::result_large_err)]
    let websocket = accept_hdr_async(stream, move |request: &Request, response: Response| {
        authorize_request(request, auth.as_deref(), peer_addr)?;
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
