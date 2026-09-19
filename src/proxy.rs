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
        http::{HeaderValue, Method, StatusCode, header},
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use tracing::{debug, info, warn};

use crate::{
    auth::{AuthConfig, authorize_request},
    http_probe::{
        ReplayStream, health_check_response, parse_plain_health_check, read_request_head,
        write_response,
    },
    target::{Protocol, Target, parse_target},
    token::{TOKEN_HEADER, generate_token},
};

// Large enough for the maximum possible UDP payload (65507 bytes over IPv4/IPv6).
const UDP_DATAGRAM_BUFFER: usize = 65536;

// A request to this path only checks that the service is reachable (and that the caller passes
// authentication), with no upstream. A websocket request completes the handshake, receives a text
// message and is closed; a plain HTTP request gets a `200 OK` with the same message as its body.
const HEALTH_CHECK_PATH: &str = "/";
const HEALTH_CHECK_MESSAGE: &str = concat!(
    "ok: ws2tcp-router ",
    env!("CARGO_PKG_VERSION"),
    " is available; health check only, no upstream connected"
);
const HEALTH_CHECK_CLOSE_REASON: &str = "health check";

#[derive(Debug, Clone)]
enum Route {
    HealthCheck,
    Proxy(Target),
}

pub async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    buffer_size: usize,
    auth: Option<Arc<AuthConfig>>,
    udp_idle_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_request_head(&mut stream)
        .await
        .context("read http request failed")?;
    if let Some(request) = parse_plain_health_check(&head) {
        let user_agent = request_user_agent(&request);
        let response = match authorize_request(&request, auth.as_deref(), peer_addr) {
            Ok(auth_user) => {
                debug!(%peer_addr, auth_user = %auth_user, %user_agent, "http health check");
                match generate_token() {
                    Ok(token) => health_check_response(HEALTH_CHECK_MESSAGE, &token),
                    Err(err) => token_error_response(&err),
                }
            }
            Err(response) => response,
        };
        // The client may already be gone; there is nothing more to do either way.
        let _ = write_response(&mut stream, &response, request.method() != Method::HEAD).await;
        return Ok(());
    }
    // The handshake must still see the request head that was just read.
    let stream = ReplayStream::new(head, stream);

    let requested_target = Arc::new(Mutex::new(None));
    let target_slot = Arc::clone(&requested_target);
    let authenticated_user = Arc::new(Mutex::new(None));
    let auth_user_slot = Arc::clone(&authenticated_user);
    let user_agent = Arc::new(Mutex::new(None));
    let user_agent_slot = Arc::clone(&user_agent);

    #[allow(clippy::result_large_err)]
    let mut websocket = accept_hdr_async(stream, move |request: &Request, response: Response| {
        *user_agent_slot.lock().expect("user agent mutex poisoned") =
            Some(request_user_agent(request));
        let auth_user = authorize_request(request, auth.as_deref(), peer_addr)?;
        *auth_user_slot.lock().expect("auth user mutex poisoned") = Some(auth_user.clone());
        capture_requested_target(request, response, &target_slot, peer_addr, &auth_user)
    })
    .await
    .context("websocket handshake failed")?;

    let route = requested_target
        .lock()
        .expect("target mutex poisoned")
        .clone()
        .ok_or_else(|| anyhow!("websocket request target was not captured"))?;
    let auth_user = authenticated_user
        .lock()
        .expect("auth user mutex poisoned")
        .clone()
        .ok_or_else(|| anyhow!("websocket auth user was not captured"))?;
    let user_agent = user_agent
        .lock()
        .expect("user agent mutex poisoned")
        .clone()
        .ok_or_else(|| anyhow!("websocket user agent was not captured"))?;

    let target = match route {
        Route::HealthCheck => {
            debug!(%peer_addr, auth_user = %auth_user, %user_agent, "websocket health check");
            // The client may already be gone; there is nothing more to do either way.
            let _ = websocket
                .send(Message::Text(HEALTH_CHECK_MESSAGE.into()))
                .await;
            let _ = websocket
                .close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: HEALTH_CHECK_CLOSE_REASON.into(),
                }))
                .await;
            return Ok(());
        }
        Route::Proxy(target) => target,
    };

    match target.protocol() {
        Protocol::Tcp => {
            info!(%peer_addr, auth_user = %auth_user, %user_agent, upstream = %target.addr(), "proxying websocket to tcp");

            let tcp = TcpStream::connect(target.addr())
                .await
                .with_context(|| format!("failed to connect upstream {}", target.addr()))?;

            proxy_tcp(websocket, tcp, buffer_size).await
        }
        Protocol::Udp => {
            info!(%peer_addr, auth_user = %auth_user, %user_agent, upstream = %target.addr(), "proxying websocket to udp");

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

pub fn request_user_agent(request: &Request) -> String {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_owned()
}

fn token_error_response(err: &anyhow::Error) -> ErrorResponse {
    warn!(error = %err, "failed to generate health check token");
    let mut response = ErrorResponse::new(Some("failed to generate token".to_owned()));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

#[allow(clippy::result_large_err)]
fn capture_requested_target(
    request: &Request,
    response: Response,
    target_slot: &Arc<Mutex<Option<Route>>>,
    peer_addr: SocketAddr,
    auth_user: &str,
) -> std::result::Result<Response, ErrorResponse> {
    if request.uri().path() == HEALTH_CHECK_PATH {
        let token = generate_token().map_err(|err| token_error_response(&err))?;
        let mut response = response;
        response.headers_mut().insert(
            TOKEN_HEADER,
            HeaderValue::from_str(&token).expect("token is base64url, a valid header value"),
        );
        *target_slot.lock().expect("target mutex poisoned") = Some(Route::HealthCheck);
        return Ok(response);
    }

    match parse_target(request.uri().path()) {
        Ok(target) => {
            *target_slot.lock().expect("target mutex poisoned") = Some(Route::Proxy(target));
            Ok(response)
        }
        Err(err) => {
            warn!(
                %peer_addr,
                auth_user = %auth_user,
                user_agent = %request_user_agent(request),
                path = %request.uri().path(),
                error = %err,
                "rejecting websocket request"
            );
            // `ErrorResponse::new` defaults to 200 OK, which tungstenite refuses to send.
            let mut response = ErrorResponse::new(Some(
                "path must be /tcp:<host>:<port> or /udp:<host>:<port>, with IPv6 hosts formatted as [host]:port"
                    .to_owned(),
            ));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            Err(response)
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

#[cfg(test)]
mod tests {
    use tokio::io::duplex;
    use tokio_tungstenite::{
        client_async,
        tungstenite::{Error as WsError, client::IntoClientRequest},
    };

    use super::*;

    fn spawn_server_with_auth(
        stream: tokio::io::DuplexStream,
        auth: Option<Arc<AuthConfig>>,
    ) -> tokio::task::JoinHandle<Result<()>> {
        let peer_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        tokio::spawn(handle_connection(
            stream,
            peer_addr,
            1024,
            auth,
            Duration::from_secs(1),
        ))
    }

    fn spawn_server(stream: tokio::io::DuplexStream) -> tokio::task::JoinHandle<Result<()>> {
        spawn_server_with_auth(stream, None)
    }

    /// Sends a raw request and returns everything the server writes until it closes.
    async fn raw_exchange(request: &str, auth: Option<Arc<AuthConfig>>) -> (String, Result<()>) {
        let (mut client, server_stream) = duplex(4096);
        let server = spawn_server_with_auth(server_stream, auth);

        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        (response, server.await.unwrap())
    }

    fn token_header(response: &str) -> Option<&str> {
        response
            .lines()
            .find_map(|line| line.strip_prefix("x-ws2tcp-token: "))
    }

    #[tokio::test]
    async fn root_path_health_check_completes_handshake_and_closes() {
        let (client_stream, server_stream) = duplex(4096);
        let server = spawn_server(server_stream);

        let (mut client, response) = client_async("ws://localhost/", client_stream)
            .await
            .expect("health check handshake should succeed");
        assert_eq!(response.status(), 101);
        let token = response
            .headers()
            .get(TOKEN_HEADER)
            .expect("handshake response carries a token")
            .to_str()
            .unwrap();
        assert_eq!(token.len(), 43);

        match client.next().await {
            Some(Ok(Message::Text(text))) => assert_eq!(text.as_str(), HEALTH_CHECK_MESSAGE),
            other => panic!("expected health check text message, got {other:?}"),
        }
        match client.next().await {
            Some(Ok(Message::Close(Some(frame)))) => {
                assert_eq!(frame.code, CloseCode::Normal);
                assert_eq!(frame.reason.as_str(), HEALTH_CHECK_CLOSE_REASON);
            }
            other => panic!("expected close frame with reason, got {other:?}"),
        }
        server
            .await
            .unwrap()
            .expect("health check should not error");
    }

    #[tokio::test]
    async fn invalid_path_is_rejected_with_bad_request() {
        let (client_stream, server_stream) = duplex(4096);
        let server = spawn_server(server_stream);

        match client_async("ws://localhost/other", client_stream).await {
            Err(WsError::Http(response)) => {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                let body = String::from_utf8_lossy(response.body().as_deref().unwrap_or_default())
                    .into_owned();
                assert!(body.contains("path must be /tcp:<host>:<port>"), "{body}");
            }
            other => panic!("expected http error response, got {other:?}"),
        }
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn proxy_request_ignores_the_token_header() {
        // A TCP upstream that echoes what it receives.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let n = socket.read(&mut buffer).await.unwrap();
            socket.write_all(&buffer[..n]).await.unwrap();
        });

        let (client_stream, server_stream) = duplex(4096);
        let auth = Arc::new(AuthConfig::with_basic_auth_for_test("alice:secret"));
        let _server = spawn_server_with_auth(server_stream, Some(auth));

        // Basic Auth decides; the token is neither required nor checked, so any value passes.
        let mut request = format!("ws://localhost/tcp:{upstream_addr}")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0"), // alice:secret
        );
        request
            .headers_mut()
            .insert(TOKEN_HEADER, HeaderValue::from_static("not-a-real-token"));

        let (mut client, response) = client_async(request, client_stream)
            .await
            .expect("token header must not affect the handshake");
        assert_eq!(response.status(), 101);

        client
            .send(Message::Binary(b"ping".to_vec().into()))
            .await
            .unwrap();
        match client.next().await {
            Some(Ok(Message::Binary(bytes))) => assert_eq!(&bytes[..], b"ping"),
            other => panic!("expected echoed bytes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plain_http_get_root_returns_health_check_message() {
        let (response, result) = raw_exchange(
            "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: probe/1.0\r\n\r\n",
            None,
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("content-type: text/plain; charset=utf-8\r\n"));
        assert!(response.contains(&format!(
            "content-length: {}\r\n",
            HEALTH_CHECK_MESSAGE.len()
        )));
        assert!(response.ends_with(HEALTH_CHECK_MESSAGE), "{response}");
        assert_eq!(
            token_header(&response).map(str::len),
            Some(43),
            "{response}"
        );
        result.expect("http health check should not error");
    }

    #[tokio::test]
    async fn every_health_check_gets_a_new_token() {
        let request = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (first, _) = raw_exchange(request, None).await;
        let (second, _) = raw_exchange(request, None).await;

        let (first, second) = (
            token_header(&first).unwrap(),
            token_header(&second).unwrap(),
        );
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn token_is_not_used_for_authentication_yet() {
        let auth = Arc::new(AuthConfig::with_basic_auth_for_test("alice:secret"));
        // A token, but no credentials: still rejected, and no new token is handed out.
        let (response, _) = raw_exchange(
            "GET / HTTP/1.1\r\nHost: x\r\nX-Ws2tcp-Token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n",
            Some(auth),
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
        assert_eq!(token_header(&response), None, "{response}");
    }

    #[tokio::test]
    async fn plain_http_head_root_omits_body() {
        let (response, result) = raw_exchange("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n", None).await;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("\r\n\r\n"), "{response}");
        result.expect("http health check should not error");
    }

    #[tokio::test]
    async fn plain_http_health_check_requires_auth_when_enabled() {
        let auth = Arc::new(AuthConfig::with_basic_auth_for_test("alice:secret"));

        let (response, _) =
            raw_exchange("GET / HTTP/1.1\r\nHost: x\r\n\r\n", Some(Arc::clone(&auth))).await;
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
        assert!(response.contains("www-authenticate: Basic realm=\"ws2tcp-router\""));
        assert!(response.ends_with("authentication required"), "{response}");

        // "alice:secret" in base64.
        let (response, result) = raw_exchange(
            "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
            Some(auth),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        result.expect("authorized http health check should not error");
    }
}
