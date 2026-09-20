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
        http::{Method, StatusCode, header},
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use tracing::{debug, info, warn};

use crate::{
    auth::{AuthConfig, authorize_request},
    client_addr::{ClientAddr, TrustedProxies},
    http_probe::{
        ReplayStream, health_check_response, parse_plain_request, read_request_head, write_response,
    },
    target::{Protocol, Target, parse_target},
    token_api::handle_auth_request,
};

// Large enough for the maximum possible UDP payload (65507 bytes over IPv4/IPv6).
const UDP_DATAGRAM_BUFFER: usize = 65536;

// A request to this path only checks that the service is reachable (and that the caller passes
// authentication), with no upstream. A websocket request completes the handshake, receives a text
// message and is closed; a plain HTTP request gets a `200 OK` with the same message as its body.
pub const HEALTH_CHECK_PATH: &str = "/";
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
    trusted_proxies: Arc<TrustedProxies>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_request_head(&mut stream)
        .await
        .context("read http request failed")?;
    // From here on the connection is reported under the client's address: behind a trusted
    // reverse proxy that is the one in `X-Forwarded-For`, not the proxy's.
    let peer_addr = trusted_proxies.client_addr(peer_addr, &head);
    if let Some(request) = parse_plain_request(&head) {
        let response = if request.uri().path() == HEALTH_CHECK_PATH {
            let user_agent = request_user_agent(&request);
            match authorize_request(&request, auth.as_deref(), peer_addr) {
                Ok(auth_user) => {
                    debug!(%peer_addr, auth_user = %auth_user, %user_agent, "http health check");
                    health_check_response(HEALTH_CHECK_MESSAGE)
                }
                Err(response) => response,
            }
        } else {
            handle_auth_request(&request, auth.as_deref(), peer_addr)
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

#[allow(clippy::result_large_err)]
fn capture_requested_target(
    request: &Request,
    response: Response,
    target_slot: &Arc<Mutex<Option<Route>>>,
    peer_addr: ClientAddr,
    auth_user: &str,
) -> std::result::Result<Response, ErrorResponse> {
    if request.uri().path() == HEALTH_CHECK_PATH {
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
    use crate::{client_addr::IpRange, token::TokenService};
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    fn spawn_server_with_auth(
        stream: tokio::io::DuplexStream,
        auth: Option<Arc<AuthConfig>>,
    ) -> tokio::task::JoinHandle<Result<()>> {
        spawn_server_behind(stream, auth, TrustedProxies::new(IpRange::loopback()))
    }

    /// Serves a connection that arrives from 127.0.0.1, with the given proxies trusted.
    fn spawn_server_behind(
        stream: tokio::io::DuplexStream,
        auth: Option<Arc<AuthConfig>>,
        trusted_proxies: TrustedProxies,
    ) -> tokio::task::JoinHandle<Result<()>> {
        let peer_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        tokio::spawn(handle_connection(
            stream,
            peer_addr,
            1024,
            auth,
            Duration::from_secs(1),
            Arc::new(trusted_proxies),
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

    #[tokio::test]
    async fn root_path_health_check_completes_handshake_and_closes() {
        let (client_stream, server_stream) = duplex(4096);
        let server = spawn_server(server_stream);

        let (mut client, response) = client_async("ws://localhost/", client_stream)
            .await
            .expect("health check handshake should succeed");
        assert_eq!(response.status(), 101);
        assert!(response.headers().get("x-ws2tcp-token").is_none());

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
        assert!(!response.contains("x-ws2tcp-token"), "{response}");
        result.expect("http health check should not error");
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

    const ALICE: &str = "Basic YWxpY2U6c2VjcmV0"; // alice:secret
    const WRONG: &str = "Basic YWxpY2U6d3Jvbmc="; // alice:wrong

    fn token_auth() -> Arc<AuthConfig> {
        let tokens = TokenService::new(
            b"0123456789abcdef0123456789abcdef",
            Duration::from_secs(600),
            Duration::from_secs(3600),
        );
        Arc::new(AuthConfig::with_tokens_for_test("alice:secret", tokens))
    }

    fn post(path: &str, authorization: Option<&str>) -> String {
        let authorization = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        format!("POST {path} HTTP/1.1\r\nHost: x\r\n{authorization}Content-Length: 0\r\n\r\n")
    }

    fn json_field(response: &str, name: &str) -> String {
        let marker = format!("\"{name}\":\"");
        let start = response.find(&marker).expect("field in response") + marker.len();
        response[start..]
            .split('"')
            .next()
            .expect("closing quote")
            .to_owned()
    }

    /// Logs in with Basic Auth and returns `(access_token, refresh_token)`.
    async fn login(auth: &Arc<AuthConfig>) -> (String, String) {
        let (response, result) =
            raw_exchange(&post("/auth/token", Some(ALICE)), Some(Arc::clone(auth))).await;
        result.expect("login should not error");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        (
            json_field(&response, "access_token"),
            json_field(&response, "refresh_token"),
        )
    }

    /// Tries a websocket handshake and returns the client on success, or the rejection status.
    async fn ws_handshake(
        auth: &Arc<AuthConfig>,
        target: &str,
        authorization: Option<&str>,
    ) -> Result<tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>, StatusCode> {
        let (client_stream, server_stream) = duplex(4096);
        let _server = spawn_server_with_auth(server_stream, Some(Arc::clone(auth)));

        let mut request = format!("ws://localhost{target}")
            .into_client_request()
            .unwrap();
        if let Some(authorization) = authorization {
            request.headers_mut().insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(authorization).unwrap(),
            );
        }
        match client_async(request, client_stream).await {
            Ok((client, _)) => Ok(client),
            Err(WsError::Http(response)) => Err(response.status()),
            Err(other) => panic!("unexpected handshake error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_endpoints_do_not_exist_without_a_token_service() {
        for auth in [
            None,
            Some(Arc::new(AuthConfig::with_basic_auth_for_test(
                "alice:secret",
            ))),
        ] {
            let (response, _) = raw_exchange(&post("/auth/token", Some(ALICE)), auth).await;
            assert!(
                response.starts_with("HTTP/1.1 404 Not Found\r\n"),
                "{response}"
            );
        }
    }

    #[tokio::test]
    async fn login_needs_valid_basic_credentials() {
        let auth = token_auth();

        for authorization in [None, Some(WRONG)] {
            let (response, _) =
                raw_exchange(&post("/auth/token", authorization), Some(Arc::clone(&auth))).await;
            assert!(
                response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
                "{response}"
            );
            assert!(response.contains("www-authenticate: Basic realm=\"ws2tcp-router\""));
            assert!(!response.contains("access_token"), "{response}");
        }

        let (response, _) = raw_exchange(&post("/auth/token", Some(ALICE)), Some(auth)).await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("content-type: application/json\r\n"));
        assert!(response.contains("cache-control: no-store\r\n"));
        assert!(response.contains("\"token_type\":\"Bearer\""), "{response}");
        assert!(response.contains("\"expires_in\":600"), "{response}");
        assert!(
            response.contains("\"refresh_expires_in\":3600"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn token_endpoints_accept_only_post_without_a_body() {
        let auth = token_auth();

        let (response, _) = raw_exchange(
            &format!("GET /auth/token HTTP/1.1\r\nHost: x\r\nAuthorization: {ALICE}\r\n\r\n"),
            Some(Arc::clone(&auth)),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{response}"
        );
        assert!(response.contains("allow: POST\r\n"), "{response}");

        let (response, _) = raw_exchange(
            &format!(
                "POST /auth/token HTTP/1.1\r\nHost: x\r\nAuthorization: {ALICE}\r\nContent-Length: 5\r\n\r\nhello"
            ),
            Some(Arc::clone(&auth)),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );

        let (response, _) = raw_exchange(&post("/auth/nope", Some(ALICE)), Some(auth)).await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn access_token_authorizes_a_proxy_request() {
        // A TCP upstream that echoes what it receives.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let n = socket.read(&mut buffer).await.unwrap();
            socket.write_all(&buffer[..n]).await.unwrap();
        });

        let auth = token_auth();
        let (access, _) = login(&auth).await;

        let mut client = ws_handshake(
            &auth,
            &format!("/tcp:{upstream_addr}"),
            Some(&format!("Bearer {access}")),
        )
        .await
        .expect("a valid access token should pass the handshake");

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
    async fn invalid_access_tokens_are_rejected_with_a_bearer_challenge() {
        let auth = token_auth();
        let (_, refresh) = login(&auth).await;

        // A refresh token is not an access token, and garbage is not a token.
        for authorization in [
            format!("Bearer {refresh}"),
            "Bearer garbage".to_owned(),
            "Bearer ".to_owned(),
        ] {
            let (client_stream, server_stream) = duplex(4096);
            let _server = spawn_server_with_auth(server_stream, Some(Arc::clone(&auth)));
            let mut request = "ws://localhost/tcp:127.0.0.1:9"
                .into_client_request()
                .unwrap();
            request.headers_mut().insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&authorization).unwrap(),
            );
            match client_async(request, client_stream).await {
                Err(WsError::Http(response)) => {
                    assert_eq!(
                        response.status(),
                        StatusCode::UNAUTHORIZED,
                        "{authorization}"
                    );
                    let challenges: Vec<_> = response
                        .headers()
                        .get_all(header::WWW_AUTHENTICATE)
                        .iter()
                        .map(|value| value.to_str().unwrap().to_owned())
                        .collect();
                    assert!(
                        challenges.iter().any(|c| c.starts_with("Basic ")),
                        "{challenges:?}"
                    );
                    assert!(
                        challenges.iter().any(|c| c.starts_with("Bearer ")),
                        "{challenges:?}"
                    );
                }
                other => panic!("expected 401, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn refresh_rotates_tokens_and_detects_reuse() {
        let auth = token_auth();
        let (access1, refresh1) = login(&auth).await;

        let (response, _) = raw_exchange(
            &post("/auth/refresh", Some(&format!("Bearer {refresh1}"))),
            Some(Arc::clone(&auth)),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let access2 = json_field(&response, "access_token");
        let refresh2 = json_field(&response, "refresh_token");
        assert_ne!(refresh1, refresh2);
        ws_handshake(&auth, "/", Some(&format!("Bearer {access2}")))
            .await
            .expect("the new access token works");

        // Presenting the rotated-out token again means it leaked: everything is revoked.
        let (response, _) = raw_exchange(
            &post("/auth/refresh", Some(&format!("Bearer {refresh1}"))),
            Some(Arc::clone(&auth)),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
        assert!(response.contains("error=\"invalid_token\""), "{response}");

        let (response, _) = raw_exchange(
            &post("/auth/refresh", Some(&format!("Bearer {refresh2}"))),
            Some(Arc::clone(&auth)),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
        for access in [access1, access2] {
            let status = ws_handshake(&auth, "/", Some(&format!("Bearer {access}")))
                .await
                .err();
            assert_eq!(status, Some(StatusCode::UNAUTHORIZED));
        }
    }

    #[tokio::test]
    async fn refresh_and_revoke_need_a_bearer_credential() {
        let auth = token_auth();
        let (access, _) = login(&auth).await;

        for path in ["/auth/refresh", "/auth/revoke"] {
            // Nothing, Basic Auth, and an access token are none of them a refresh token.
            for authorization in [
                None,
                Some(ALICE.to_owned()),
                Some(format!("Bearer {access}")),
            ] {
                let (response, _) = raw_exchange(
                    &post(path, authorization.as_deref()),
                    Some(Arc::clone(&auth)),
                )
                .await;
                if path == "/auth/revoke" && authorization.is_some_and(|a| a.starts_with("Bearer"))
                {
                    // Revoking is answered the same for unknown tokens.
                    assert!(
                        response.starts_with("HTTP/1.1 204 No Content\r\n"),
                        "{response}"
                    );
                    assert!(!response.contains("content-length"), "{response}");
                } else {
                    assert!(
                        response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
                        "{path}: {response}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn revoke_logs_the_client_out() {
        let auth = token_auth();
        let (access, refresh) = login(&auth).await;
        ws_handshake(&auth, "/", Some(&format!("Bearer {access}")))
            .await
            .expect("access token works before logout");

        let (response, _) = raw_exchange(
            &post("/auth/revoke", Some(&format!("Bearer {refresh}"))),
            Some(Arc::clone(&auth)),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 204 No Content\r\n"),
            "{response}"
        );

        let status = ws_handshake(&auth, "/", Some(&format!("Bearer {access}")))
            .await
            .err();
        assert_eq!(status, Some(StatusCode::UNAUTHORIZED));
        let (response, _) = raw_exchange(
            &post("/auth/refresh", Some(&format!("Bearer {refresh}"))),
            Some(auth),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn basic_auth_is_still_accepted_next_to_tokens() {
        let auth = token_auth();

        ws_handshake(&auth, "/tcp:127.0.0.1:9", Some(ALICE))
            .await
            .expect("Basic Auth keeps working next to tokens");
        let status = ws_handshake(&auth, "/tcp:127.0.0.1:9", Some(WRONG))
            .await
            .err();
        assert_eq!(status, Some(StatusCode::UNAUTHORIZED));
    }

    /// Collects what `tracing` logs, so a test can check which address a connection was logged
    /// under.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Sends `request` from 127.0.0.1 and returns the logs it produced.
    async fn logs_of(request: &str, trusted_proxies: TrustedProxies) -> String {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        // The tests run on a current-thread runtime, so the connection task logs on this thread.
        let _guard = tracing::subscriber::set_default(subscriber);

        let (mut client, server_stream) = duplex(4096);
        let server = spawn_server_behind(server_stream, None, trusted_proxies);
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        server.await.unwrap().unwrap();

        let logs = capture.0.lock().unwrap().clone();
        String::from_utf8(logs).unwrap()
    }

    #[tokio::test]
    async fn logs_the_client_address_from_a_trusted_proxy() {
        let request = "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 10.9.9.9, 203.0.113.7\r\n\r\n";

        let logs = logs_of(request, TrustedProxies::new(IpRange::loopback())).await;
        assert!(logs.contains("peer_addr=203.0.113.7"), "{logs}");
        assert!(!logs.contains("10.9.9.9"), "{logs}");
        assert!(!logs.contains("127.0.0.1"), "{logs}");
    }

    #[tokio::test]
    async fn logs_the_peer_address_when_the_proxy_is_not_trusted() {
        let request = "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n";

        // Nobody trusted: the header is only what the sender claims.
        let logs = logs_of(request, TrustedProxies::default()).await;
        assert!(logs.contains("peer_addr=127.0.0.1:1"), "{logs}");
        assert!(!logs.contains("203.0.113.7"), "{logs}");

        // Someone else trusted: same.
        let other = TrustedProxies::new(vec!["10.0.0.0/8".parse().unwrap()]);
        let logs = logs_of(request, other).await;
        assert!(logs.contains("peer_addr=127.0.0.1:1"), "{logs}");
    }

    #[tokio::test]
    async fn logs_a_websocket_handshake_under_the_forwarded_address_too() {
        let (client_stream, server_stream) = duplex(4096);
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let server = spawn_server_with_auth(server_stream, None);

        let mut request = "ws://localhost/".into_client_request().unwrap();
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        let (mut client, _) = client_async(request, client_stream).await.unwrap();
        while client.next().await.is_some() {}
        server.await.unwrap().unwrap();

        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("websocket health check"), "{logs}");
        assert!(logs.contains("peer_addr=203.0.113.7"), "{logs}");
    }
}
