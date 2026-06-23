use std::{
    fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
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
        http::{StatusCode, header},
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
    #[arg(long, default_value_t = 8000)]
    port: u16,

    /// Only accept IPv6 connections when binding an IPv6 address.
    #[arg(long)]
    ipv6_only: bool,

    /// Maximum TCP read buffer size in bytes.
    #[arg(long, default_value_t = 16 * 1024)]
    buffer_size: usize,

    /// Require HTTP Basic authentication for WebSocket handshakes. Can be repeated.
    #[arg(long, value_name = "USER:PASS")]
    basic_auth: Vec<String>,

    /// Load HTTP Basic authentication credentials from a line-based USER:PASS file.
    #[arg(long, value_name = "PATH")]
    basic_auth_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct AuthConfig {
    expected_authorizations: Vec<String>,
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
                warn!(%peer_addr, error = ?err, "connection closed with error");
            }
        });
    }
}

async fn handle_connection(
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

fn build_auth_config(args: &Args) -> Result<Option<AuthConfig>> {
    let auth_enabled = !args.basic_auth.is_empty() || args.basic_auth_file.is_some();
    if !auth_enabled {
        return Ok(None);
    }

    let mut credentials = args.basic_auth.clone();

    if let Some(path) = &args.basic_auth_file {
        let file = fs::read_to_string(path)
            .with_context(|| format!("failed to read basic auth file {}", path.display()))?;
        for (index, line) in file.lines().enumerate() {
            let credential = line.trim();
            if credential.is_empty() || credential.starts_with('#') {
                continue;
            }
            validate_basic_auth_credential(credential).with_context(|| {
                format!(
                    "invalid basic auth credential in {} at line {}",
                    path.display(),
                    index + 1
                )
            })?;
            credentials.push(credential.to_owned());
        }
    }

    if credentials.is_empty() {
        bail!("basic auth is enabled, but no credentials were configured");
    }

    let expected_authorizations = credentials
        .iter()
        .map(|credential| {
            validate_basic_auth_credential(credential)?;
            Ok(format!("Basic {}", STANDARD.encode(credential)))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(AuthConfig {
        expected_authorizations,
    }))
}

fn validate_basic_auth_credential(credential: &str) -> Result<()> {
    let (username, password) = credential
        .split_once(':')
        .ok_or_else(|| anyhow!("basic auth credential must be formatted as USER:PASS"))?;

    if username.is_empty() {
        bail!("basic auth username must not be empty");
    }
    if password.is_empty() {
        bail!("basic auth password must not be empty");
    }

    Ok(())
}

#[allow(clippy::result_large_err)]
fn authorize_request(
    request: &Request,
    auth: Option<&AuthConfig>,
    peer_addr: SocketAddr,
) -> std::result::Result<(), ErrorResponse> {
    let Some(auth) = auth else {
        return Ok(());
    };

    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|authorization| {
            auth.expected_authorizations
                .iter()
                .any(|expected| authorization == expected)
        });

    if authorized {
        Ok(())
    } else {
        warn!(%peer_addr, "rejecting websocket request with invalid basic auth");
        Err(unauthorized_response())
    }
}

fn unauthorized_response() -> ErrorResponse {
    let mut response = ErrorResponse::new(Some("authentication required".to_owned()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        r#"Basic realm="ws2tcp-router", charset="UTF-8""#
            .parse()
            .expect("valid WWW-Authenticate header"),
    );
    response
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
    use tokio_tungstenite::tungstenite::http::Uri;

    fn request_with_authorization(authorization: Option<&str>) -> Request {
        let mut request = Request::builder()
            .uri(Uri::from_static("/tcp:127.0.0.1:80"))
            .body(())
            .unwrap();
        if let Some(authorization) = authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, authorization.parse().unwrap());
        }
        request
    }

    fn default_args() -> Args {
        Args {
            bind: "::".to_owned(),
            port: 8000,
            ipv6_only: false,
            buffer_size: 16 * 1024,
            basic_auth: Vec::new(),
            basic_auth_file: None,
        }
    }

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

    #[test]
    fn validates_basic_auth_credentials() {
        assert!(validate_basic_auth_credential("alice:secret").is_ok());
        assert!(validate_basic_auth_credential("alice:sec:ret").is_ok());
        assert!(validate_basic_auth_credential("alice").is_err());
        assert!(validate_basic_auth_credential(":secret").is_err());
        assert!(validate_basic_auth_credential("alice:").is_err());
    }

    #[test]
    fn disables_basic_auth_when_no_auth_options_are_set() {
        let args = default_args();

        assert!(build_auth_config(&args).unwrap().is_none());
    }

    #[test]
    fn builds_basic_auth_config_from_repeated_credentials() {
        let mut args = default_args();
        args.basic_auth = vec!["alice:secret".to_owned(), "bob:secret2".to_owned()];

        let auth = build_auth_config(&args).unwrap().unwrap();

        assert_eq!(
            auth.expected_authorizations,
            vec![
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldDI=".to_owned(),
            ]
        );
    }

    #[test]
    fn rejects_empty_basic_auth_file_when_auth_is_enabled() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ws2tcp-router-empty-auth-{}.txt",
            std::process::id()
        ));
        fs::write(&path, "\n# no credentials\n").unwrap();

        let mut args = default_args();
        args.basic_auth_file = Some(path.clone());
        let result = build_auth_config(&args);

        fs::remove_file(path).unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn allows_request_when_basic_auth_is_disabled() {
        let request = request_with_authorization(None);
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert!(authorize_request(&request, None, peer_addr).is_ok());
    }

    #[test]
    fn rejects_request_without_basic_auth_header_when_enabled() {
        let request = request_with_authorization(None);
        let auth = AuthConfig {
            expected_authorizations: vec!["Basic YWxpY2U6c2VjcmV0".to_owned()],
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        let response = authorize_request(&request, Some(&auth), peer_addr).unwrap_err();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="ws2tcp-router", charset="UTF-8""#
        );
    }

    #[test]
    fn rejects_request_with_invalid_basic_auth_header() {
        let request = request_with_authorization(Some("Basic Ym9iOnNlY3JldA=="));
        let auth = AuthConfig {
            expected_authorizations: vec!["Basic YWxpY2U6c2VjcmV0".to_owned()],
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert!(authorize_request(&request, Some(&auth), peer_addr).is_err());
    }

    #[test]
    fn allows_request_with_matching_basic_auth_header() {
        let request = request_with_authorization(Some("Basic Ym9iOnNlY3JldDI="));
        let auth = AuthConfig {
            expected_authorizations: vec![
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldDI=".to_owned(),
            ],
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert!(authorize_request(&request, Some(&auth), peer_addr).is_ok());
    }
}
