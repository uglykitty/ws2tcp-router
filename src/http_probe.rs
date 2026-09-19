//! Plain HTTP handling for the health check path.
//!
//! `tokio-tungstenite` consumes the stream during the handshake and sends nothing back when the
//! request is not a websocket upgrade. To answer a plain `GET /`, the request head is read first;
//! everything read is then replayed to the websocket handshake through [`ReplayStream`].

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request},
    http::{HeaderValue, Method, Response, StatusCode, header},
};

use crate::token::TOKEN_HEADER;

const MAX_REQUEST_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

/// Reads until the end of the HTTP request head (`\r\n\r\n`), EOF, or [`MAX_REQUEST_HEAD`].
///
/// A websocket client sends nothing after the head until it gets the handshake response, so
/// stopping here never blocks a valid handshake. The bytes read are returned unmodified so they
/// can be replayed.
pub async fn read_request_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut chunk = [0_u8; 2048];

    while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < MAX_REQUEST_HEAD {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
    }

    Ok(head)
}

/// Returns the request when `head` is a complete plain (non-upgrade) `GET`/`HEAD /` request.
///
/// Anything else, including malformed or partial requests, returns `None` and is left to the
/// websocket handshake.
pub fn parse_plain_health_check(head: &[u8]) -> Option<Request> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    if !matches!(parsed.parse(head), Ok(httparse::Status::Complete(_))) {
        return None;
    }

    let method = Method::from_bytes(parsed.method?.as_bytes()).ok()?;
    if method != Method::GET && method != Method::HEAD {
        return None;
    }

    let target = parsed.path?;
    let path = target.split(['?', '#']).next().unwrap_or(target);
    if path != "/" {
        return None;
    }

    let mut request = Request::builder().method(method).uri(target);
    for header in parsed.headers.iter() {
        request = request.header(header.name, HeaderValue::from_bytes(header.value).ok()?);
    }
    let request = request.body(()).ok()?;

    let is_upgrade = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    (!is_upgrade).then_some(request)
}

/// Builds the `200 OK` response to a plain health check request, carrying `token` in the
/// [`TOKEN_HEADER`] header.
pub fn health_check_response(message: &str, token: &str) -> ErrorResponse {
    let mut response = Response::new(Some(message.to_owned()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        TOKEN_HEADER,
        HeaderValue::from_str(token).expect("token is base64url, a valid header value"),
    );
    response
}

/// Writes `response` as HTTP/1.1 and closes the connection. For `HEAD` the body is omitted.
pub async fn write_response<S>(
    stream: &mut S,
    response: &ErrorResponse,
    include_body: bool,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = response.body().as_deref().unwrap_or("");
    let status = response.status();

    let mut out = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_str(),
        status.canonical_reason().unwrap_or("")
    );
    for (name, value) in response.headers() {
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(&String::from_utf8_lossy(value.as_bytes()));
        out.push_str("\r\n");
    }
    out.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    if include_body {
        out.push_str(body);
    }

    stream.write_all(out.as_bytes()).await?;
    stream.shutdown().await
}

/// A stream that yields `prefix` before reading from `inner`; writes go straight to `inner`.
pub struct ReplayStream<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> ReplayStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.position < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.position);
            buf.put_slice(&this.prefix[this.position..this.position + n]);
            this.position += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_plain_root_request() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: probe/1.0\r\n\r\n";
        let request = parse_plain_health_check(head).expect("plain health check");
        assert_eq!(request.method(), Method::GET);
        assert_eq!(
            request.headers().get(header::USER_AGENT).unwrap(),
            "probe/1.0"
        );
        assert!(parse_plain_health_check(b"HEAD /?x=1 HTTP/1.1\r\nHost: x\r\n\r\n").is_some());
    }

    #[test]
    fn leaves_other_requests_to_the_websocket_handshake() {
        // Upgrade request, other paths and methods, and partial or malformed heads.
        let upgrade =
            b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(parse_plain_health_check(upgrade).is_none());
        assert!(parse_plain_health_check(b"GET /tcp:h:1 HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        assert!(parse_plain_health_check(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        assert!(parse_plain_health_check(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
        assert!(parse_plain_health_check(b"\x16\x03\x01garbage").is_none());
    }

    #[tokio::test]
    async fn replay_stream_yields_prefix_then_inner() {
        let (mut peer, inner) = tokio::io::duplex(64);
        peer.write_all(b"world").await.unwrap();
        drop(peer);

        let mut stream = ReplayStream::new(b"hello ".to_vec(), inner);
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }
}
