# ws2tcp-router

`ws2tcp-router` is a small Tokio-based proxy that accepts WebSocket connections and forwards each connection to a TCP or UDP upstream selected by the request path.

For example:

```text
ws://10.15.108.29:8000/tcp:116.63.8.64:12345
```

means:

- listen for a WebSocket connection on `10.15.108.29:8000`
- connect to TCP upstream `116.63.8.64:12345`
- forward WebSocket binary frames to TCP
- forward TCP bytes back as WebSocket binary frames

Text WebSocket frames are also accepted and forwarded to TCP as UTF-8 bytes.

Use `/udp:` instead of `/tcp:` to forward to a UDP upstream:

```text
ws://10.15.108.29:8000/udp:116.63.8.64:12345
```

Each WebSocket message is forwarded as one UDP datagram, and each UDP datagram
received back is forwarded as one WebSocket binary message, preserving
datagram boundaries. Since UDP has no connection teardown signal, the session
is closed after `--udp-idle-timeout` seconds without traffic in either
direction. See [UDP Forwarding](#udp-forwarding) below.

## Build

```bash
cargo build --release
```

## Docker

Published images are available from GitHub Container Registry:

```bash
podman pull ghcr.io/uglykitty/ws2tcp-router:0.1.16
podman run --rm -p 8000:8000 ghcr.io/uglykitty/ws2tcp-router:0.1.16
```

Build the image:

```bash
docker build -t ws2tcp-router .
```

Run with the default WS listener on port `80`:

```bash
docker run --rm -p 80:80 ws2tcp-router
```

Pass any CLI option after the image name:

```bash
docker run --rm -p 8000:8000 ws2tcp-router --bind 0.0.0.0 --port 8000
docker run --rm -p 8000:8000 -e RUST_LOG=ws2tcp_router=debug ws2tcp-router
docker run --rm -p 8000:8000 -v "$PWD/logs:/logs" ws2tcp-router --log-file /logs/ws2tcp-router.log
```

Docker images and GitHub Release binaries are published by GitHub Actions when
a version tag is pushed:

```bash
git tag v0.1.16
git push origin v0.1.16
```

The Release contains single-file executables:

- `ws2tcp-router-linux-x86_64`
- `ws2tcp-router-linux-arm64`
- `ws2tcp-router-windows-x86_64.exe`
- `ws2tcp-router-windows-arm64.exe`
- `ws2tcp-router-macos-x86_64`
- `ws2tcp-router-macos-arm64`

After the first publish, set the package visibility to public in GitHub if the
image should be pullable without authentication.

## Run

Bind on all interfaces and the default WS port `80`:

```bash
cargo run -- --bind ::
```

Bind on a non-privileged WS port:

```bash
cargo run -- --bind :: --port 8000
```

Load options from a TOML configuration file:

```bash
cargo run -- --config ./config.example.toml
```

Command-line options override values from the configuration file:

```bash
cargo run -- --config ./config.example.toml --bind 0.0.0.0 --port 9000
```

Bind on IPv6 only:

```bash
cargo run -- --bind :: --port 8000 --ipv6-only
```

Bind on a specific address:

```bash
cargo run -- --bind 10.15.108.29 --port 8000
cargo run -- --bind 2001:db8::10 --port 8000
```

Require HTTP Basic authentication:

```bash
cargo run -- --basic-auth alice:secret --basic-auth bob:secret2
```

Load HTTP Basic authentication credentials from a file:

```bash
cargo run -- --basic-auth-file ./users.txt
```

Then connect with a WebSocket client:

```text
ws://10.15.108.29:8000/tcp:116.63.8.64:12345
```

Serve WSS with a PEM certificate chain and private key:

```bash
cargo run -- --bind 0.0.0.0 --service-mode wss-only --tls-port 443 --tls-cert ./cert.pem --tls-key ./key.pem
```

Then connect with a secure WebSocket client:

```text
wss://10.15.108.29/tcp:116.63.8.64:12345
```

## Options

```text
--config <PATH>       Load options from a TOML configuration file.
--bind <ADDR>          Address to bind the WebSocket server to. Default: ::
--service-mode <MODE>  Service mode to run: ws-only, wss-only, or both. Default: ws-only
--port <PORT>          Port to bind the WS server to. Default: 80
--tls-port <PORT>      Port to bind the WSS server to. Default: 443
--ipv6-only            Only accept IPv6 connections when binding an IPv6 address.
--no-ipv6-only         Accept both IPv4 and IPv6 when binding an IPv6 address.
--buffer-size <BYTES>  TCP read buffer size. Default: 16384
--udp-idle-timeout <SECONDS>
                       Seconds of inactivity before an idle UDP forwarding
                       session is closed. Default: 60
--basic-auth <USER:PASS>
                       Require HTTP Basic authentication. Can be repeated.
--basic-auth-file <PATH>
                       Load HTTP Basic authentication credentials from a file.
--anonymous-target <HOST:PORT>
                       Allow anonymous access to this upstream target even when
                       Basic authentication is enabled. Can be repeated.
--anonymous-target-file <PATH>
                       Load anonymous upstream targets from a file.
--tls-cert <PATH>      PEM-encoded TLS certificate chain for serving WSS.
--tls-key <PATH>       PEM-encoded TLS private key for serving WSS.
--auto-self-signed-cert
                       Generate an in-memory 10-year self-signed certificate for WSS.
--no-auto-self-signed-cert
                       Disable automatic self-signed certificate generation from a config file.
--log-file <PATH>      Append logs to this file instead of standard error.
--log-level <FILTER>   Logging filter, overriding RUST_LOG. Example: ws2tcp_router=debug
```

When binding an IPv6 address without `--ipv6-only`, the listener allows dual-stack
operation where the operating system supports it. Use `--ipv6-only` to reject
IPv4-mapped connections. If a configuration file sets `ipv6-only = true`, use
`--no-ipv6-only` to override it from the command line.

## Configuration File

Use `--config <PATH>` to load options from a TOML configuration file. The file
uses the same kebab-case names as the long command-line options:

```toml
bind = "::"
service-mode = "ws-only"
port = 80
tls-port = 443
ipv6-only = false
buffer-size = 16384
udp-idle-timeout = 60

basic-auth = ["alice:secret", "bob:secret2"]
basic-auth-file = "./users.txt"
anonymous-target = ["ocs.wangguofang.net:8443"]
anonymous-target-file = "./anonymous-targets.txt"
tls-cert = "./cert.pem"
tls-key = "./key.pem"
auto-self-signed-cert = false
log-file = "./logs/ws2tcp-router.log"
log-level = "ws2tcp_router=info"
```

Every setting is optional. Missing settings use the same defaults as the CLI.
When both `--config` and command-line options are present, command-line options
take precedence. See `config.example.toml` for a complete commented example.

Logging is controlled with `RUST_LOG`:

```bash
RUST_LOG=ws2tcp_router=debug cargo run -- --bind :: --port 8000
```

Use `--log-level` to set the same filter from the command line:

```bash
cargo run -- --bind :: --port 8000 --log-level ws2tcp_router=debug
```

By default logs are written to standard error. Use `--log-file` to append logs
to a file instead:

```bash
cargo run -- --bind :: --port 8000 --log-file ./logs/ws2tcp-router.log
```

## HTTP Basic Authentication

Authentication is disabled unless `--basic-auth` or `--basic-auth-file` is
specified. When either option is used, every WebSocket upgrade request must
include a matching HTTP Basic `Authorization` header.

`--basic-auth` accepts one `USER:PASS` credential and can be repeated:

```bash
cargo run -- --basic-auth alice:secret --basic-auth bob:secret2
```

`--anonymous-target` allows selected upstream targets to skip Basic
authentication. It accepts one `HOST:PORT` target and can be repeated:

```bash
cargo run -- --basic-auth alice:secret --anonymous-target ocs.wangguofang.net:8443
```

The request path must match the configured target exactly after target
normalization. For example, the command above allows anonymous access to:

```text
ws://10.15.108.29:8000/tcp:ocs.wangguofang.net:8443
```

IPv6 targets must use bracket notation, such as `[2001:db8::1]:443`.

`--anonymous-target-file` reads one `HOST:PORT` target per line. Empty lines and
lines beginning with `#` are ignored:

```text
# anonymous-targets.txt
ocs.wangguofang.net:8443
[2001:db8::1]:443
```

Targets from the file are combined with any repeated `--anonymous-target`
options. The file is checked once per second and reloaded without restarting
the service. If it cannot be read or contains an invalid target, the service
keeps using the last valid targets and logs a warning.

`--basic-auth-file` reads one `USER:PASS` credential per line. Empty lines and
lines beginning with `#` are ignored:

```text
# users.txt
alice:secret
bob:secret2
```

The file is checked once per second and reloaded without restarting the
service. If a changed file cannot be read, contains an invalid credential, or
contains no credentials (unless `--basic-auth` also supplies one), the service
keeps using the last valid credentials and logs a warning.

Basic authentication does not encrypt credentials. Use it behind TLS when
serving untrusted networks.

## TLS / WSS

TLS is disabled by default. Configure both `--tls-cert` and `--tls-key` to serve
secure WebSocket connections with `wss://`:

```bash
cargo run -- --service-mode wss-only --tls-cert ./cert.pem --tls-key ./key.pem
```

`--tls-cert` must point to a PEM certificate chain, and `--tls-key` must point to
a PEM private key. Configure clients to trust the certificate authority that
issued the certificate, or use a publicly trusted certificate for public
deployments.

For local or controlled deployments, `--auto-self-signed-cert` generates an
in-memory self-signed certificate that is valid for 10 years. The certificate SAN
list includes the server's current IPv4 and IPv6 addresses. This option cannot
be used together with `--tls-cert` or `--tls-key`:

```bash
cargo run -- --service-mode wss-only --auto-self-signed-cert
```

Run both WS and WSS listeners at the same time:

```bash
cargo run -- --service-mode both --port 80 --tls-port 443 --auto-self-signed-cert
```

## Path Format

The request path must be:

```text
/tcp:<host>:<port>
/udp:<host>:<port>
```

IPv6 upstream addresses must be enclosed in brackets:

```text
/tcp:[<ipv6-address>]:<port>
/udp:[<ipv6-address>]:<port>
```

Examples:

```text
/tcp:116.63.8.64:12345
/tcp:example.com:80
/tcp:[2001:db8::1]:443
/udp:116.63.8.64:12345
/udp:[2001:db8::1]:53
```

`--anonymous-target` and `--anonymous-target-file` match by `host:port` only,
regardless of protocol: allowing `ocs.wangguofang.net:8443` permits anonymous
access to both `/tcp:ocs.wangguofang.net:8443` and
`/udp:ocs.wangguofang.net:8443`.

### Health check

A request to the root path `/` does not connect to any upstream, so a client can
use it to verify that the service is reachable before opening a real connection.
The server tells the client what happened, in one of two ways:

- **WebSocket** (`ws://10.15.108.29:8000/`): the handshake succeeds, the server
  sends a text message, then a close frame with code `1000` (normal closure) and
  reason `health check`.
- **Plain HTTP** (`curl http://10.15.108.29:8000/`, or `https://` when serving
  WSS): the server replies `200 OK` with the same text as a `text/plain` body.
  `HEAD /` returns the headers only.

The text message looks like this:

```text
ok: ws2tcp-router 0.1.16 is available; health check only, no upstream connected
```

Each successful health check, in either form, also returns a freshly generated
random token in the `X-Ws2tcp-Token` response header (on the `101` handshake
response for WebSocket, and on the `200` response for HTTP). Clients are expected
to send it back in the `X-Ws2tcp-Token` request header on their proxy requests,
next to the Basic Auth credentials. **The token is not verified yet**: the server
neither remembers nor checks it and ignores the header on proxy requests, so
authentication is still Basic Auth only. Verification is planned for a later
version.

When Basic Auth is enabled, the health check still requires valid credentials,
because `/` is not an anonymous target: without them, both forms fail with
`401 Unauthorized`.

A WebSocket request with a path that is not `/`, `/tcp:` or `/udp:` is rejected
with `400 Bad Request` and a body explaining the expected path format. Plain
HTTP requests to any other path are still closed without a response.

## UDP Forwarding

Connect with a `/udp:` path to forward to a UDP upstream instead of TCP:

```bash
cargo run -- --bind :: --port 8000
```

```text
ws://10.15.108.29:8000/udp:116.63.8.64:12345
```

Each WebSocket message is forwarded as exactly one UDP datagram to the
upstream, and each UDP datagram received from the upstream is forwarded back
as exactly one WebSocket binary message. Datagram boundaries are preserved in
both directions; unlike the TCP path, message contents are never split or
coalesced.

UDP has no connection or close signal, so the proxy cannot detect when a
upstream is done responding. Instead, the forwarding session for a WebSocket
connection is closed after `--udp-idle-timeout` seconds pass with no traffic
in either direction:

```bash
cargo run -- --bind :: --port 8000 --udp-idle-timeout 30
```

The default is 60 seconds. As with any UDP forwarding, delivery, ordering, and
retransmission are the responsibility of the client and upstream; the proxy
does not add reliability on top of UDP.
