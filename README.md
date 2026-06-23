# ws2tcp-router

`ws2tcp-router` is a small Tokio-based proxy that accepts WebSocket connections and forwards each connection to a TCP upstream selected by the request path.

For example:

```text
ws://10.15.108.29:22345/tcp:116.63.8.64:12345
```

means:

- listen for a WebSocket connection on `10.15.108.29:22345`
- connect to TCP upstream `116.63.8.64:12345`
- forward WebSocket binary frames to TCP
- forward TCP bytes back as WebSocket binary frames

Text WebSocket frames are also accepted and forwarded to TCP as UTF-8 bytes.

## Build

```bash
cargo build --release
```

## Docker

Published images are available from GitHub Container Registry:

```bash
podman pull ghcr.io/uglykitty/ws2tcp-router:0.1.5
podman run --rm -p 22345:22345 ghcr.io/uglykitty/ws2tcp-router:0.1.5
```

Build the image:

```bash
docker build -t ws2tcp-router .
```

Run with the default listener on port `22345`:

```bash
docker run --rm -p 22345:22345 ws2tcp-router
```

Pass any CLI option after the image name:

```bash
docker run --rm -p 22345:22345 ws2tcp-router --bind 0.0.0.0 --port 22345
docker run --rm -p 22345:22345 -e RUST_LOG=ws2tcp_router=debug ws2tcp-router
```

Docker images and GitHub Release binaries are published by GitHub Actions when
a version tag is pushed:

```bash
git tag v0.1.5
git push origin v0.1.5
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

Bind on all interfaces and port `22345`:

```bash
cargo run -- --bind :: --port 22345
```

Bind on IPv6 only:

```bash
cargo run -- --bind :: --port 22345 --ipv6-only
```

Bind on a specific address:

```bash
cargo run -- --bind 10.15.108.29 --port 22345
cargo run -- --bind 2001:db8::10 --port 22345
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
ws://10.15.108.29:22345/tcp:116.63.8.64:12345
```

## Options

```text
--bind <ADDR>          Address to bind the WebSocket server to. Default: ::
--port <PORT>          Port to bind the WebSocket server to. Default: 22345
--ipv6-only            Only accept IPv6 connections when binding an IPv6 address.
--buffer-size <BYTES>  TCP read buffer size. Default: 16384
--basic-auth <USER:PASS>
                       Require HTTP Basic authentication. Can be repeated.
--basic-auth-file <PATH>
                       Load HTTP Basic authentication credentials from a file.
```

When binding an IPv6 address without `--ipv6-only`, the listener allows dual-stack
operation where the operating system supports it. Use `--ipv6-only` to reject
IPv4-mapped connections.

Logging is controlled with `RUST_LOG`:

```bash
RUST_LOG=ws2tcp_router=debug cargo run -- --bind :: --port 22345
```

## HTTP Basic Authentication

Authentication is disabled unless `--basic-auth` or `--basic-auth-file` is
specified. When either option is used, every WebSocket upgrade request must
include a matching HTTP Basic `Authorization` header.

`--basic-auth` accepts one `USER:PASS` credential and can be repeated:

```bash
cargo run -- --basic-auth alice:secret --basic-auth bob:secret2
```

`--basic-auth-file` reads one `USER:PASS` credential per line. Empty lines and
lines beginning with `#` are ignored:

```text
# users.txt
alice:secret
bob:secret2
```

Basic authentication does not encrypt credentials. Use it behind TLS when
serving untrusted networks.

## Path Format

The request path must be:

```text
/tcp:<host>:<port>
```

IPv6 upstream addresses must be enclosed in brackets:

```text
/tcp:[<ipv6-address>]:<port>
```

Examples:

```text
/tcp:116.63.8.64:12345
/tcp:example.com:80
/tcp:[2001:db8::1]:443
```
