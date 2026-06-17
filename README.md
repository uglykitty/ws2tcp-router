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

## Run

Bind on all interfaces and port `22345`:

```bash
cargo run -- --bind 0.0.0.0 --port 22345
```

Bind on a specific address:

```bash
cargo run -- --bind 10.15.108.29 --port 22345
```

Then connect with a WebSocket client:

```text
ws://10.15.108.29:22345/tcp:116.63.8.64:12345
```

## Options

```text
--bind <ADDR>          Address to bind the WebSocket server to. Default: 0.0.0.0
--port <PORT>          Port to bind the WebSocket server to. Default: 22345
--buffer-size <BYTES>  TCP read buffer size. Default: 16384
```

Logging is controlled with `RUST_LOG`:

```bash
RUST_LOG=ws2tcp_router=debug cargo run -- --bind 0.0.0.0 --port 22345
```

## Path Format

The request path must be:

```text
/tcp:<host>:<port>
```

Examples:

```text
/tcp:116.63.8.64:12345
/tcp:example.com:80
```
