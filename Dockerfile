FROM rust:1-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/uglykitty/ws2tcp-router"

COPY --from=builder /app/target/release/ws2tcp-router /usr/local/bin/ws2tcp-router

USER 10001:10001
EXPOSE 22345

ENV RUST_LOG=ws2tcp_router=info

ENTRYPOINT ["ws2tcp-router"]
CMD ["--bind", "::", "--port", "22345"]
