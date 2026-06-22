# Repository Guidelines

## Project Structure

- `src/main.rs` contains the Tokio WebSocket-to-TCP proxy implementation.
- `Cargo.toml` defines the crate metadata and runtime dependencies.
- `.github/workflows/release.yml` builds release binaries.
- `.github/workflows/docker-publish.yml` publishes multi-arch Docker images to GHCR.

## Build and Test

- Run `cargo fmt --check` before submitting Rust changes.
- Run `cargo clippy --all-targets --all-features -- -D warnings` for lint coverage.
- Run `cargo test --all-targets --all-features` for tests.
- Run `cargo build --locked --release` to verify the release build.

## Release

Version tags must use the `vX.Y.Z` format, matching the version in `Cargo.toml`.
Publish the crate to crates.io from a local authenticated Cargo environment:

```bash
cargo publish --locked --dry-run
cargo publish --locked
```

When a matching tag is pushed, GitHub Actions publishes:

- GitHub Release binaries from `.github/workflows/release.yml`
- Docker images to GHCR from `.github/workflows/docker-publish.yml`

Before tagging, update `Cargo.toml`, `Cargo.lock`, and README examples that mention
the version. Publish to crates.io locally before pushing the release tag.
