use std::{fs::File, io::BufReader, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use crate::args::Args;

pub fn build_tls_config(args: &Args) -> Result<Option<Arc<ServerConfig>>> {
    let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };

    let certs = load_certs(cert_path.to_string_lossy().as_ref())?;
    let key = load_private_key(key_path.to_string_lossy().as_ref())?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;

    Ok(Some(Arc::new(config)))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open TLS certificate {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read TLS certificate {path}"))?;

    if certs.is_empty() {
        bail!("TLS certificate {path} does not contain any certificates");
    }

    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("failed to open TLS private key {path}"))?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to read TLS private key {path}"))?
        .ok_or_else(|| anyhow!("TLS private key {path} does not contain a private key"))
}
