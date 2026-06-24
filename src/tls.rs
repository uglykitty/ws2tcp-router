use std::{
    collections::BTreeSet,
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use local_ip_address::list_afinet_netifas;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use crate::args::Args;

pub fn build_tls_config(args: &Args) -> Result<Option<Arc<ServerConfig>>> {
    if args.auto_self_signed_cert {
        let (certs, key) = generate_self_signed_cert()?;
        return Ok(Some(build_server_config(certs, key)?));
    }

    let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };

    let certs = load_certs(cert_path.to_string_lossy().as_ref())?;
    let key = load_private_key(key_path.to_string_lossy().as_ref())?;
    Ok(Some(build_server_config(certs, key)?))
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;

    Ok(Arc::new(config))
}

fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let ips = server_ip_addresses()?;
    let subject_alt_names: Vec<_> = ips.iter().map(ToString::to_string).collect();
    let mut params =
        CertificateParams::new(subject_alt_names).context("failed to create certificate params")?;
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(365 * 10);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "ws2tcp-router self-signed");

    let key_pair = KeyPair::generate().context("failed to generate self-signed private key")?;
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed certificate")?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    Ok((vec![cert_der], key_der))
}

fn server_ip_addresses() -> Result<Vec<IpAddr>> {
    let mut ips = BTreeSet::new();

    for (_, ip) in list_afinet_netifas().context("failed to list server IP addresses")? {
        ips.insert(ip);
    }

    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

    Ok(ips.into_iter().collect())
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
