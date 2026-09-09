use anyhow::{Context, Result, anyhow, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct Target {
    protocol: Protocol,
    host: String,
    port: u16,
}

impl Target {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

pub fn parse_target(path: &str) -> Result<Target> {
    let (protocol, target) = if let Some(rest) = path.strip_prefix("/tcp:") {
        (Protocol::Tcp, rest)
    } else if let Some(rest) = path.strip_prefix("/udp:") {
        (Protocol::Udp, rest)
    } else {
        bail!("path must start with /tcp: or /udp:");
    };

    let (host, port) = parse_host_port(target)?;
    Ok(Target {
        protocol,
        host,
        port,
    })
}

// Used for the anonymous-target allowlist, which is matched by `Target::addr()` only
// (see `AuthConfig::allows_anonymous_target`), so the protocol here is a placeholder.
pub fn parse_target_addr(target: &str) -> Result<Target> {
    let (host, port) = parse_host_port(target)?;
    Ok(Target {
        protocol: Protocol::Tcp,
        host,
        port,
    })
}

fn parse_host_port(target: &str) -> Result<(String, u16)> {
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

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_from_path() {
        let target = parse_target("/tcp:116.63.8.64:12345").unwrap();
        assert_eq!(target.protocol, Protocol::Tcp);
        assert_eq!(target.host, "116.63.8.64");
        assert_eq!(target.port, 12345);
    }

    #[test]
    fn parse_udp_target_from_path() {
        let target = parse_target("/udp:116.63.8.64:12345").unwrap();
        assert_eq!(target.protocol, Protocol::Udp);
        assert_eq!(target.host, "116.63.8.64");
        assert_eq!(target.port, 12345);
        assert_eq!(target.addr(), "116.63.8.64:12345");
    }

    #[test]
    fn parse_target_from_addr() {
        let target = parse_target_addr("ocs.wangguofang.net:8443").unwrap();
        assert_eq!(target.host, "ocs.wangguofang.net");
        assert_eq!(target.port, 8443);
        assert_eq!(target.addr(), "ocs.wangguofang.net:8443");
    }

    #[test]
    fn parse_bracketed_ipv6_target_from_path() {
        let target = parse_target("/tcp:[2001:db8::1]:443").unwrap();
        assert_eq!(target.host, "[2001:db8::1]");
        assert_eq!(target.port, 443);
        assert_eq!(target.addr(), "[2001:db8::1]:443");
    }

    #[test]
    fn parse_bracketed_ipv6_udp_target_from_path() {
        let target = parse_target("/udp:[2001:db8::1]:443").unwrap();
        assert_eq!(target.protocol, Protocol::Udp);
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
        assert!(parse_target("/udp:116.63.8.64").is_err());
        assert!(parse_target("/udp::12345").is_err());
    }
}
