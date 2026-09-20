//! Where a connection really came from.
//!
//! Behind a reverse proxy every connection arrives from the proxy, so the logs would show the
//! proxy's address for every client. The proxy passes the client's address on in
//! `X-Forwarded-For`, but any client can send that header itself, so it is believed only when the
//! connection comes from a *trusted proxy*, and then only the part that trusted proxies added: the
//! header is read from the right, skipping the trusted proxies' own addresses, and the first other
//! address is the client. Whatever a client puts to the left of that cannot change the outcome.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde::Deserialize;

const MAX_HEADERS: usize = 64;
const FORWARDED_FOR: &str = "x-forwarded-for";

/// An IP address range: a single address, or a CIDR block such as `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct IpRange {
    addr: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// The loopback addresses, where a reverse proxy on the same host connects from.
    pub fn loopback() -> Vec<Self> {
        ["127.0.0.0/8", "::1/128"]
            .into_iter()
            .map(|range| range.parse().expect("valid built-in range"))
            .collect()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // A dual-stack listener reports IPv4 peers as IPv4-mapped IPv6 addresses.
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for IpRange {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, String> {
        let (addr, prefix) = match input.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (input, None),
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("{input:?} is not an IP address or a CIDR range"))?;
        if addr.to_canonical() != addr {
            return Err(format!(
                "{input:?} is an IPv4-mapped IPv6 address; write the IPv4 address instead"
            ));
        }

        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(prefix) => prefix
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .ok_or_else(|| format!("invalid prefix length in {input:?}, expected 0-{max}"))?,
        };
        Ok(Self { addr, prefix })
    }
}

impl TryFrom<String> for IpRange {
    type Error = String;

    fn try_from(input: String) -> Result<Self, String> {
        input.parse()
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// The proxies whose `X-Forwarded-For` is believed.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    ranges: Vec<IpRange>,
}

impl TrustedProxies {
    pub fn new(ranges: Vec<IpRange>) -> Self {
        Self { ranges }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|range| range.contains(ip))
    }

    /// The address to report for a connection from `peer` that sent the request `head`.
    pub fn client_addr(&self, peer: SocketAddr, head: &[u8]) -> ClientAddr {
        let forwarded = if self.contains(peer.ip()) {
            self.forwarded_client(head)
        } else {
            None
        };
        ClientAddr { peer, forwarded }
    }

    fn forwarded_client(&self, head: &[u8]) -> Option<IpAddr> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        if !matches!(request.parse(head), Ok(httparse::Status::Complete(_))) {
            return None;
        }

        // Several header lines count as one comma-separated list, in order.
        let entries: Vec<&str> = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(FORWARDED_FOR))
            .filter_map(|header| std::str::from_utf8(header.value).ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect();
        self.select_client(&entries)
    }

    /// The client among `X-Forwarded-For` entries: the rightmost one that is not a trusted proxy.
    ///
    /// Each proxy appends the address it received the request from, so the rightmost entries
    /// were written by our own proxies and the ones further left by whoever sent the request.
    /// When every entry is a trusted proxy, the leftmost is the best there is. An entry that is
    /// not an address stops the search: the header cannot be understood, so it is not used.
    fn select_client(&self, entries: &[&str]) -> Option<IpAddr> {
        for entry in entries.iter().rev() {
            let ip = parse_forwarded_address(entry)?;
            if !self.contains(ip) {
                return Some(ip);
            }
        }
        entries
            .first()
            .and_then(|entry| parse_forwarded_address(entry))
    }
}

impl fmt::Display for TrustedProxies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ranges.is_empty() {
            return f.write_str("none");
        }
        for (index, range) in self.ranges.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{range}")?;
        }
        Ok(())
    }
}

/// An `X-Forwarded-For` entry: an IP address, possibly with a port (`1.2.3.4:5678`,
/// `[2001:db8::1]:443`) or in brackets (`[2001:db8::1]`).
fn parse_forwarded_address(entry: &str) -> Option<IpAddr> {
    let ip = entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<SocketAddr>().map(|addr| addr.ip()))
        .or_else(|_| {
            entry
                .strip_prefix('[')
                .and_then(|entry| entry.strip_suffix(']'))
                .ok_or(())
                .and_then(|entry| entry.parse::<IpAddr>().map_err(|_| ()))
        })
        .ok()?;
    Some(ip.to_canonical())
}

/// The address a connection is reported under in the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr {
    /// Who connected to us: the client, or the reverse proxy in front of it.
    peer: SocketAddr,
    /// The client behind a trusted proxy, from `X-Forwarded-For`.
    forwarded: Option<IpAddr>,
}

impl From<SocketAddr> for ClientAddr {
    fn from(peer: SocketAddr) -> Self {
        Self {
            peer,
            forwarded: None,
        }
    }
}

/// The client's IP address when a trusted proxy reported it (the port of the proxy's connection
/// would say nothing about the client), else the peer's socket address, as always.
impl fmt::Display for ClientAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.forwarded {
            Some(ip) => write!(f, "{ip}"),
            None => write!(f, "{}", self.peer),
        }
    }
}

#[cfg(test)]
impl FromStr for ClientAddr {
    type Err = std::net::AddrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        input.parse::<SocketAddr>().map(Self::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(input: &str) -> IpAddr {
        input.parse().unwrap()
    }

    fn range(input: &str) -> IpRange {
        input.parse().unwrap()
    }

    fn proxies(ranges: &[&str]) -> TrustedProxies {
        TrustedProxies::new(ranges.iter().map(|range| range.parse().unwrap()).collect())
    }

    fn head(headers: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\nHost: x\r\n{headers}\r\n").into_bytes()
    }

    #[test]
    fn parses_addresses_and_cidr_ranges() {
        assert!(range("10.0.0.0/8").contains(ip("10.255.0.1")));
        assert!(!range("10.0.0.0/8").contains(ip("11.0.0.1")));
        // A bare address is a range of one; host bits in a range are ignored.
        assert!(range("192.0.2.7").contains(ip("192.0.2.7")));
        assert!(!range("192.0.2.7").contains(ip("192.0.2.8")));
        assert!(range("10.1.2.3/8").contains(ip("10.9.9.9")));
        assert!(range("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(range("2001:db8::/32").contains(ip("2001:db8:1::1")));
        assert!(!range("2001:db8::/32").contains(ip("2001:db9::1")));
        assert!(range("::1/128").contains(ip("::1")));
        // Families never match each other.
        assert!(!range("10.0.0.0/8").contains(ip("2001:db8::1")));
    }

    #[test]
    fn ipv4_peers_of_a_dual_stack_listener_match_ipv4_ranges() {
        assert!(range("127.0.0.0/8").contains(ip("::ffff:127.0.0.1")));
        assert!(range("10.0.0.0/8").contains(ip("::ffff:10.1.2.3")));
        assert!(!range("10.0.0.0/8").contains(ip("::ffff:11.1.2.3")));
    }

    #[test]
    fn rejects_bad_ranges() {
        for bad in [
            "",
            "nope",
            "10.0.0.0/33",
            "::1/129",
            "10.0.0.0/",
            "10.0.0.0/x",
            "::ffff:10.0.0.1",
        ] {
            assert!(bad.parse::<IpRange>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn displays_ranges_and_lists() {
        assert_eq!(range("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(range("2001:db8::1").to_string(), "2001:db8::1/128");
        assert_eq!(proxies(&[]).to_string(), "none");
        assert_eq!(
            TrustedProxies::new(IpRange::loopback()).to_string(),
            "127.0.0.0/8, ::1/128"
        );
    }

    #[test]
    fn reads_the_client_behind_a_trusted_proxy() {
        let trusted = proxies(&["127.0.0.0/8"]);
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();

        let client = trusted.client_addr(peer, &head("X-Forwarded-For: 203.0.113.7\r\n"));
        assert_eq!(client.to_string(), "203.0.113.7");
    }

    #[test]
    fn ignores_the_header_from_anyone_else() {
        let trusted = proxies(&["127.0.0.0/8"]);
        let peer: SocketAddr = "198.51.100.4:5555".parse().unwrap();

        let client = trusted.client_addr(peer, &head("X-Forwarded-For: 203.0.113.7\r\n"));
        assert_eq!(client.to_string(), "198.51.100.4:5555");

        // Nobody is trusted when the list is empty.
        let client = proxies(&[]).client_addr(
            "127.0.0.1:5555".parse().unwrap(),
            &head("X-Forwarded-For: 203.0.113.7\r\n"),
        );
        assert_eq!(client.to_string(), "127.0.0.1:5555");
    }

    #[test]
    fn without_the_header_the_peer_is_reported() {
        let trusted = proxies(&["127.0.0.0/8"]);
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();

        assert_eq!(
            trusted.client_addr(peer, &head("")).to_string(),
            "127.0.0.1:5555"
        );
        // A head that is not a complete request is not read either.
        assert_eq!(
            trusted
                .client_addr(peer, b"GET / HTTP/1.1\r\nX-Forwarded-For: 203.0.113.7\r\n")
                .to_string(),
            "127.0.0.1:5555"
        );
        assert_eq!(
            trusted.client_addr(peer, b"\x16\x03\x01").to_string(),
            "127.0.0.1:5555"
        );
    }

    #[test]
    fn a_client_cannot_forge_the_address_by_prepending_entries() {
        let trusted = proxies(&["127.0.0.0/8"]);
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();

        // The client sent `X-Forwarded-For: 10.0.0.1`, and nginx appended what it saw.
        let client = trusted.client_addr(peer, &head("X-Forwarded-For: 10.0.0.1, 203.0.113.7\r\n"));
        assert_eq!(client.to_string(), "203.0.113.7");
    }

    #[test]
    fn skips_the_trusted_proxies_in_a_chain() {
        let trusted = proxies(&["127.0.0.0/8", "10.0.0.0/8"]);
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();

        // client, then a proxy of ours (10.0.0.5), then the one that connected to us.
        let client = trusted.client_addr(peer, &head("X-Forwarded-For: 203.0.113.7, 10.0.0.5\r\n"));
        assert_eq!(client.to_string(), "203.0.113.7");
    }

    #[test]
    fn uses_the_leftmost_entry_when_every_entry_is_a_trusted_proxy() {
        let trusted = proxies(&["127.0.0.0/8", "10.0.0.0/8"]);

        assert_eq!(
            trusted.select_client(&["10.0.0.9", "10.0.0.5", "127.0.0.2"]),
            Some(ip("10.0.0.9"))
        );
    }

    #[test]
    fn several_header_lines_are_one_list() {
        let trusted = proxies(&["127.0.0.0/8"]);
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();

        let client = trusted.client_addr(
            peer,
            &head("x-forwarded-for: 10.0.0.1\r\nX-FORWARDED-FOR: 203.0.113.7\r\n"),
        );
        assert_eq!(client.to_string(), "203.0.113.7");
    }

    #[test]
    fn an_entry_that_is_not_an_address_makes_the_header_unusable() {
        let trusted = proxies(&["127.0.0.0/8"]);

        // Garbage where our proxy's entry should be: do not guess.
        assert_eq!(trusted.select_client(&["203.0.113.7", "unknown"]), None);
        assert_eq!(trusted.select_client(&["unknown"]), None);
        // Garbage further left is never reached, so it cannot hide the client.
        assert_eq!(
            trusted.select_client(&["garbage", "203.0.113.7"]),
            Some(ip("203.0.113.7"))
        );
        assert_eq!(trusted.select_client(&[]), None);
    }

    #[test]
    fn understands_ports_brackets_and_mapped_addresses() {
        assert_eq!(
            parse_forwarded_address("203.0.113.7"),
            Some(ip("203.0.113.7"))
        );
        assert_eq!(
            parse_forwarded_address("203.0.113.7:4711"),
            Some(ip("203.0.113.7"))
        );
        assert_eq!(
            parse_forwarded_address("2001:db8::1"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_address("[2001:db8::1]"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_address("[2001:db8::1]:443"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_address("::ffff:203.0.113.7"),
            Some(ip("203.0.113.7"))
        );
        assert_eq!(parse_forwarded_address("_hidden"), None);
        assert_eq!(parse_forwarded_address("203.0.113.7, 1.1.1.1"), None);
    }

    #[test]
    fn a_dual_stack_proxy_peer_is_recognised() {
        let trusted = proxies(&["127.0.0.0/8"]);
        let peer: SocketAddr = "[::ffff:127.0.0.1]:5555".parse().unwrap();

        let client = trusted.client_addr(peer, &head("X-Forwarded-For: 203.0.113.7\r\n"));
        assert_eq!(client.to_string(), "203.0.113.7");
    }

    #[test]
    fn a_direct_client_is_displayed_as_before() {
        let peer: SocketAddr = "192.0.2.1:40000".parse().unwrap();

        assert_eq!(ClientAddr::from(peer).to_string(), "192.0.2.1:40000");
    }
}
