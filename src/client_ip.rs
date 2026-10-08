//! Client IP resolution: trusted-proxy forwarding and IPv6 /64 keying.

use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use ipnet::IpNet;

/// The shared list of trusted reverse-proxy networks, read by the
/// `ClientAddr` extractor from app state.
#[derive(Debug, Clone)]
pub struct TrustedProxies(pub Arc<Vec<IpNet>>);

/// True if `ip` falls inside any network in `trusted`. `ip` must already be
/// canonicalised.
fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

/// Resolves the client IP per the spec: every address is canonicalised with
/// `to_canonical()` before matching. If `peer` is not trusted, the client IP
/// is `peer`, and `xff` is ignored. If `peer` is trusted, this walks the
/// comma-separated `xff` right to left and returns the first entry that
/// parses and is not itself a trusted proxy; if no such entry exists, it
/// falls back to `peer`.
pub fn resolve(peer: IpAddr, xff: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    if !is_trusted(peer, trusted) {
        return peer;
    }
    let Some(xff) = xff else {
        return peer;
    };
    for entry in xff.rsplit(',').map(str::trim) {
        if let Ok(addr) = entry.parse::<IpAddr>() {
            let addr = addr.to_canonical();
            if !is_trusted(addr, trusted) {
                return addr;
            }
        }
    }
    peer
}

/// Every `X-Forwarded-For` header line in `headers`, in order, joined with
/// `,` into the single list RFC 9110 says they are equivalent to; `None`
/// when there is no such header. A line that is not visible ASCII becomes
/// an empty entry, which `resolve` skips like any other unparseable one.
fn forwarded_for(headers: &HeaderMap) -> Option<String> {
    let lines: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .map(|v| v.to_str().unwrap_or(""))
        .collect();
    (!lines.is_empty()).then(|| lines.join(","))
}

/// A client's rate-limiting and logging key: the full IPv4 address, or the
/// top 64 bits (the /64 prefix) of an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(Ipv4Addr),
    V6Prefix(u64),
}

impl ClientKey {
    /// Derives the key from an IP address, canonicalising IPv4-mapped IPv6
    /// addresses to IPv4 first.
    pub fn from_ip(ip: IpAddr) -> ClientKey {
        match ip.to_canonical() {
            IpAddr::V4(v4) => ClientKey::V4(v4),
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                let prefix = ((segments[0] as u64) << 48)
                    | ((segments[1] as u64) << 32)
                    | ((segments[2] as u64) << 16)
                    | (segments[3] as u64);
                ClientKey::V6Prefix(prefix)
            }
        }
    }
}

impl fmt::Display for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientKey::V4(addr) => write!(f, "{addr}"),
            ClientKey::V6Prefix(prefix) => {
                let segments = [
                    ((prefix >> 48) & 0xffff) as u16,
                    ((prefix >> 32) & 0xffff) as u16,
                    ((prefix >> 16) & 0xffff) as u16,
                    (prefix & 0xffff) as u16,
                    0,
                    0,
                    0,
                    0,
                ];
                let addr = Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    0,
                    0,
                    0,
                    0,
                );
                write!(f, "{addr}/64")
            }
        }
    }
}

/// The resolved client IP and its rate-limiting/logging key, extracted from
/// a request's connection info and `X-Forwarded-For` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr {
    pub ip: IpAddr,
    pub key: ClientKey,
}

impl<S> FromRequestParts<S> for ClientAddr
where
    TrustedProxies: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let trusted = TrustedProxies::from_ref(state);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let xff = forwarded_for(&parts.headers);
        let ip = resolve(peer, xff.as_deref(), &trusted.0);
        let key = ClientKey::from_ip(ip);
        Ok(ClientAddr { ip, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr};

    fn trusted_loopback() -> Vec<IpNet> {
        vec!["127.0.0.1/32".parse().unwrap(), "::1/128".parse().unwrap()]
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let peer: IpAddr = "203.0.113.5".parse().unwrap();
        let resolved = resolve(peer, Some("1.2.3.4"), &trusted_loopback());
        assert_eq!(resolved, "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();

        let resolved = resolve(peer, Some("6.6.6.6, 1.2.3.4"), &trusted_loopback());
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());

        let resolved = resolve(peer, Some("1.2.3.4, 127.0.0.1"), &trusted_loopback());
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn every_xff_line_counts_rightmost_last() {
        // A proxy that appends its own header line, after one the client
        // sent: the rightmost entry is in the last line, not the first.
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        headers.append("x-forwarded-for", "1.2.3.4, 127.0.0.1".parse().unwrap());
        let xff = forwarded_for(&headers);
        assert_eq!(xff.as_deref(), Some("6.6.6.6,1.2.3.4, 127.0.0.1"));

        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let resolved = resolve(peer, xff.as_deref(), &trusted_loopback());
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());

        assert_eq!(forwarded_for(&HeaderMap::new()), None);
    }

    #[test]
    fn trusted_peer_bad_xff_falls_back() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let resolved = resolve(peer, Some("garbage"), &trusted_loopback());
        assert_eq!(resolved, peer);
    }

    #[test]
    fn ipv4_mapped_matches_v4() {
        let peer: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        // Because the mapped peer counts as trusted, the untrusted xff entry wins.
        let resolved = resolve(peer, Some("1.2.3.4"), &trusted_loopback());
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn v6_keys_by_64() {
        let a = ClientKey::from_ip("2001:db8::1".parse().unwrap());
        let b = ClientKey::from_ip("2001:db8::ffff".parse().unwrap());
        let c = ClientKey::from_ip("2001:db8:0:1::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn client_key_v4_is_full_address() {
        let a = ClientKey::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        let b = ClientKey::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6)));
        assert_ne!(a, b);
    }
}
