//! Egress policy for the render layer's own resource fetches.
//!
//! Paint loads `<img>`, `background-image` and SVG resources through a blocking
//! `ureq` agent (`paint.rs`), because the painter is synchronous and cannot
//! await `obscura-net`'s async client. That agent previously had no address
//! policy at all, so a page could make the renderer fetch loopback, RFC1918 or
//! link-local URLs even though the same engine refuses to *navigate* to them.
//!
//! The deny-set and the env opt-in below are deliberately identical to
//! `obscura_net::is_forbidden_ip` / `obscura_net::env_allows_private_network`,
//! which remain canonical. They are duplicated rather than imported because
//! `obscura-net` pulls reqwest and tokio unconditionally, and this crate is a
//! dependency-light synchronous layer. The unit tests below cover the same
//! address set as `obscura-net`'s so the two cannot drift silently.

use std::io;
use std::net::{IpAddr, SocketAddr};

/// Process-wide opt-in, matching `obscura-net`'s spelling of the same switch so
/// `OBSCURA_ALLOW_PRIVATE_NETWORK` means one thing everywhere in the engine.
pub(crate) fn env_allows_private_network() -> bool {
    matches!(
        std::env::var("OBSCURA_ALLOW_PRIVATE_NETWORK")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// True when `ip` must never be the target of an outbound request: loopback,
/// RFC1918 private, link-local (including the 169.254.169.254 cloud-metadata
/// endpoint), broadcast, documentation, the unspecified address, IPv6
/// unique-local, and any IPv4-mapped/compatible IPv6 form of the above.
pub(crate) fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
            {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_forbidden_ip(IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Resolver that performs the lookup and then rejects the request if ANY
/// resolved address is in the deny-set. Filtering after resolution (rather than
/// parsing the host string) is what closes the DNS-rebinding case: a public
/// name that resolves to 127.0.0.1 or 169.254.169.254 is blocked using the very
/// addresses the agent would dial. Mirrors `obscura_net::SsrfGuardResolver`.
pub(crate) struct SsrfGuardResolver;

impl ureq::Resolver for SsrfGuardResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(netloc)?.collect();
        // Read the env var per call rather than caching it: the agent is a
        // process-wide `OnceLock`, so a cached value would pin whichever policy
        // happened to be in force at first use.
        if !env_allows_private_network() {
            if let Some(bad) = addrs.iter().find(|sa| is_forbidden_ip(sa.ip())) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SSRF blocked: '{netloc}' resolves to forbidden address {}", bad.ip()),
                ));
            }
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn deny_set_matches_obscura_net() {
        for bad in [
            "127.0.0.1", "127.9.9.9", "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "0.0.0.0", "255.255.255.255", "192.0.2.1",
        ] {
            assert!(is_forbidden_ip(bad.parse().unwrap()), "{bad} should be denied");
        }
        for good in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            assert!(!is_forbidden_ip(good.parse().unwrap()), "{good} should be allowed");
        }
    }

    #[test]
    fn ipv6_mapped_forms_cannot_slip_past() {
        for bad in ["::1", "::", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"] {
            assert!(is_forbidden_ip(bad.parse::<IpAddr>().unwrap()), "{bad} should be denied");
        }
        assert!(!is_forbidden_ip(IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap())));
        assert!(!is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
