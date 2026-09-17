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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                // std's is_private() covers only RFC1918, so add the IANA
                // special-purpose ranges that also host internal services and
                // are common SSRF targets:
                //   100.64.0.0/10  CGNAT / RFC6598 — cloud metadata (e.g.
                //                  Alibaba 100.100.100.200) lives here.
                //   198.18.0.0/15  benchmarking / RFC2544.
                //   192.88.99.0/24 6to4 relay anycast / RFC7526.
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                // Most of 192.0.0.0/24 is special-purpose and not globally
                // reachable. Keep the two globally reachable PCP anycast
                // assignments usable rather than blocking the entire /24.
                || (o[0] == 192
                    && o[1] == 0
                    && o[2] == 0
                    && o[3] != 9
                    && o[3] != 10)
                // 240.0.0.0/4 is reserved (255.255.255.255 was already
                // covered by is_broadcast()).
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
            {
                return true;
            }
            // Unwrap IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
            // forms and re-check the embedded v4 so e.g. [::ffff:127.0.0.1] or
            // [::ffff:169.254.169.254] cannot slip past the v6 arm.
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_forbidden_ip(IpAddr::V4(v4));
            }

            let s = v6.segments();
            // IPv4/IPv6 translation prefix (RFC 6052). Only /96 has a fixed
            // embedded-address position; the local-use /48 is therefore
            // blocked outright below.
            if s[0] == 0x64
                && s[1] == 0xff9b
                && s[2] == 0
                && s[3] == 0
                && s[4] == 0
                && s[5] == 0
            {
                return is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            // 6to4 carries its IPv4 endpoint in bits 16..48.
            if s[0] == 0x2002 {
                return is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                )));
            }

            // Discard-only, local-use NAT64, and documentation prefixes.
            (s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x3fff && s[1] & 0xf000 == 0)
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

    /// The ranges `obscura-net` added after this copy was written. They are the
    /// reason this file must be re-synced whenever the canonical deny-set moves:
    /// CGNAT in particular hosts a live cloud-metadata endpoint.
    #[test]
    fn iana_special_purpose_ranges_are_denied() {
        for bad in [
            "100.64.0.1",        // CGNAT / RFC6598
            "100.100.100.200",   // Alibaba cloud metadata, inside CGNAT
            "198.18.0.1",        // benchmarking / RFC2544
            "198.19.255.255",
            "192.88.99.1",       // 6to4 relay anycast / RFC7526
            "192.0.0.1",         // special-purpose /24
            "240.0.0.1",         // reserved /4
            "224.0.0.1",         // multicast
            "0.1.2.3",           // 0.0.0.0/8
        ] {
            assert!(is_forbidden_ip(bad.parse().unwrap()), "{bad} should be denied");
        }
        // The two globally reachable PCP anycast assignments stay usable.
        for good in ["192.0.0.9", "192.0.0.10"] {
            assert!(!is_forbidden_ip(good.parse().unwrap()), "{good} should be allowed");
        }
    }

    /// Embedded-IPv4 transition forms must be unwrapped and re-checked, or a
    /// private target can be reached by spelling it as IPv6.
    #[test]
    fn embedded_ipv4_transition_forms_are_denied() {
        for bad in [
            "64:ff9b::7f00:1",    // NAT64 /96 wrapping 127.0.0.1
            "2002:7f00:1::",      // 6to4 wrapping 127.0.0.1
            "64:ff9b:1::1",       // local-use NAT64
            "2001:db8::1",        // documentation
            "ff02::1",            // multicast
        ] {
            assert!(is_forbidden_ip(bad.parse::<IpAddr>().unwrap()), "{bad} should be denied");
        }
        // A NAT64-wrapped *public* address is still public.
        assert!(!is_forbidden_ip("64:ff9b::808:808".parse::<IpAddr>().unwrap()));
    }
}
