//! Deciding whether an outbound HTTP target is safe to reach.
//!
//! Server-side request forgery is the failure mode that matters when an agent
//! chooses its own URLs. The classic target is a cloud metadata endpoint at
//! `169.254.169.254`, which usually hands out credentials to anyone inside the
//! instance who asks.
//!
//! Naive URL validation does not stop it. Each of these defeats a check that
//! looks reasonable:
//!
//! | attempt | why a simple check misses it |
//! |---|---|
//! | `http://169.254.169.254/` | caught by a literal blocklist, but only that one |
//! | `http://[::ffff:169.254.169.254]/` | IPv4-mapped IPv6 spells the same address differently |
//! | `http://metadata.evil.com/` | resolves to a private address; the string looks public |
//! | `https://ok.com/` → 302 → `http://169.254.169.254/` | the redirect is the request that matters |
//! | DNS returns a public IP to the checker, private to the client | the check and the connection resolve separately |
//!
//! This module answers the first three; the fourth needs the caller to refuse
//! redirects and the fifth needs the caller to connect to the address that was
//! *validated* rather than re-resolving. [`crate::http::HttpTool`] does both,
//! and there is a test asserting it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

/// Why a destination was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    /// The URL had no scheme, or one this crate does not speak.
    #[error("unsupported URL scheme")]
    Scheme,
    /// The URL was malformed.
    #[error("malformed URL: {0}")]
    Malformed(&'static str),
    /// The URL embedded a username or password.
    #[error("URL must not embed credentials")]
    EmbeddedCredentials,
    /// Plain HTTP was used for a non-loopback host.
    #[error("plain http is only permitted for loopback hosts")]
    PlaintextToRemote,
    /// HTTPS was used for a loopback host.
    #[error("https to a loopback host is not supported; use http for local development")]
    TlsToLoopback,
    /// The host did not resolve.
    #[error("host does not resolve")]
    Unresolvable,
    /// The host resolved to an address that is not permitted.
    #[error("host resolves to a blocked address")]
    BlockedAddress,
    /// The port is not on the permitted list.
    #[error("port is not permitted")]
    BlockedPort,
}

/// How a destination was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationClass {
    /// Plain HTTP to a loopback address, for local development.
    LoopbackHttp,
    /// HTTPS to a public address.
    PublicHttps,
}

/// A destination that passed policy, with the addresses it resolved to.
///
/// Connect to [`ValidatedDestination::addrs`] rather than re-resolving the
/// host. Re-resolution reopens the DNS rebinding window this type exists to
/// close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDestination {
    /// How it was classified.
    pub class: DestinationClass,
    /// Lowercased hostname.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Every address the host resolved to. All of them passed policy.
    pub addrs: Vec<SocketAddr>,
}

/// Ports permitted for public HTTPS.
///
/// An allowlist rather than a blocklist. An agent that can choose an arbitrary
/// port can port-scan the network it runs on and use timing differences to map
/// it, even when every address check holds.
const ALLOWED_HTTPS_PORTS: &[u16] = &[443, 8443];

/// Ports permitted for loopback HTTP (local dev). Restrict to common dev ports to limit port-scan.
const ALLOWED_LOOPBACK_PORTS: &[u16] = &[80, 3000, 4000, 5000, 7000, 8000, 8080, 9000, 8443];

/// Parse a URL and return its lowercased host, without resolving anything.
///
/// Exists so a caller can apply a host allowlist *before* a DNS lookup
/// happens. Resolving first turns every rejected request into a DNS query the
/// caller did not intend to make, and a hostname is an excellent place to
/// smuggle data out of a network that blocks everything else.
pub fn host_of(url: &str) -> Result<String, DestinationError> {
    let (_, host, _) = parse(url)?;
    Ok(host.to_ascii_lowercase())
}

/// Validate and resolve an outbound target.
pub fn validate_destination(url: &str) -> Result<ValidatedDestination, DestinationError> {
    let (scheme, host, port) = parse(url)?;
    let host = host.to_ascii_lowercase();

    let class = match scheme {
        Scheme::Http => {
            if !is_loopback_name(&host) {
                return Err(DestinationError::PlaintextToRemote);
            }
            if !ALLOWED_LOOPBACK_PORTS.contains(&port) {
                return Err(DestinationError::BlockedPort);
            }
            DestinationClass::LoopbackHttp
        }
        Scheme::Https => {
            if is_loopback_name(&host) {
                return Err(DestinationError::TlsToLoopback);
            }
            if !ALLOWED_HTTPS_PORTS.contains(&port) {
                return Err(DestinationError::BlockedPort);
            }
            DestinationClass::PublicHttps
        }
    };

    let loopback_only = class == DestinationClass::LoopbackHttp;
    let addrs = resolve(&host, port, loopback_only)?;

    Ok(ValidatedDestination {
        class,
        host,
        port,
        addrs,
    })
}

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

fn is_numeric_ip_bypass(host: &str) -> bool {
    // Host that looks like an IP but fails standard parse -> likely octal/hex/integer encoding.
    // Standard dotted decimal that parses as IpAddr is already handled; this catches bypass forms.
    let is_numeric_host = host
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '.' || c == 'x' || c == 'X');
    if !is_numeric_host {
        // Also catch pure decimal integer like "3232235777"
        if host.chars().all(|c| c.is_ascii_digit()) && host.len() > 7 {
            return host.parse::<IpAddr>().is_err();
        }
        return false;
    }
    // Contains hex/octal indicators or all digits/dots but not valid IpAddr
    if host.contains('x') || host.contains('X') {
        return host.parse::<IpAddr>().is_err();
    }
    // Leading zero octal like 0300.0250...
    if host
        .split('.')
        .any(|part| part.len() > 1 && part.starts_with('0'))
    {
        return host.parse::<IpAddr>().is_err();
    }
    false
}

fn is_loopback_name(host: &str) -> bool {
    if matches!(host, "localhost" | "::1") {
        return true;
    }
    // 127.0.0.0/8 is all loopback, not just 127.0.0.1. `IpAddr::is_loopback`
    // correctly handles the whole range.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    false
}

fn parse(url: &str) -> Result<(Scheme, String, u16), DestinationError> {
    let url = url.trim();

    // Reject control characters and whitespace anywhere: these are how request
    // smuggling and header injection get started.
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(DestinationError::Malformed("control characters in URL"));
    }

    let lowered = url.to_ascii_lowercase();
    let (scheme, rest) = if let Some(rest) = lowered.strip_prefix("https://") {
        (Scheme::Https, &url[url.len() - rest.len()..])
    } else if let Some(rest) = lowered.strip_prefix("http://") {
        (Scheme::Http, &url[url.len() - rest.len()..])
    } else {
        return Err(DestinationError::Scheme);
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(DestinationError::Malformed("missing host"));
    }
    if authority.contains('@') {
        return Err(DestinationError::EmbeddedCredentials);
    }

    let default_port = match scheme {
        Scheme::Https => 443,
        Scheme::Http => 80,
    };

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or(DestinationError::Malformed("unterminated IPv6 literal"))?;
        let host = rest[..end].to_string();
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| DestinationError::Malformed("invalid port"))?,
            None if rest.len() == end + 1 => default_port,
            None => return Err(DestinationError::Malformed("trailing junk after IPv6 host")),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && !p.is_empty() => {
                let port = p
                    .parse()
                    .map_err(|_| DestinationError::Malformed("invalid port"))?;
                (h.to_string(), port)
            }
            Some(_) => return Err(DestinationError::Malformed("invalid authority")),
            None => (authority.to_string(), default_port),
        }
    };

    if host.is_empty() {
        return Err(DestinationError::Malformed("missing host"));
    }
    // Reject percent-encoded hosts: allowlist example.com should not be bypassed via %65%78...
    if host.contains('%') {
        return Err(DestinationError::Malformed("percent-encoded host"));
    }
    // Reject alternative numeric IP encodings (octal, hex, integer) that `parse::<IpAddr>` rejects
    // but `getaddrinfo` might interpret (e.g. 0xC0.0xA8..., 0300.0250..., 3232235777).
    if is_numeric_ip_bypass(&host) {
        return Err(DestinationError::Malformed("numeric IP bypass"));
    }
    // A trailing dot is a distinct name to a resolver but the same host; strip
    // it so it cannot be used to sidestep a name comparison.
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        return Err(DestinationError::Malformed("missing host"));
    }

    Ok((scheme, host, port))
}

/// Resolve a host and check every address it produced.
///
/// If the system resolver fails, this fails. The original fell back to a
/// hand-rolled DNS client that queried 1.1.1.1 over UDP without verifying the
/// response transaction ID, which is spoofable off-path — a fallback that
/// weakens exactly the check it is part of. Failing closed is better.
fn resolve(
    host: &str,
    port: u16,
    loopback_only: bool,
) -> Result<Vec<SocketAddr>, DestinationError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        check_address(ip, loopback_only)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let resolved: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| DestinationError::Unresolvable)?
        .collect();

    if resolved.is_empty() {
        return Err(DestinationError::Unresolvable);
    }

    // Every address must pass. A host with one public and one private A record
    // is a rebinding attempt, not a partially-valid destination.
    for addr in &resolved {
        check_address(addr.ip(), loopback_only)?;
    }
    Ok(resolved)
}

fn check_address(ip: IpAddr, loopback_only: bool) -> Result<(), DestinationError> {
    let ip = normalize(ip);

    if loopback_only {
        return if ip.is_loopback() {
            Ok(())
        } else {
            Err(DestinationError::BlockedAddress)
        };
    }

    if is_blocked(ip) {
        Err(DestinationError::BlockedAddress)
    } else {
        Ok(())
    }
}

/// Collapse the alternative spellings of an IPv4 address.
///
/// `::ffff:169.254.169.254` and `::169.254.169.254` are the metadata endpoint
/// written as IPv6. Without this they reach the v6 checks, which do not know
/// about link-local IPv4.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else if let Some(v4) = v6.to_ipv4() {
                // IPv4-compatible (deprecated, still routable in places).
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        other => other,
    }
}

fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        // link-local, which is where 169.254.169.254 lives
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return true;
    }

    let o = ip.octets();
    matches!(o[0], 0)                                   // 0.0.0.0/8
        || (o[0] == 100 && (64..=127).contains(&o[1]))  // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)      // IETF protocol assignments
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)    // 6to4 relay anycast
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))  // benchmarking 198.18.0.0/15
        || o[0] >= 240 // reserved 240.0.0.0/4, includes 255.255.255.255
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }

    let s = ip.segments();
    (s[0] & 0xffc0) == 0xfe80          // link-local fe80::/10
        || (s[0] & 0xfe00) == 0xfc00   // unique local fc00::/7
        || (s[0] & 0xffc0) == 0xfec0   // site-local fec0::/10 deprecated
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
        || (s[0] == 0x2001 && s[1] == 0x0000) // Teredo — tunnels an IPv4 dest 2001::/32
        || s[0] == 0x2002 // 6to4 — embeds an arbitrary IPv4 address 2002::/16
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 64:ff9b::/96 (+ 64:ff9b:1::/48)
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // ORCHID 2001:10::/28
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020) // ORCHIDv2 2001:20::/28
        || s[0] == 0x0100 // discard 100::/64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_is_allowed() {
        let d = validate_destination("http://127.0.0.1:8080/v1/x").unwrap();
        assert_eq!(d.class, DestinationClass::LoopbackHttp);
        assert_eq!(d.port, 8080);
    }

    #[test]
    fn plain_http_to_a_remote_host_is_refused() {
        assert_eq!(
            validate_destination("http://example.com/x"),
            Err(DestinationError::PlaintextToRemote)
        );
    }

    #[test]
    fn https_to_loopback_is_refused() {
        assert_eq!(
            validate_destination("https://127.0.0.1/x"),
            Err(DestinationError::TlsToLoopback)
        );
        assert_eq!(
            validate_destination("https://localhost/x"),
            Err(DestinationError::TlsToLoopback)
        );
    }

    #[test]
    fn the_metadata_endpoint_is_blocked_however_it_is_spelled() {
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "https://[::ffff:169.254.169.254]/latest/",
            "https://[::ffff:a9fe:a9fe]/latest/",
        ] {
            assert_eq!(
                validate_destination(url),
                Err(DestinationError::BlockedAddress),
                "not blocked: {url}"
            );
        }
    }

    #[test]
    fn private_and_reserved_ranges_are_blocked() {
        for url in [
            "https://10.0.0.1/",
            "https://172.16.0.1/",
            "https://192.168.1.1/",
            "https://127.0.0.2/",
            "https://0.0.0.0/",
            "https://100.64.0.1/",  // CGNAT
            "https://192.88.99.1/", // 6to4 relay
            "https://198.18.0.1/",  // benchmarking
            "https://240.0.0.1/",   // reserved
            "https://[fd00::1]/",   // unique local
            "https://[fe80::1]/",   // link-local
            "https://[::1]/",
            "https://[2002:a9fe:a9fe::1]/", // 6to4 embedding link-local v4
        ] {
            assert!(
                matches!(
                    validate_destination(url),
                    Err(DestinationError::BlockedAddress) | Err(DestinationError::TlsToLoopback)
                ),
                "not blocked: {url}"
            );
        }
    }

    #[test]
    fn embedded_credentials_are_refused() {
        assert_eq!(
            validate_destination("https://user:pass@example.com/"),
            Err(DestinationError::EmbeddedCredentials)
        );
        // The `@`-confusion shape: some parsers read the host as example.com.
        assert_eq!(
            validate_destination("https://example.com@169.254.169.254/"),
            Err(DestinationError::EmbeddedCredentials)
        );
    }

    #[test]
    fn unusual_ports_are_refused_for_https() {
        // Otherwise an agent can port-scan its own network through timing.
        assert_eq!(
            validate_destination("https://example.com:22/"),
            Err(DestinationError::BlockedPort)
        );
        assert_eq!(
            validate_destination("https://example.com:6379/"),
            Err(DestinationError::BlockedPort)
        );
    }

    #[test]
    fn an_uppercase_scheme_is_still_recognised() {
        // Recognised and then judged, rather than falling through to "unknown
        // scheme" by accident — the two differ if a rule is ever added.
        assert_eq!(
            validate_destination("HTTP://example.com/"),
            Err(DestinationError::PlaintextToRemote)
        );
    }

    #[test]
    fn control_characters_are_refused() {
        assert!(matches!(
            validate_destination("https://example.com/\r\nHost: evil"),
            Err(DestinationError::Malformed(_))
        ));
        assert!(matches!(
            validate_destination("https://exa mple.com/"),
            Err(DestinationError::Malformed(_))
        ));
    }

    #[test]
    fn a_trailing_dot_does_not_evade_the_loopback_check() {
        assert_eq!(
            validate_destination("https://localhost./"),
            Err(DestinationError::TlsToLoopback)
        );
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for url in [
            "file:///etc/passwd",
            "gopher://x/",
            "ftp://x/",
            "//example.com/",
        ] {
            assert_eq!(
                validate_destination(url),
                Err(DestinationError::Scheme),
                "{url}"
            );
        }
    }

    #[test]
    fn a_public_address_passes() {
        let d = validate_destination("https://8.8.8.8/").unwrap();
        assert_eq!(d.class, DestinationClass::PublicHttps);
        assert_eq!(d.addrs.len(), 1);
        assert_eq!(d.port, 443);
    }

    #[test]
    fn normalization_collapses_ipv4_spellings() {
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert_eq!(
            normalize(mapped),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert!(is_blocked(normalize(mapped)));
    }
}
