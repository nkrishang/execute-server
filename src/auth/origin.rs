//! Allowed origins: where a client ID may be used from.
//!
//! An entry is a browser origin in canonical form, `scheme://host[:port]`: lowercase, no path, no
//! default port. The host may start with `*.` to allow every subdomain (not the domain itself).
//! `https` everywhere, `http` only for local development hosts. The browser sets `Origin` on every
//! cross-origin request and scripts cannot change it, so a client ID lifted from one site does not
//! work from another's pages. (Outside a browser anyone can send any `Origin`; a client ID can only
//! create addresses, which is harmless, and it is rate limited on its own.)

use url::{Host, Url};

/// Checks an entry for the allowed-origins list; `Err` says what to write instead.
pub fn validate(entry: &str) -> Result<(), String> {
    let (scheme, rest) = entry.split_once("://").ok_or("expected an origin such as \"https://app.example.com\"")?;
    let (wildcard, host_port) = match rest.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    // Parse with a concrete host so the URL parser can normalise it.
    let url = Url::parse(&format!("{scheme}://{host_port}")).map_err(|e| format!("not a valid origin: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err("an origin has no credentials, query or fragment".into());
    }
    if url.path() != "/" || host_port.contains('/') {
        return Err("an origin has no path: drop everything after the host".into());
    }
    let host = match url.host() {
        Some(Host::Domain(d)) => d.to_owned(),
        Some(Host::Ipv4(ip)) if !wildcard => ip.to_string(),
        Some(Host::Ipv6(ip)) if !wildcard => format!("[{ip}]"),
        Some(_) => return Err("a wildcard needs a domain, e.g. \"https://*.example.com\"".into()),
        None => return Err("an origin needs a host".into()),
    };
    if wildcard && host.split('.').count() < 2 {
        return Err("a wildcard must be under a registrable domain, e.g. \"https://*.example.com\"".into());
    }
    let local =
        !wildcard && (host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        "http" => return Err("use https; http is allowed for localhost only".into()),
        other => return Err(format!("unsupported scheme {other}")),
    }
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let canonical = format!("{}://{}{host}{port}", url.scheme(), if wildcard { "*." } else { "" });
    if canonical != entry {
        return Err(format!("write it as \"{canonical}\""));
    }
    Ok(())
}

/// Whether `origin` (a request's `Origin` header) is one of `allowed`.
pub fn is_allowed(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| matches(origin, entry))
}

fn matches(origin: &str, entry: &str) -> bool {
    if origin == entry {
        return true;
    }
    let Some((scheme, rest)) = entry.split_once("://*.") else { return false };
    let Some(origin_rest) = origin.strip_prefix(scheme).and_then(|r| r.strip_prefix("://")) else { return false };
    // `rest` is `example.com[:port]`: the origin must be a subdomain with the same port.
    let (suffix_host, suffix_port) = split_port(rest);
    let (origin_host, origin_port) = split_port(origin_rest);
    origin_port == suffix_port
        && origin_host.len() > suffix_host.len() + 1
        && origin_host.ends_with(suffix_host)
        && origin_host.as_bytes()[origin_host.len() - suffix_host.len() - 1] == b'.'
}

fn split_port(host_port: &str) -> (&str, &str) {
    match host_port.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || host_port.starts_with('[') => (host, port),
        _ => (host_port, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_origins_are_accepted() {
        for ok in [
            "https://app.example.com",
            "https://example.com:8443",
            "https://*.example.com",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://app.localhost:3000",
        ] {
            assert_eq!(validate(ok), Ok(()), "{ok}");
        }
    }

    #[test]
    fn everything_else_says_what_to_write() {
        assert_eq!(validate("https://App.Example.com"), Err("write it as \"https://app.example.com\"".into()));
        assert_eq!(validate("https://app.example.com:443"), Err("write it as \"https://app.example.com\"".into()));
        assert!(validate("https://app.example.com/").unwrap_err().contains("no path"));
        assert!(validate("https://app.example.com/x").unwrap_err().contains("no path"));
        assert!(validate("http://app.example.com").unwrap_err().contains("use https"));
        assert!(validate("app.example.com").unwrap_err().contains("expected an origin"));
        assert!(validate("https://*.com").unwrap_err().contains("registrable domain"));
        assert!(validate("ftp://example.com").is_err());
    }

    #[test]
    fn matching() {
        let allowed = vec![
            "https://app.example.com".to_owned(),
            "https://*.preview.example.com".to_owned(),
            "http://localhost:3000".to_owned(),
        ];
        assert!(is_allowed("https://app.example.com", &allowed));
        assert!(is_allowed("https://pr-12.preview.example.com", &allowed));
        assert!(is_allowed("https://a.b.preview.example.com", &allowed));
        assert!(is_allowed("http://localhost:3000", &allowed));
        assert!(!is_allowed("https://preview.example.com", &allowed), "a wildcard does not cover the domain itself");
        assert!(!is_allowed("https://evilpreview.example.com", &allowed));
        assert!(!is_allowed("http://app.example.com", &allowed), "scheme must match");
        assert!(!is_allowed("http://localhost:3001", &allowed), "port must match");
        assert!(!is_allowed("https://app.example.com.evil.com", &allowed));
        assert!(!is_allowed("null", &allowed));
    }
}
