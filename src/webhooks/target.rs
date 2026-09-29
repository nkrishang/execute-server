//! Validation of app-supplied webhook URLs: public https only in production, so a caller can
//! never point us at the private network gum-engine and gum-indexer live on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

pub fn validate(raw: &str, allow_insecure: bool) -> Result<Url, String> {
    if raw.len() > 2048 {
        return Err("URL is longer than 2048 characters".into());
    }
    let url = Url::parse(raw).map_err(|e| format!("not a valid URL: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in the URL are not allowed".into());
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure => {}
        "http" => return Err("webhook_url must use https".into()),
        other => return Err(format!("unsupported scheme {other}")),
    }
    let host = url.host().ok_or("URL has no host")?;
    if allow_insecure {
        return Ok(url);
    }
    match host {
        Host::Ipv4(ip) if !is_public(IpAddr::V4(ip)) => Err("webhook_url must be a public address".into()),
        Host::Ipv6(ip) if !is_public(IpAddr::V6(ip)) => Err("webhook_url must be a public address".into()),
        Host::Domain(d)
            if d.eq_ignore_ascii_case("localhost")
                || d.ends_with(".localhost")
                || d.ends_with(".internal")
                || d.ends_with(".local")
                || !d.contains('.') =>
        {
            Err("webhook_url must be a public address".into())
        }
        _ => Ok(url),
    }
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 100 && (64..=127).contains(&o[1]) // CGNAT 100.64/10
                || o[0] == 0
                || v4 == Ipv4Addr::new(169, 254, 169, 254))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || v6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)
                || v6.to_ipv4_mapped().is_some_and(|v4| !is_public(IpAddr::V4(v4))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rules() {
        assert!(validate("https://app.example.com/hooks/execute", false).is_ok());
        assert!(validate("http://app.example.com/hooks", false).is_err(), "https only");
        assert!(validate("https://user:pw@app.example.com/", false).is_err());
        assert!(validate("https://localhost/x", false).is_err());
        assert!(validate("https://gum-engine.railway.internal/x", false).is_err());
        assert!(validate("https://10.0.0.1/x", false).is_err());
        assert!(validate("https://127.0.0.1/x", false).is_err());
        assert!(validate("https://169.254.169.254/x", false).is_err());
        assert!(validate("https://100.64.0.1/x", false).is_err());
        assert!(validate("https://[fd00::1]/x", false).is_err());
        assert!(validate("https://[::ffff:127.0.0.1]/x", false).is_err());
        assert!(validate("https://intranet/x", false).is_err(), "single-label hosts");
        assert!(validate("ftp://example.com/x", false).is_err());
    }

    #[test]
    fn local_mode_allows_http_and_private_hosts() {
        assert!(validate("http://127.0.0.1:19000/hooks", true).is_ok());
        assert!(validate("http://sink.internal/hooks", true).is_ok());
    }
}
