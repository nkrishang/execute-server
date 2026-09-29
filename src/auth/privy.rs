//! Privy token verification (docs.privy.io): ES256 JWTs, issuer `privy.io`, audience = app id.
//!
//! Both access tokens (`Authorization: Bearer …`) and identity tokens (`privy-id-token` header or
//! cookie) are signed with the app's verification key and carry the user's DID in `sub`.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;

use crate::config::PrivyConfig;

#[derive(Debug, Deserialize)]
pub struct PrivyClaims {
    /// The user's Privy DID, e.g. `did:privy:cm…`.
    pub sub: String,
    #[serde(default)]
    pub sid: Option<String>,
    pub exp: u64,
    #[serde(default)]
    pub iat: Option<u64>,
    /// Identity tokens only: stringified JSON array of linked accounts.
    #[serde(default)]
    pub linked_accounts: Option<String>,
}

pub struct PrivyVerifier {
    key: Option<DecodingKey>,
    validation: Validation,
}

#[derive(Debug, thiserror::Error)]
pub enum PrivyError {
    #[error("privy authentication is not configured")]
    NotConfigured,
    #[error("invalid token: {0}")]
    Invalid(String),
}

impl PrivyVerifier {
    pub fn new(cfg: &PrivyConfig) -> anyhow::Result<Self> {
        let key =
            if cfg.verification_key.trim().is_empty() || cfg.app_id.trim().is_empty() {
                None
            } else {
                Some(DecodingKey::from_ec_pem(cfg.verification_key.as_bytes()).map_err(|e| {
                    anyhow::anyhow!("privy.verification_key is not a PEM-encoded ES256 public key: {e}")
                })?)
            };
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&["privy.io"]);
        validation.set_audience(&[cfg.app_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "iss"]);
        validation.leeway = cfg.clock_skew_secs;
        Ok(Self { key, validation })
    }

    pub fn is_configured(&self) -> bool {
        self.key.is_some()
    }

    pub fn verify(&self, token: &str) -> Result<PrivyClaims, PrivyError> {
        let key = self.key.as_ref().ok_or(PrivyError::NotConfigured)?;
        let data =
            decode::<PrivyClaims>(token, key, &self.validation).map_err(|e| PrivyError::Invalid(e.to_string()))?;
        if !data.claims.sub.starts_with("did:privy:") {
            return Err(PrivyError::Invalid("subject is not a Privy DID".into()));
        }
        Ok(data.claims)
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    //! An ES256 key pair and token minter so routes can be tested without Privy.
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;

    // A throwaway P-256 key pair (PKCS#8 / SPKI), generated for tests only.
    pub const PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU7hql39QEntx0whR
u9fUwJhXuy/iDeoMBKhKL1YrnIuhRANCAASJTbshE2SLSlSHIfUw7qrgjI7oQmm6
zUc8RblUTkKx6Gnwx4Ixw7EB9x3HtTogGCOSTXUyQ4b/qIblZbWMxl4m
-----END PRIVATE KEY-----
";
    pub const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiU27IRNki0pUhyH1MO6q4IyO6EJp
us1HPEW5VE5Csehp8MeCMcOxAfcdx7U6IBgjkk11MkOG/6iG5WW1jMZeJg==
-----END PUBLIC KEY-----
";

    #[derive(Serialize)]
    struct Claims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        iat: u64,
        exp: u64,
        sid: &'a str,
    }

    pub fn mint(app_id: &str, sub: &str, exp: u64) -> String {
        let key = EncodingKey::from_ec_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let claims = Claims { sub, iss: "privy.io", aud: app_id, iat: exp.saturating_sub(3600), exp, sid: "sess" };
        encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PrivyConfig {
        PrivyConfig { app_id: "app-123".into(), verification_key: testkit::PUBLIC_KEY_PEM.into(), clock_skew_secs: 5 }
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn accepts_a_valid_token() {
        let v = PrivyVerifier::new(&cfg()).unwrap();
        let claims = v.verify(&testkit::mint("app-123", "did:privy:abc", now() + 600)).unwrap();
        assert_eq!(claims.sub, "did:privy:abc");
    }

    #[test]
    fn rejects_wrong_audience_expired_and_non_did_subjects() {
        let v = PrivyVerifier::new(&cfg()).unwrap();
        assert!(v.verify(&testkit::mint("other-app", "did:privy:abc", now() + 600)).is_err());
        assert!(v.verify(&testkit::mint("app-123", "did:privy:abc", now() - 600)).is_err());
        assert!(v.verify(&testkit::mint("app-123", "user-1", now() + 600)).is_err());
        assert!(v.verify("not.a.jwt").is_err());
    }

    #[test]
    fn unconfigured_verifier_refuses_everything() {
        let v = PrivyVerifier::new(&PrivyConfig {
            app_id: String::new(),
            verification_key: String::new(),
            clock_skew_secs: 0,
        })
        .unwrap();
        assert!(!v.is_configured());
        assert!(matches!(v.verify("x.y.z"), Err(PrivyError::NotConfigured)));
    }
}
