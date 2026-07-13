use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::provider::Protocol;

/// Session data serialized into the encrypted cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    /// Session format version for future migration.
    pub version: u8,
    /// Provider that authenticated this session.
    pub provider_name: String,
    /// Protocol used (oidc or saml).
    pub protocol: SessionProtocol,
    /// Extracted identity claims.
    pub claims: HashMap<String, String>,
    /// Unix timestamp when the session expires.
    pub expires_at: u64,
    /// OIDC refresh token, if available.
    pub refresh_token: Option<String>,
    /// SAML `SessionIndex` for SLO.
    pub session_index: Option<String>,
    /// SAML `NameID` for SLO.
    pub name_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionProtocol {
    Oidc,
    Saml,
}

impl From<Protocol> for SessionProtocol {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Oidc => Self::Oidc,
            Protocol::Saml => Self::Saml,
        }
    }
}

/// Current session cookie format version prefix.
const COOKIE_VERSION: u8 = 1;

impl SsoSession {
    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        crate::util::now_secs() >= self.expires_at
    }

    /// Encrypt and encode the session into a cookie value.
    pub fn encrypt(&self, config: &PluginConfig) -> Result<String, String> {
        let plaintext = postcard::to_allocvec(self).map_err(|e| format!("serialize: {e}"))?;

        let key = derive_key(config.active_secret());
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::<Aes256Gcm>::generate();

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| format!("encrypt: {e}"))?;

        // Format: version(1) || nonce(12) || ciphertext
        let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
        blob.push(COOKIE_VERSION);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&blob))
    }

    /// Decrypt and decode a session from a cookie value.
    pub fn decrypt(cookie: &str, config: &PluginConfig) -> Result<Self, String> {
        let blob = URL_SAFE_NO_PAD
            .decode(cookie)
            .map_err(|e| format!("base64 decode: {e}"))?;

        if blob.len() < 1 + 12 + 16 {
            return Err("cookie too short".into());
        }

        // blob[0] is the version byte — reserved for future migration.
        let nonce =
            Nonce::<Aes256Gcm>::try_from(&blob[1..13]).map_err(|_| "invalid nonce".to_owned())?;
        let ciphertext = &blob[13..];

        // Try active secret first.
        if let Ok(session) = try_decrypt(ciphertext, &nonce, config.active_secret()) {
            return Ok(session);
        }

        // Fall back to secondary secret for rotation support.
        if let Some(fallback) = config.fallback_secret() {
            if let Ok(session) = try_decrypt(ciphertext, &nonce, fallback) {
                return Ok(session);
            }
        }

        Err("decryption failed with all available secrets".into())
    }
}

fn try_decrypt(
    ciphertext: &[u8],
    nonce: &Nonce<Aes256Gcm>,
    secret: &[u8],
) -> Result<SsoSession, String> {
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new(&key.into());

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decrypt: {e}"))?;

    postcard::from_bytes(&plaintext).map_err(|e| format!("deserialize: {e}"))
}

fn derive_key(secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut key = [0u8; 32];
    hk.expand(b"sso-auth-cookie-v1", &mut key)
        .expect("32 bytes is valid for HKDF-SHA256");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PluginConfig {
        PluginConfig {
            cookie_secret_1: b"test-secret-one-at-least-16-chars".to_vec(),
            cookie_secret_2: Some(b"test-secret-two-at-least-16-chars".to_vec()),
            current_cookie_secret: 1,
            cookie_domain: "example.com".into(),
            cookie_secure: true,
            cookie_httponly: true,
            cookie_samesite: "Lax".into(),
            cookie_lifetime_secs: 36000,
            default_timeout_ms: 5000,
            fail_open: false,
            max_providers: 256,
            clock_skew_secs: 60,
            discovery_ttl_secs: 3600,
        }
    }

    fn test_session() -> SsoSession {
        let mut claims = HashMap::new();
        claims.insert("email".into(), "test@example.com".into());
        claims.insert("name".into(), "Test User".into());
        SsoSession {
            version: 1,
            provider_name: "mykeycloak".into(),
            protocol: SessionProtocol::Oidc,
            claims,
            expires_at: u64::MAX,
            refresh_token: Some("refresh-tok".into()),
            session_index: None,
            name_id: None,
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let config = test_config();
        let session = test_session();
        let cookie = session.encrypt(&config).unwrap();
        let decrypted = SsoSession::decrypt(&cookie, &config).unwrap();
        assert_eq!(decrypted.provider_name, "mykeycloak");
        assert_eq!(decrypted.claims.get("email").unwrap(), "test@example.com");
        assert_eq!(decrypted.refresh_token.as_deref(), Some("refresh-tok"));
    }

    #[test]
    fn dual_key_rotation() {
        let config = test_config();
        let session = test_session();
        // Encrypt with secret_1 (current).
        let cookie = session.encrypt(&config).unwrap();

        // Rotate to secret_2 as current.
        let mut rotated_config = config;
        rotated_config.current_cookie_secret = 2;

        // Old cookie should still decrypt via fallback.
        let decrypted = SsoSession::decrypt(&cookie, &rotated_config).unwrap();
        assert_eq!(decrypted.provider_name, "mykeycloak");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let config = test_config();
        let session = test_session();
        let mut cookie = session.encrypt(&config).unwrap();
        // Tamper with the last character.
        let len = cookie.len();
        unsafe {
            cookie.as_bytes_mut()[len - 1] ^= 0xFF;
        }
        assert!(SsoSession::decrypt(&cookie, &config).is_err());
    }

    #[test]
    fn expired_session_detected() {
        let mut session = test_session();
        session.expires_at = 0; // Already expired.
        assert!(session.is_expired());
    }
}
