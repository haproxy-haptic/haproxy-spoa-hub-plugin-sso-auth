use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::provider::{Protocol, ProviderConfig};
use crate::util::SESSION_COOKIE_NAME;

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
    /// The provider's `pass_token` (ID or access token), forwarded to the backend.
    pub token: Option<String>,
    /// Unix timestamp when `token` expires; 0 when there is none.
    pub token_expires_at: u64,
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

/// Current session cookie format version prefix. Version 1 cookies (no
/// token fields, uncompressed) fail to decrypt and start a new sign-in.
const COOKIE_VERSION: u8 = 2;

/// Session cookies are split into chunks of this many bytes, below the
/// browsers' 4096-byte limit for one cookie including its attributes.
pub const COOKIE_CHUNK_LEN: usize = 3800;
/// `sso_session`, `sso_session_1`, `sso_session_2`: about 11 KiB, which still
/// fits `HAProxy`'s default request buffer next to the other headers.
pub const MAX_COOKIE_CHUNKS: usize = 3;

/// Cookie name of session chunk `index`.
pub fn chunk_cookie_name(index: usize) -> String {
    if index == 0 {
        SESSION_COOKIE_NAME.to_owned()
    } else {
        format!("{SESSION_COOKIE_NAME}_{index}")
    }
}

/// Split an encrypted session into cookie values, at most `MAX_COOKIE_CHUNKS`.
pub fn split_chunks(cookie: &str) -> Result<Vec<String>, String> {
    // Base64url is ASCII, so byte offsets are char boundaries.
    let chunks: Vec<String> = cookie
        .as_bytes()
        .chunks(COOKIE_CHUNK_LEN)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    if chunks.len() > MAX_COOKIE_CHUNKS {
        return Err(format!(
            "session cookie is {} bytes, over the {} byte limit; extract fewer claims or use a smaller token",
            cookie.len(),
            COOKIE_CHUNK_LEN * MAX_COOKIE_CHUNKS
        ));
    }
    Ok(chunks)
}

impl SsoSession {
    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        crate::util::now_secs() >= self.expires_at
    }

    /// The request's session if it decrypts and belongs to `provider`: a
    /// session from another provider sharing the cookie domain doesn't
    /// authenticate here.
    pub fn decrypt_for(
        cookie: Option<&str>,
        config: &PluginConfig,
        provider: &ProviderConfig,
    ) -> Option<Self> {
        Self::decrypt(cookie?, config, provider)
            .ok()
            .filter(|s| s.provider_name == provider.name)
    }

    /// Encrypt the session and check that it fits the cookie chunks.
    pub fn seal(&self, config: &PluginConfig, provider: &ProviderConfig) -> Result<String, String> {
        let cookie = self.encrypt(config, provider)?;
        split_chunks(&cookie)?;
        Ok(cookie)
    }

    /// Encrypt and encode the session into a cookie value.
    pub fn encrypt(
        &self,
        config: &PluginConfig,
        provider: &ProviderConfig,
    ) -> Result<String, String> {
        let serialized = postcard::to_allocvec(self).map_err(|e| format!("serialize: {e}"))?;
        let plaintext = compress(&serialized)?;

        let key = derive_key(config.active_secret(provider));
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
    pub fn decrypt(
        cookie: &str,
        config: &PluginConfig,
        provider: &ProviderConfig,
    ) -> Result<Self, String> {
        let blob = URL_SAFE_NO_PAD
            .decode(cookie)
            .map_err(|e| format!("base64 decode: {e}"))?;

        if blob.len() < 1 + 12 + 16 {
            return Err("cookie too short".into());
        }

        if blob[0] != COOKIE_VERSION {
            return Err(format!("unsupported session cookie version {}", blob[0]));
        }
        let nonce =
            Nonce::<Aes256Gcm>::try_from(&blob[1..13]).map_err(|_| "invalid nonce".to_owned())?;
        let ciphertext = &blob[13..];

        // Try active secret first.
        if let Ok(session) = try_decrypt(ciphertext, &nonce, config.active_secret(provider)) {
            return Ok(session);
        }

        // Fall back to secondary secret for rotation support.
        if let Some(fallback) = config.fallback_secret(provider) {
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

    // Authenticated above, so the compressed stream is our own output.
    let serialized = decompress(&plaintext)?;
    postcard::from_bytes(&serialized).map_err(|e| format!("deserialize: {e}"))
}

fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(data)
        .and_then(|()| encoder.finish())
        .map_err(|e| format!("compress: {e}"))
}

fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| format!("decompress: {e}"))?;
    Ok(out)
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
    use crate::config::test_config;
    use crate::provider::test_provider;

    pub(crate) fn test_session() -> SsoSession {
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
            token: Some("tok".into()),
            token_expires_at: 42,
        }
    }

    #[test]
    fn keycloak_sized_session_fits_two_chunks() {
        let config = test_config();
        let mut session = test_session();
        // Random base64 doesn't compress: a worst case for real JWTs.
        let random = |n: usize| -> String {
            let bytes: Vec<u8> = (0..n)
                .map(|_| Generate::generate())
                .map(|b: [u8; 1]| b[0])
                .collect();
            URL_SAFE_NO_PAD.encode(bytes)
        };
        session.token = Some(random(1500));
        session.refresh_token = Some(random(900));
        let cookie = session.encrypt(&config, &test_provider()).unwrap();
        let chunks = split_chunks(&cookie).unwrap();
        assert!(chunks.len() <= 2, "{} chunks", chunks.len());
        assert!(chunks.iter().all(|c| c.len() <= COOKIE_CHUNK_LEN));
        let decrypted = SsoSession::decrypt(&chunks.concat(), &config, &test_provider()).unwrap();
        assert_eq!(decrypted.token, session.token);
        assert_eq!(chunk_cookie_name(0), "sso_session");
        assert_eq!(chunk_cookie_name(2), "sso_session_2");
    }

    #[test]
    fn oversized_session_rejected() {
        let cookie = "a".repeat(COOKIE_CHUNK_LEN * MAX_COOKIE_CHUNKS + 1);
        assert!(split_chunks(&cookie).is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let config = test_config();
        let session = test_session();
        let cookie = session.encrypt(&config, &test_provider()).unwrap();
        let decrypted = SsoSession::decrypt(&cookie, &config, &test_provider()).unwrap();
        assert_eq!(decrypted.provider_name, "mykeycloak");
        assert_eq!(decrypted.claims.get("email").unwrap(), "test@example.com");
        assert_eq!(decrypted.refresh_token.as_deref(), Some("refresh-tok"));
        assert_eq!(decrypted.token.as_deref(), Some("tok"));
        assert_eq!(decrypted.token_expires_at, 42);
    }

    #[test]
    fn dual_key_rotation() {
        let config = test_config();
        let session = test_session();
        // Encrypt with secret_1 (current).
        let cookie = session.encrypt(&config, &test_provider()).unwrap();

        // Rotate to secret_2 as current.
        let mut rotated_config = config;
        rotated_config.current_cookie_secret = 2;

        // Old cookie should still decrypt via fallback.
        let decrypted = SsoSession::decrypt(&cookie, &rotated_config, &test_provider()).unwrap();
        assert_eq!(decrypted.provider_name, "mykeycloak");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let config = test_config();
        let session = test_session();
        let mut cookie = session.encrypt(&config, &test_provider()).unwrap();
        // Tamper with the last character.
        let len = cookie.len();
        unsafe {
            cookie.as_bytes_mut()[len - 1] ^= 0xFF;
        }
        assert!(SsoSession::decrypt(&cookie, &config, &test_provider()).is_err());
    }

    #[test]
    fn provider_secret_and_binding_isolate_providers() {
        let config = test_config();
        let mut own = test_provider();
        own.cookie_secret = Some(crate::util::Redacted("tenant-a-secret-16-chars-min".into()));
        let cookie = test_session().encrypt(&config, &own).unwrap();

        // The global keys can't read a cookie sealed with a provider's own key.
        assert!(SsoSession::decrypt(&cookie, &config, &test_provider()).is_err());
        assert!(SsoSession::decrypt_for(Some(&cookie), &config, &own).is_some());

        // A session sealed for another provider name doesn't authenticate.
        let mut other = own.clone();
        other.name = "other".into();
        assert!(SsoSession::decrypt_for(Some(&cookie), &config, &other).is_none());
    }

    #[test]
    fn expired_session_detected() {
        let mut session = test_session();
        session.expires_at = 0; // Already expired.
        assert!(session.is_expired());
    }
}
