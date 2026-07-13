use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Short-lived state persisted in an encrypted cookie between the
/// OIDC redirect (step 1) and the callback (step 2).
///
/// This solves the stateless plugin problem: PKCE verifier, CSRF
/// token, and nonce must survive across two separate SPOE requests.
/// The plugin encrypts them into a cookie returned as a SPOE variable
/// during the redirect, and reads the cookie back during the callback.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthState {
    /// PKCE code verifier (base64url-encoded random bytes).
    pub pkce_verifier: String,
    /// CSRF state token sent in the authorization request.
    pub csrf_state: String,
    /// Nonce sent in the authorization request.
    pub nonce: String,
    /// Original request path (to redirect back after auth).
    pub original_path: Option<String>,
}

const AUTH_STATE_VERSION: u8 = 1;

impl AuthState {
    /// Encrypt the auth state into a cookie value.
    pub fn encrypt(&self, secret: &[u8]) -> Result<String, String> {
        let plaintext =
            postcard::to_allocvec(self).map_err(|e| format!("serialize auth state: {e}"))?;

        let key = derive_auth_state_key(secret);
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::<Aes256Gcm>::generate();

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| format!("encrypt auth state: {e}"))?;

        let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
        blob.push(AUTH_STATE_VERSION);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&blob))
    }

    /// Decrypt an auth state from a cookie value.
    pub fn decrypt(cookie: &str, secret: &[u8]) -> Result<Self, String> {
        let blob = URL_SAFE_NO_PAD
            .decode(cookie)
            .map_err(|e| format!("base64 decode auth state: {e}"))?;

        if blob.len() < 1 + 12 + 16 {
            return Err("auth state cookie too short".into());
        }

        // blob[0] is the version byte — reserved for future migration.
        let nonce =
            Nonce::<Aes256Gcm>::try_from(&blob[1..13]).map_err(|_| "invalid nonce".to_owned())?;
        let ciphertext = &blob[13..];

        let key = derive_auth_state_key(secret);
        let cipher = Aes256Gcm::new(&key.into());

        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| "auth state decryption failed".to_owned())?;

        postcard::from_bytes(&plaintext).map_err(|e| format!("deserialize auth state: {e}"))
    }
}

fn derive_auth_state_key(secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut key = [0u8; 32];
    hk.expand(b"sso-auth-state-v1", &mut key)
        .expect("32 bytes is valid for HKDF-SHA256");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_state_round_trip() {
        let secret = b"test-secret-at-least-16-chars!!!";
        let state = AuthState {
            pkce_verifier: "verifier123".into(),
            csrf_state: "csrf456".into(),
            nonce: "nonce789".into(),
            original_path: Some("/app/dashboard".into()),
        };
        let cookie = state.encrypt(secret).unwrap();
        let decrypted = AuthState::decrypt(&cookie, secret).unwrap();
        assert_eq!(decrypted.pkce_verifier, "verifier123");
        assert_eq!(decrypted.csrf_state, "csrf456");
        assert_eq!(decrypted.nonce, "nonce789");
        assert_eq!(decrypted.original_path.as_deref(), Some("/app/dashboard"));
    }

    #[test]
    fn auth_state_tampered_rejected() {
        let secret = b"test-secret-at-least-16-chars!!!";
        let state = AuthState {
            pkce_verifier: "v".into(),
            csrf_state: "s".into(),
            nonce: "n".into(),
            original_path: None,
        };
        let mut cookie = state.encrypt(secret).unwrap();
        let len = cookie.len();
        unsafe {
            cookie.as_bytes_mut()[len - 1] ^= 0xFF;
        }
        assert!(AuthState::decrypt(&cookie, secret).is_err());
    }

    #[test]
    fn auth_state_wrong_secret_rejected() {
        let state = AuthState {
            pkce_verifier: "v".into(),
            csrf_state: "s".into(),
            nonce: "n".into(),
            original_path: None,
        };
        let cookie = state.encrypt(b"secret-one-at-least-16chars!").unwrap();
        assert!(AuthState::decrypt(&cookie, b"secret-two-at-least-16chars!").is_err());
    }
}
