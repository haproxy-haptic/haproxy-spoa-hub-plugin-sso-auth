use std::collections::HashMap;
use std::time::Duration;

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, JsonWebKeySet, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
};

use crate::action::{AuthAction, lacks_required_group};
use crate::auth_state::AuthState;
use crate::cache::{CachedProvider, ProviderCache};
use crate::config::PluginConfig;
use crate::metrics::AuthMetrics;
use crate::provider::{PassToken, ProviderConfig};
use crate::session::{SessionProtocol, SsoSession};
use crate::urlencoding;
use crate::util::now_secs;

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// The per-request inputs of an OIDC decision.
#[derive(Debug, Default)]
pub struct OidcRequest<'a> {
    pub cookie: Option<&'a str>,
    pub auth_state_cookie: Option<&'a str>,
    pub callback_code: Option<&'a str>,
    pub callback_state: Option<&'a str>,
    pub is_logout: bool,
    /// Path and query of the request.
    pub request_path: Option<&'a str>,
    pub allowed_groups: &'a [&'a str],
    /// Host header, completing a path-only `redirect_uri`.
    pub host: Option<&'a str>,
}

/// Handle an OIDC request: redirect to identity provider, process callback, or
/// validate session.
pub fn handle_oidc_request(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    metrics: &AuthMetrics,
    req: &OidcRequest,
) -> AuthAction {
    let session = SsoSession::decrypt_for(req.cookie, config, provider);

    if req.is_logout && session.is_some() {
        metrics.inc_logout(&provider.name);
        return handle_oidc_logout(provider);
    }

    // `code` and `state` only mean a callback on the redirect_uri path; on
    // any other path they belong to the application.
    let callback = req
        .request_path
        .is_some_and(|p| p.split('?').next() == Some(provider.redirect_path()))
        .then_some(req.callback_code.zip(req.callback_state))
        .flatten();

    if let (Some(session), None) = (session, callback) {
        if !session.is_expired() && !needs_token_refresh(provider, config, &session) {
            return allow_session(provider, session, None, req.allowed_groups);
        }
        if let Some(ref refresh_tok) = session.refresh_token {
            match refresh_session(provider, cache, config, &session, refresh_tok, req.host) {
                Ok((renewed, cookie)) => {
                    log::info!("OIDC token refresh success for provider {}", provider.name);
                    metrics.inc_token_refresh(&provider.name);
                    return allow_session(provider, renewed, Some(cookie), req.allowed_groups);
                }
                Err(e) => {
                    log::warn!(
                        "OIDC token refresh failed for provider {}: {e}",
                        provider.name
                    );
                    metrics.inc_token_refresh_failure(&provider.name);
                }
            }
        }
    }

    // Check circuit breaker.
    if let Some(cached) = cache.get(&provider.name) {
        if cached.is_circuit_open(5, 30) {
            log::warn!(
                "OIDC circuit open for provider {} ({} consecutive failures)",
                provider.name,
                cached.consecutive_failures
            );
            return apply_failure_policy(config, &provider.name, "circuit breaker open");
        }
    }

    let http_client = oidc_http_client(provider, config);
    let client = match build_client(provider, cache, config, &http_client, req.host) {
        Ok(c) => c,
        Err(e) => {
            metrics.inc_idp_error(&provider.name);
            cache.update(&provider.name, CachedProvider::record_failure);
            return apply_failure_policy(config, &provider.name, &e);
        }
    };

    if let Some((code, state)) = callback {
        // Decrypt the auth state cookie to recover PKCE verifier, nonce, CSRF.
        let Some(auth_state) = req
            .auth_state_cookie
            .and_then(|c| AuthState::decrypt(c, config.active_secret(provider)).ok())
        else {
            metrics.inc_auth_failure(&provider.name);
            return AuthAction::Deny {
                error: "missing or invalid auth state cookie".into(),
            };
        };

        if state != auth_state.csrf_state {
            metrics.inc_auth_failure(&provider.name);
            return AuthAction::Deny {
                error: "CSRF state mismatch".into(),
            };
        }

        return handle_callback_with_client(
            &client,
            provider,
            config,
            metrics,
            cache,
            code,
            &auth_state,
            &http_client,
        );
    }

    // No session, no callback → redirect to IdP with PKCE.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_req = client.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    // The client always requests openid.
    for scope in provider.scopes.iter().filter(|s| *s != "openid") {
        auth_req = auth_req.add_scope(Scope::new(scope.clone()));
    }
    auth_req = auth_req.set_pkce_challenge(pkce_challenge);

    let (authorize_url, csrf_state, nonce) = auth_req.url();

    // Persist PKCE verifier + nonce + CSRF in an encrypted cookie.
    let auth_state = AuthState {
        pkce_verifier: pkce_verifier.secret().clone(),
        csrf_state: csrf_state.secret().clone(),
        nonce: nonce.secret().clone(),
        original_path: req.request_path.map(String::from),
    };

    match auth_state.encrypt(config.active_secret(provider)) {
        Ok(state_cookie) => AuthAction::Redirect {
            redirect_url: authorize_url.to_string(),
            set_auth_state_cookie: Some(state_cookie),
        },
        Err(e) => AuthAction::Deny {
            error: format!("failed to encrypt auth state: {e}"),
        },
    }
}

fn needs_token_refresh(
    provider: &ProviderConfig,
    config: &PluginConfig,
    session: &SsoSession,
) -> bool {
    provider.pass_token.is_some() && session.token_expires_at <= now_secs() + config.clock_skew_secs
}

fn allow_session(
    provider: &ProviderConfig,
    session: SsoSession,
    set_cookie: Option<String>,
    allowed_groups: &[&str],
) -> AuthAction {
    if lacks_required_group(&session.claims, &provider.groups_claim, allowed_groups) {
        return AuthAction::Forbidden {
            error: "not a member of a required group".into(),
        };
    }
    AuthAction::Allow {
        claims: session.claims,
        set_cookie,
        token: provider.pass_token.and(session.token),
    }
}

/// Where to send the browser after the callback: the recorded path when it
/// is local, `/` otherwise. `//host` and `/\host` are protocol-relative URLs
/// in browsers and would make the callback an open redirect.
fn safe_return_path(original: Option<&str>) -> String {
    match original {
        Some(p)
            if p.starts_with('/')
                && !p.starts_with("//")
                && !p.starts_with("/\\")
                && !p.chars().any(char::is_control) =>
        {
            p.to_owned()
        }
        _ => "/".to_owned(),
    }
}

fn build_client(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    http_client: &openidconnect::ureq::Agent,
    host: Option<&str>,
) -> Result<OidcClient, String> {
    let metadata = resolve_metadata(provider, cache, config, http_client)?;
    let client_id = ClientId::new(provider.client_id.clone());
    let client_secret = provider
        .client_secret
        .as_ref()
        .map(|s| ClientSecret::new(s.clone()));
    let redirect_uri = RedirectUrl::new(provider.redirect_uri_for(host)?)
        .map_err(|e| format!("invalid redirect_uri: {e}"))?;
    Ok(
        CoreClient::from_provider_metadata(metadata, client_id, client_secret)
            .set_redirect_uri(redirect_uri),
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_callback_with_client(
    client: &OidcClient,
    provider: &ProviderConfig,
    config: &PluginConfig,
    metrics: &AuthMetrics,
    cache: &ProviderCache,
    code: &str,
    auth_state: &AuthState,
    http_client: &openidconnect::ureq::Agent,
) -> AuthAction {
    // Exchange code with the PKCE verifier from the auth state cookie.
    let pkce_verifier = PkceCodeVerifier::new(auth_state.pkce_verifier.clone());

    let token_request = match client.exchange_code(AuthorizationCode::new(code.to_owned())) {
        Ok(req) => req.set_pkce_verifier(pkce_verifier),
        Err(e) => {
            metrics.inc_auth_failure(&provider.name);
            return AuthAction::Deny {
                error: format!("no token endpoint: {e}"),
            };
        }
    };

    let token_response = match token_request.request(http_client) {
        Ok(resp) => {
            cache.update(&provider.name, CachedProvider::record_success);
            resp
        }
        Err(e) => {
            log::error!(
                "OIDC token exchange failed for provider {}: {e}",
                provider.name
            );
            metrics.inc_auth_failure(&provider.name);
            metrics.inc_idp_error(&provider.name);
            cache.update(&provider.name, CachedProvider::record_failure);
            return AuthAction::Deny {
                error: format!("token exchange failed: {e}"),
            };
        }
    };

    // Validate the ID token with proper nonce verification.
    let Some(id_token) = token_response.extra_fields().id_token() else {
        metrics.inc_auth_failure(&provider.name);
        return AuthAction::Deny {
            error: "server did not return an ID token".into(),
        };
    };

    let verifier = client.id_token_verifier();
    let expected_nonce = Nonce::new(auth_state.nonce.clone());
    let claims = match id_token.claims(&verifier, &expected_nonce) {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "OIDC ID token validation failed for provider {}: {e}",
                provider.name
            );
            metrics.inc_auth_failure(&provider.name);
            return AuthAction::Deny {
                error: format!("ID token validation failed: {e}"),
            };
        }
    };

    let extracted =
        extract_claims_from_verified(claims, &id_token.to_string(), &provider.extract_claims);
    let refresh_token = token_response.refresh_token().map(|t| t.secret().clone());
    let (token, token_expires_at) = pass_token(
        provider,
        &token_response,
        Some((id_token.to_string(), claims.expiration().timestamp())),
    );

    let session = create_session(
        provider,
        config,
        extracted.clone(),
        refresh_token,
        token,
        token_expires_at,
    );
    match session.seal(config, provider) {
        Ok(cookie) => {
            log::info!("OIDC auth success for provider {}", provider.name);
            metrics.inc_auth_success(&provider.name);
            AuthAction::Callback {
                set_cookie: cookie,
                claims: extracted,
                redirect_url: Some(safe_return_path(auth_state.original_path.as_deref())),
            }
        }
        Err(e) => {
            metrics.inc_auth_failure(&provider.name);
            AuthAction::Deny {
                error: format!("session creation failed: {e}"),
            }
        }
    }
}

/// The token the provider forwards and its expiry. `id_token` is the
/// verified ID token and its `exp`; an access token without `expires_in`
/// lives as long as the session.
fn pass_token(
    provider: &ProviderConfig,
    token_response: &openidconnect::core::CoreTokenResponse,
    id_token: Option<(String, i64)>,
) -> (Option<String>, u64) {
    match provider.pass_token {
        None => (None, 0),
        Some(PassToken::IdToken) => id_token.map_or((None, 0), |(jwt, exp)| {
            (Some(jwt), u64::try_from(exp).unwrap_or(0))
        }),
        Some(PassToken::AccessToken) => (
            Some(token_response.access_token().secret().clone()),
            token_response
                .expires_in()
                .map_or(u64::MAX, |d| now_secs() + d.as_secs()),
        ),
    }
}

/// Exchange the refresh token for new tokens. The renewed session keeps the
/// old claims unless the provider returns a new ID token.
fn refresh_session(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    old: &SsoSession,
    refresh_token_str: &str,
    host: Option<&str>,
) -> Result<(SsoSession, String), String> {
    let http_client = oidc_http_client(provider, config);
    let client = build_client(provider, cache, config, &http_client, host)?;

    let refresh_token = RefreshToken::new(refresh_token_str.to_owned());
    let token_response = client
        .exchange_refresh_token(&refresh_token)
        .map_err(|e| format!("no token endpoint for refresh: {e}"))?
        .request(&http_client)
        .map_err(|e| format!("refresh request failed: {e}"))?;

    cache.update(&provider.name, CachedProvider::record_success);

    let mut claims = old.claims.clone();
    let mut verified_id_token = None;
    if let Some(id_token) = token_response.extra_fields().id_token() {
        let verifier = client.id_token_verifier();
        // Refreshed ID tokens carry no nonce (OIDC Core §12.2).
        let verified = id_token
            .claims(&verifier, |_: Option<&Nonce>| -> Result<(), String> {
                Ok(())
            })
            .map_err(|e| format!("refreshed ID token invalid: {e}"))?;
        claims =
            extract_claims_from_verified(verified, &id_token.to_string(), &provider.extract_claims);
        verified_id_token = Some((id_token.to_string(), verified.expiration().timestamp()));
    }

    let (token, token_expires_at) = pass_token(provider, &token_response, verified_id_token);
    if provider.pass_token.is_some() && token.is_none() {
        return Err("refresh response has no ID token to forward".into());
    }

    let new_refresh = token_response
        .refresh_token()
        .map(|t| t.secret().clone())
        .or_else(|| Some(refresh_token_str.to_owned()));

    let session = create_session(
        provider,
        config,
        claims,
        new_refresh,
        token,
        token_expires_at,
    );
    let cookie = session.seal(config, provider)?;
    Ok((session, cookie))
}

fn resolve_metadata(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    http_client: &openidconnect::ureq::Agent,
) -> Result<CoreProviderMetadata, String> {
    let cached = cache.get(&provider.name);
    if let Some(metadata) = cached
        .filter(|c| !c.is_discovery_stale(config.discovery_ttl_secs))
        .and_then(|c| c.oidc_metadata)
    {
        return Ok(metadata);
    }

    let metadata = if let Some(discovery_url) = provider.discovery_url.as_deref() {
        let issuer_str = discovery_url
            .trim_end_matches("/.well-known/openid-configuration")
            .trim_end_matches("/.well-known/openid-configuration/");
        let issuer_url = IssuerUrl::new(issuer_str.to_owned())
            .map_err(|e| format!("invalid issuer URL: {e}"))?;
        CoreProviderMetadata::discover(&issuer_url, http_client)
            .map_err(|e| format!("OIDC discovery failed: {e}"))?
    } else {
        // FR-003: fallback to manual endpoints.
        let metadata = build_metadata_from_manual_endpoints(provider)?;
        let jwks = JsonWebKeySet::fetch(metadata.jwks_uri(), http_client)
            .map_err(|e| format!("fetch JWKS: {e}"))?;
        metadata.set_jwks(jwks)
    };

    // Cached as the value, not JSON: the signing keys aren't serialized, and a
    // metadata rebuilt from JSON fails every signature check.
    let now = now_secs();
    let to_cache = metadata.clone();
    cache.update(&provider.name, |entry| {
        entry.oidc_metadata = Some(to_cache);
        entry.oidc_discovery_fetched_at = Some(now);
    });

    Ok(metadata)
}

/// FR-003: Build provider metadata from manual endpoint configuration
/// when `discovery_url` is not provided.
fn build_metadata_from_manual_endpoints(
    provider: &ProviderConfig,
) -> Result<CoreProviderMetadata, String> {
    let auth_url = provider
        .auth_url
        .as_deref()
        .ok_or("OIDC provider requires discovery_url or auth_url")?;
    let token_url = provider
        .token_url
        .as_deref()
        .ok_or("OIDC provider requires discovery_url or token_url")?;
    let jwks_uri = provider.jwks_url.as_deref().ok_or(
        "OIDC provider without discovery_url requires jwks_url \
                for ID token signature verification",
    )?;

    // This function is only reached when discovery_url is None,
    // so use auth_url as the issuer.
    let issuer = auth_url;

    // Use serde_json::json! to avoid injection from config values.
    let json = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": auth_url,
        "token_endpoint": token_url,
        "jwks_uri": jwks_uri,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [
            "RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512",
            "PS256", "PS384", "PS512",
            "HS256", "HS384", "HS512"
        ]
    });

    serde_json::from_value::<CoreProviderMetadata>(json)
        .map_err(|e| format!("build manual metadata: {e}"))
}

/// Extract standard + configured claims from a verified ID token.
/// `jwt` is the ID token `claims` were verified from. Configured claims are
/// read from its payload: `CoreIdTokenClaims` drops non-standard claims such
/// as `groups` when it parses the token.
fn extract_claims_from_verified(
    claims: &openidconnect::core::CoreIdTokenClaims,
    jwt: &str,
    extract_claims: &[String],
) -> HashMap<String, String> {
    let mut extracted = HashMap::new();
    extracted.insert("sub".into(), claims.subject().to_string());
    if let Some(email) = claims.email() {
        extracted.insert("email".into(), email.to_string());
    }
    if let Some(name) = claims.name() {
        if let Some(localized) = name.get(None) {
            extracted.insert("name".into(), localized.to_string());
        }
    }

    if let Some(payload) = jwt_payload(jwt) {
        for claim_name in extract_claims {
            if extracted.contains_key(claim_name) {
                continue;
            }
            if let Some(val) = json_value_to_string(payload.get(claim_name)) {
                extracted.insert(claim_name.clone(), val);
            }
        }
    }
    extracted
}

fn jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let segment = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Convert a JSON value to a string representation.
fn json_value_to_string(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr
                .iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            Some(items.join(","))
        }
        other => Some(other.to_string()),
    }
}

fn handle_oidc_logout(provider: &ProviderConfig) -> AuthAction {
    if let Some(ref logout_url) = provider.logout_url {
        let mut url = logout_url.clone();
        if let Some(ref post_logout) = provider.post_logout_redirect_uri {
            let sep = if url.contains('?') { '&' } else { '?' };
            url.push(sep);
            url.push_str("post_logout_redirect_uri=");
            url.push_str(&urlencoding::encode(post_logout));
        }
        log::info!("OIDC logout for provider {}", provider.name);
        AuthAction::Logout { redirect_url: url }
    } else {
        AuthAction::Logout {
            redirect_url: provider
                .post_logout_redirect_uri
                .clone()
                .unwrap_or_else(|| "/".into()),
        }
    }
}

fn create_session(
    provider: &ProviderConfig,
    config: &PluginConfig,
    claims: HashMap<String, String>,
    refresh_token: Option<String>,
    token: Option<String>,
    token_expires_at: u64,
) -> SsoSession {
    let expires_at = now_secs() + config.cookie_lifetime_secs;
    SsoSession {
        version: 1,
        provider_name: provider.name.clone(),
        protocol: SessionProtocol::Oidc,
        claims,
        expires_at,
        refresh_token,
        session_index: None,
        name_id: None,
        token,
        token_expires_at,
    }
}

fn oidc_http_client(
    provider: &ProviderConfig,
    config: &PluginConfig,
) -> openidconnect::ureq::Agent {
    let timeout_ms = provider.timeout_ms.unwrap_or(config.default_timeout_ms);
    openidconnect::ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_millis(timeout_ms))
        .build()
}

pub fn apply_failure_policy(config: &PluginConfig, provider_name: &str, error: &str) -> AuthAction {
    if config.fail_open {
        log::warn!(
            "fail-open: allowing despite error for provider \
             {provider_name}: {error}"
        );
        AuthAction::Error {
            error: error.to_owned(),
            allow: true,
        }
    } else {
        log::error!(
            "fail-closed: denying due to error for provider \
             {provider_name}: {error}"
        );
        AuthAction::Error {
            error: error.to_owned(),
            allow: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_payload_reads_custom_claims() {
        // {"alg":"none"}.{"sub":"u","groups":["a","b"]}.
        let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1IiwiZ3JvdXBzIjpbImEiLCJiIl19.";
        let payload = jwt_payload(jwt).unwrap();
        assert_eq!(
            json_value_to_string(payload.get("groups")).as_deref(),
            Some("a,b")
        );
        assert!(jwt_payload("not-a-jwt").is_none());
    }

    #[test]
    fn safe_return_path_blocks_open_redirects() {
        assert_eq!(safe_return_path(Some("/app?x=1")), "/app?x=1");
        assert_eq!(safe_return_path(Some("//evil.com/")), "/");
        assert_eq!(safe_return_path(Some("/\\evil.com")), "/");
        assert_eq!(safe_return_path(Some("https://evil.com")), "/");
        assert_eq!(safe_return_path(None), "/");
    }
}
