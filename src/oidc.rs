use std::collections::HashMap;
use std::time::Duration;

use openidconnect::core::{CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
};

use crate::action::AuthAction;
use crate::auth_state::AuthState;
use crate::cache::{CachedProvider, ProviderCache};
use crate::config::PluginConfig;
use crate::metrics::AuthMetrics;
use crate::provider::ProviderConfig;
use crate::session::{SessionProtocol, SsoSession};
use crate::urlencoding;
use crate::util::now_secs;

/// Handle an OIDC request: redirect to identity provider, process callback, or
/// validate session.
#[allow(clippy::too_many_arguments)]
pub fn handle_oidc_request(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    metrics: &AuthMetrics,
    cookie: Option<&str>,
    auth_state_cookie: Option<&str>,
    callback_code: Option<&str>,
    callback_state: Option<&str>,
    is_logout: bool,
    request_path: Option<&str>,
) -> AuthAction {
    // Logout.
    if is_logout {
        if let Some(cookie_val) = cookie {
            if SsoSession::decrypt(cookie_val, config).is_ok() {
                metrics.inc_logout(&provider.name);
                return handle_oidc_logout(provider);
            }
        }
    }

    // Valid session cookie → allow.
    if let Some(cookie_val) = cookie {
        if let Ok(session) = SsoSession::decrypt(cookie_val, config) {
            if !session.is_expired() {
                return AuthAction::Allow {
                    claims: session.claims.clone(),
                    set_cookie: None,
                };
            }
            // Expired but has refresh token → try refresh.
            if let Some(ref refresh_tok) = session.refresh_token {
                match handle_token_refresh(provider, cache, config, metrics, refresh_tok) {
                    Ok(action) => return action,
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

    // Resolve discovery metadata.
    let http_client = oidc_http_client(provider, config);
    let metadata = match resolve_metadata(provider, cache, config, &http_client) {
        Ok(m) => m,
        Err(e) => {
            metrics.inc_idp_error(&provider.name);
            cache.update(&provider.name, CachedProvider::record_failure);
            return apply_failure_policy(config, &provider.name, &e);
        }
    };

    let client_id = ClientId::new(provider.client_id.clone());
    let client_secret = provider
        .client_secret
        .as_ref()
        .map(|s| ClientSecret::new(s.clone()));
    let redirect_uri = match RedirectUrl::new(provider.redirect_uri.clone()) {
        Ok(u) => u,
        Err(e) => {
            return AuthAction::Deny {
                error: format!("invalid redirect_uri: {e}"),
            };
        }
    };

    let client =
        openidconnect::core::CoreClient::from_provider_metadata(metadata, client_id, client_secret)
            .set_redirect_uri(redirect_uri);

    // OIDC callback (has code + state + auth_state_cookie).
    if let (Some(code), Some(state)) = (callback_code, callback_state) {
        // Decrypt the auth state cookie to recover PKCE verifier, nonce, CSRF.
        let Some(auth_state) =
            auth_state_cookie.and_then(|c| AuthState::decrypt(c, config.active_secret()).ok())
        else {
            metrics.inc_auth_failure(&provider.name);
            return AuthAction::Deny {
                error: "missing or invalid auth state cookie".into(),
            };
        };

        // Validate CSRF state.
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

    for scope in &provider.scopes {
        auth_req = auth_req.add_scope(Scope::new(scope.clone()));
    }
    auth_req = auth_req.set_pkce_challenge(pkce_challenge);

    let (authorize_url, csrf_state, nonce) = auth_req.url();

    // Persist PKCE verifier + nonce + CSRF in an encrypted cookie.
    let auth_state = AuthState {
        pkce_verifier: pkce_verifier.secret().clone(),
        csrf_state: csrf_state.secret().clone(),
        nonce: nonce.secret().clone(),
        original_path: request_path.map(String::from),
    };

    match auth_state.encrypt(config.active_secret()) {
        Ok(state_cookie) => AuthAction::Redirect {
            redirect_url: authorize_url.to_string(),
            set_auth_state_cookie: Some(state_cookie),
        },
        Err(e) => AuthAction::Deny {
            error: format!("failed to encrypt auth state: {e}"),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_callback_with_client(
    client: &openidconnect::core::CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    >,
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

    let extracted = extract_claims_from_verified(claims, &provider.extract_claims);

    let refresh_token = token_response.refresh_token().map(|t| t.secret().clone());

    let session = create_session(provider, config, extracted.clone(), refresh_token);
    match session.encrypt(config) {
        Ok(cookie) => {
            log::info!("OIDC auth success for provider {}", provider.name);
            metrics.inc_auth_success(&provider.name);
            AuthAction::Callback {
                set_cookie: cookie,
                claims: extracted,
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

fn handle_token_refresh(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    metrics: &AuthMetrics,
    refresh_token_str: &str,
) -> Result<AuthAction, String> {
    let http_client = oidc_http_client(provider, config);
    let metadata = resolve_metadata(provider, cache, config, &http_client)?;

    let client_id = ClientId::new(provider.client_id.clone());
    let client_secret = provider
        .client_secret
        .as_ref()
        .map(|s| ClientSecret::new(s.clone()));
    let redirect_uri = RedirectUrl::new(provider.redirect_uri.clone())
        .map_err(|e| format!("invalid redirect_uri: {e}"))?;

    let client =
        openidconnect::core::CoreClient::from_provider_metadata(metadata, client_id, client_secret)
            .set_redirect_uri(redirect_uri);

    let refresh_token = RefreshToken::new(refresh_token_str.to_owned());
    let token_response = client
        .exchange_refresh_token(&refresh_token)
        .map_err(|e| format!("no token endpoint for refresh: {e}"))?
        .request(&http_client)
        .map_err(|e| format!("refresh request failed: {e}"))?;

    cache.update(&provider.name, CachedProvider::record_success);

    // Extract claims from new ID token if present.
    let mut extracted = HashMap::new();
    if let Some(id_token) = token_response.extra_fields().id_token() {
        let verifier = client.id_token_verifier();
        // Refresh tokens don't use nonce — skip nonce verification per OIDC spec §12.2.
        if let Ok(claims) = id_token.claims(&verifier, |_: Option<&Nonce>| -> Result<(), String> {
            Ok(())
        }) {
            extracted = extract_claims_from_verified(claims, &provider.extract_claims);
        }
    }

    let new_refresh = token_response
        .refresh_token()
        .map(|t| t.secret().clone())
        .or_else(|| Some(refresh_token_str.to_owned()));

    let session = create_session(provider, config, extracted.clone(), new_refresh);
    let cookie = session
        .encrypt(config)
        .map_err(|e| format!("encrypt: {e}"))?;

    log::info!("OIDC token refresh success for provider {}", provider.name);
    metrics.inc_token_refresh(&provider.name);
    Ok(AuthAction::Allow {
        claims: extracted,
        set_cookie: Some(cookie),
    })
}

fn resolve_metadata(
    provider: &ProviderConfig,
    cache: &ProviderCache,
    config: &PluginConfig,
    http_client: &openidconnect::ureq::Agent,
) -> Result<CoreProviderMetadata, String> {
    let Some(discovery_url) = provider.discovery_url.as_deref() else {
        // FR-003: fallback to manual endpoints.
        return build_metadata_from_manual_endpoints(provider);
    };

    // Check cache.
    let cached = cache.get(&provider.name);
    let is_stale = cached
        .as_ref()
        .is_none_or(|c| c.is_discovery_stale(config.discovery_ttl_secs));

    if !is_stale {
        if let Some(json) = cached.and_then(|c| c.oidc_discovery_json.clone()) {
            return serde_json::from_str::<CoreProviderMetadata>(&json)
                .map_err(|e| format!("parse cached discovery: {e}"));
        }
    }

    // Fetch fresh.
    let issuer_str = discovery_url
        .trim_end_matches("/.well-known/openid-configuration")
        .trim_end_matches("/.well-known/openid-configuration/");

    let issuer_url =
        IssuerUrl::new(issuer_str.to_owned()).map_err(|e| format!("invalid issuer URL: {e}"))?;

    let metadata = CoreProviderMetadata::discover(&issuer_url, http_client)
        .map_err(|e| format!("OIDC discovery failed: {e}"))?;

    // Cache it.
    if let Ok(json) = serde_json::to_string(&metadata) {
        let now = now_secs();
        cache.update(&provider.name, |entry| {
            entry.oidc_discovery_json = Some(json);
            entry.oidc_discovery_fetched_at = Some(now);
        });
    }

    Ok(metadata)
}

/// FR-003: Build provider metadata from manual endpoint configuration
/// when `discovery_url` is not provided.
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
fn extract_claims_from_verified(
    claims: &openidconnect::core::CoreIdTokenClaims,
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

    // Extract additional configured claims from the serialized token.
    if !extract_claims.is_empty() {
        if let Ok(raw_json) = serde_json::to_string(claims) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_json) {
                for claim_name in extract_claims {
                    if extracted.contains_key(claim_name) {
                        continue;
                    }
                    if let Some(val) = json_value_to_string(parsed.get(claim_name)) {
                        extracted.insert(claim_name.clone(), val);
                    }
                }
            }
        }
    }
    extracted
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
