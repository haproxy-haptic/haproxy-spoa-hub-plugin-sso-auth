use std::collections::HashMap;

use samael::key_info::{KeyInfo, X509Data};
use samael::metadata::{Endpoint, EntityDescriptor, IdpSsoDescriptor, KeyDescriptor};
use samael::service_provider::ServiceProvider;
use samael::traits::ToXml;

use crate::action::{AuthAction, lacks_required_group};
use crate::config::PluginConfig;
use crate::metrics::AuthMetrics;
use crate::oidc::apply_failure_policy;
use crate::provider::ProviderConfig;
use crate::session::{SessionProtocol, SsoSession};
use crate::urlencoding;
use crate::util::now_secs;

/// Handle a SAML request: redirect with `AuthnRequest`, process
/// callback, or validate session.
#[allow(clippy::too_many_arguments)]
pub fn handle_saml_request(
    provider: &ProviderConfig,
    config: &PluginConfig,
    metrics: &AuthMetrics,
    cookie: Option<&str>,
    auth_state_cookie: Option<&str>,
    callback_saml_response: Option<&str>,
    is_logout: bool,
    allowed_groups: &[&str],
) -> AuthAction {
    // FR-005: Enforce idp_cert as required for SAML.
    if provider.idp_cert.is_none() {
        return AuthAction::Deny {
            error: "SAML provider missing required idp_cert \
                    (IdP signing certificate)"
                .into(),
        };
    }
    let session = SsoSession::decrypt_for(cookie, config, provider);

    // Logout.
    if is_logout {
        if let Some(ref session) = session {
            metrics.inc_logout(&provider.name);
            return handle_saml_logout(provider, session);
        }
        return build_saml_redirect(provider, config);
    }

    // Valid session cookie → allow. SAML has no refresh tokens, so an
    // expired session must re-authenticate.
    if let Some(session) = session.filter(|s| !s.is_expired()) {
        if lacks_required_group(&session.claims, &provider.groups_claim, allowed_groups) {
            return AuthAction::Forbidden {
                error: "not a member of a required group".into(),
            };
        }
        return AuthAction::Allow {
            claims: session.claims,
            set_cookie: None,
            token: None,
        };
    }

    // SAML callback (has SAMLResponse).
    if let Some(saml_response) = callback_saml_response {
        // Recover the AuthnRequest ID from the auth state cookie for
        // InResponseTo validation.
        let request_id = auth_state_cookie
            .and_then(|c| {
                crate::auth_state::AuthState::decrypt(c, config.active_secret(provider)).ok()
            })
            .map(|s| s.csrf_state); // request ID is stored in csrf_state field
        return handle_saml_callback(
            provider,
            config,
            metrics,
            saml_response,
            request_id.as_deref(),
        );
    }

    // No session, no callback → redirect to IdP with AuthnRequest.
    build_saml_redirect(provider, config)
}

/// Build a `ServiceProvider` from provider config.
fn build_service_provider(
    provider: &ProviderConfig,
    config: &PluginConfig,
) -> Result<ServiceProvider, String> {
    let idp_metadata = build_idp_metadata(provider)?;

    // FR-014: Use configurable clock skew tolerance.
    let clock_skew =
        chrono::Duration::seconds(i64::try_from(config.clock_skew_secs).unwrap_or(180));

    let mut sp = ServiceProvider {
        idp_metadata,
        entity_id: Some(provider.client_id.clone()),
        acs_url: Some(provider.redirect_uri.clone()),
        max_clock_skew: clock_skew,
        allow_idp_initiated: false,
        ..Default::default()
    };

    if let Some(ref slo_url) = provider.logout_url {
        sp.slo_url = Some(slo_url.clone());
    }

    Ok(sp)
}

/// Build minimal IDP metadata from provider config.
fn build_idp_metadata(provider: &ProviderConfig) -> Result<EntityDescriptor, String> {
    let auth_url = provider
        .auth_url
        .as_deref()
        .ok_or("SAML provider missing auth_url (IdP SSO endpoint)")?;

    let mut key_descriptors = Vec::new();
    if let Some(ref cert_pem) = provider.idp_cert {
        key_descriptors.push(KeyDescriptor {
            key_use: Some("signing".into()),
            key_info: KeyInfo {
                id: None,
                x509_data: Some(X509Data {
                    certificates: vec![cert_pem.clone()],
                }),
            },
            encryption_methods: None,
        });
    }

    let mut single_logout_services = Vec::new();
    if let Some(ref slo_url) = provider.logout_url {
        single_logout_services.push(Endpoint {
            binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
            location: slo_url.clone(),
            response_location: None,
        });
    }

    let idp_sso_descriptor = IdpSsoDescriptor {
        id: None,
        valid_until: None,
        cache_duration: None,
        protocol_support_enumeration: Some("urn:oasis:names:tc:SAML:2.0:protocol".into()),
        error_url: None,
        signature: None,
        key_descriptors,
        organization: None,
        contact_people: vec![],
        artifact_resolution_service: vec![],
        single_logout_services,
        manage_name_id_services: vec![],
        name_id_formats: vec![],
        want_authn_requests_signed: None,
        single_sign_on_services: vec![Endpoint {
            binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
            location: auth_url.into(),
            response_location: None,
        }],
        name_id_mapping_services: vec![],
        assertion_id_request_services: vec![],
        attribute_profiles: vec![],
        attributes: vec![],
    };

    Ok(EntityDescriptor {
        entity_id: Some(provider.client_id.clone()),
        idp_sso_descriptors: Some(vec![idp_sso_descriptor]),
        ..Default::default()
    })
}

fn build_saml_redirect(provider: &ProviderConfig, config: &PluginConfig) -> AuthAction {
    match build_authn_request_url(provider, config) {
        Ok((url, request_id)) => {
            // Store the AuthnRequest ID in an auth state cookie for
            // InResponseTo validation on callback.
            let auth_state = crate::auth_state::AuthState {
                pkce_verifier: String::new(), // unused for SAML
                csrf_state: request_id,       // re-use field for request ID
                nonce: String::new(),         // unused for SAML
                original_path: None,
            };
            let state_cookie = auth_state.encrypt(config.active_secret(provider)).ok();
            AuthAction::Redirect {
                redirect_url: url,
                set_auth_state_cookie: state_cookie,
            }
        }
        Err(e) => {
            log::error!(
                "SAML AuthnRequest failed for provider {}: {e}",
                provider.name
            );
            apply_failure_policy(config, &provider.name, &e)
        }
    }
}

/// Returns `(redirect_url, authn_request_id)`.
fn build_authn_request_url(
    provider: &ProviderConfig,
    config: &PluginConfig,
) -> Result<(String, String), String> {
    let auth_url = provider
        .auth_url
        .as_deref()
        .ok_or("SAML provider missing auth_url")?;

    let sp = build_service_provider(provider, config)?;

    let authn_request = sp
        .make_authentication_request(auth_url)
        .map_err(|e| format!("build AuthnRequest: {e}"))?;

    let request_id = authn_request.id.clone();

    // Use HTTP-Redirect binding with DEFLATE compression.
    let redirect_url = authn_request
        .redirect("")
        .map_err(|e| format!("encode AuthnRequest redirect: {e}"))?
        .ok_or("AuthnRequest redirect URL is None")?;

    Ok((redirect_url.to_string(), request_id))
}

fn handle_saml_callback(
    provider: &ProviderConfig,
    config: &PluginConfig,
    metrics: &AuthMetrics,
    saml_response_b64: &str,
    request_id: Option<&str>,
) -> AuthAction {
    match validate_saml_response(provider, config, saml_response_b64, request_id) {
        Ok((claims, session_index, name_id)) => {
            let session =
                create_saml_session(provider, config, claims.clone(), session_index, name_id);
            match session.seal(config, provider) {
                Ok(cookie) => {
                    log::info!("SAML auth success for provider {}", provider.name);
                    metrics.inc_auth_success(&provider.name);
                    AuthAction::Callback {
                        set_cookie: cookie,
                        claims,
                        redirect_url: None,
                    }
                }
                Err(e) => {
                    log::error!("session encrypt failed: {e}");
                    AuthAction::Deny {
                        error: format!("session creation failed: {e}"),
                    }
                }
            }
        }
        Err(e) => {
            log::error!(
                "SAML response validation failed for provider {}: {e}",
                provider.name
            );
            metrics.inc_auth_failure(&provider.name);
            AuthAction::Deny {
                error: format!("SAML validation failed: {e}"),
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn validate_saml_response(
    provider: &ProviderConfig,
    config: &PluginConfig,
    saml_response_b64: &str,
    request_id: Option<&str>,
) -> Result<(HashMap<String, String>, Option<String>, Option<String>), String> {
    let sp = build_service_provider(provider, config)?;

    // parse_base64_response handles:
    // 1. Base64 decoding
    // 2. XML parsing
    // 3. Signature verification (if IdP cert is configured)
    // 4. Assertion condition validation (audience, NotBefore, NotOnOrAfter)
    // Pass the AuthnRequest ID for InResponseTo validation.
    let request_ids: Vec<&str> = request_id.into_iter().collect();
    let possible_ids = if request_ids.is_empty() {
        None
    } else {
        Some(request_ids.as_slice())
    };

    let assertion = sp
        .parse_base64_response(saml_response_b64, possible_ids)
        .map_err(|e| format!("SAML response validation: {e}"))?;

    // Extract attributes.
    let mut claims = HashMap::new();
    if let Some(ref attr_statements) = assertion.attribute_statements {
        for attr_stmt in attr_statements {
            for attr in &attr_stmt.attributes {
                if let Some(ref attr_name) = attr.name {
                    // Check if this attribute is in the extract list,
                    // or extract all if no list is configured.
                    let should_extract = provider.extract_claims.is_empty()
                        || provider
                            .extract_claims
                            .iter()
                            .any(|c| c == attr_name || attr_name.ends_with(c));

                    if should_extract {
                        // Use the short name (after last /) or the full name.
                        let short_name = attr_name.rsplit('/').next().unwrap_or(attr_name);

                        // Collect all attribute values (comma-separated
                        // for multi-valued attributes like groups).
                        let values: Vec<String> =
                            attr.values.iter().filter_map(|v| v.value.clone()).collect();
                        if !values.is_empty() {
                            claims.insert(short_name.to_owned(), values.join(","));
                        }
                    }
                }
            }
        }
    }

    // Extract SessionIndex for SLO.
    let session_index = assertion
        .authn_statements
        .as_ref()
        .and_then(|stmts| stmts.first())
        .and_then(|stmt| stmt.session_index.clone());

    // Extract NameID for SLO.
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|subj| subj.name_id.as_ref())
        .map(|nid| nid.value.clone());

    Ok((claims, session_index, name_id))
}

fn handle_saml_logout(provider: &ProviderConfig, session: &SsoSession) -> AuthAction {
    if let Some(ref logout_url) = provider.logout_url {
        // Build LogoutRequest using samael types.
        let logout_request = samael::schema::LogoutRequest {
            id: Some(format!("_id{}", generate_request_id())),
            version: Some("2.0".into()),
            issue_instant: Some(chrono::Utc::now()),
            destination: Some(logout_url.clone()),
            issuer: Some(samael::schema::Issuer {
                value: Some(provider.client_id.clone()),
                ..Default::default()
            }),
            signature: None,
            session_index: session.session_index.clone(),
            name_id: session.name_id.as_ref().map(|val| samael::schema::NameID {
                format: None,
                value: val.clone(),
            }),
        };

        // Serialize and use HTTP-Redirect binding with DEFLATE.
        match logout_request.to_string() {
            Ok(xml) => {
                use base64::Engine;
                use base64::engine::general_purpose::STANDARD;
                use flate2::Compression;
                use flate2::write::DeflateEncoder;
                use std::io::Write;

                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                if encoder.write_all(xml.as_bytes()).is_ok() {
                    if let Ok(compressed) = encoder.finish() {
                        let encoded = STANDARD.encode(&compressed);
                        let sep = if logout_url.contains('?') { '&' } else { '?' };
                        let url = format!(
                            "{logout_url}{sep}SAMLRequest={encoded}",
                            encoded = urlencoding::encode(&encoded),
                        );
                        log::info!("SAML logout for provider {}", provider.name);
                        return AuthAction::Logout { redirect_url: url };
                    }
                }
                // Fallback if encoding fails.
                AuthAction::Logout {
                    redirect_url: logout_url.clone(),
                }
            }
            Err(e) => {
                log::error!("SAML LogoutRequest serialization failed: {e}");
                AuthAction::Logout {
                    redirect_url: logout_url.clone(),
                }
            }
        }
    } else {
        AuthAction::Logout {
            redirect_url: provider
                .post_logout_redirect_uri
                .clone()
                .unwrap_or_else(|| "/".into()),
        }
    }
}

fn create_saml_session(
    provider: &ProviderConfig,
    config: &PluginConfig,
    claims: HashMap<String, String>,
    session_index: Option<String>,
    name_id: Option<String>,
) -> SsoSession {
    let expires_at = now_secs() + config.cookie_lifetime_secs;

    SsoSession {
        version: 1,
        provider_name: provider.name.clone(),
        protocol: SessionProtocol::Saml,
        claims,
        expires_at,
        refresh_token: None,
        session_index,
        name_id,
        token: None,
        token_expires_at: 0,
    }
}

fn generate_request_id() -> String {
    use aes_gcm::aead::Generate;
    use std::fmt::Write;

    let bytes: [u8; 16] = Generate::generate();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
