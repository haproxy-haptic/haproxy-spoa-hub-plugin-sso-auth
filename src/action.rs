use haproxy_spoa_hub_plugin_api::{ProcessingResult, RString, SpoeValue, TxnVariable};
use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::util::{AUTH_STATE_COOKIE_NAME, SESSION_COOKIE_NAME};

/// The plugin's authentication decision for a given request.
#[derive(Debug)]
pub enum AuthAction {
    /// Redirect the user to the identity provider for authentication.
    Redirect {
        redirect_url: String,
        /// Encrypted auth state cookie (PKCE verifier + nonce + CSRF).
        set_auth_state_cookie: Option<String>,
    },
    /// Identity provider callback processed successfully — set session cookie.
    Callback {
        set_cookie: String,
        claims: HashMap<String, String>,
    },
    /// Valid session — pass through with extracted claims.
    Allow {
        claims: HashMap<String, String>,
        set_cookie: Option<String>,
    },
    /// Authentication denied.
    Deny { error: String },
    /// Logout — redirect to identity provider logout endpoint and clear cookie.
    Logout { redirect_url: String },
    /// Identity provider error — apply failure policy.
    Error { error: String, allow: bool },
}

impl AuthAction {
    /// Convert the auth decision into SPOE transaction variables.
    ///
    /// In addition to the core variables (`set_cookie`, `clear_cookie`,
    /// `set_auth_state_cookie`), this emits convenience variables with
    /// complete `Set-Cookie` headers (`set_cookie_header`,
    /// `set_auth_state_header`, `clear_cookie_header`) so operators
    /// can use either the raw value or the pre-built header.
    pub fn into_variables(self, config: &PluginConfig) -> ProcessingResult {
        let mut vars = Vec::new();

        match self {
            Self::Redirect {
                redirect_url,
                set_auth_state_cookie,
            } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_var(
                    &mut vars,
                    "action",
                    SpoeValue::String(RString::from("redirect")),
                );
                push_var(
                    &mut vars,
                    "redirect_url",
                    SpoeValue::String(RString::from(redirect_url)),
                );
                if let Some(ref cookie) = set_auth_state_cookie {
                    push_var(
                        &mut vars,
                        "set_auth_state_cookie",
                        SpoeValue::String(RString::from(cookie.as_str())),
                    );
                    // Convenience: complete Set-Cookie header for auth state.
                    let header = build_cookie_header(
                        AUTH_STATE_COOKIE_NAME,
                        cookie,
                        config,
                        Some(600), // 10 min TTL for auth state
                    );
                    push_var(
                        &mut vars,
                        "set_auth_state_header",
                        SpoeValue::String(RString::from(header)),
                    );
                }
            }
            Self::Callback { set_cookie, claims } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(true));
                push_var(
                    &mut vars,
                    "action",
                    SpoeValue::String(RString::from("allow")),
                );
                push_var(
                    &mut vars,
                    "set_cookie",
                    SpoeValue::String(RString::from(set_cookie.as_str())),
                );
                // Convenience: complete Set-Cookie header for session.
                let header = build_cookie_header(
                    SESSION_COOKIE_NAME,
                    &set_cookie,
                    config,
                    Some(config.cookie_lifetime_secs),
                );
                push_var(
                    &mut vars,
                    "set_cookie_header",
                    SpoeValue::String(RString::from(header)),
                );
                push_claims(&mut vars, &claims);
            }
            Self::Allow { claims, set_cookie } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(true));
                push_var(
                    &mut vars,
                    "action",
                    SpoeValue::String(RString::from("allow")),
                );
                if let Some(ref cookie) = set_cookie {
                    push_var(
                        &mut vars,
                        "set_cookie",
                        SpoeValue::String(RString::from(cookie.as_str())),
                    );
                    let header = build_cookie_header(
                        SESSION_COOKIE_NAME,
                        cookie,
                        config,
                        Some(config.cookie_lifetime_secs),
                    );
                    push_var(
                        &mut vars,
                        "set_cookie_header",
                        SpoeValue::String(RString::from(header)),
                    );
                }
                push_claims(&mut vars, &claims);
            }
            Self::Deny { error } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_var(
                    &mut vars,
                    "action",
                    SpoeValue::String(RString::from("deny")),
                );
                push_var(&mut vars, "error", SpoeValue::String(RString::from(error)));
                push_var(&mut vars, "status_code", SpoeValue::Uint32(401));
            }
            Self::Logout { redirect_url } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_var(
                    &mut vars,
                    "action",
                    SpoeValue::String(RString::from("redirect")),
                );
                push_var(
                    &mut vars,
                    "redirect_url",
                    SpoeValue::String(RString::from(redirect_url)),
                );
                push_var(&mut vars, "clear_cookie", SpoeValue::Bool(true));
                // Convenience: complete Set-Cookie header to clear session.
                let header = build_cookie_header(SESSION_COOKIE_NAME, "", config, Some(0));
                push_var(
                    &mut vars,
                    "clear_cookie_header",
                    SpoeValue::String(RString::from(header)),
                );
            }
            Self::Error { error, allow } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(allow));
                push_var(
                    &mut vars,
                    "action",
                    SpoeValue::String(RString::from(if allow { "allow" } else { "deny" })),
                );
                push_var(&mut vars, "error", SpoeValue::String(RString::from(error)));
                if !allow {
                    push_var(&mut vars, "status_code", SpoeValue::Uint32(503));
                }
            }
        }

        ProcessingResult::from_vars(vars)
    }
}

/// Build a complete `Set-Cookie` header value using the plugin's
/// global cookie configuration.
fn build_cookie_header(
    name: &str,
    value: &str,
    config: &PluginConfig,
    max_age: Option<u64>,
) -> String {
    let mut header = format!("{name}={value}; Path=/");
    if !config.cookie_domain.is_empty() {
        header.push_str("; Domain=");
        header.push_str(&config.cookie_domain);
    }
    if config.cookie_secure {
        header.push_str("; Secure");
    }
    if config.cookie_httponly {
        header.push_str("; HttpOnly");
    }
    if !config.cookie_samesite.is_empty() {
        header.push_str("; SameSite=");
        header.push_str(&config.cookie_samesite);
    }
    if let Some(age) = max_age {
        use std::fmt::Write;
        let _ = write!(header, "; Max-Age={age}");
    }
    header
}

fn push_var(vars: &mut Vec<TxnVariable>, name: &str, value: SpoeValue) {
    vars.push(TxnVariable::transaction(name, value));
}

fn push_claims(vars: &mut Vec<TxnVariable>, claims: &HashMap<String, String>) {
    for (name, value) in claims {
        push_var(vars, name, SpoeValue::String(RString::from(value.as_str())));
    }
}
