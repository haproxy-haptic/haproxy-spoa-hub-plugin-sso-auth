use haproxy_spoa_hub_plugin_api::{RString, SpoeValue, TxnVariable};
use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::session::{MAX_COOKIE_CHUNKS, chunk_cookie_name, split_chunks};
use crate::util::{AUTH_STATE_COOKIE_NAME, SESSION_COOKIE_NAME};

/// Output variable names a claim must not overwrite.
const RESERVED_VARS: &[&str] = &[
    "allowed",
    "action",
    "redirect_url",
    "error",
    "status_code",
    "token",
    "pass_token",
    "set_cookie",
    "clear_cookie",
    "set_auth_state_cookie",
    "set_auth_state_header",
    "clear_cookie_header",
];

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
    /// With `redirect_url` the browser is sent back to the page that started
    /// the sign-in; without it the callback request itself is allowed.
    Callback {
        set_cookie: String,
        claims: HashMap<String, String>,
        redirect_url: Option<String>,
    },
    /// Valid session — pass through with extracted claims.
    Allow {
        claims: HashMap<String, String>,
        set_cookie: Option<String>,
        token: Option<String>,
    },
    /// Signed in, but not a member of any group the route requires.
    Forbidden { error: String },
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
    /// In addition to the raw values (`set_cookie`, `clear_cookie`,
    /// `set_auth_state_cookie`), this emits complete `Set-Cookie` headers:
    /// the session goes out in up to `MAX_COOKIE_CHUNKS` chunks as
    /// `set_cookie_header`, `set_cookie_header_1`, … and a slot whose chunk
    /// the request carried but the new session doesn't need clears it.
    /// `present_chunks` is the number of session chunks the request carried.
    pub fn into_variables(self, config: &PluginConfig, present_chunks: usize) -> Vec<TxnVariable> {
        let mut vars = Vec::new();

        match self {
            Self::Redirect {
                redirect_url,
                set_auth_state_cookie,
            } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_str(&mut vars, "action", "redirect");
                push_str(&mut vars, "redirect_url", &redirect_url);
                if let Some(ref cookie) = set_auth_state_cookie {
                    push_str(&mut vars, "set_auth_state_cookie", cookie);
                    let header = build_cookie_header(
                        AUTH_STATE_COOKIE_NAME,
                        cookie,
                        config,
                        Some(600), // 10 min TTL for auth state
                    );
                    push_str(&mut vars, "set_auth_state_header", &header);
                }
            }
            Self::Callback {
                set_cookie,
                claims,
                redirect_url,
            } => {
                if let Some(url) = redirect_url {
                    push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                    push_str(&mut vars, "action", "redirect");
                    push_str(&mut vars, "redirect_url", &url);
                } else {
                    push_var(&mut vars, "allowed", SpoeValue::Bool(true));
                    push_str(&mut vars, "action", "allow");
                    push_claims(&mut vars, &claims);
                }
                push_str(&mut vars, "set_cookie", &set_cookie);
                push_session_cookies(&mut vars, Some(&set_cookie), config, present_chunks);
            }
            Self::Allow {
                claims,
                set_cookie,
                token,
            } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(true));
                push_str(&mut vars, "action", "allow");
                if let Some(ref cookie) = set_cookie {
                    push_str(&mut vars, "set_cookie", cookie);
                    push_session_cookies(&mut vars, Some(cookie), config, present_chunks);
                }
                if let Some(ref token) = token {
                    push_str(&mut vars, "token", token);
                }
                push_claims(&mut vars, &claims);
            }
            Self::Forbidden { error } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_str(&mut vars, "action", "forbidden");
                push_str(&mut vars, "error", &error);
                push_var(&mut vars, "status_code", SpoeValue::Uint32(403));
            }
            Self::Deny { error } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_str(&mut vars, "action", "deny");
                push_str(&mut vars, "error", &error);
                push_var(&mut vars, "status_code", SpoeValue::Uint32(401));
            }
            Self::Logout { redirect_url } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(false));
                push_str(&mut vars, "action", "redirect");
                push_str(&mut vars, "redirect_url", &redirect_url);
                push_var(&mut vars, "clear_cookie", SpoeValue::Bool(true));
                let header = build_cookie_header(SESSION_COOKIE_NAME, "", config, Some(0));
                push_str(&mut vars, "clear_cookie_header", &header);
                push_session_cookies(&mut vars, None, config, present_chunks);
            }
            Self::Error { error, allow } => {
                push_var(&mut vars, "allowed", SpoeValue::Bool(allow));
                push_str(&mut vars, "action", if allow { "allow" } else { "deny" });
                push_str(&mut vars, "error", &error);
                if !allow {
                    push_var(&mut vars, "status_code", SpoeValue::Uint32(503));
                }
            }
        }

        vars
    }
}

/// `set_cookie_header[_N]` for every chunk of `session`, and a clearing
/// header for each chunk the request carried that `session` doesn't use.
fn push_session_cookies(
    vars: &mut Vec<TxnVariable>,
    session: Option<&str>,
    config: &PluginConfig,
    present_chunks: usize,
) {
    // Callers sealed the session with `seal_session`, which checked the size.
    let chunks = session
        .map(|s| split_chunks(s).unwrap_or_else(|_| vec![s.to_owned()]))
        .unwrap_or_default();
    for index in 0..MAX_COOKIE_CHUNKS {
        let header = if let Some(chunk) = chunks.get(index) {
            build_cookie_header(
                &chunk_cookie_name(index),
                chunk,
                config,
                Some(config.cookie_lifetime_secs),
            )
        } else if index < present_chunks {
            build_cookie_header(&chunk_cookie_name(index), "", config, Some(0))
        } else {
            continue;
        };
        let var = if index == 0 {
            "set_cookie_header".to_owned()
        } else {
            format!("set_cookie_header_{index}")
        };
        push_str(vars, &var, &header);
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

fn push_str(vars: &mut Vec<TxnVariable>, name: &str, value: &str) {
    push_var(vars, name, SpoeValue::String(RString::from(value)));
}

/// True when the route requires groups and `claims[groups_claim]` (a comma
/// list) names none of them.
pub fn lacks_required_group(
    claims: &HashMap<String, String>,
    groups_claim: &str,
    allowed_groups: &[&str],
) -> bool {
    if allowed_groups.is_empty() {
        return false;
    }
    !claims.get(groups_claim).is_some_and(|groups| {
        groups
            .split(',')
            .any(|g| allowed_groups.contains(&g.trim()))
    })
}

/// Claims become variables named after the claim, so a claim can neither
/// shadow a decision variable nor carry a name `HAProxy` would reject.
fn push_claims(vars: &mut Vec<TxnVariable>, claims: &HashMap<String, String>) {
    for (name, value) in claims {
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
        if !valid || RESERVED_VARS.contains(&name.as_str()) || name.starts_with("set_cookie_header")
        {
            log::warn!("sso_auth: claim '{name}' not exported: reserved or invalid variable name");
            continue;
        }
        push_str(vars, name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_config;

    fn var_names(vars: &[TxnVariable]) -> Vec<String> {
        vars.iter().map(|v| v.name.to_string()).collect()
    }

    fn string_var(vars: &[TxnVariable], name: &str) -> Option<String> {
        vars.iter()
            .find(|v| v.name.as_str() == name)
            .and_then(|v| match &v.value {
                SpoeValue::String(s) => Some(s.to_string()),
                _ => None,
            })
    }

    #[test]
    fn allow_emits_token_and_filters_claims() {
        let claims = HashMap::from([
            ("email".to_owned(), "a@b".to_owned()),
            ("allowed".to_owned(), "true".to_owned()),
            ("https://x/roles".to_owned(), "admin".to_owned()),
        ]);
        let vars = AuthAction::Allow {
            claims,
            set_cookie: None,
            token: Some("jwt".into()),
        }
        .into_variables(&test_config(), 0);
        assert_eq!(string_var(&vars, "token").as_deref(), Some("jwt"));
        assert_eq!(string_var(&vars, "email").as_deref(), Some("a@b"));
        let names = var_names(&vars);
        assert_eq!(names.iter().filter(|n| *n == "allowed").count(), 1);
        assert!(!names.iter().any(|n| n.contains("roles")));
    }

    #[test]
    fn callback_redirects_and_clears_stale_chunks() {
        let vars = AuthAction::Callback {
            set_cookie: "abc".into(),
            claims: HashMap::new(),
            redirect_url: Some("/app?x=1".into()),
        }
        .into_variables(&test_config(), 3);
        assert_eq!(string_var(&vars, "action").as_deref(), Some("redirect"));
        assert_eq!(
            string_var(&vars, "redirect_url").as_deref(),
            Some("/app?x=1")
        );
        assert!(
            string_var(&vars, "set_cookie_header")
                .unwrap()
                .starts_with("sso_session=abc;")
        );
        assert!(
            string_var(&vars, "set_cookie_header_1")
                .unwrap()
                .starts_with("sso_session_1=;")
        );
        assert!(
            string_var(&vars, "set_cookie_header_2")
                .unwrap()
                .ends_with("Max-Age=0")
        );
    }

    #[test]
    fn large_session_spans_chunks() {
        let session = "x".repeat(crate::session::COOKIE_CHUNK_LEN + 10);
        let vars = AuthAction::Allow {
            claims: HashMap::new(),
            set_cookie: Some(session),
            token: None,
        }
        .into_variables(&test_config(), 0);
        assert!(
            string_var(&vars, "set_cookie_header_1")
                .unwrap()
                .starts_with("sso_session_1=xxxxxxxxxx;")
        );
        assert!(string_var(&vars, "set_cookie_header_2").is_none());
    }

    #[test]
    fn forbidden_is_403() {
        let vars = AuthAction::Forbidden { error: "no".into() }.into_variables(&test_config(), 0);
        assert_eq!(string_var(&vars, "action").as_deref(), Some("forbidden"));
        assert!(
            vars.iter()
                .any(|v| v.name.as_str() == "status_code"
                    && matches!(v.value, SpoeValue::Uint32(403)))
        );
    }
}
