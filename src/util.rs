use haproxy_spoa_hub_plugin_api::SpoeMessage;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extract a non-empty string argument from an SPOE message.
///
/// Wraps [`SpoeMessage::get_string`] but treats empty strings as absent,
/// matching `HAProxy`'s habit of sending empty values for unset fetch results.
pub fn get_nonempty_string<'a>(message: &'a SpoeMessage, key: &str) -> Option<&'a str> {
    message.get_string(key).filter(|s| !s.is_empty())
}

/// Cookie name constants.
pub const SESSION_COOKIE_NAME: &str = "sso_session";
pub const AUTH_STATE_COOKIE_NAME: &str = "sso_auth_state";
