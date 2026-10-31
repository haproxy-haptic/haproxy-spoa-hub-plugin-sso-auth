use haproxy_spoa_hub_plugin_api::{ConfigValue, PluginContext};
use std::collections::HashMap;

use crate::provider::ProviderConfig;
use crate::util::Redacted;

/// Global plugin configuration from `[plugins.params]`.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Optional when every provider has its own `cookie_secret`.
    pub cookie_secret_1: Option<Redacted<Vec<u8>>>,
    pub cookie_secret_2: Option<Redacted<Vec<u8>>>,
    pub current_cookie_secret: u8,
    pub cookie_domain: String,
    pub cookie_secure: bool,
    pub cookie_httponly: bool,
    pub cookie_samesite: String,
    pub cookie_lifetime_secs: u64,
    pub default_timeout_ms: u64,
    pub fail_open: bool,
    pub max_providers: usize,
    pub clock_skew_secs: u64,
    pub discovery_ttl_secs: u64,
    /// Providers from `[providers.<name>]`; a request naming one needs no
    /// `provider_config` arg.
    pub providers: HashMap<String, ProviderConfig>,
}

impl PluginConfig {
    /// Load the config, reading every `*_file` secret.
    pub fn from_context(context: &PluginContext) -> Result<Self, String> {
        Self::parse(context, true)
    }

    /// Check the config without reading `*_file` secrets: `--validate-socket`
    /// mode runs where the secret files aren't mounted.
    pub fn validate(context: &PluginContext) -> Result<(), String> {
        Self::parse(context, false).map(|_| ())
    }

    fn parse(context: &PluginContext, read_files: bool) -> Result<Self, String> {
        let cookie_secret_1 = get_secret(context, "cookie_secret_1", read_files)?;
        let cookie_secret_2 = get_secret(context, "cookie_secret_2", read_files)?;
        for (key, secret) in [
            ("cookie_secret_1", &cookie_secret_1),
            ("cookie_secret_2", &cookie_secret_2),
        ] {
            if secret.as_ref().is_some_and(|s| s.len() < 16) {
                return Err(format!("{key} must be at least 16 characters"));
            }
        }
        if cookie_secret_2.is_some() && cookie_secret_1.is_none() {
            return Err("cookie_secret_2 is set but cookie_secret_1 is not".into());
        }

        let current_cookie_secret = get_optional_int(context, "current_cookie_secret").unwrap_or(1);
        if current_cookie_secret != 1 && current_cookie_secret != 2 {
            return Err("current_cookie_secret must be 1 or 2".into());
        }
        if current_cookie_secret == 2 && cookie_secret_2.is_none() {
            return Err("current_cookie_secret is 2 but cookie_secret_2 is not set".into());
        }

        // Empty: host-only cookies, never sent to sibling hosts.
        let cookie_domain = get_optional_str(context, "cookie_domain").unwrap_or_default();

        let default_timeout_ms = get_optional_int(context, "default_timeout_ms").unwrap_or(5000);
        if default_timeout_ms == 0 {
            return Err("default_timeout_ms must be positive".into());
        }

        let max_providers = get_optional_int(context, "max_providers").unwrap_or(256);
        if max_providers == 0 {
            return Err("max_providers must be positive".into());
        }
        let max_providers: usize = max_providers
            .try_into()
            .map_err(|e| format!("max_providers: {e}"))?;

        let providers = parse_providers(context, read_files)?;
        if providers.len() > max_providers {
            return Err(format!(
                "{} providers configured but max_providers is {max_providers}",
                providers.len()
            ));
        }

        let config = Self {
            cookie_secret_1: cookie_secret_1.map(|s| Redacted(s.into_bytes())),
            cookie_secret_2: cookie_secret_2.map(|s| Redacted(s.into_bytes())),
            current_cookie_secret: u8::try_from(current_cookie_secret)
                .map_err(|e| format!("current_cookie_secret: {e}"))?,
            cookie_domain,
            cookie_secure: get_optional_bool(context, "cookie_secure").unwrap_or(true),
            cookie_httponly: get_optional_bool(context, "cookie_httponly").unwrap_or(true),
            cookie_samesite: get_optional_str(context, "cookie_samesite")
                .unwrap_or_else(|| "Lax".into()),
            cookie_lifetime_secs: get_optional_int(context, "cookie_lifetime_secs")
                .unwrap_or(36000)
                .try_into()
                .map_err(|e| format!("cookie_lifetime_secs: {e}"))?,
            default_timeout_ms: default_timeout_ms
                .try_into()
                .map_err(|e| format!("default_timeout_ms: {e}"))?,
            fail_open: get_optional_bool(context, "fail_open").unwrap_or(false),
            max_providers,
            clock_skew_secs: get_optional_int(context, "clock_skew_secs")
                .unwrap_or(60)
                .try_into()
                .map_err(|e| format!("clock_skew_secs: {e}"))?,
            discovery_ttl_secs: get_optional_int(context, "discovery_ttl_secs")
                .unwrap_or(3600)
                .try_into()
                .map_err(|e| format!("discovery_ttl_secs: {e}"))?,
            providers,
        };
        for provider in config.providers.values() {
            config.check_keys(provider)?;
        }

        Ok(config)
    }

    /// Fails when `provider` has no cookie secret of its own and there is no
    /// global one. The secret accessors below rely on this having passed.
    pub fn check_keys(&self, provider: &ProviderConfig) -> Result<(), String> {
        if provider.cookie_secret.is_none()
            && provider.cookie_secret_file.is_none()
            && self.cookie_secret_1.is_none()
        {
            return Err(format!(
                "provider '{}' has no cookie_secret and cookie_secret_1 is not set",
                provider.name
            ));
        }
        Ok(())
    }

    /// The secret that encrypts new cookies for `provider`.
    pub fn active_secret<'a>(&'a self, provider: &'a ProviderConfig) -> &'a [u8] {
        if let Some(ref own) = provider.cookie_secret {
            return own.0.as_bytes();
        }
        let global = if self.current_cookie_secret == 2 {
            self.cookie_secret_2.as_ref().map(|s| s.0.as_slice())
        } else {
            self.cookie_secret_1.as_ref().map(|s| s.0.as_slice())
        };
        global.expect("check_keys passed for this provider")
    }

    /// The previous global secret, still accepted for decryption during a
    /// rotation. Providers with their own secret have none.
    pub fn fallback_secret(&self, provider: &ProviderConfig) -> Option<&[u8]> {
        if provider.cookie_secret.is_some() {
            return None;
        }
        if self.current_cookie_secret == 2 {
            self.cookie_secret_1.as_ref().map(|s| s.0.as_slice())
        } else {
            self.cookie_secret_2.as_ref().map(|s| s.0.as_slice())
        }
    }

    pub fn config_schema() -> &'static str {
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json")
    }
}

/// `<key>` inline, or `<key>_file` naming a file whose content (trailing
/// newline trimmed) is the secret. Without `read_files`, a file reference
/// yields a placeholder that passes the length check.
fn get_secret(
    context: &PluginContext,
    key: &str,
    read_files: bool,
) -> Result<Option<String>, String> {
    let file_key = format!("{key}_file");
    match (
        get_optional_str(context, key),
        get_optional_str(context, &file_key),
    ) {
        (Some(_), Some(_)) => Err(format!("set {key} or {file_key}, not both")),
        (Some(v), None) => Ok(Some(v)),
        (None, Some(path)) if read_files => read_secret_file(&path).map(Some),
        (None, Some(_)) => Ok(Some("x".repeat(16))),
        (None, None) => Ok(None),
    }
}

pub fn read_secret_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|e| format!("read secret file {path}: {e}"))
}

fn parse_providers(
    context: &PluginContext,
    read_files: bool,
) -> Result<HashMap<String, ProviderConfig>, String> {
    let Some(value) = context.get_config("providers") else {
        return Ok(HashMap::new());
    };
    let table = value.as_table().ok_or("providers must be a table")?;
    let mut providers = HashMap::new();
    for entry in table {
        let name = entry.0.as_str();
        let mut provider = ProviderConfig::from_value(name, &to_json(entry.1))?;
        // One provider's missing file must not stop the plugin for every
        // other provider; its requests retry the read and fail closed.
        if read_files {
            if let Err(e) = provider.load_secret_files() {
                log::error!("sso_auth: {e}");
            }
        }
        providers.insert(name.to_owned(), provider);
    }
    Ok(providers)
}

fn to_json(value: &ConfigValue) -> serde_json::Value {
    match value {
        ConfigValue::String(s) => serde_json::Value::String(s.to_string()),
        ConfigValue::Integer(i) => serde_json::Value::from(*i),
        ConfigValue::Float(f) => serde_json::Value::from(*f),
        ConfigValue::Bool(b) => serde_json::Value::Bool(*b),
        ConfigValue::Array(a) => a.iter().map(to_json).collect(),
        ConfigValue::Table(t) => t
            .iter()
            .map(|e| (e.0.to_string(), to_json(e.1)))
            .collect::<serde_json::Map<_, _>>()
            .into(),
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
pub fn test_config() -> PluginConfig {
    PluginConfig {
        cookie_secret_1: Some(Redacted(b"test-secret-one-at-least-16-chars".to_vec())),
        cookie_secret_2: Some(Redacted(b"test-secret-two-at-least-16-chars".to_vec())),
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
        providers: HashMap::new(),
    }
}

fn get_optional_str(context: &PluginContext, key: &str) -> Option<String> {
    context
        .get_config(key)
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn get_optional_int(context: &PluginContext, key: &str) -> Option<i64> {
    context
        .get_config(key)
        .and_then(haproxy_spoa_hub_plugin_api::ConfigValue::as_integer)
}

fn get_optional_bool(context: &PluginContext, key: &str) -> Option<bool> {
    context
        .get_config(key)
        .and_then(haproxy_spoa_hub_plugin_api::ConfigValue::as_bool)
}
