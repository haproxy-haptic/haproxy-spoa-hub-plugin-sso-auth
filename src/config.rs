use haproxy_spoa_hub_plugin_api::PluginContext;

/// Global plugin configuration from `[plugins.params]`.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub cookie_secret_1: Vec<u8>,
    pub cookie_secret_2: Option<Vec<u8>>,
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
}

impl PluginConfig {
    pub fn from_context(context: &PluginContext) -> Result<Self, String> {
        let cookie_secret_1 = get_required_str(context, "cookie_secret_1")?;
        if cookie_secret_1.len() < 16 {
            return Err("cookie_secret_1 must be at least 16 characters".into());
        }

        let cookie_secret_2 = get_optional_str(context, "cookie_secret_2");
        if let Some(ref s) = cookie_secret_2 {
            if s.len() < 16 {
                return Err("cookie_secret_2 must be at least 16 characters".into());
            }
        }

        let current_cookie_secret = get_optional_int(context, "current_cookie_secret").unwrap_or(1);
        if current_cookie_secret != 1 && current_cookie_secret != 2 {
            return Err("current_cookie_secret must be 1 or 2".into());
        }
        if current_cookie_secret == 2 && cookie_secret_2.is_none() {
            return Err("current_cookie_secret is 2 but cookie_secret_2 is not set".into());
        }

        let cookie_domain = get_required_str(context, "cookie_domain")?;

        let default_timeout_ms = get_optional_int(context, "default_timeout_ms").unwrap_or(5000);
        if default_timeout_ms == 0 {
            return Err("default_timeout_ms must be positive".into());
        }

        let max_providers = get_optional_int(context, "max_providers").unwrap_or(256);
        if max_providers == 0 {
            return Err("max_providers must be positive".into());
        }

        let config = Self {
            cookie_secret_1: cookie_secret_1.into_bytes(),
            cookie_secret_2: cookie_secret_2.map(String::into_bytes),
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
            max_providers: max_providers
                .try_into()
                .map_err(|e| format!("max_providers: {e}"))?,
            clock_skew_secs: get_optional_int(context, "clock_skew_secs")
                .unwrap_or(60)
                .try_into()
                .map_err(|e| format!("clock_skew_secs: {e}"))?,
            discovery_ttl_secs: get_optional_int(context, "discovery_ttl_secs")
                .unwrap_or(3600)
                .try_into()
                .map_err(|e| format!("discovery_ttl_secs: {e}"))?,
        };

        Ok(config)
    }

    /// Returns the currently active encryption secret.
    pub fn active_secret(&self) -> &[u8] {
        if self.current_cookie_secret == 2 {
            self.cookie_secret_2
                .as_deref()
                .expect("validated in from_context")
        } else {
            &self.cookie_secret_1
        }
    }

    /// Returns the fallback decryption secret, if configured.
    pub fn fallback_secret(&self) -> Option<&[u8]> {
        if self.current_cookie_secret == 2 {
            Some(&self.cookie_secret_1)
        } else {
            self.cookie_secret_2.as_deref()
        }
    }

    pub fn config_schema() -> &'static str {
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json")
    }
}

fn get_required_str(context: &PluginContext, key: &str) -> Result<String, String> {
    context
        .get_config(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| format!("missing required config: {key}"))
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
