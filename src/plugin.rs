#[allow(unused_imports)] // Used by define_plugin! macro expansion.
use haproxy_spoa_hub_plugin_api::{PluginContext, ProcessingResult, SpoeMessage, define_plugin};
use std::sync::OnceLock;

use crate::action::AuthAction;
use crate::cache::ProviderCache;
use crate::config::PluginConfig;
use crate::metrics::AuthMetrics;
use crate::oidc;
use crate::provider::{Protocol, ProviderConfig};
use crate::saml;
use crate::util::get_nonempty_string;

static CONFIG: OnceLock<PluginConfig> = OnceLock::new();
static CACHE: OnceLock<ProviderCache> = OnceLock::new();
static METRICS: OnceLock<AuthMetrics> = OnceLock::new();

#[derive(Debug)]
struct SsoAuthPlugin;

define_plugin!(SsoAuthPlugin, {
    fn new() -> Self {
        SsoAuthPlugin
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context)?;
        let max_providers = config.max_providers;
        let _ = CONFIG.set(config);
        let _ = CACHE.set(ProviderCache::new(max_providers));
        let _ = METRICS.set(AuthMetrics::new());
        log::info!("sso_auth plugin initialized (max_providers={max_providers})");
        Ok(())
    }

    fn name(&self) -> &str {
        "sso_auth"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn process(
        &self,
        message: &SpoeMessage,
    ) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
        let config = CONFIG.get().ok_or("sso_auth: plugin not initialized")?;
        let cache = CACHE
            .get()
            .ok_or("sso_auth: provider cache not initialized")?;
        let metrics = METRICS.get().ok_or("sso_auth: metrics not initialized")?;

        let action = match process_message(message, config, cache, metrics) {
            Ok(action) => action,
            Err(e) => {
                log::error!("sso_auth: message processing error: {e}");
                oidc::apply_failure_policy(config, "unknown", &e)
            }
        };

        Ok(action.into_variables(config))
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }
});

fn process_message(
    message: &SpoeMessage,
    config: &PluginConfig,
    cache: &ProviderCache,
    metrics: &AuthMetrics,
) -> Result<AuthAction, String> {
    let provider_config = ProviderConfig::parse_from_args(message)?;
    let provider_name = provider_config.name.clone();

    cache.upsert(provider_name.clone(), provider_config, metrics);

    let cached = cache
        .get(&provider_name)
        .ok_or_else(|| format!("sso_auth: failed to cache provider: {provider_name}"))?;
    let provider = &cached.config;

    let cookie = get_nonempty_string(message, "cookie");
    let auth_state_cookie = get_nonempty_string(message, "auth_state_cookie");
    let is_logout = get_nonempty_string(message, "is_logout").is_some_and(|s| s == "true");
    let request_path = get_nonempty_string(message, "request_path");

    let action = match provider.protocol {
        Protocol::Oidc => {
            let callback_code = get_nonempty_string(message, "callback_code");
            let callback_state = get_nonempty_string(message, "callback_state");
            oidc::handle_oidc_request(
                provider,
                cache,
                config,
                metrics,
                cookie,
                auth_state_cookie,
                callback_code,
                callback_state,
                is_logout,
                request_path,
            )
        }
        Protocol::Saml => {
            let callback_saml_response = get_nonempty_string(message, "callback_saml_response");
            saml::handle_saml_request(
                provider,
                config,
                metrics,
                cookie,
                auth_state_cookie,
                callback_saml_response,
                is_logout,
            )
        }
    };

    Ok(action)
}
