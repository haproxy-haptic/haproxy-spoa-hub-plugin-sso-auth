use crate::action::AuthAction;
use crate::cache::ProviderCache;
use crate::config::PluginConfig;
use crate::metrics::AuthMetrics;
use crate::oidc;
use crate::provider::{Protocol, ProviderConfig};
use crate::saml;
use crate::session::MAX_COOKIE_CHUNKS;
use crate::util::get_nonempty_string;
#[allow(unused_imports)] // Used by define_plugin! macro expansion.
use haproxy_spoa_hub_plugin_api::{
    Diagnostic, MetricRecorder, PluginContext, ProcessingResult, SpoeMessage, SpoeValue,
    TxnVariable, define_plugin,
};

/// Plugin-scoped Prometheus metric recorder, surfaced through the hub's
/// `/metrics` endpoint. `AuthMetrics` is separate internal accounting.
static PROM_METRICS: MetricRecorder = MetricRecorder::new();

/// State lives in the instance, not in statics: a hub reload initialises a
/// new instance in the same process, and a `OnceLock` would keep the first
/// configuration forever.
#[derive(Debug, Default)]
struct SsoAuthPlugin {
    state: Option<PluginState>,
}

#[derive(Debug)]
struct PluginState {
    config: PluginConfig,
    cache: ProviderCache,
    metrics: AuthMetrics,
}

define_plugin!(SsoAuthPlugin, {
    fn new() -> Self {
        SsoAuthPlugin::default()
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context)?;
        let max_providers = config.max_providers;
        self.state = Some(PluginState {
            config,
            cache: ProviderCache::new(max_providers),
            metrics: AuthMetrics::new(),
        });
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
        let PluginState {
            config,
            cache,
            metrics,
        } = self
            .state
            .as_ref()
            .ok_or("sso_auth: plugin not initialized")?;

        let started = std::time::Instant::now();
        let present_chunks = session_chunks(message).len();
        let (action, pass_token) = match process_message(message, config, cache, metrics) {
            Ok(result) => result,
            // A provider that can't be resolved is a configuration error, not
            // an IdP outage, so fail_open doesn't apply.
            Err(e) => {
                log::error!("sso_auth: message processing error: {e}");
                (
                    AuthAction::Error {
                        error: e,
                        allow: false,
                    },
                    false,
                )
            }
        };

        // Hub adds `plugin_sso_auth_` prefix. `outcome` is the action
        // kind so operators can see at a glance whether SSO is moving
        // traffic through or stuck in a redirect loop. The histogram
        // is unlabelled for bounded cardinality; per-provider tails
        // matter less than the global p50/p99 for SSO sizing.
        let outcome = match &action {
            AuthAction::Redirect { .. } => "redirect",
            AuthAction::Callback { .. } => "callback",
            AuthAction::Allow { .. } => "allow",
            AuthAction::Forbidden { .. } => "forbidden",
            AuthAction::Deny { .. } => "deny",
            AuthAction::Logout { .. } => "logout",
            AuthAction::Error { .. } => "error",
        };
        PROM_METRICS.counter("auth_decisions_total", &[("outcome", outcome)], 1);
        PROM_METRICS.histogram(
            "auth_decision_duration_seconds",
            &[],
            started.elapsed().as_secs_f64(),
        );

        let mut vars = action.into_variables(config, present_chunks);
        if pass_token {
            // Tells HAProxy to drop the client's Authorization header even
            // when no token comes back, so it can't be forged.
            vars.push(TxnVariable::transaction(
                "pass_token",
                SpoeValue::Bool(true),
            ));
        }
        Ok(ProcessingResult::from_vars(vars))
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }

    fn validate(&self, context: &PluginContext) -> Vec<Diagnostic> {
        match PluginConfig::validate(context) {
            Ok(()) => Vec::new(),
            Err(e) => vec![Diagnostic::error(0, 0, e)],
        }
    }

    metrics_static = PROM_METRICS;
});

fn process_message(
    message: &SpoeMessage,
    config: &PluginConfig,
    cache: &ProviderCache,
    metrics: &AuthMetrics,
) -> Result<(AuthAction, bool), String> {
    let mut provider_config = match get_nonempty_string(message, "provider")
        .and_then(|name| config.providers.get(name))
    {
        Some(p) => p.clone(),
        None => ProviderConfig::parse_from_args(message)?,
    };
    // ponytail: re-reads the files on every request until a reload loads
    // them; only reached while a provider's secret files are missing.
    if !provider_config.secrets_loaded() {
        provider_config.load_secret_files()?;
    }
    config.check_keys(&provider_config)?;
    let provider_name = provider_config.name.clone();

    cache.upsert(provider_name.clone(), provider_config, metrics);

    let cached = cache
        .get(&provider_name)
        .ok_or_else(|| format!("sso_auth: failed to cache provider: {provider_name}"))?;
    let provider = &cached.config;

    let chunks = session_chunks(message);
    let cookie = (!chunks.is_empty()).then(|| chunks.concat());
    let cookie = cookie.as_deref();
    let auth_state_cookie = get_nonempty_string(message, "auth_state_cookie");
    let is_logout = get_nonempty_string(message, "is_logout").is_some_and(|s| s == "true");
    let request_path = get_nonempty_string(message, "request_path");
    let allowed_groups: Vec<&str> = get_nonempty_string(message, "allowed_groups")
        .map(|g| {
            g.split(',')
                .map(str::trim)
                .filter(|g| !g.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let action = match provider.protocol {
        Protocol::Oidc => oidc::handle_oidc_request(
            provider,
            cache,
            config,
            metrics,
            &oidc::OidcRequest {
                cookie,
                auth_state_cookie,
                callback_code: get_nonempty_string(message, "callback_code"),
                callback_state: get_nonempty_string(message, "callback_state"),
                is_logout,
                request_path,
                allowed_groups: &allowed_groups,
                host: get_nonempty_string(message, "request_host"),
            },
        ),
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
                &allowed_groups,
            )
        }
    };

    Ok((action, provider.pass_token.is_some()))
}

/// The session cookie chunks the request carried (`cookie`, `cookie_1`, …),
/// up to the first missing one.
fn session_chunks(message: &SpoeMessage) -> Vec<&str> {
    let mut chunks = Vec::new();
    for index in 0..MAX_COOKIE_CHUNKS {
        let arg = if index == 0 {
            "cookie".to_owned()
        } else {
            format!("cookie_{index}")
        };
        match get_nonempty_string(message, &arg) {
            Some(chunk) => chunks.push(chunk),
            None => break,
        }
    }
    chunks
}
