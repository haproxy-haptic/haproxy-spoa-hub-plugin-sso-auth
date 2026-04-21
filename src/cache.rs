use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::RwLock;

use crate::metrics::AuthMetrics;
use crate::provider::ProviderConfig;
use crate::util::now_secs;

/// Cached provider entry with resolved OIDC metadata and circuit breaker state.
#[derive(Debug, Clone)]
pub struct CachedProvider {
    pub config: ProviderConfig,
    pub oidc_discovery_json: Option<String>,
    pub oidc_discovery_fetched_at: Option<u64>,
    pub consecutive_failures: u32,
    pub last_failure_at: Option<u64>,
}

impl CachedProvider {
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            oidc_discovery_json: None,
            oidc_discovery_fetched_at: None,
            consecutive_failures: 0,
            last_failure_at: None,
        }
    }

    pub fn is_discovery_stale(&self, ttl_secs: u64) -> bool {
        self.oidc_discovery_fetched_at
            .is_none_or(|t| now_secs().saturating_sub(t) >= ttl_secs)
    }

    /// Check if the circuit breaker is open (too many consecutive failures).
    pub fn is_circuit_open(&self, threshold: u32, reset_after_secs: u64) -> bool {
        if self.consecutive_failures < threshold {
            return false;
        }
        self.last_failure_at
            .is_some_and(|t| now_secs().saturating_sub(t) < reset_after_secs)
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_failure_at = None;
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure_at = Some(now_secs());
    }
}

/// Thread-safe LRU cache for provider configurations.
pub struct ProviderCache {
    inner: RwLock<LruCache<String, CachedProvider>>,
}

impl ProviderCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: RwLock::new(LruCache::new(cap)),
        }
    }

    pub fn get(&self, name: &str) -> Option<CachedProvider> {
        self.inner.write().ok()?.get(name).cloned()
    }

    /// Insert or update a provider. Preserves cached discovery and
    /// circuit-breaker state when the config changes.
    pub fn upsert(&self, name: String, new_config: ProviderConfig, metrics: &AuthMetrics) {
        if let Ok(mut cache) = self.inner.write() {
            if let Some(existing) = cache.get_mut(&name) {
                existing.config = new_config;
            } else {
                if cache.len() == cache.cap().get() {
                    log::info!(
                        "sso_auth: provider cache full ({}/{}), evicting LRU entry",
                        cache.len(),
                        cache.cap()
                    );
                    metrics.inc_cache_eviction();
                }
                cache.put(name, CachedProvider::new(new_config));
            }
        }
    }

    pub fn update<F>(&self, name: &str, f: F)
    where
        F: FnOnce(&mut CachedProvider),
    {
        if let Ok(mut cache) = self.inner.write() {
            if let Some(entry) = cache.get_mut(name) {
                f(entry);
            }
        }
    }
}

impl std::fmt::Debug for ProviderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.inner.read().map_or(0, |c| c.len());
        f.debug_struct("ProviderCache").field("len", &len).finish()
    }
}
