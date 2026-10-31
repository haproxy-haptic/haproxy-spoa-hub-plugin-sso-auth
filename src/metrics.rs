use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-provider auth-domain counters.
#[derive(Debug, Default)]
pub struct ProviderCounters {
    pub auth_success: AtomicU64,
    pub auth_failure: AtomicU64,
    pub token_refresh: AtomicU64,
    pub token_refresh_failure: AtomicU64,
    pub idp_errors: AtomicU64,
    pub logouts: AtomicU64,
}

/// Auth-domain counters broken down by provider name (FR-021).
#[derive(Debug)]
pub struct AuthMetrics {
    providers: RwLock<HashMap<String, ProviderCounters>>,
    pub cache_evictions: AtomicU64,
}

impl Default for AuthMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthMetrics {
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            cache_evictions: AtomicU64::new(0),
        }
    }

    fn with_provider<F>(&self, provider: &str, f: F)
    where
        F: FnOnce(&ProviderCounters),
    {
        // Fast path: read lock.
        if let Ok(map) = self.providers.read() {
            if let Some(counters) = map.get(provider) {
                f(counters);
                return;
            }
        }
        // Slow path: write lock to insert.
        if let Ok(mut map) = self.providers.write() {
            let counters = map.entry(provider.to_owned()).or_default();
            f(counters);
        }
    }

    pub fn inc_auth_success(&self, provider: &str) {
        self.with_provider(provider, |c| {
            c.auth_success.fetch_add(1, Ordering::Relaxed);
        });
    }

    pub fn inc_auth_failure(&self, provider: &str) {
        self.with_provider(provider, |c| {
            c.auth_failure.fetch_add(1, Ordering::Relaxed);
        });
    }

    pub fn inc_token_refresh(&self, provider: &str) {
        self.with_provider(provider, |c| {
            c.token_refresh.fetch_add(1, Ordering::Relaxed);
        });
    }

    pub fn inc_token_refresh_failure(&self, provider: &str) {
        self.with_provider(provider, |c| {
            c.token_refresh_failure.fetch_add(1, Ordering::Relaxed);
        });
    }

    pub fn inc_idp_error(&self, provider: &str) {
        self.with_provider(provider, |c| {
            c.idp_errors.fetch_add(1, Ordering::Relaxed);
        });
    }

    pub fn inc_logout(&self, provider: &str) {
        self.with_provider(provider, |c| {
            c.logouts.fetch_add(1, Ordering::Relaxed);
        });
    }

    pub fn inc_cache_eviction(&self) {
        self.cache_evictions.fetch_add(1, Ordering::Relaxed);
    }
}
