# Data Model: SSO Auth Plugin

## Entities

### PluginConfig

Global settings from `[plugins.params]`. Loaded once at `init()`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| cookie_secret_1 | String | (required) | Primary cookie encryption secret |
| cookie_secret_2 | String | (optional) | Secondary secret for rotation |
| current_cookie_secret | u8 | 1 | Which secret is active (1 or 2) |
| cookie_domain | String | (required) | Cookie `Domain` attribute |
| cookie_secure | bool | true | Cookie `Secure` flag |
| cookie_httponly | bool | true | Cookie `HttpOnly` flag |
| cookie_samesite | String | "Lax" | Cookie `SameSite` attribute |
| cookie_lifetime_secs | u64 | 36000 | Session cookie lifetime (10h) |
| default_timeout_ms | u64 | 5000 | Default IdP request timeout |
| fail_open | bool | false | Allow on IdP error if true |
| max_providers | usize | 256 | Max cached provider configs |
| clock_skew_secs | u64 | 60 | Token/assertion time tolerance |
| discovery_ttl_secs | u64 | 3600 | OIDC discovery + JWKS cache TTL |

### ProviderConfig

Parsed from SPOE message args. Cached in LRU by provider name.

| Field | Type | Source (SPOE arg) | Description |
|-------|------|-------------------|-------------|
| name | String | `provider` | Unique provider identifier |
| protocol | Enum | `protocol` | "oidc" or "saml" |
| client_id | String | `client_id` | OIDC client ID / SAML entity ID |
| client_secret | String | `client_secret` | OIDC client secret (optional for PKCE-only) |
| discovery_url | String | `discovery_url` | OIDC discovery endpoint |
| auth_url | String | `auth_url` | Authorization / SSO endpoint (manual override) |
| token_url | String | `token_url` | Token endpoint (manual override) |
| jwks_url | String | `jwks_url` | JWKS endpoint (manual override) |
| logout_url | String | `logout_url` | End session / SLO endpoint |
| redirect_uri | String | `redirect_uri` | Callback URI registered with IdP |
| post_logout_redirect_uri | String | `post_logout_redirect_uri` | Post-logout redirect |
| scopes | String | `scopes` | Comma-separated OIDC scopes |
| extract_claims | String | `extract_claims` | Comma-separated claim names to extract |
| idp_cert | String | `idp_cert` | SAML IdP X.509 certificate (PEM) |
| signing_key | String | `signing_key` | SAML SP signing key (PEM) |
| signing_algo | String | `signing_algo` | SAML signing algorithm |
| sign_authn_requests | bool | `sign_authn_requests` | Sign AuthnRequests |
| timeout_ms | u64 | `timeout_ms` | Per-provider timeout override |

### SsoSession

Serialized into the encrypted session cookie.

| Field | Type | Description |
|-------|------|-------------|
| version | u8 | Session format version (for migration) |
| provider_name | String | Provider that authenticated this session |
| protocol | Enum | oidc or saml |
| claims | HashMap<String, String> | Extracted identity claims |
| expires_at | u64 | Unix timestamp of session expiry |
| refresh_token | Option<String> | OIDC refresh token (if available) |
| session_index | Option<String> | SAML SessionIndex (for SLO) |
| name_id | Option<String> | SAML NameID (for SLO) |

### AuthAction

The plugin's decision returned as SPOE variables.

| Variant | Description | Output Variables |
|---------|-------------|------------------|
| Redirect | Redirect to IdP for auth | `action`="redirect", `redirect_url`, `allowed`=false |
| Callback | Process IdP callback | `action`="allow", `allowed`=true, `set_cookie`, claims... |
| Allow | Valid session, pass through | `action`="allow", `allowed`=true, claims... |
| Deny | Auth failed or invalid | `action`="deny", `allowed`=false, `error` |
| Logout | Redirect to IdP logout | `action`="redirect", `redirect_url`, `clear_cookie`=true |
| Error | IdP unreachable / malformed | `action`=per fail_open policy, `error` |

### CachedProvider

In-memory cache entry wrapping ProviderConfig + resolved metadata
and circuit breaker state. LRU tracking is delegated to the `lru`
crate rather than a manual timestamp.

| Field | Type | Description |
|-------|------|-------------|
| config | ProviderConfig | Parsed provider config from SPOE args |
| oidc_discovery_json | Option<String> | Cached OIDC discovery JSON (includes JWKS URI) |
| oidc_discovery_fetched_at | Option<u64> | Timestamp of last discovery fetch |
| consecutive_failures | u32 | Circuit breaker: consecutive IdP failure count |
| last_failure_at | Option<u64> | Circuit breaker: timestamp of last failure |

## State Transitions

### Request Processing Flow

```text
SPOE Message Received
        │
        ▼
  Parse provider name + config args
        │
        ▼
  ┌─ Provider cached? ──┐
  │ yes                  │ no
  ▼                      ▼
  Use cached         Parse config from args
  provider           Cache in LRU (evict if full)
        │                │
        └──────┬─────────┘
               ▼
  ┌─ Has session cookie? ──┐
  │ yes                     │ no
  ▼                         ▼
  Decrypt cookie         ┌─ Is callback? ──┐
  │                      │ yes             │ no
  ├─ Valid + fresh?      ▼                 ▼
  │  → Allow + claims    Process callback  Redirect to IdP
  │                      Validate token
  ├─ Expired + has       Set cookie
  │  refresh token?      → Allow + claims
  │  → Refresh tokens
  │  → Allow + claims
  │  + updated cookie
  │
  ├─ Expired, no
  │  refresh?
  │  → Redirect to IdP
  │
  └─ Decryption failed?
     → Redirect to IdP
```

### Session Cookie Lifecycle

```text
Created ──→ Valid ──→ Expired
               │          │
               │     (has refresh token?)
               │     yes: Refresh → Valid (new cookie)
               │     no:  → Redirect to IdP
               │
          (logout request)
               │
               ▼
           Cleared (clear_cookie=true)
```
