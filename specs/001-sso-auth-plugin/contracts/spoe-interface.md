# SPOE Interface Contract

## Plugin Identity

- **Name**: `sso_auth`
- **SPOE messages**: `check-sso-auth` (configurable in hub TOML)

## Input: SPOE Message Arguments

### Required Arguments

| Arg Name | Type | Description |
|----------|------|-------------|
| `provider` | String | Provider name (cache key, used for LRU caching and metrics) |
| `provider_config` | String | JSON string with all provider settings (from a single HAProxy map file) |

The `provider_config` JSON contains all provider-specific fields.
See "Provider Config JSON Fields" below for the full schema.

### Provider Config JSON Fields

**Common (required):**

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | String | `"oidc"` or `"saml"` |
| `client_id` | String | OIDC client ID or SAML SP entity ID |
| `redirect_uri` | String | Callback URI registered with the IdP |

**OIDC-specific:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `discovery_url` | String | Yes (or manual endpoints) | `.well-known/openid-configuration` URL |
| `client_secret` | String | No | Client secret (optional with PKCE) |
| `auth_url` | String | No | Manual authorization endpoint |
| `token_url` | String | No | Manual token endpoint |
| `jwks_url` | String | No | Manual JWKS endpoint |
| `logout_url` | String | No | End session endpoint |
| `post_logout_redirect_uri` | String | No | Post-logout redirect |
| `scopes` | String | No | Comma-separated (default: `"openid"`) |

**SAML-specific:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `auth_url` | String | Yes | IdP SSO endpoint |
| `idp_cert` | String | Yes | IdP X.509 certificate (PEM, base64) |
| `logout_url` | String | No | IdP SLO endpoint |
| `signing_key` | String | No | SP signing key (PEM, base64) |
| `signing_algo` | String | No | e.g., `"rsa-sha256"` |
| `sign_authn_requests` | String | No | `"true"` or `"false"` |

### Common Arguments

| Arg Name | Type | Required | Description |
|----------|------|----------|-------------|
| `extract_claims` | String | No | Comma-separated claim names |
| `timeout_ms` | String | No | Per-provider timeout override |
| `cookie` | String | No | Current session cookie value |
| `request_path` | String | No | Original request path |
| `request_method` | String | No | Original request method |
| `callback_code` | String | No | Authorization code (OIDC callback) |
| `callback_state` | String | No | State parameter (OIDC callback) |
| `callback_saml_response` | String | No | Base64 SAMLResponse (SAML callback) |
| `callback_relay_state` | String | No | RelayState (SAML callback) |
| `is_logout` | String | No | "true" if logout request |
| `auth_state_cookie` | String | No | Encrypted auth state cookie (carries PKCE verifier, CSRF token, nonce between OIDC redirect and callback; carries AuthnRequest ID for SAML InResponseTo validation) |

## Output: SPOE Transaction Variables

All variables are scoped to `Transaction` and prefixed by the hub
as `txn.spoe.sso_auth.*`.

### Always Set

| Variable | Type | Description |
|----------|------|-------------|
| `allowed` | Bool | Auth decision (true=allow, false=deny/redirect) |
| `action` | String | "allow", "redirect", or "deny" |

### Conditionally Set

| Variable | Type | Condition | Description |
|----------|------|-----------|-------------|
| `redirect_url` | String | action=redirect | Full redirect URL (to IdP or post-logout) |
| `set_cookie` | String | Successful auth/refresh | Encrypted session cookie value |
| `clear_cookie` | Bool | Logout | true to clear the session cookie |
| `error` | String | Error occurred | Human-readable error message |
| `status_code` | Uint32 | Error | Suggested HTTP status code |
| `set_auth_state_cookie` | String | action=redirect (OIDC/SAML) | Encrypted auth state cookie value (raw). Use with custom `Set-Cookie` header for full control. |
| `set_cookie_header` | String | Successful auth/refresh | Complete `Set-Cookie` header for session cookie (includes Domain, Path, Secure, HttpOnly, SameSite, Max-Age from plugin config). Use for simplified setup. |
| `set_auth_state_header` | String | action=redirect | Complete `Set-Cookie` header for auth state cookie (10 min TTL). Use for simplified setup. |
| `clear_cookie_header` | String | Logout | Complete `Set-Cookie` header that clears the session cookie (Max-Age=0). Use for simplified setup. |
| `<claim_name>` | String | Authenticated + claim exists | Extracted claim value |

## Example HAProxy Configuration

```haproxy
# SPOE config (spoe-sso-auth.conf)
[sso-auth]
spoe-agent sso-auth-agent
    groups check-sso-auth-group
    option var-prefix spoe
    option continue-on-error
    timeout hello      2s
    timeout idle       5m
    timeout processing 10s
    use-backend spoa-hub-backend

spoe-message check-sso-auth
    args provider=var(txn.sso_provider) \
         protocol=var(txn.sso_protocol) \
         client_id=var(txn.sso_client_id) \
         client_secret=var(txn.sso_client_secret) \
         discovery_url=var(txn.sso_discovery_url) \
         redirect_uri=var(txn.sso_redirect_uri) \
         extract_claims=var(txn.sso_extract_claims) \
         cookie=req.cook(sso_session) \
         request_path=path \
         request_method=method \
         callback_code=url_param(code) \
         callback_state=url_param(state) \
         is_logout=var(txn.is_logout)

spoe-group check-sso-auth-group
    messages check-sso-auth
```

```haproxy
# HAProxy frontend config
frontend https
    bind *:443 ssl crt /etc/ssl/certs/
    filter spoe engine sso-auth config /etc/haproxy/spoe-sso-auth.conf

    # Provider config from map files (populated by HAPTIC from K8s secrets)
    http-request set-var(txn.sso_provider) str(mykeycloak) \
        if { path_beg /app }
    http-request set-var(txn.sso_protocol) \
        var(txn.sso_provider),map_str(/etc/haproxy/maps/sso-protocol.map)
    http-request set-var(txn.sso_client_id) \
        var(txn.sso_provider),map_str(/etc/haproxy/maps/sso-client-id.map)
    http-request set-var(txn.sso_client_secret) \
        var(txn.sso_provider),map_str(/etc/haproxy/maps/sso-client-secret.map)
    http-request set-var(txn.sso_discovery_url) \
        var(txn.sso_provider),map_str(/etc/haproxy/maps/sso-discovery-url.map)
    http-request set-var(txn.sso_redirect_uri) \
        var(txn.sso_provider),map_str(/etc/haproxy/maps/sso-redirect-uri.map)
    http-request set-var(txn.sso_extract_claims) \
        var(txn.sso_provider),map_str(/etc/haproxy/maps/sso-extract-claims.map)

    # Detect logout requests
    http-request set-var(txn.is_logout) str(true) \
        if { path_end /logout }

    # Trigger SPOE
    http-request send-spoe-group sso-auth check-sso-auth-group \
        if { var(txn.sso_provider) -m found }

    # Handle auth decisions
    http-request redirect location %[var(txn.spoe.sso_auth.redirect_url)] \
        if { var(txn.spoe.sso_auth.action) -m str redirect }

    http-request deny deny_status 401 \
        if { var(txn.spoe.sso_auth.action) -m str deny }

    # Set cookie on successful auth
    http-response set-header Set-Cookie \
        "sso_session=%[var(txn.spoe.sso_auth.set_cookie)]; \
         Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax" \
        if { var(txn.spoe.sso_auth.set_cookie) -m found }

    # Clear cookie on logout
    http-response set-header Set-Cookie \
        "sso_session=; Domain=example.com; Path=/; Secure; HttpOnly; \
         Max-Age=0" \
        if { var(txn.spoe.sso_auth.clear_cookie) -m bool }

    # Forward claims to backend
    http-request set-header X-Auth-Email \
        %[var(txn.spoe.sso_auth.email)] \
        if { var(txn.spoe.sso_auth.email) -m found }

    default_backend app
```

## Map File Format

```text
# /etc/haproxy/maps/sso-protocol.map
mykeycloak oidc
corporate-adfs saml

# /etc/haproxy/maps/sso-client-id.map
mykeycloak haproxy-app-client
corporate-adfs urn:haproxy:sp

# /etc/haproxy/maps/sso-discovery-url.map
mykeycloak https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration
```
