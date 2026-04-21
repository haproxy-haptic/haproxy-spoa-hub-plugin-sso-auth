# Quickstart: SSO Auth Plugin

## Build

```bash
cargo build --release
```

Produces `target/release/libsso_auth_plugin.so`.

### Build Dependencies (SAML support)

The SAML module requires C libraries for XML signature verification:

```bash
# Debian/Ubuntu
apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl \
    pkg-config libclang-dev

# Fedora/RHEL
dnf install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel \
    pkg-config clang-devel
```

## Hub Configuration

```toml
# hub.toml
plugin_dir = "/opt/spoa-plugins"
default_timeout_ms = 100
log_level = "info"

[[listeners]]
type = "unix"
address = "/var/run/haproxy-spoa-hub.sock"

[[plugins]]
name = "sso_auth"
library = "libsso_auth_plugin.so"
messages = ["check-sso-auth"]
timeout_ms = 10000

[plugins.params]
cookie_secret_1 = "your-secret-at-least-16-chars"
cookie_domain = "example.com"
# cookie_secret_2 = "rotation-secret"
# current_cookie_secret = 1
# cookie_lifetime_secs = 36000
# default_timeout_ms = 5000
# fail_open = false
# max_providers = 256
```

## HAProxy Configuration

### SPOE Engine

```haproxy
# /etc/haproxy/spoe-sso-auth.conf
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

### Frontend (OIDC Example)

```haproxy
frontend https
    bind *:443 ssl crt /etc/ssl/certs/
    filter spoe engine sso-auth config /etc/haproxy/spoe-sso-auth.conf

    # Map files populated by HAPTIC from K8s secrets
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

    http-request set-var(txn.is_logout) str(true) \
        if { path_end /logout }

    http-request send-spoe-group sso-auth check-sso-auth-group \
        if { var(txn.sso_provider) -m found }

    # Auth decision handling
    http-request redirect location \
        %[var(txn.spoe.sso_auth.redirect_url)] \
        if { var(txn.spoe.sso_auth.action) -m str redirect }
    http-request deny deny_status 401 \
        if { var(txn.spoe.sso_auth.action) -m str deny }

    # Set/clear session cookie
    http-response set-header Set-Cookie \
        "sso_session=%[var(txn.spoe.sso_auth.set_cookie)]; \
         Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax" \
        if { var(txn.spoe.sso_auth.set_cookie) -m found }
    http-response set-header Set-Cookie \
        "sso_session=; Domain=example.com; Path=/; Max-Age=0; \
         Secure; HttpOnly" \
        if { var(txn.spoe.sso_auth.clear_cookie) -m bool }

    # Forward claims to backend
    http-request set-header X-Auth-Email \
        %[var(txn.spoe.sso_auth.email)] \
        if { var(txn.spoe.sso_auth.email) -m found }

    default_backend app

backend spoa-hub-backend
    server hub unix@/var/run/haproxy-spoa-hub.sock
```

## Verify

```bash
# Unauthenticated request → redirect
curl -v https://example.com/app/
# Expected: 302 redirect to IdP

# After IdP login → callback sets cookie
# Expected: 302 to original URL + Set-Cookie header

# Authenticated request → pass through
curl -v -H "Cookie: sso_session=<value>" https://example.com/app/
# Expected: 200 + X-Auth-Email header
```
