# Implementation Plan: SSO Auth Plugin

**Branch**: `001-sso-auth-plugin` | **Date**: 2026-04-12 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-sso-auth-plugin/spec.md`

## Summary

Implement a haproxy-spoa-hub plugin providing OIDC and SAML 2.0
single sign-on authentication. The plugin receives all provider
configuration via SPOE message arguments (enabling dynamic provider
management from HAPTIC without hub restarts), delegates protocol
logic to `openidconnect` (OIDC) and `samael` (SAML), and maintains
sessions via AES-256-GCM encrypted cookies with dual-secret rotation.

## Technical Context

**Language/Version**: Rust 2024 edition, MSRV 1.86
**Primary Dependencies**:
- `haproxy-spoa-hub-plugin-api` 0.1 (plugin interface)
- `abi_stable` 0.11 (FFI safety)
- `openidconnect` 4.0 with `ureq` backend (OIDC)
- `samael` 0.0.20 with `xmlsec` feature (SAML)
- `ureq` 3 (HTTP client, matching external-auth)
- `aes-gcm` 0.10 + `hkdf` 0.12 (cookie encryption)
- `postcard` + `serde` (compact session serialization)
- `lru` (bounded provider cache)
- `log` 0.4 (structured logging)
- `base64` (cookie encoding)

**Storage**: In-memory only (LRU cache for providers, cookie-based
sessions)
**Testing**: `cargo test` + `criterion` benchmarks + `tiny_http`
mock servers + kind cluster e2e tests (OIDC + SAML flows)
**Target Platform**: Linux (x86_64, aarch64, armv7)
**Project Type**: Shared library plugin (`cdylib` + `rlib`)
**Performance Goals**: <5ms p99 for cookie validation, <1ms p50
**Constraints**: ~4KB cookie size limit, Unix socket IPC
**Scale/Scope**: 10,000+ concurrent sessions, 256 cached providers

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Single-responsibility modules (config, oidc, saml, session, cache). Clippy pedantic. Public API documented. |
| II. Testing Standards | PASS | Unit tests per module, integration tests with mock IdPs (tiny_http), criterion benchmarks, kind-based e2e tests for full OIDC/SAML flows. Deterministic (mock IdPs, no live services). |
| III. UX Consistency | PASS | SPOE arg naming follows HAProxy conventions (snake_case). Actionable error messages with provider name. Graceful degradation on IdP failures. Structured logging. |
| IV. Performance | PASS | Cookie validation hot path is local-only (decrypt + deserialize, no network). LRU cache avoids per-request parsing. ureq connection pooling for IdP calls. Benchmarks for cookie encrypt/decrypt. |

## Project Structure

### Documentation (this feature)

```text
specs/001-sso-auth-plugin/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── spoe-interface.md
│   └── plugin-config-schema.json
└── tasks.md
```

### Source Code (repository root)

```text
src/
├── lib.rs               # Module declarations, define_plugin! macro
├── plugin.rs            # SpoePlugin implementation (init, process, dispatch)
├── config.rs            # PluginConfig parsing, validation, JSON schema
├── provider.rs          # ProviderConfig parsing from SPOE args
├── cache.rs             # LRU provider cache with TTL support
├── session.rs           # SsoSession: encrypt/decrypt/serialize/deserialize
├── oidc.rs              # OIDC flow: discovery, auth URL, callback, refresh, logout
├── saml.rs              # SAML flow: AuthnRequest, response validation, logout
└── action.rs            # AuthAction enum, conversion to SPOE variables

tests/
├── config_test.rs       # Config parsing and validation
├── session_test.rs      # Cookie encrypt/decrypt, dual-key rotation
├── oidc_test.rs         # OIDC flow with mock IdP
├── saml_test.rs         # SAML flow with mock IdP responses
├── cache_test.rs        # LRU eviction, TTL expiry
├── provider_test.rs     # Provider config parsing from SPOE args
└── e2e/                 # End-to-end tests (kind cluster)
    ├── run.sh           # Test orchestrator (create cluster, deploy, test, teardown)
    ├── Makefile         # Convenience targets (e2e, e2e-clean)
    ├── Dockerfile.hub   # Multi-stage: build plugin + hub base image
    └── manifests/
        ├── namespace.yaml
        ├── configmaps.yaml    # HAProxy, SPOE, hub config, map files
        ├── mock-oidc.yaml     # navikt/mock-oauth2-server
        ├── mock-saml-idp.yaml # Mock SAML IdP (samling or custom)
        └── haproxy-hub.yaml   # HAProxy + hub pod (shared unix socket)

benches/
└── session_bench.rs     # Cookie encrypt/decrypt benchmarks

examples/
├── hub.toml             # Example hub configuration
├── spoe-sso-auth.conf   # Example SPOE configuration
└── haproxy.cfg          # Example HAProxy frontend
```

**Structure Decision**: Single-crate project matching the
external-auth plugin layout. Source modules split by responsibility:
plugin interface, config, provider parsing, caching, session
management, OIDC protocol, SAML protocol, and action/variable
mapping.

## E2E Test Design

### Infrastructure

Kind cluster with the following pod topology, matching the
external-auth plugin's proven e2e pattern:

```text
┌─── haproxy-hub pod ─────────────────────────┐
│                                              │
│  ┌───────────┐       ┌──────────────────┐   │
│  │  HAProxy  │◄─────►│  SPOA Hub        │   │
│  │  :8080    │ unix  │  + sso_auth      │   │
│  └───────────┘ sock  │    plugin (.so)  │   │
│                       └──────────────────┘   │
│  emptyDir: /var/run/spoe/hub.sock            │
└──────────────────────────────────────────────┘

┌─── mock-oidc pod ──┐  ┌─── mock-saml-idp pod ──┐
│  navikt/mock-      │  │  Mock SAML IdP          │
│  oauth2-server     │  │  (auto-grant +          │
│  :8080             │  │   signed responses)     │
│  auto-grant mode   │  │  :8080                  │
└────────────────────┘  └─────────────────────────┘
```

**Dockerfile.hub** (multi-stage):
1. Build stage: `rust:1.86-bookworm` — compile plugin with SAML C
   dependencies (`libxml2-dev`, `libxmlsec1-dev`, `libxmlsec1-openssl`)
2. Runtime stage: `registry.gitlab.com/haproxy-haptic/haproxy-spoa-hub:latest`
   — copy `.so` to plugin directory

**ConfigMaps** provide:
- HAProxy config with SPOE filter and map-file-based provider config
- SPOE config with all SSO-auth message args
- Hub TOML with global plugin params (cookie secrets, etc.)
- Map files for provider config (protocol, client_id, client_secret,
  discovery_url, redirect_uri, extract_claims)

### Mock OIDC IdP

Image: `ghcr.io/navikt/mock-oauth2-server:2.1.10`

Configuration: `interactiveLogin: false` (auto-grants all tokens).
Fixed claims: `sub=testuser`, `email=testuser@example.com`,
`name=Test User`, `groups=["admin","users"]`.

Exposes standard OIDC endpoints:
- `/.well-known/openid-configuration` (discovery)
- `/default/authorize` (authorization)
- `/default/token` (token exchange)
- `/default/jwks` (signing keys)
- `/default/endsession` (logout)

### Mock SAML IdP

A lightweight mock SAML IdP that auto-grants authentication and
returns signed SAMLResponse assertions. Options:
- Custom minimal responder built with `samael` (preferred — keep
  test infrastructure in Rust, reuse the same library)
- Or `ghcr.io/kristophjunge/docker-saml-idp` if available

Must provide:
- SSO endpoint that accepts AuthnRequest and returns a signed
  SAMLResponse via HTTP-POST binding
- Fixed attributes: `displayname=Test User`,
  `email=testuser@example.com`, `groups=admin,users`
- SP metadata endpoint for SAML trust setup
- SLO endpoint for logout testing

### Test Scenarios

**OIDC Tests:**

| # | Scenario | Method | Expected |
|---|----------|--------|----------|
| 1 | Unauthenticated request | GET /oidc-app | 302 redirect to mock-oidc authorize endpoint |
| 2 | Full OIDC flow (auto-grant) | GET /oidc-app -L (follow redirects, save cookies) | 200 + `allowed=true` + `email=testuser@example.com` |
| 3 | Authenticated request with cookie | GET /oidc-app (with cookie from test 2) | 200 + `allowed=true` + claims present |
| 4 | Claim extraction | GET /oidc-app (with cookie) | X-Auth-Email and X-Auth-Groups headers forwarded to backend |
| 5 | Logout | GET /oidc-app/logout | 302 redirect to mock-oidc endsession + cookie cleared |
| 6 | Post-logout request | GET /oidc-app (after logout, no cookie) | 302 redirect to authorize (new auth required) |

**SAML Tests:**

| # | Scenario | Method | Expected |
|---|----------|--------|----------|
| 7 | Unauthenticated request | GET /saml-app | 302 redirect to mock-saml-idp SSO endpoint with AuthnRequest |
| 8 | Full SAML flow (auto-grant) | GET /saml-app -L (follow redirects, save cookies) | 200 + `allowed=true` + `email=testuser@example.com` |
| 9 | Authenticated request with cookie | GET /saml-app (with cookie from test 8) | 200 + `allowed=true` + attributes present |
| 10 | Attribute extraction | GET /saml-app (with cookie) | X-Auth-Email header forwarded to backend |

**Cross-Cutting Tests:**

| # | Scenario | Method | Expected |
|---|----------|--------|----------|
| 11 | Fail-closed (OIDC IdP down) | Scale mock-oidc to 0, GET /oidc-app | Not 200 (deny or error) |
| 12 | Multiple providers | GET /oidc-app → OIDC flow, GET /saml-app → SAML flow | Both work independently with separate sessions |
| 13 | Expired cookie | Manually craft expired cookie, GET /oidc-app | 302 redirect (re-auth) |

**Hub Log Verification:**
- After all tests, inspect hub container logs
- Verify: log lines contain `plugin completed` for each request
- Verify: no ERROR-level log lines (except test 11 fail-closed)

### Test Runner (run.sh)

Follows the external-auth plugin's pattern:
1. Generate random cluster name + port
2. Create kind cluster with NodePort mapping
3. Build and load Docker image
4. Apply manifests (namespace → configmaps → mock IdPs → haproxy-hub)
5. Wait for pod readiness (120s timeout per pod)
6. Execute test scenarios with curl + assertion helpers
7. Inspect hub logs
8. Report PASSED/FAILED counts
9. Cleanup via trap on EXIT (delete kind cluster)

## Complexity Tracking

| Concern | Why Needed | Simpler Alternative Rejected Because |
|---------|------------|-------------------------------------|
| C dependency (xmlsec1) | samael requires it for SAML XML signature verification | No pure-Rust SAML signature verification library exists. Implementing C14N + XML sig verify from scratch is riskier than using xmlsec1. |
| LRU cache with TTL | FR-023 requires bounded cache with eviction | Simple HashMap grows unbounded; TTL needed for OIDC discovery/JWKS refresh. |
| Dual-protocol in single binary | Both OIDC and SAML in one plugin | Separate plugins would duplicate session/cookie/cache logic and complicate operator config. |
