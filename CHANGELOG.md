# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Development and releases moved to GitHub (`https://github.com/haproxy-haptic/haproxy-spoa-hub-plugin-sso-auth`); GitLab is a read-only mirror.
- Bumped `aes-gcm` `0.10` → `0.11` (new `aead` 0.6 / `hybrid-array` backend). Cookie encryption is unchanged on the wire — existing session and auth-state cookies keep decrypting across the upgrade.

## [0.3.0] - 2026-05-15

### Added

- **Prometheus metrics** via the `haproxy-spoa-hub` v0.6.0 plugin-API v2 vtable. Surfaced through the hub's `/metrics` endpoint under the `plugin_sso_auth_` prefix.

  | metric                            | kind      | labels       |
  |-----------------------------------|-----------|--------------|
  | `auth_decisions_total`            | counter   | `outcome`    |
  | `auth_decision_duration_seconds`  | histogram | _(none)_     |

  `outcome` ∈ `{redirect, callback, allow, deny, logout, error}` — corresponds 1:1 to the `AuthAction` variants the plugin returns. Operators can chart "redirects accumulating without callbacks" (broken SSO flow) or "denies without errors" (genuine rejected sessions vs IdP-side problems) in single PromQL queries.

  The hub-surfaced recorder uses a separate static (`PROM_METRICS`) so it doesn't collide with the existing internal `METRICS: AuthMetrics` static the plugin uses for per-provider accounting (cache-eviction decisions etc.). The two have different roles: AuthMetrics is internal logic state, the new recorder is user-facing observability.

### Changed

- Plugin-API dep `^0.5` → `^0.6` to pick up `MetricRecorder` and the `metrics_static` macro arm. Vtable change is append-only — this plugin's v0.3.0 .so still loads on v0.5.x hubs (metrics silent there).

## [0.2.0] - 2026-05-04

### Changed

- **BREAKING**: Bumped `haproxy-spoa-hub-plugin-api` dependency to `0.5` (the hand-rolled `#[repr(C)]` vtable migration). This plugin's `.so` will only load on `haproxy-spoa-hub` v0.5.0 or newer. Older hubs reject the load with a "missing required symbol 'get_plugin_vtable'" error since the entry-symbol naming changed.
- Switched `haproxy-spoa-hub-plugin-api` from a git source dependency on the `haproxy-spoa-hub` repository to the crates.io release. CI no longer needs to fetch the upstream repo at build time.
- Dropped the direct `abi_stable = "0.11"` dependency. Plugin-api re-exports the abi_stable types this crate uses; no direct dep is required.

## [0.1.1] - 2026-04-28

### Added

- Release artifacts (plugin `.so` files) published to the GitLab Generic
  Package Registry under `packages/generic/sso-auth/<tag>/` with stable URLs
- Per-file `<artifact>.sha256` sidecars and a combined `SHA256SUMS` for
  batch verification with `sha256sum -c SHA256SUMS`
- Cosign keyless signatures (`<artifact>.cosign.bundle`) for every release
  artifact, signed via the GitLab OIDC id token (Sigstore Fulcio + Rekor)
- `make verify-release VERSION=vX.Y.Z` target plus `scripts/verify-release.sh`
  for end-to-end consumer verification (downloads `SHA256SUMS`, checks all
  hashes, runs `cosign verify-blob` against the project's tag identity)
- Unsigned SLSA v0.2 provenance metadata emitted next to build artifacts
  via `RUNNER_GENERATE_ARTIFACTS_METADATA` (free SLSA-L1)

### Changed

- Release builds now use `cargo auditable build --release`, embedding a
  compressed `Cargo.lock`-equivalent in every binary so SBOM tools can
  enumerate Rust dependencies without source access

## [0.1.0] - 2026-04-21

### Added

- SSO authentication plugin for haproxy-spoa-hub supporting OIDC and SAML,
  feature-comparable to HAProxy Enterprise SSO modules.
- OIDC flow: authorization redirect with state + nonce, authorization-code
  exchange, ID-token validation, encrypted session cookie, claim forwarding
  as HAProxy headers.
- SAML flow (via `samael` / `xmlsec`): AuthnRequest generation, SP-initiated
  SSO, signed-response validation, assertion parsing, encrypted session
  cookie.
- Encrypted session cookie: AES-GCM with HKDF-derived keys, postcard
  serialization, configurable cookie name and TTL.
- LRU-based auth-state cache for in-flight authorization requests.
- Per-provider configuration: operators can register multiple identity
  providers and route requests to them via an HAProxy-side `sso-providers`
  map.
- Multi-architecture builds: amd64, arm64 (native cross-compile) and armv7
  (Docker-based cross-compile to work around bindgen/libclang struct-layout
  issues under QEMU armv7 for `samael`/`xmlsec`).
- Smoke stage verifying the plugin loads under arm64 and armv7 via QEMU
  binfmt.
- End-to-end test harness with a mock OIDC provider (KIND-based).
