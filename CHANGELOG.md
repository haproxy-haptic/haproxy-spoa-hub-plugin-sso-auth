# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
