# Research: SSO Auth Plugin

## OIDC Client Library

**Decision**: `openidconnect` v4.0 with `ureq` backend

**Rationale**: The only mature OIDC library in Rust (~6.9M total
downloads, 612 GitHub stars, actively maintained). Covers all
requirements: discovery, Authorization Code Flow with PKCE (S256),
ID token validation (JWKS, issuer, audience, expiration, nonce),
token refresh, RP-Initiated Logout, and all required signing
algorithms (RS/ES/HS/PS 256/384/512). Built on the `oauth2` crate
(~30M downloads, same author).

The `ureq` feature flag provides a synchronous HTTP backend with
no async runtime dependency — ideal for the hub's blocking thread
pool context. This also aligns with the external-auth plugin's use
of `ureq` for HTTP calls.

**Alternatives considered**:
- `oidc` crate — abandoned since 2019, not viable.
- Rolling own with `oauth2` + `jsonwebtoken` — strictly more work
  with no benefit; `openidconnect` already wraps `oauth2`.

## SAML SP Library

**Decision**: `samael` v0.0.20

**Rationale**: The only viable SAML 2.0 SP library in Rust (~405k
downloads, 96 GitHub stars, last updated 2026-03-20). Covers
AuthnRequest generation, SAMLResponse parsing/validation, XML
signature verification (via `xmlsec` feature), assertion condition
checking, and attribute extraction. Synchronous API fits the
plugin context.

**Concerns**:
- **Pre-1.0 (v0.0.20)**: API stability not guaranteed. Pin exact
  version.
- **Heavy C dependencies**: Requires `xmlsec1`, `libxml2`, `libxslt`,
  `openssl` at build and runtime. Complicates cross-compilation and
  multi-arch CI (amd64, arm64, armv7).
- **ECDSA support**: Depends on xmlsec1 being compiled with OpenSSL
  EC support. Must be tested explicitly.
- **Open issue**: xmlsec 1.2.3x signature verification may fail
  due to missing `xmlSecAddIDs` registration. Investigate before
  deployment.
- **Single maintainer**: Bus factor of 1.

**Mitigations**:
- Pin exact version (`=0.0.20`).
- Wrap samael behind a trait interface to allow future replacement.
- Docker build images with pinned C library versions for CI.
- Explicit ECDSA integration tests against real IdPs.
- Watch `saml-rs` (terminaloutcomes) as a potential future
  replacement (security-first, pure Rust, but not yet published to
  crates.io).

**Alternatives considered**:
- `saml-rs` — not published to crates.io, author says it's "in a
  lot of flux". Not production-ready.
- `flp-saml2` — 853 lines, GPL-3.0 license, no signature
  verification. Not suitable.

## Session Cookie Encryption

**Decision**: `aes-gcm` + `hkdf` + `postcard` (compact serde format)

**Rationale**: The plugin does not set cookies directly — it returns
an encrypted session blob as an SPOE variable, and HAProxy handles
the actual `Set-Cookie` header. Therefore cookie formatting libraries
(`cookie`, `biscotti`) add unnecessary abstraction. A minimal stack
gives full control:

- `aes-gcm` (v0.10): AES-256-GCM AEAD encryption. Audited by NCC
  Group, constant-time implementation, pure Rust.
- `hkdf` (v0.12): HKDF-SHA256 key derivation from master secrets.
  Distinct `info` strings per key version.
- `postcard` (serde): Compact binary serialization of session data.
  Smaller than JSON/bincode, important for the ~4KB cookie limit.
- `base64`: Encode encrypted blob for cookie transport.

**Dual-key rotation**: 1-byte version prefix on the encrypted blob.
Decryption tries the current key first; on `aead::Error`, falls back
to the previous key. Re-encryption with the current key on successful
fallback decryption.

**Cookie budget**: 12-byte nonce + 16-byte auth tag + ciphertext +
1-byte version + base64 overhead (~37%). For a session containing
protocol type, provider name, claims, expiry, and optionally a
refresh token, the plaintext is estimated at 500-2000 bytes,
yielding ~700-2800 bytes after encryption + base64. Well within
the 4KB limit.

**Alternatives considered**:
- `biscotti` — built-in key rotation but adds cookie formatting we
  don't need (HAProxy handles Set-Cookie).
- `ring` — RUSTSEC-2025-0007 unmaintained advisory; security-only
  maintenance. Not suitable for new projects.
- `chacha20poly1305` — valid alternative to AES-GCM (192-bit
  nonces avoid collision risk), but AES-GCM is more ubiquitous in
  enterprise contexts and has hardware acceleration on x86.

## LRU Cache

**Decision**: `lru` crate or `hashbrown` + manual LRU

The provider config cache (FR-023) needs an LRU eviction policy
with O(1) get/put. The `lru` crate (~12M downloads) provides a
simple `LruCache<K, V>` with configurable capacity. Thread safety
via `std::sync::RwLock` (read-heavy workload: most requests hit
cached providers).

## HTTP Client

**Decision**: `ureq` v3 (same as external-auth plugin)

Used for all IdP communication: OIDC discovery, token exchange,
JWKS fetch, token refresh. Synchronous, no async runtime, connection
pooling via agent reuse. Matches the external-auth plugin's approach.

## Logging

**Decision**: `log` crate (same as external-auth plugin)

The hub's tracing subscriber captures `log` output. No need for
the `tracing` crate in the plugin itself.
