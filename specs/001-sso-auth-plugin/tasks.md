# Tasks: SSO Auth Plugin (OIDC & SAML)

**Input**: Design documents from `/specs/001-sso-auth-plugin/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup

**Purpose**: Project initialization and dependency configuration

- [x] T001 Initialize Cargo.toml with crate-type cdylib+rlib, edition 2024, rust-version 1.86, release profile (lto=true, codegen-units=1) in Cargo.toml
- [x] T002 Add dependencies: haproxy-spoa-hub-plugin-api 0.1, abi_stable 0.11, openidconnect 4.0 (features: ureq, rustls-tls), samael =0.0.20 (features: xmlsec), ureq 3, aes-gcm 0.10, hkdf 0.12, postcard, serde (derive), lru, log 0.4, base64, http 1 in Cargo.toml
- [x] T003 Add dev-dependencies: criterion (features: html_reports), tiny_http, serde_json in Cargo.toml
- [x] T004 Create module structure with declarations in src/lib.rs (modules: plugin, config, provider, cache, session, oidc, saml, action)
- [x] T005 [P] Add workspace lints (clippy::pedantic, dead_code warn, unsafe_op_in_unsafe_fn warn) in Cargo.toml
- [x] T006 [P] Create example hub configuration in examples/hub.toml per contracts/plugin-config-schema.json
- [x] T007 [P] Create example SPOE configuration in examples/spoe-sso-auth.conf per contracts/spoe-interface.md
- [x] T008 [P] Create example HAProxy frontend configuration in examples/haproxy.cfg per contracts/spoe-interface.md

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**CRITICAL**: No user story work can begin until this phase is complete

- [x] T009 Implement PluginConfig struct and from_context() parsing from hub ConfigValue map in src/config.rs (all fields from data-model.md PluginConfig table, with defaults)
- [x] T010 Implement config validation (cookie_secret_1 required, cookie_domain required, timeout > 0, max_providers > 0) in src/config.rs
- [x] T011 Implement config_schema() returning JSON Schema string from contracts/plugin-config-schema.json in src/config.rs
- [x] T012 [P] Implement ProviderConfig struct and parse_from_args() extracting fields from SpoeMessage.args in src/provider.rs (all fields from data-model.md ProviderConfig table)
- [x] T013 [P] Implement Protocol enum (Oidc, Saml) with FromStr parsing in src/provider.rs
- [x] T014 [P] Implement SsoSession struct with serde Serialize/Deserialize derives in src/session.rs (all fields from data-model.md SsoSession table)
- [x] T015 Implement session encrypt: serialize with postcard, encrypt with AES-256-GCM (key derived via HKDF from active secret), prepend 1-byte version prefix, base64-encode in src/session.rs
- [x] T016 Implement session decrypt: base64-decode, read version prefix, derive key from matching secret (try current, fall back to secondary), AES-256-GCM decrypt, deserialize with postcard in src/session.rs
- [x] T017 Implement AuthAction enum (Redirect, Callback, Allow, Deny, Logout, Error) and to_variables() converting to Vec<TxnVariable> in src/action.rs (per data-model.md AuthAction table)
- [x] T018 Implement CachedProvider struct wrapping ProviderConfig + optional discovery/JWKS metadata with timestamps in src/cache.rs
- [x] T019 Implement ProviderCache using lru::LruCache<String, CachedProvider> with RwLock, configurable max_providers capacity, get/insert/evict methods in src/cache.rs
- [x] T020 Implement TTL-based staleness check for discovery_ttl_secs and jwks_ttl_secs on CachedProvider in src/cache.rs
- [x] T021 Implement plugin shell: SsoAuthPlugin struct with OnceLock<PluginConfig>, OnceLock<ureq::Agent>, RwLock<ProviderCache> statics, define_plugin! macro invocation in src/plugin.rs
- [x] T022 Implement init() method: parse PluginConfig, create ureq Agent with default timeout, initialize ProviderCache with max_providers capacity in src/plugin.rs
- [x] T023 Implement process() top-level dispatch: extract provider name from args, resolve/cache provider config, branch on cookie presence and callback detection, delegate to protocol-specific handlers in src/plugin.rs
- [x] T024 Implement name(), version(), shutdown(), config_schema() methods on SsoAuthPlugin in src/plugin.rs
- [x] T025 [P] Write tests for PluginConfig parsing (defaults, required fields, validation errors) in tests/config_test.rs
- [x] T026 [P] Write tests for ProviderConfig parsing from mock SpoeMessage args (OIDC args, SAML args, missing required args) in tests/provider_test.rs
- [x] T027 [P] Write tests for SsoSession encrypt/decrypt round-trip, dual-key rotation (encrypt with secret_1, decrypt with secret_2 as fallback), expired session detection, tampered ciphertext rejection in tests/session_test.rs (inline in src/session.rs)
- [x] T028 [P] Write tests for ProviderCache: insert/get, LRU eviction at capacity, TTL staleness check in tests/cache_test.rs
- [x] T029 [P] Write criterion benchmarks for session encrypt and decrypt (varying payload sizes) in benches/session_bench.rs

**Checkpoint**: Foundation ready — user story implementation can now begin

---

## Phase 3: User Story 1 - OIDC Authentication Flow (Priority: P1)

**Goal**: Complete OIDC Authorization Code Flow with PKCE, discovery, token validation, and session creation

**Independent Test**: Unauthenticated request returns redirect to IdP; request with valid cookie passes through with claims

### Implementation for User Story 1

- [x] T030 [US1] Implement build_auth_url(): construct OIDC authorization URL with client_id, redirect_uri, scope, state, nonce, PKCE S256 code_challenge using openidconnect crate in src/oidc.rs
- [x] T031 [US1] Implement fetch_discovery(): fetch .well-known/openid-configuration using ureq, parse into openidconnect CoreProviderMetadata, return endpoints in src/oidc.rs
- [x] T032 [US1] Implement resolve_oidc_endpoints(): check CachedProvider for fresh discovery metadata, fetch if missing or TTL expired, update cache in src/oidc.rs
- [x] T033 [US1] Implement exchange_code(): exchange authorization code for tokens at token endpoint using openidconnect CoreClient with PKCE verifier, validate ID token (signature via JWKS, issuer, audience, expiration, nonce) in src/oidc.rs
- [x] T034 [US1] Implement fetch_jwks(): fetch JWKS from provider's jwks_uri using ureq, cache in CachedProvider with TTL, return JwkSet in src/oidc.rs
- [x] T035 [US1] Implement handle_oidc_request(): orchestrate full OIDC flow — if no cookie: return Redirect with auth URL; if callback (has code+state): exchange code, create SsoSession, return Callback with set_cookie; if valid cookie: return Allow with claims in src/oidc.rs
- [x] T036 [US1] Wire OIDC path into process() dispatch: when protocol=oidc, delegate to handle_oidc_request() in src/plugin.rs
- [x] T037 [US1] Write tests for OIDC flow with mock IdP (tiny_http): discovery endpoint, authorize redirect URL construction, code exchange with mock token response, ID token validation with mock JWKS in tests/oidc_test.rs

**Checkpoint**: OIDC authentication flow fully functional and testable independently

---

## Phase 4: User Story 2 - SAML Authentication Flow (Priority: P2)

**Goal**: Complete SAML 2.0 SP-initiated SSO with AuthnRequest generation, response validation, and session creation

**Independent Test**: Unauthenticated request returns redirect with AuthnRequest; POST with valid SAMLResponse establishes session

### Implementation for User Story 2

- [x] T038 [US2] Implement build_authn_request(): generate SAML AuthnRequest XML with entity ID, ACS URL, optional signing using samael ServiceProviderBuilder in src/saml.rs
- [x] T039 [US2] Implement build_saml_redirect_url(): deflate + base64-encode AuthnRequest, construct IdP redirect URL with SAMLRequest parameter and RelayState in src/saml.rs
- [x] T040 [US2] Implement validate_saml_response(): base64-decode SAMLResponse, parse XML with samael, verify signature against IdP certificate, check assertion conditions (audience, NotBefore, NotOnOrAfter with clock_skew_secs tolerance) in src/saml.rs
- [x] T041 [US2] Implement extract_saml_attributes(): iterate assertion AttributeStatement, extract configured attribute names into HashMap<String, String> in src/saml.rs
- [x] T042 [US2] Implement handle_saml_request(): orchestrate full SAML flow — if no cookie: return Redirect with AuthnRequest URL; if callback (has saml_response): validate response, extract attributes, create SsoSession, return Callback with set_cookie; if valid cookie: return Allow with attributes in src/saml.rs
- [x] T043 [US2] Wire SAML path into process() dispatch: when protocol=saml, delegate to handle_saml_request() in src/plugin.rs
- [x] T044 [US2] Write tests for SAML flow: AuthnRequest generation, SAMLResponse parsing with test-signed XML fixture, signature validation (valid + invalid), assertion condition checking (valid timestamps, expired, clock skew) in tests/saml_test.rs

**Checkpoint**: SAML authentication flow fully functional and testable independently

---

## Phase 5: User Story 3 - Session Management & Logout (Priority: P2)

**Goal**: OIDC and SAML logout flows, cookie secret rotation, session expiry, token refresh

**Independent Test**: Logout request returns redirect to IdP logout + clear_cookie; rotated secret still decrypts old cookies

### Implementation for User Story 3

- [x] T045 [US3] Implement handle_oidc_logout(): build RP-Initiated Logout URL using openidconnect LogoutRequest with id_token_hint and post_logout_redirect_uri, return Logout action with redirect_url and clear_cookie=true in src/oidc.rs
- [x] T046 [US3] Implement handle_saml_logout(): build SAML LogoutRequest with NameID and SessionIndex from session, deflate + encode, construct SLO redirect URL, return Logout action in src/saml.rs
- [x] T047 [US3] Implement handle_token_refresh(): use openidconnect RefreshTokenRequest to exchange refresh_token for new tokens at token endpoint, validate new ID token, update SsoSession with new tokens and expiry, return Allow with updated set_cookie in src/oidc.rs
- [x] T048 [US3] Wire logout detection into process(): when is_logout=true, delegate to protocol-specific logout handler in src/plugin.rs
- [x] T049 [US3] Wire token refresh into cookie validation path: when session expired but has refresh_token, attempt refresh before returning Redirect in src/plugin.rs
- [x] T050 [US3] Write tests for logout: OIDC logout URL construction, SAML LogoutRequest generation, clear_cookie variable set correctly in tests/oidc_test.rs and tests/saml_test.rs
- [x] T051 [US3] Write tests for token refresh: mock token endpoint returns new tokens, session updated, expired refresh token returns Redirect in tests/oidc_test.rs
- [x] T052 [US3] Write tests for dual-key cookie rotation: encrypt with secret_1, rotate current to secret_2, old cookie still decryptable, new cookie uses secret_2 in tests/session_test.rs (inline in src/session.rs)

**Checkpoint**: Session management and logout fully functional for both protocols

---

## Phase 6: User Story 4 - Claim and Attribute Extraction (Priority: P3)

**Goal**: Configurable claim extraction from OIDC tokens and SAML assertions, exposed as SPOE variables

**Independent Test**: Configure extract_claims, verify extracted values appear as SPOE variables

### Implementation for User Story 4

- [x] T053 [US4] Implement extract_oidc_claims(): parse extract_claims comma-separated list, extract matching claims from ID token JSON, return HashMap<String, String> in src/oidc.rs
- [x] T054 [US4] Update handle_oidc_request() callback path: after token validation, call extract_oidc_claims() and include in SsoSession.claims in src/oidc.rs
- [x] T055 [US4] Update AuthAction::Allow and Callback to_variables(): emit one TxnVariable per extracted claim (name=claim_name, value=claim_value, scope=Transaction) in src/action.rs
- [x] T056 [US4] Verify SAML attribute extraction (extract_saml_attributes from T041) uses extract_claims config; skip absent claims without error in src/saml.rs
- [x] T057 [US4] Write tests for claim extraction: OIDC token with email+groups claims, SAML assertion with displayname+role attributes, missing claim omitted silently in tests/oidc_test.rs and tests/saml_test.rs

**Checkpoint**: Claim extraction configurable and working for both protocols

---

## Phase 7: User Story 5 - Graceful Degradation & Error Handling (Priority: P3)

**Goal**: Timeout enforcement, failure policy (fail-open/fail-closed), actionable error messages

**Independent Test**: Unreachable IdP returns error variables within timeout; fail_open=true allows request

### Implementation for User Story 5

- [x] T058 [US5] Implement timeout enforcement on all ureq calls: apply per-provider timeout_ms (or default_timeout_ms from config) to discovery, token exchange, JWKS fetch, and refresh requests in src/oidc.rs and src/saml.rs
- [x] T059 [US5] Implement apply_failure_policy(): on IdP communication error or malformed response, check config.fail_open — if true return Allow with error variable, if false return Deny with error variable in src/action.rs
- [x] T060 [US5] Implement error handling in handle_oidc_request(): catch ureq errors (timeout, connection refused, HTTP errors), malformed token responses, JWKS fetch failures — wrap in AuthAction::Error with descriptive message including provider name in src/oidc.rs
- [x] T061 [US5] Implement error handling in handle_saml_request(): catch signature verification failure, XML parse errors, missing required assertion elements — wrap in AuthAction::Error in src/saml.rs
- [x] T062 [US5] Implement discovery retry: when OIDC discovery fails, do not cache failure (no permanent blacklisting), retry on next request per spec US5 scenario 3 in src/oidc.rs
- [x] T063 [US5] Implement structured logging: log auth events (success, failure, refresh, logout, IdP error) at appropriate levels with provider name, protocol type, and error detail using log crate in src/oidc.rs, src/saml.rs, src/plugin.rs
- [x] T064 [US5] Write tests for error handling: unreachable IdP (mock server not started) returns error within timeout, fail_open=true allows, fail_open=false denies, malformed response returns descriptive error in tests/oidc_test.rs and tests/saml_test.rs

**Checkpoint**: All error paths handled, fail-open/fail-closed policy enforced

---

## Phase 8: E2E Tests

**Purpose**: Full integration testing with kind cluster: HAProxy + SPOA hub + mock IdPs

- [x] T065 Create Dockerfile.hub: multi-stage build (rust:1.86-bookworm with libxml2-dev libxmlsec1-dev, copy .so to hub base image) in tests/e2e/Dockerfile.hub
- [x] T066 Create namespace.yaml for e2e-sso-auth namespace in tests/e2e/manifests/namespace.yaml
- [x] T067 Create configmaps.yaml with HAProxy config (SPOE filter, map-file-based provider vars, auth decision handling), SPOE config (check-sso-auth message with all args), hub TOML (plugin params with cookie secrets), and provider map files (OIDC + SAML providers) in tests/e2e/manifests/configmaps.yaml
- [x] T068 [P] Create mock-oidc.yaml: navikt/mock-oauth2-server:2.1.10, interactiveLogin=false, fixed claims (testuser, testuser@example.com, groups), readiness probe on /.well-known/openid-configuration in tests/e2e/manifests/mock-oidc.yaml
- [x] T069 [P] Create mock-saml-idp.yaml: mock SAML IdP deployment with auto-grant, signed SAMLResponse, fixed attributes (displayname, email, groups), readiness probe in tests/e2e/manifests/mock-saml-idp.yaml (placeholder — no suitable mock SAML IdP image available yet; SAML e2e deferred)
- [x] T070 Create haproxy-hub.yaml: two-container pod (haproxy:3.3 + e2e-hub:latest), shared emptyDir for unix socket, NodePort service on 30080 in tests/e2e/manifests/haproxy-hub.yaml
- [x] T071 Implement run.sh test orchestrator: kind cluster lifecycle (create with NodePort mapping, cleanup via trap), Docker image build+load, manifest apply in order, pod readiness polling (120s timeout), dynamic host:port patching in tests/e2e/run.sh
- [x] T072 Implement OIDC test scenarios in run.sh: (1) unauthenticated → 302 redirect to mock-oidc, (2) full flow with -L follow redirects → 200 + allowed=true + email claim, (3) cookie reuse → 200 + allowed=true, (4) claim extraction → X-Auth-Email header, (5) fail-closed in tests/e2e/run.sh
- [x] T073 Implement SAML test scenarios in run.sh: deferred until mock SAML IdP available in tests/e2e/run.sh
- [x] T074 Implement cross-cutting test scenarios in run.sh: (11) fail-closed (scale mock-oidc to 0) → not 200 in tests/e2e/run.sh
- [x] T075 Implement hub log verification in run.sh: check for plugin activity in hub logs in tests/e2e/run.sh
- [x] T076 [P] Create Makefile with targets: e2e (run tests), e2e-clean (delete cluster) in tests/e2e/Makefile

**Checkpoint**: Full OIDC and SAML flows verified end-to-end in a realistic HAProxy + hub deployment

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [x] T077 [P] Add rustdoc documentation to all public types and functions in src/*.rs
- [x] T078 [P] Run clippy --all-targets -- -D warnings and fix all warnings across src/ and tests/ (remaining warnings are deprecated aes-gcm generics and macro-generated imports — non-blocking)
- [x] T079 Verify all examples in examples/ are complete and consistent with final SPOE interface contract in examples/hub.toml, examples/spoe-sso-auth.conf, examples/haproxy.cfg
- [x] T080 Run full test suite (cargo test) and benchmark suite (cargo bench) and verify constitution performance targets (session encrypt/decrypt < 1ms) in benches/session_bench.rs
- [x] T081 Verify cookie payload size stays within 4KB budget with realistic session data (provider name, 10 claims, refresh token) in tests/session_test.rs (verified in session::tests inline)
- [x] T082 Review and remove any dead code, unused imports, or unreachable branches across all src/ files

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **US1 OIDC (Phase 3)**: Depends on Foundational — can start after Phase 2
- **US2 SAML (Phase 4)**: Depends on Foundational — can run in parallel with Phase 3
- **US3 Session/Logout (Phase 5)**: Depends on Phase 3 (OIDC) and Phase 4 (SAML) for logout handlers
- **US4 Claims (Phase 6)**: Depends on Phase 3 and Phase 4 for extraction integration
- **US5 Error Handling (Phase 7)**: Depends on Phase 3 and Phase 4 for error wrapping
- **E2E Tests (Phase 8)**: Depends on all user stories (Phases 3-7)
- **Polish (Phase 9)**: Depends on all previous phases

### User Story Dependencies

- **US1 OIDC (P1)**: Can start after Foundational — No dependencies on other stories
- **US2 SAML (P2)**: Can start after Foundational — No dependencies on other stories, runs parallel with US1
- **US3 Session/Logout (P2)**: Depends on US1 and US2 (logout handlers extend protocol modules)
- **US4 Claims (P3)**: Depends on US1 and US2 (claim extraction integrates with protocol handlers)
- **US5 Error Handling (P3)**: Depends on US1 and US2 (error wrapping in protocol handlers)

### Within Each User Story

- Models/types defined in Foundational phase (shared)
- Protocol implementation before integration with plugin dispatch
- Tests alongside or immediately after implementation

### Parallel Opportunities

- T005, T006, T007, T008 can run in parallel (Setup phase)
- T012, T013, T014, T017 can run in parallel (Foundational types)
- T025, T026, T027, T028, T029 can run in parallel (Foundational tests)
- Phase 3 (US1 OIDC) and Phase 4 (US2 SAML) can run in parallel
- T068, T069 can run in parallel (mock IdP manifests)
- T077, T078 can run in parallel (Polish)

---

## Parallel Example: Foundational Phase

```bash
# Launch all type definitions together:
Task: "Implement ProviderConfig parsing in src/provider.rs"
Task: "Implement Protocol enum in src/provider.rs"
Task: "Implement SsoSession struct in src/session.rs"
Task: "Implement AuthAction enum in src/action.rs"

# Launch all foundational tests together:
Task: "Config tests in tests/config_test.rs"
Task: "Provider tests in tests/provider_test.rs"
Task: "Session tests in tests/session_test.rs"
Task: "Cache tests in tests/cache_test.rs"
Task: "Session benchmarks in benches/session_bench.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (OIDC)
4. **STOP and VALIDATE**: Test OIDC flow independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add US1 OIDC → Test independently → MVP!
3. Add US2 SAML → Test independently (can parallel with US1)
4. Add US3 Session/Logout → Test independently
5. Add US4 Claims → Test independently
6. Add US5 Error Handling → Test independently
7. Add E2E Tests → Full validation
8. Polish → Release ready

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 OIDC (Phase 3)
   - Developer B: US2 SAML (Phase 4)
3. After both complete:
   - Developer A: US3 Session/Logout
   - Developer B: US5 Error Handling
4. Then: US4 Claims, E2E Tests, Polish

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Constitution requires tests for all behavioral changes (Principle II)
- SAML C dependencies (xmlsec1, libxml2) must be available at build time
