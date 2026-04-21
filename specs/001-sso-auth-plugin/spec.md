# Feature Specification: SSO Auth Plugin (OIDC & SAML)

**Feature Branch**: `001-sso-auth-plugin`
**Created**: 2026-04-12
**Status**: Draft
**Input**: User description: "HAProxy SPOA hub plugin for SSO auth via OIDC and SAML, feature-comparable to HAProxy Enterprise SSO modules"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - OIDC Authentication Flow (Priority: P1)

A HAProxy operator configures the plugin to protect web applications
behind OpenID Connect authentication. When an unauthenticated user
accesses a protected route, they are redirected to the identity
provider's sign-in page. After successful authentication, the user is
redirected back and granted access. Subsequent requests use an
encrypted session cookie to avoid repeated IdP round-trips.

**Why this priority**: OIDC is the most widely adopted SSO protocol for
modern web applications and APIs. It covers the majority of enterprise
IdP deployments (Entra ID, Okta, Keycloak, Auth0).

**Independent Test**: Can be fully tested by configuring a single
protected backend with an OIDC provider. An unauthenticated request
returns a redirect to the IdP; a request with a valid session cookie
passes through with identity claims forwarded as headers.

**Acceptance Scenarios**:

1. **Given** an unauthenticated user, **When** they request a protected
   resource, **Then** the plugin returns variables instructing HAProxy
   to redirect the user to the IdP's authorization endpoint with a
   valid authorization request including state and nonce parameters.

2. **Given** the IdP redirects back with an authorization code,
   **When** the callback request reaches the plugin, **Then** the
   plugin exchanges the code for tokens, validates the ID token,
   and returns variables instructing HAProxy to set an encrypted
   session cookie and grant access.

3. **Given** a user with a valid session cookie, **When** they request
   a protected resource, **Then** the plugin decrypts and validates the
   cookie, and returns identity claims as SPOE variables without
   contacting the IdP.

4. **Given** a user with an expired session cookie containing a refresh
   token, **When** they request a protected resource, **Then** the
   plugin silently refreshes the tokens and returns an updated cookie
   alongside the identity claims.

5. **Given** an OIDC provider that supports discovery, **When** the
   plugin receives the first request for that provider, **Then** it
   fetches the provider's `.well-known/openid-configuration` document,
   auto-configures the authorization, token, JWKS, and end-session
   endpoints, and caches the result for subsequent requests.

---

### User Story 2 - SAML Authentication Flow (Priority: P2)

A HAProxy operator configures the plugin to protect web applications
behind SAML 2.0 authentication. The plugin acts as a SAML Service
Provider, generating AuthnRequest messages and validating
SAMLResponse assertions from the Identity Provider.

**Why this priority**: SAML remains essential for enterprise
environments, government systems, and legacy IdP integrations that do
not support OIDC. Many organizations require both protocols.

**Independent Test**: Can be fully tested by configuring a single
protected backend with a SAML IdP. An unauthenticated request triggers
an SP-initiated AuthnRequest redirect; a POST with a valid
SAMLResponse establishes a session.

**Acceptance Scenarios**:

1. **Given** an unauthenticated user, **When** they request a protected
   resource, **Then** the plugin returns variables instructing HAProxy
   to redirect the user to the IdP with a valid AuthnRequest
   (HTTP-Redirect binding).

2. **Given** the IdP posts a SAMLResponse to the Assertion Consumer
   Service URL, **When** the callback reaches the plugin, **Then**
   the plugin validates the response signature, checks assertion
   conditions (audience, timestamps), extracts attributes, and
   returns variables instructing HAProxy to set an encrypted session
   cookie and grant access.

3. **Given** a user with a valid SAML session cookie, **When** they
   request a protected resource, **Then** the plugin validates the
   cookie and returns the cached SAML attributes as SPOE variables
   without contacting the IdP.

4. **Given** a SAMLResponse with an invalid signature or expired
   conditions, **When** the callback reaches the plugin, **Then** the
   plugin rejects the response and returns denial variables.

---

### User Story 3 - Session Management & Logout (Priority: P2)

An operator needs users to be able to log out, and needs session
cookies to be secure, rotatable, and time-bounded. Both OIDC and SAML
sessions share a common encrypted cookie mechanism.

**Why this priority**: Session management is cross-cutting for both
protocols and essential for security compliance. Rated P2 because it
builds on the authentication flows from US1/US2.

**Independent Test**: Can be tested by issuing a logout request and
verifying the session cookie is cleared and the user is redirected to
the IdP's logout endpoint. Cookie rotation can be tested by changing
the active secret and verifying old cookies are still valid.

**Acceptance Scenarios**:

1. **Given** an authenticated user (OIDC or SAML), **When** they
   request the configured logout path, **Then** the plugin returns
   variables instructing HAProxy to clear the session cookie and
   redirect to the IdP's logout endpoint.

2. **Given** a session cookie encrypted with a previous secret,
   **When** the operator has rotated to a new secret, **Then** the
   plugin can still decrypt the old cookie (dual-secret support)
   and issues a new cookie encrypted with the current secret.

3. **Given** a session cookie whose lifetime has expired, **When** the
   user sends a request, **Then** the plugin treats the user as
   unauthenticated and triggers a new authentication flow.

4. **Given** an OIDC session with a refresh token, **When** the
   access token has expired but the refresh token is still valid,
   **Then** the plugin refreshes the tokens transparently without
   user interaction.

---

### User Story 4 - Claim and Attribute Extraction (Priority: P3)

An operator wants to forward identity attributes from the IdP to
backend services as HTTP headers or make them available as HAProxy
variables for authorization decisions (e.g., group-based access
control).

**Why this priority**: Claim extraction enables authorization logic in
HAProxy ACLs and header-based identity propagation to backends. P3
because it enhances the core authentication flows from US1/US2.

**Independent Test**: Can be tested by configuring claim mappings and
verifying the extracted values appear as SPOE variables and can be
used in HAProxy ACLs or set as request headers.

**Acceptance Scenarios**:

1. **Given** an OIDC authentication, **When** the ID token contains
   claims (e.g., `email`, `name`, `groups`), **Then** the plugin
   extracts configured claims and returns them as SPOE variables
   (e.g., `txn.spoe.sso_auth.email`).

2. **Given** a SAML authentication, **When** the assertion contains
   attributes (e.g., `displayname`, `role`, `groups`), **Then** the
   plugin extracts configured attributes and returns them as SPOE
   variables.

3. **Given** an operator configures a list of claims/attributes to
   extract, **When** a claim is absent from the token/assertion,
   **Then** the plugin either uses a configured default value or
   omits the variable (no error).

---

### User Story 5 - Graceful Degradation & Error Handling (Priority: P3)

When the IdP is unreachable or returns errors, the plugin MUST NOT
crash or leave HAProxy connections hanging. The operator configures a
failure policy to control behavior during outages.

**Why this priority**: Operational resilience is critical in production
but depends on the core flows being functional first.

**Independent Test**: Can be tested by making the IdP unreachable and
verifying the plugin returns appropriate error variables within the
configured timeout.

**Acceptance Scenarios**:

1. **Given** the IdP is unreachable during token exchange, **When**
   the configured timeout elapses, **Then** the plugin returns error
   variables indicating the failure reason, and HAProxy can apply its
   configured error handling (deny, redirect, or fail-open).

2. **Given** the IdP returns an invalid or malformed response,
   **When** the plugin processes it, **Then** the plugin returns
   denial variables with a descriptive error message rather than
   crashing.

3. **Given** the OIDC discovery endpoint is unreachable on first
   request for a provider, **When** the plugin attempts discovery,
   **Then** it returns error variables for that request and retries
   discovery on subsequent requests (no permanent blacklisting).

---

### Edge Cases

- What happens when the clock skew between HAProxy and the IdP exceeds
  the token/assertion validity window? (configurable skew tolerance)
- How does the plugin handle concurrent requests from the same user
  during the authorization code exchange? (state parameter prevents
  replay; concurrent redirects are idempotent)
- What happens when the SAML response exceeds the SPOE message size
  limit? (only extracted attributes are returned, not the full
  assertion)
- How does the plugin handle IdP certificate rotation? (JWKS refresh
  for OIDC; certificate reload on SIGHUP for SAML)
- What happens when the provider cache reaches its maximum size?
  (LRU eviction — the least recently used provider is dropped; next
  request for that provider rebuilds the cache entry, including a
  fresh OIDC discovery fetch if applicable)

## Clarifications

### Session 2026-04-12

- Q: Should PKCE (Proof Key for Code Exchange) be required for the OIDC Authorization Code Flow? → A: Require PKCE (S256) for all OIDC flows.
- Q: Should the plugin support multiple identity providers per instance? → A: Multiple providers configured in plugin, selected per-request via SPOE message args.
- Q: What observability signals should the plugin emit beyond hub-level metrics? → A: Structured logging plus auth-domain counters (success/failure/refresh counts) exposed via hub metrics.
- Q: Where should provider-specific config (client_id, client_secret, endpoints) live? → A: All provider config comes via SPOE message args. The hub runs in the same pod as HAProxy (unix socket IPC), so secrets in HAProxy map files are acceptable — same trust boundary, no network exposure. The plugin caches parsed provider configs in memory keyed by provider name. Static `[plugins.params]` holds only global settings (cookie secrets, default timeout, failure policy). This avoids hub restarts when providers are added/removed and supports the HAPTIC ingress controller workflow where annotations + K8s secrets drive HAProxy config via the Data Plane API.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST implement the OAuth 2.0 Authorization Code
  Flow as specified by OpenID Connect Core 1.0, including state and
  nonce parameters for CSRF and replay protection. PKCE with S256
  challenge method MUST be used for all OIDC flows.
- **FR-002**: System MUST implement SAML 2.0 SP-initiated SSO with
  HTTP-Redirect binding for AuthnRequest and HTTP-POST binding for
  SAMLResponse.
- **FR-003**: System MUST support automatic OIDC provider discovery
  via the `.well-known/openid-configuration` endpoint on first
  request for a given provider, with fallback to manually specified
  endpoints in the SPOE message args.
- **FR-004**: System MUST validate OIDC ID tokens (signature, issuer,
  audience, expiration, nonce) using the provider's published JWKS.
- **FR-005**: System MUST validate SAML response signatures and
  assertion conditions (audience restriction, NotBefore, NotOnOrAfter).
- **FR-006**: System MUST maintain sessions via encrypted cookies with
  configurable lifetime, domain, secure flag, and SameSite attribute.
- **FR-007**: System MUST support cookie encryption secret rotation
  with dual-secret decryption during the transition period.
- **FR-008**: System MUST support OIDC token refresh using refresh
  tokens when access tokens expire.
- **FR-009**: System MUST support OIDC RP-Initiated Logout and SAML
  Single Logout (SLO).
- **FR-010**: System MUST extract configurable claims from OIDC tokens
  and SAML assertions and expose them as SPOE transaction variables.
- **FR-011**: System MUST support multiple signing algorithms: RSA
  (RS256, RS384, RS512), ECDSA (ES256, ES384, ES512), and HMAC
  (HS256, HS384, HS512) for OIDC; RSA and ECDSA for SAML.
- **FR-012**: System MUST enforce configurable timeouts on all
  external HTTP requests (IdP communication) with circuit-breaker
  behavior.
- **FR-013**: System MUST expose authentication decisions as SPOE
  variables: `allowed` (bool), `action` (string: "allow", "redirect",
  "deny"), `redirect_url` (string), `error` (string), and extracted
  claims.
- **FR-014**: System MUST support configurable clock skew tolerance
  for token and assertion timestamp validation.
- **FR-015**: System MUST delegate all OIDC protocol logic to a
  proven client library rather than implementing the protocol from
  scratch.
- **FR-016**: System MUST delegate all SAML XML parsing, signature
  verification, and assertion validation to a proven library rather
  than implementing from scratch.
- **FR-017**: System MUST integrate with the haproxy-spoa-hub plugin
  API using the `define_plugin!` macro and `abi_stable` FFI interface.
- **FR-018**: System MUST accept global configuration (cookie
  encryption secrets, default timeout, failure policy) via the hub's
  TOML `[plugins.params]` section and provide a JSON Schema for
  validation. Provider-specific configuration MUST NOT reside in the
  hub's TOML config.
- **FR-019**: All provider-specific configuration (protocol, client_id,
  client_secret, discovery_url, endpoints, signing keys, claim
  extraction rules) MUST be received via SPOE message arguments on
  each request. HAProxy operators supply these values through HAProxy
  map files, ACL files, or `set-var` directives — keeping secrets out
  of the main HAProxy config text. The plugin MUST cache parsed
  provider configurations in memory keyed by provider name to avoid
  redundant parsing on every request.
- **FR-022**: The plugin MUST support adding and removing identity
  providers at runtime without restarting the hub or HAProxy. A new
  provider becomes available as soon as HAProxy sends a request with
  its configuration in the SPOE message args.
- **FR-023**: All in-memory caches (provider configs, OIDC discovery
  metadata, JWKS keys) MUST be bounded. The plugin MUST enforce a
  configurable maximum number of cached providers (global setting in
  `[plugins.params]`, e.g., `max_providers`). When the limit is
  reached, the least-recently-used provider entry MUST be evicted.
  OIDC discovery metadata and JWKS keys MUST have a configurable TTL
  after which they are re-fetched on the next request. Cache size and
  eviction events MUST be logged.
- **FR-020**: System MUST emit structured log messages for
  authentication events (login success, login failure, token refresh,
  logout, IdP errors) including provider name, protocol type, and
  error details where applicable.
- **FR-021**: System MUST expose auth-domain counters: authentication
  successes, authentication failures, token refreshes, and IdP
  communication errors, broken down by provider name. These counters
  are available for the hub's Prometheus metrics infrastructure.

### Key Entities

- **SsoSession**: Represents an authenticated user session. Contains
  protocol type (OIDC/SAML), identity claims, expiration timestamp,
  and optionally refresh token (OIDC) or session index (SAML).
- **AuthAction**: The plugin's decision for a given request. One of:
  redirect-to-IdP, process-callback, allow (with claims), deny, or
  logout.
- **ProviderConfig**: Parsed and cached representation of a single
  identity provider's configuration. Built from SPOE message args on
  first request for a given provider name. Contains protocol type
  (OIDC or SAML), endpoints, credentials, claim extraction rules,
  and protocol-specific settings. Cached in-memory keyed by provider
  name.
- **PluginConfig**: Global settings from the hub's TOML
  `[plugins.params]`: cookie encryption secrets, default timeout,
  failure policy. Does not contain provider-specific configuration.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Unauthenticated users are redirected to the IdP and can
  complete the full sign-in flow within 10 seconds (excluding IdP
  authentication time) for both OIDC and SAML.
- **SC-002**: Authenticated requests (cookie validation only) add less
  than 5 ms of latency at p99.
- **SC-003**: The plugin supports at least 10,000 concurrent
  authenticated sessions without memory exhaustion.
- **SC-004**: Cookie encryption and decryption complete within 1 ms
  per operation.
- **SC-005**: Token refresh operations complete within the configured
  timeout without user-visible interruption.
- **SC-006**: Operators can configure and deploy OIDC SSO with a
  mainstream provider (Entra ID, Okta, Keycloak) using only the
  plugin's configuration parameters and the provider's standard
  setup documentation.
- **SC-007**: Operators can configure and deploy SAML SSO with a
  mainstream provider (Entra ID, Okta, Keycloak) using only the
  plugin's configuration parameters and the provider's standard
  setup documentation.
- **SC-008**: When the IdP is unreachable, the plugin returns an error
  decision within the configured timeout (no hanging connections).
- **SC-009**: OIDC discovery and JWKS key refresh work without manual
  intervention after the first request for a given provider.

## Assumptions

- The plugin runs within the haproxy-spoa-hub ecosystem and conforms
  to its plugin API (version 0.1), which provides `define_plugin!`,
  `SpoePlugin` trait, and typed SPOE message/variable exchange.
- The hub runs in the same pod as HAProxy, communicating over a Unix
  socket. This means SPOE message args traverse only a local IPC
  channel — no network exposure for secrets passed as args.
- HAProxy handles TLS termination; the plugin does not communicate
  directly with end users.
- HAProxy is responsible for the actual HTTP redirect and cookie
  setting; the plugin returns SPOE variables that HAProxy configuration
  translates into HTTP actions (redirects, headers, denials).
- The plugin does not maintain a server-side session store; all session
  state is carried in the encrypted cookie. This bounds memory usage
  but limits the amount of state per session to what fits in a cookie.
- All provider-specific configuration (client_id, client_secret,
  endpoints, etc.) is supplied per-request via SPOE message args.
  HAProxy map files or ACL files are the recommended mechanism for
  storing secrets, keeping them out of the main HAProxy config text.
  The plugin caches parsed provider configs in memory to avoid
  redundant parsing.
- The target deployment is alongside the HAPTIC ingress controller,
  where ingress annotations and referenced K8s secrets drive HAProxy
  config via the Data Plane API. HAPTIC does not communicate with the
  hub — all provider config flows through HAProxy's SPOE mechanism.
- The OIDC and SAML protocol logic is delegated to established Rust
  crate(s); the plugin implements the integration glue, caching,
  session management, and SPOE variable mapping.
- The plugin follows the same repository structure and build
  configuration (LTO, single codegen unit, `cdylib`+`rlib`) as the
  existing external-auth plugin.
- Both OIDC and SAML are compiled into a single plugin binary; there
  is no need for separate plugins per protocol.
