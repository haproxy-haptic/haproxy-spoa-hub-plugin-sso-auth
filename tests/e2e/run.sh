#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLUSTER_NAME="e2e-sso-auth-$(shuf -i 1000-9999 -n 1)"
E2E_PORT="${E2E_PORT:-$(shuf -i 20000-50000 -n 1)}"
PASSED=0
FAILED=0
TMPDIR="$(mktemp -d)"
COOKIE_JAR="${TMPDIR}/cookies.txt"

cleanup() {
    echo "--- Cleanup ---"
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

# --- Assertion helpers ---
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        echo "  PASS: ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: ${desc} (expected='${expected}', actual='${actual}')"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if [[ "${haystack}" == *"${needle}"* ]]; then
        echo "  PASS: ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: ${desc} (output does not contain '${needle}')"
        FAILED=$((FAILED + 1))
    fi
}

assert_not_eq() {
    local desc="$1" unexpected="$2" actual="$3"
    if [[ "${unexpected}" != "${actual}" ]]; then
        echo "  PASS: ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: ${desc} (got unexpected '${unexpected}')"
        FAILED=$((FAILED + 1))
    fi
}

# --- Resolve host for Docker-in-Docker ---
# In DinD, NodePort is on the Docker service container, not the CI job.
if [[ -n "${DOCKER_HOST:-}" ]]; then
    NODE_HOST=$(echo "$DOCKER_HOST" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
    NODE_HOST=${NODE_HOST:-docker}
    API_ADDR="0.0.0.0"
else
    NODE_HOST="127.0.0.1"
    API_ADDR="127.0.0.1"
fi
BASE_URL="http://${NODE_HOST}:${E2E_PORT}"

echo "=== E2E Test: SSO Auth Plugin ==="
echo "Cluster: ${CLUSTER_NAME}"
echo "Port: ${E2E_PORT}"
echo "Base URL: ${BASE_URL}"
echo ""

# --- Create kind cluster ---
echo "--- Creating kind cluster ---"
cat <<EOF | kind create cluster --name "${CLUSTER_NAME}" --wait 60s --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "${API_ADDR}"
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: ${E2E_PORT}
    protocol: TCP
EOF

# In DinD, replace 0.0.0.0 in kubeconfig with the Docker service hostname.
if [ -n "${DOCKER_HOST:-}" ]; then
    DOCKER_HOST_NAME=$(echo "$DOCKER_HOST" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
    DOCKER_HOST_NAME=${DOCKER_HOST_NAME:-docker}
    sed -i "s|server: https://0\.0\.0\.0:|server: https://${DOCKER_HOST_NAME}:|" "$HOME/.kube/config"
    kubectl config set-cluster "kind-${CLUSTER_NAME}" --insecure-skip-tls-verify=true
fi

echo "Waiting for cluster readiness..."
for i in $(seq 1 60); do
    if kubectl get nodes >/dev/null 2>&1; then
        echo "API server reachable after ${i}s"
        break
    fi
    sleep 2
done
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# --- Build and load Docker image ---
echo "--- Building plugin image ---"
docker build -t e2e-hub:latest -f "${SCRIPT_DIR}/Dockerfile.hub" "${REPO_ROOT}"
kind load docker-image e2e-hub:latest --name "${CLUSTER_NAME}"

# --- Patch redirect URI with actual host:port ---
REDIRECT_URI="${BASE_URL}/oidc-app/callback"
sed "s|__REDIRECT_URI__|${REDIRECT_URI}|g" \
    "${SCRIPT_DIR}/manifests/configmaps.yaml" > "${TMPDIR}/configmaps.yaml"

# --- Apply manifests ---
echo "--- Deploying manifests ---"
kubectl apply -f "${SCRIPT_DIR}/manifests/namespace.yaml"
kubectl apply -f "${TMPDIR}/configmaps.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/mock-oidc.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/haproxy-hub.yaml"

# --- Wait for pods ---
echo "--- Waiting for pods ---"
kubectl -n e2e-sso-auth wait --for=condition=Ready pod -l app=mock-oidc --timeout=120s
kubectl -n e2e-sso-auth wait --for=condition=Ready pod -l app=haproxy-hub --timeout=120s

# Wait for HAProxy to start accepting connections.
echo "Waiting for HAProxy readiness..."
HAPROXY_READY=false
for i in $(seq 1 60); do
    if curl -sf -o /dev/null --max-time 3 "${BASE_URL}/mock-oidc/default/.well-known/openid-configuration" 2>/dev/null; then
        echo "HAProxy ready after ${i}s"
        HAPROXY_READY=true
        break
    fi
    sleep 2
done
if [[ "${HAPROXY_READY}" != "true" ]]; then
    echo "WARNING: HAProxy readiness check timed out after 120s"
    echo "Attempting to continue anyway..."
    # Dump pod status for debugging.
    kubectl -n e2e-sso-auth get pods -o wide 2>/dev/null || true
    echo "--- HAProxy container logs ---"
    kubectl -n e2e-sso-auth logs -l app=haproxy-hub -c haproxy --tail=30 2>/dev/null || true
    echo "--- Hub container logs ---"
    kubectl -n e2e-sso-auth logs -l app=haproxy-hub -c hub --tail=30 2>/dev/null || true
fi

echo ""
echo "=== Running OIDC Tests ==="

# The browser leg runs inside the cluster: the mock IdP's authorize endpoint
# carries its in-cluster host name, which the host can't resolve.
APP="http://haproxy-hub:8080"
incurl() {
    kubectl -n e2e-sso-auth exec deploy/haproxy-hub -c curl -- curl -s --max-time 15 "$@"
}

# --- Test 1: Unauthenticated request returns redirect ---
echo "Test 1: Unauthenticated request returns redirect"
HEADERS=$(incurl -D - -o /dev/null "${APP}/oidc-app/page?x=1" || true)
assert_contains "HTTP status is 302" "${HEADERS}" "302"
assert_contains "Redirect to authorize endpoint" "${HEADERS}" "authorize"
assert_contains "Redirect contains code_challenge" "${HEADERS}" "code_challenge"
assert_contains "Auth state cookie set on the redirect" "${HEADERS}" "sso_auth_state="
LEGACY=$(incurl -D - -o /dev/null "${APP}/legacy-app" || true)
assert_contains "provider_config map provider still redirects" "${LEGACY}" "authorize"

# --- Test 2: Full OIDC flow returns to the original page ---
echo ""
echo "Test 2: Full OIDC flow with auto-grant"
RESPONSE=$(incurl -L -c /tmp/jar -b /tmp/jar --max-redirs 10 -w '\nfinal=%{url_effective}' "${APP}/oidc-app/page?x=1" || true)
if [[ "${RESPONSE}" != *"allowed=true"* ]]; then
    echo "--- Sign-in response chain ---"
    incurl -v -L -c /tmp/jar-debug -b /tmp/jar-debug --max-redirs 10 "${APP}/oidc-app/page?x=1" 2>&1 | grep -E '^[<>] (GET|HTTP|[Ll]ocation|[Ss]et-[Cc]ookie|[Cc]ookie)' || true
    echo "--- Hub log ---"
    kubectl -n e2e-sso-auth logs deploy/haproxy-hub -c hub --tail=30 2>/dev/null || true
fi
echo "--- Signed-in response ---"
printf '%s\n' "${RESPONSE}" | cut -c1-120
assert_contains "Response contains allowed=true" "${RESPONSE}" "allowed=true"
assert_contains "Returned to the original page" "${RESPONSE}" "final=${APP}/oidc-app/page?x=1"
assert_contains "Claim extracted" "${RESPONSE}" "email=testuser@example.com"
TOKEN=$(printf '%s\n' "${RESPONSE}" | sed -n 's/^token=//p')
assert_eq "ID token passed (three JWT segments)" "3" "$(printf '%s' "${TOKEN}" | awk -F. '{print NF}')"
JAR=$(kubectl -n e2e-sso-auth exec deploy/haproxy-hub -c curl -- cat /tmp/jar 2>/dev/null || true)
assert_contains "Session cookie stored" "${JAR}" "sso_session"

# --- Test 3: Authenticated request with cookie ---
echo ""
echo "Test 3: Authenticated request with cookie"
RESPONSE=$(incurl -D - -b /tmp/jar "${APP}/oidc-app/other-page" || true)
assert_contains "Authenticated response" "${RESPONSE}" "allowed=true"
assert_contains "Expiring token refreshed into a new session cookie" "${RESPONSE}" "set-cookie: sso_session="

# --- Test 4: Group check ---
echo ""
echo "Test 4: Signed-in user outside the required group gets 403"
CODE=$(incurl -o /dev/null -w '%{http_code}' -b /tmp/jar "${APP}/admin-app" || echo "000")
assert_eq "HTTP status is 403" "403" "${CODE}"

echo "Test 4a: Signed-in user in one of the required groups is admitted"
RESPONSE=$(incurl -b /tmp/jar "${APP}/users-app" || true)
assert_contains "Group member admitted" "${RESPONSE}" "allowed=true"
assert_contains "Groups claim extracted" "${RESPONSE}" "groups=admin,users"

# --- Test 4b: Forged session rejected ---
echo ""
echo "Test 4b: Forged session cookie starts a new sign-in"
CODE=$(incurl -o /dev/null -w '%{http_code}' -H 'Cookie: sso_session=AAAA' "${APP}/oidc-app" || echo "000")
assert_eq "HTTP status is 302" "302" "${CODE}"

# --- Test 5: Fail-closed (OIDC IdP down) ---
echo ""
echo "Test 5: Fail-closed when IdP is down"
kubectl -n e2e-sso-auth scale deployment/mock-oidc --replicas=0 2>/dev/null
sleep 5
# Clear cookies for a fresh unauthenticated request.
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/oidc-app" 2>/dev/null || echo "000")
assert_not_eq "Not HTTP 200 when IdP down" "200" "${HTTP_CODE}"

# Restore mock-oidc.
kubectl -n e2e-sso-auth scale deployment/mock-oidc --replicas=1 2>/dev/null

# --- Hub log verification ---
echo ""
echo "=== Hub Log Verification ==="
HUB_POD=$(kubectl -n e2e-sso-auth get pods -l app=haproxy-hub -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -n "${HUB_POD}" ]]; then
    HUB_LOGS=$(kubectl -n e2e-sso-auth logs "${HUB_POD}" -c hub 2>/dev/null || echo "")
    if [[ -n "${HUB_LOGS}" ]]; then
        assert_contains "Hub logs contain plugin activity" "${HUB_LOGS}" "sso_auth"
    else
        echo "  SKIP: No hub logs available"
    fi
else
    echo "  SKIP: Hub pod not found"
fi

# --- Results ---
echo ""
echo "=== Results ==="
echo "PASSED: ${PASSED}"
echo "FAILED: ${FAILED}"
TOTAL=$((PASSED + FAILED))
echo "TOTAL:  ${TOTAL}"

if [[ ${FAILED} -gt 0 ]]; then
    exit 1
fi
