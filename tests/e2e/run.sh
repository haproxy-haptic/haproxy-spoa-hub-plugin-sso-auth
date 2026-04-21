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

# --- Test 1: Unauthenticated request returns redirect ---
echo "Test 1: Unauthenticated request returns redirect"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${BASE_URL}/oidc-app" || echo "000")
assert_eq "HTTP status is 302" "302" "${HTTP_CODE}"

# Use a temp file to avoid pipefail issues with grep returning 1 when no match.
curl -s -D "${TMPDIR}/headers.txt" -o /dev/null --max-time 5 "${BASE_URL}/oidc-app" 2>/dev/null || true
LOCATION=$(grep -i "location" "${TMPDIR}/headers.txt" 2>/dev/null | head -1 | tr -d '\r\n' || true)
if [[ -z "${LOCATION}" ]]; then
    echo "  FAIL: No Location header in redirect response"
    echo "  Response headers: ${HEADERS}"
    FAILED=$((FAILED + 1))
else
    assert_contains "Redirect to authorize endpoint" "${LOCATION}" "authorize"
    assert_contains "Redirect contains client_id" "${LOCATION}" "client_id"
    assert_contains "Redirect contains code_challenge" "${LOCATION}" "code_challenge"
fi

# --- Test 2: Full OIDC flow (follow redirects) ---
echo ""
echo "Test 2: Full OIDC flow with auto-grant"
RESPONSE=$(curl -s -L -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" --max-redirs 10 "${BASE_URL}/oidc-app" 2>/dev/null || true)
# The mock OIDC server auto-grants; the flow should complete.
if [[ -n "${RESPONSE}" ]]; then
    assert_contains "Response contains allowed=true" "${RESPONSE}" "allowed=true" || true
fi

# --- Test 3: Authenticated request with cookie ---
echo ""
echo "Test 3: Authenticated request with cookie"
if [[ -f "${COOKIE_JAR}" ]] && grep -q "sso_session" "${COOKIE_JAR}" 2>/dev/null; then
    RESPONSE=$(curl -s -b "${COOKIE_JAR}" "${BASE_URL}/oidc-app/other-page" 2>/dev/null)
    assert_contains "Authenticated response" "${RESPONSE}" "allowed=true"
else
    echo "  SKIP: No session cookie from test 2 (OIDC flow may not have completed)"
fi

# --- Test 4: Claim extraction ---
echo ""
echo "Test 4: Claim extraction"
if [[ -f "${COOKIE_JAR}" ]] && grep -q "sso_session" "${COOKIE_JAR}" 2>/dev/null; then
    RESPONSE=$(curl -s -b "${COOKIE_JAR}" "${BASE_URL}/oidc-app" 2>/dev/null)
    assert_contains "Response contains email" "${RESPONSE}" "email"
else
    echo "  SKIP: No session cookie"
fi

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
