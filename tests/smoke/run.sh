#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SMOKE_PORT="${SMOKE_PORT:-$(shuf -i 20000-50000 -n 1)}"
LIB_NAME="libhaproxy_spoa_hub_plugin_sso_auth"
GLIBC_VERSION="2.36"

# --- Parse arguments ---
ARCH=""
MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "${ARCH}" || -z "${MODE}" ]]; then
    echo "Usage: $0 --arch {arm64|armv7} --mode {load-only|oidc-flow}"
    exit 1
fi

case "${ARCH}" in
    arm64)  DOCKER_PLATFORM="linux/arm64" ;;
    armv7)  DOCKER_PLATFORM="linux/arm/v7" ;;
    *)      echo "Unsupported arch: ${ARCH}"; exit 1 ;;
esac

# --- Resolve host for Docker-in-Docker ---
if [[ -n "${DOCKER_HOST:-}" ]]; then
    NODE_HOST=$(echo "$DOCKER_HOST" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
    NODE_HOST=${NODE_HOST:-docker}
else
    NODE_HOST="127.0.0.1"
fi
BASE_URL="http://${NODE_HOST}:${SMOKE_PORT}"

echo "=== Smoke Test: ${ARCH} (${MODE}) ==="
echo "Platform: ${DOCKER_PLATFORM}"
echo "Port: ${SMOKE_PORT}"
echo ""

# --- Locate the pre-built .so artifact ---
ARTIFACT="${REPO_ROOT}/artifacts/${LIB_NAME}-${ARCH}-glibc${GLIBC_VERSION}.so"
if [[ ! -f "${ARTIFACT}" ]]; then
    echo "ERROR: Artifact not found: ${ARTIFACT}"
    exit 1
fi
cp "${ARTIFACT}" "${SCRIPT_DIR}/plugin.so"

# --- Cleanup ---
cleanup() {
    echo "--- Cleanup ---"
    docker rm -f smoke-hub smoke-haproxy smoke-mock-oidc 2>/dev/null || true
    docker network rm smoke-net 2>/dev/null || true
    docker volume rm smoke-spoe 2>/dev/null || true
    rm -f "${SCRIPT_DIR}/plugin.so" "${SCRIPT_DIR}/sso-providers-resolved.map"
}
trap cleanup EXIT

# --- Build hub image for target platform ---
echo "--- Building hub image (${DOCKER_PLATFORM}) ---"
DOCKER_BUILDKIT=1 docker build \
    --platform "${DOCKER_PLATFORM}" \
    -t smoke-hub:latest \
    -f "${SCRIPT_DIR}/Dockerfile.hub" \
    "${SCRIPT_DIR}"

# --- Create network and volume ---
docker network create smoke-net
docker volume create smoke-spoe

# --- Start hub ---
echo "--- Starting hub ---"
docker run -d --name smoke-hub \
    --network smoke-net \
    --platform "${DOCKER_PLATFORM}" \
    -v "${SCRIPT_DIR}/hub-config.toml:/config/config.toml:ro" \
    -v smoke-spoe:/var/run/spoe \
    smoke-hub:latest \
    --config /config/config.toml

# --- Wait for plugin to load ---
echo "Waiting for plugin initialization..."
PLUGIN_LOADED=false
for i in $(seq 1 60); do
    if docker logs smoke-hub 2>&1 | grep -q "sso_auth"; then
        echo "Plugin loaded after ${i}s"
        PLUGIN_LOADED=true
        break
    fi
    sleep 1
done

if [[ "${PLUGIN_LOADED}" != "true" ]]; then
    echo "FAIL: Plugin did not initialize within 60s"
    echo "--- Hub logs ---"
    docker logs smoke-hub 2>&1 || true
    exit 1
fi

echo "PASS: Plugin loaded successfully"

if [[ "${MODE}" == "load-only" ]]; then
    echo ""
    echo "=== Results ==="
    echo "PASSED: 1"
    echo "FAILED: 0"
    exit 0
fi

# --- OIDC flow test (oidc-flow mode) ---
echo ""
echo "--- Starting OIDC flow test ---"

# Resolve redirect URI in provider map
sed "s|__REDIRECT_URI__|${BASE_URL}/oidc-app/callback|g" \
    "${SCRIPT_DIR}/sso-providers.map" > "${SCRIPT_DIR}/sso-providers-resolved.map"

# Start mock OIDC server
docker run -d --name smoke-mock-oidc \
    --network smoke-net \
    --platform "${DOCKER_PLATFORM}" \
    -e JSON_CONFIG_PATH=/config/config.json \
    -v "${SCRIPT_DIR}/mock-oidc-config.json:/config/config.json:ro" \
    ghcr.io/navikt/mock-oauth2-server:2.1.10

# Start HAProxy
docker run -d --name smoke-haproxy \
    --network smoke-net \
    --platform "${DOCKER_PLATFORM}" \
    -p "${SMOKE_PORT}:8080" \
    -v "${SCRIPT_DIR}/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "${SCRIPT_DIR}/spoe-sso-auth.conf:/etc/haproxy/spoe-sso-auth.conf:ro" \
    -v "${SCRIPT_DIR}/sso-providers-resolved.map:/etc/haproxy/maps/sso-providers.map:ro" \
    -v smoke-spoe:/var/run/spoe \
    haproxytech/haproxy-debian:3.3

# Wait for HAProxy to accept connections
echo "Waiting for HAProxy readiness..."
HAPROXY_READY=false
for i in $(seq 1 90); do
    if curl -sf -o /dev/null --max-time 3 "${BASE_URL}/mock-oidc/default/.well-known/openid-configuration" 2>/dev/null; then
        echo "HAProxy ready after ${i}s"
        HAPROXY_READY=true
        break
    fi
    sleep 2
done

PASSED=0
FAILED=0

if [[ "${HAPROXY_READY}" != "true" ]]; then
    echo "FAIL: HAProxy did not become ready within 180s"
    echo "--- HAProxy logs ---"
    docker logs smoke-haproxy 2>&1 | tail -20 || true
    echo "--- Hub logs ---"
    docker logs smoke-hub 2>&1 | tail -20 || true
    echo "--- Mock OIDC logs ---"
    docker logs smoke-mock-oidc 2>&1 | tail -20 || true
    FAILED=$((FAILED + 1))
else
    # Test: Unauthenticated request returns 302 redirect
    echo "Test: Unauthenticated request returns redirect"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/oidc-app" || echo "000")
    if [[ "${HTTP_CODE}" == "302" ]]; then
        echo "  PASS: HTTP status is 302"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: HTTP status is ${HTTP_CODE}, expected 302"
        FAILED=$((FAILED + 1))
    fi

    # Test: Redirect contains authorize endpoint
    TMPHEADERS="$(mktemp)"
    curl -s -D "${TMPHEADERS}" -o /dev/null --max-time 10 "${BASE_URL}/oidc-app" 2>/dev/null || true
    LOCATION=$(grep -i "location" "${TMPHEADERS}" 2>/dev/null | head -1 || true)
    rm -f "${TMPHEADERS}"
    if echo "${LOCATION}" | grep -q "authorize"; then
        echo "  PASS: Redirect to authorize endpoint"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: Location header does not contain 'authorize'"
        FAILED=$((FAILED + 1))
    fi
fi

# Plugin load counts as a pass too
PASSED=$((PASSED + 1))

echo ""
echo "=== Results ==="
echo "PASSED: ${PASSED}"
echo "FAILED: ${FAILED}"
TOTAL=$((PASSED + FAILED))
echo "TOTAL:  ${TOTAL}"

if [[ ${FAILED} -gt 0 ]]; then
    exit 1
fi
