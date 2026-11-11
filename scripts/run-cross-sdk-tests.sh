#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ENV_FILE="$REPO_ROOT/scripts/cross-sdk.env"
ENV_FILE="${1:-$DEFAULT_ENV_FILE}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Environment file '$ENV_FILE' not found."
  echo "Copy scripts/cross-sdk.env.example to scripts/cross-sdk.env and update the values, or pass a custom path."
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required environment variable: $name"
    exit 1
  fi
}

require_env "ZTWARD_KEY_ACCESS_URL"
require_env "ZTWARD_KEY_MANAGER_URL"
require_env "ZTWARD_KEYCLOAK_URL"
require_env "ZTWARD_KEYCLOAK_REALM"
# Tokens expire within minutes, so fetch a fresh one when credentials are configured
if [[ -z "${ZTWARD_BEARER_TOKEN:-}" && -n "${ZTWARD_USERNAME:-}" && -n "${ZTWARD_PASSWORD:-}" ]]; then
  token_args=(--data-urlencode "client_id=${ZTWARD_CLIENT_ID:?ZTWARD_CLIENT_ID is required to fetch a token}")
  if [[ -n "${ZTWARD_CLIENT_SECRET:-}" ]]; then
    token_args+=(--data-urlencode "client_secret=$ZTWARD_CLIENT_SECRET")
  fi
  token_response="$(curl -sS -X POST "$ZTWARD_KEYCLOAK_URL/realms/$ZTWARD_KEYCLOAK_REALM/protocol/openid-connect/token" \
    "${token_args[@]}" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$ZTWARD_USERNAME" \
    --data-urlencode "password=$ZTWARD_PASSWORD")"
  ZTWARD_BEARER_TOKEN="$(jq -r '.access_token // empty' <<<"$token_response")"
  if [[ -z "$ZTWARD_BEARER_TOKEN" ]]; then
    echo "Failed to fetch a token for $ZTWARD_USERNAME: $(jq -r '.error_description // .error // .' <<<"$token_response")"
    exit 1
  fi
  export ZTWARD_BEARER_TOKEN
fi
require_env "ZTWARD_BEARER_TOKEN"
require_env "ZTWARD_POLICY_BASE64"

# One CA setting for every SDK: Go and Java read ZTWARD_GRPC_CA_FILE, Node needs NODE_EXTRA_CA_CERTS.
if [[ -n "${ZTWARD_GRPC_CA_FILE:-}" ]]; then
  [[ "$ZTWARD_GRPC_CA_FILE" = /* ]] || ZTWARD_GRPC_CA_FILE="$REPO_ROOT/$ZTWARD_GRPC_CA_FILE"
  export ZTWARD_GRPC_CA_FILE
  export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-$ZTWARD_GRPC_CA_FILE}"
fi

export ZTWARD_KEY_ACCESS_ADDR="${ZTWARD_KEY_ACCESS_ADDR:-$ZTWARD_KEY_ACCESS_URL}"
export ZTWARD_KEY_ACCESS_URI="${ZTWARD_KEY_ACCESS_URI:-$ZTWARD_KEY_ACCESS_URL}"
export ZTWARD_KEY_MANAGER_ADDR="${ZTWARD_KEY_MANAGER_ADDR:-$ZTWARD_KEY_MANAGER_URL}"
export ZTWARD_KEY_MANAGER_URI="${ZTWARD_KEY_MANAGER_URI:-$ZTWARD_KEY_MANAGER_URL}"
export ZTWARD_PLATFORM_ADDR="${ZTWARD_PLATFORM_ADDR:-${ZTWARD_PLATFORM_URL:-}}"

export ZTWARD_RESOURCE="${ZTWARD_RESOURCE:-integration-resource}"
export ZTWARD_FILENAME="${ZTWARD_FILENAME:-interop.txt}"
export ZTWARD_CONTENT_TYPE="${ZTWARD_CONTENT_TYPE:-text/plain}"

GO_KEY_DIR="${ZTWARD_GO_KEY_DIR:-$REPO_ROOT/artifacts/client-keys/go}"
JS_KEY_DIR="${ZTWARD_JS_KEY_DIR:-$REPO_ROOT/artifacts/client-keys/js}"

mkdir -p "$GO_KEY_DIR" "$JS_KEY_DIR"

export ZTWARD_GO_KEY_DIR="$GO_KEY_DIR"
export ZTWARD_JS_KEY_DIR="$JS_KEY_DIR"

pushd "$REPO_ROOT/sdk/go" > /dev/null
echo "Running cross-SDK integration tests..."
go test -count=1 ./integration
popd > /dev/null
