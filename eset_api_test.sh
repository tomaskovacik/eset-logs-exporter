#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Quick test of the ESET Connect API (ESET PROTECT Cloud).
#
# Usage:
#   export ESET_USER='api-user@example.com'
#   export ESET_PASS='secret'          # optional, prompted if unset
#   export ESET_REGION='eu'            # eu | us | de | ca | jpn (default: eu)
#   ./eset_api_test.sh                 # auth + list first page of devices
#   ./eset_api_test.sh device-management /v1/devices
#   ./eset_api_test.sh incident-management /v1/detections
#
# Requires: curl, jq

set -euo pipefail

REGION="${ESET_REGION:-eu}"
SERVICE="${1:-device-management}"
API_PATH="${2:-/v1/devices}"
PAGE_SIZE="${PAGE_SIZE:-10}"

AUTH_URL="https://${REGION}.business-account.iam.eset.systems/oauth/token"
API_URL="https://${REGION}.${SERVICE}.eset.systems${API_PATH}"

for bin in curl jq; do
  command -v "$bin" >/dev/null || { echo "Missing dependency: $bin" >&2; exit 1; }
done

: "${ESET_USER:?Set ESET_USER to the API user email}"
if [[ -z "${ESET_PASS:-}" ]]; then
  read -rsp "Password for ${ESET_USER}: " ESET_PASS; echo
fi

echo "==> Authenticating at ${AUTH_URL}"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT

auth_code=$(curl -sS -o "$TMP" -w '%{http_code}' -X POST "$AUTH_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode "username=${ESET_USER}" \
  --data-urlencode "password=${ESET_PASS}")
auth_body=$(<"$TMP")

if [[ "$auth_code" != 200 ]]; then
  echo "Auth failed (HTTP ${auth_code}):" >&2
  echo "$auth_body" | jq . 2>/dev/null >&2 || echo "$auth_body" >&2
  exit 1
fi

TOKEN=$(jq -r '.access_token' <<<"$auth_body")
expires=$(jq -r '.expires_in // "?"' <<<"$auth_body")
echo "    OK - token received (expires in ${expires}s)"

echo "==> GET ${API_URL}?pageSize=${PAGE_SIZE}"
api_code=$(curl -sS -o "$TMP" -w '%{http_code}' -G "$API_URL" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Accept: application/json' \
  --data-urlencode "pageSize=${PAGE_SIZE}")
api_body=$(<"$TMP")

echo "    HTTP ${api_code}"
echo "$api_body" | jq . 2>/dev/null || echo "$api_body"

[[ "$api_code" == 200 ]]
