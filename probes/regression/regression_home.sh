#!/usr/bin/env bash
# regression_home
#   action: GET /, expect app metadata JSON.
#   exit 0 = pass, exit 1 = fail
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"

resp=$(curl -sS --max-time 5 "http://${TARGET_HOST}:${TARGET_PORT}/" 2>&1) || true

echo "---raw---"
echo "$resp"
echo "---/raw---"

if echo "$resp" | grep -q '"app":"vulnerable-pinger"'; then
  echo "EVIDENCE: homepage JSON intact"
  exit 0
fi
echo "EVIDENCE: homepage broken"
exit 1
