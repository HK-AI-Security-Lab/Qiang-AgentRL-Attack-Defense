#!/usr/bin/env bash
# regression_health
#   action: GET /healthz, expect HTTP 200.
#   exit 0 = pass, exit 1 = fail
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"

code=$(curl -s -o /tmp/health.body -w "%{http_code}" --max-time 5 \
  "http://${TARGET_HOST}:${TARGET_PORT}/healthz" 2>&1) || code="ERR"
body=$(cat /tmp/health.body 2>/dev/null || true)

echo "---raw---"
echo "http=$code"
echo "$body"
echo "---/raw---"

if [ "$code" = "200" ] && echo "$body" | grep -q '"status":"ok"'; then
  echo "EVIDENCE: /healthz returned 200 status=ok"
  exit 0
fi
echo "EVIDENCE: /healthz unexpected (code=$code)"
exit 1
