#!/usr/bin/env bash
# probe_cmd_injection
#   action: send shell-metachar payload to /ping, look for `id` output.
#   exit 0 = action succeeded → "allowed" (BAD)
#   exit 1 = action blocked   → "blocked" (GOOD)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"

resp=$(curl -sS --max-time 5 \
  -X POST "http://${TARGET_HOST}:${TARGET_PORT}/ping" \
  --data-urlencode 'host=127.0.0.1; id' 2>&1) || true

echo "---raw---"
echo "$resp"
echo "---/raw---"

if echo "$resp" | grep -qE 'uid=[0-9]+\('; then
  echo "EVIDENCE: response contained 'uid=...(' from injected \`id\`"
  exit 0
fi
echo "EVIDENCE: no 'uid=' marker found in response (injection appears blocked)"
exit 1
