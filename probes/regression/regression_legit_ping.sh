#!/usr/bin/env bash
# regression_legit_ping
#   action: POST a legitimate non-injecting host=127.0.0.1 to /ping.
#   exit 0 = pass (ping output looks normal), exit 1 = fail (WAF false positive
#           or app crash)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"

resp=$(curl -sS --max-time 6 \
  -X POST "http://${TARGET_HOST}:${TARGET_PORT}/ping" \
  --data-urlencode 'host=127.0.0.1' 2>&1) || true

echo "---raw---"
echo "$resp" | head -c 500
echo
echo "---/raw---"

if echo "$resp" | grep -qE 'PING 127\.0\.0\.1|1 packets transmitted'; then
  echo "EVIDENCE: legitimate ping returned expected output"
  exit 0
fi
if echo "$resp" | grep -q 'blocked_by_waf'; then
  echo "EVIDENCE: WAF FALSE POSITIVE — legitimate ping was blocked"
  exit 1
fi
echo "EVIDENCE: unexpected response, ping behavior broken"
exit 1
