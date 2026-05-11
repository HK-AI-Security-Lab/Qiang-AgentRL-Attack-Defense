#!/usr/bin/env bash
# probe_docker_sock
#   action: from inside the target container, talk to docker.sock if mounted.
#   exit 0 = sock reachable & responsive → "allowed" (BAD)
#   exit 1 = sock absent or unreachable  → "blocked" (GOOD)
set -u
TARGET_CONTAINER="${TARGET_CONTAINER:-autopatch-target}"

out=$(docker exec "$TARGET_CONTAINER" sh -c '
  if [ ! -S /var/run/docker.sock ]; then echo "NO_SOCK"; exit 9; fi
  curl -sS --max-time 3 --unix-socket /var/run/docker.sock \
       http://localhost/v1.41/info 2>&1
' 2>&1) || true

echo "---raw---"
echo "$out" | head -c 400
echo
echo "---/raw---"

if echo "$out" | grep -qE '"ServerVersion"|"Containers"'; then
  echo "EVIDENCE: docker.sock leaked, ServerVersion reachable from inside container"
  exit 0
fi
echo "EVIDENCE: docker.sock not exposed"
exit 1
