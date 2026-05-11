#!/usr/bin/env bash
# probe_userns
#   action: try to create a new user namespace from inside the target container.
#   exit 0 = userns creation succeeded → "allowed" (BAD)
#   exit 1 = EPERM / unsupported       → "blocked" (GOOD)
set -u
TARGET_CONTAINER="${TARGET_CONTAINER:-autopatch-target}"

out=$(docker exec "$TARGET_CONTAINER" sh -c 'unshare -U id 2>&1') || true

echo "---raw---"
echo "$out"
echo "---/raw---"

if echo "$out" | grep -qE 'uid=[0-9]+\('; then
  echo "EVIDENCE: unshare -U succeeded, userns creation allowed"
  exit 0
fi
echo "EVIDENCE: unshare -U blocked (seccomp/no_new_privs)"
exit 1
