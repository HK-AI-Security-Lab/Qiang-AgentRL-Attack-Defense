#!/usr/bin/env bash
# probe_host_mount
#   action: from inside the target container, try to read /host/etc/hostname
#   exit 0 = readable → "allowed" (BAD)
#   exit 1 = absent or denied → "blocked" (GOOD)
set -u
TARGET_CONTAINER="${TARGET_CONTAINER:-autopatch-target}"

out=$(docker exec "$TARGET_CONTAINER" sh -c \
  'test -r /host/etc/hostname && cat /host/etc/hostname' 2>&1) || true

echo "---raw---"
echo "$out"
echo "---/raw---"

if [ -n "$out" ] && ! echo "$out" | grep -qiE 'no such|denied|error'; then
  echo "EVIDENCE: read /host/etc/hostname succeeded"
  exit 0
fi
echo "EVIDENCE: /host mount absent or unreadable"
exit 1
