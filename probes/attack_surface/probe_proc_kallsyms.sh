#!/usr/bin/env bash
# probe_proc_kallsyms
#   action: read kernel symbol addresses from inside the target container.
#   exit 0 = leak (non-zero addresses)             → "allowed" (BAD)
#   exit 1 = file absent / zero / kptr_restrict   → "blocked" (GOOD)
set -u
TARGET_CONTAINER="${TARGET_CONTAINER:-autopatch-target}"

out=$(docker exec "$TARGET_CONTAINER" sh -c 'head -3 /proc/kallsyms 2>&1') || true

echo "---raw---"
echo "$out"
echo "---/raw---"

if echo "$out" | grep -qE '^[1-9a-f][0-9a-f]{8,} '; then
  echo "EVIDENCE: /proc/kallsyms leaks non-zero kernel addresses"
  exit 0
fi
echo "EVIDENCE: /proc/kallsyms zeroed, missing or unreadable"
exit 1
