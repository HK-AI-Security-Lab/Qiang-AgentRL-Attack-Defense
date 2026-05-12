#!/usr/bin/env bash
set -euo pipefail
docker rm -f autopatch-target >/dev/null 2>&1 || true
docker run -d --rm --name autopatch-target -p 18080:8080 --security-opt no-new-privileges:true --user 1000:1000 --cap-drop ALL --cap-add NET_RAW -v '/Users/qli/Desktop/agent-rl-attack&defense/reports/runs/20260512-000154/iters/iter-002/waf_rules.json:/etc/autopatch/waf_rules.json:ro' -e WAF_RULES_PATH=/etc/autopatch/waf_rules.json autopatch-target:vuln
