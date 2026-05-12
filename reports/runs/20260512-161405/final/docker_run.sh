#!/usr/bin/env bash
set -euo pipefail
docker rm -f autopatch-target >/dev/null 2>&1 || true
docker run -d --rm --name autopatch-target -p 18080:8080 --cap-add SYS_ADMIN --security-opt seccomp=unconfined -v '/Users/qli/Desktop/agent-rl-attack&defense/reports/runs/20260512-161405/iters/iter-001/waf_rules.json:/etc/autopatch/waf_rules.json:ro' -e WAF_RULES_PATH=/etc/autopatch/waf_rules.json autopatch-target:vuln
