#!/usr/bin/env bash
set -euo pipefail
docker rm -f autopatch-target >/dev/null 2>&1 || true
docker run -d --rm --name autopatch-target -p 18080:8080 --security-opt no-new-privileges:true --cap-drop ALL --cap-add NET_RAW -v 'D:\Codebase\AutoPatch-RL Demo\Qiang-AgentRL-Attack-Defense\reports\runs\20260514-201752\iters\iter-009\waf_rules.json:/etc/autopatch/waf_rules.json:ro' -e WAF_RULES_PATH=/etc/autopatch/waf_rules.json autopatch-target:vuln
