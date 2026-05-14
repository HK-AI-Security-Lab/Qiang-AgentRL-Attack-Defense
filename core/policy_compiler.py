"""Deterministic compiler: policy_intent.yaml -> runnable artifacts.

Outputs into the iteration directory:
  - docker_run.sh    bash script that (re)starts the target container
  - waf_rules.json   read by the Flask app at request time
  - seccomp.json     optional, when profile==RuntimeDefault we emit None and
                     rely on docker's --security-opt seccomp=runtime/default
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

import yaml

CONTAINER_NAME = os.environ.get("TARGET_CONTAINER", "autopatch-target")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "18080"))


def _docker_run_lines(pi: dict[str, Any], iter_dir: Path) -> list[str]:
    img = pi["target"]["image"]
    c = pi["controls"]

    args: list[str] = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        CONTAINER_NAME,
        "-p",
        f"{TARGET_PORT}:8080",
    ]

    cs = c["container_security"]
    if cs.get("privileged"):
        args.append("--privileged")
    if cs.get("read_only_root_fs"):
        args += ["--read-only", "--tmpfs", "/tmp"]
    if cs.get("no_new_privileges"):
        args += ["--security-opt", "no-new-privileges:true"]
    if cs.get("run_as_non_root"):
        args += ["--user", "1000:1000"]

    for cap in c["capabilities"].get("drop", []):
        args += ["--cap-drop", cap]
    for cap in c["capabilities"].get("add", []):
        args += ["--cap-add", cap]

    profile = c["seccomp"]["profile"]
    if profile == "Unconfined":
        args += ["--security-opt", "seccomp=unconfined"]

    if c["namespace"].get("pid_host"):
        args += ["--pid", "host"]

    for m in c["mounts"].get("bind", []):
        ro = ":ro" if m.get("readonly") else ""
        args += ["-v", f"{m['host_path']}:{m['container_path']}{ro}"]

    waf_path = iter_dir / "waf_rules.json"
    args += ["-v", f"{waf_path.resolve()}:/etc/autopatch/waf_rules.json:ro"]
    args += ["-e", "WAF_RULES_PATH=/etc/autopatch/waf_rules.json"]

    args.append(img)
    return [shlex.join(args)]


def _waf_rules(pi: dict[str, Any]) -> dict[str, Any]:
    waf = pi["controls"]["app_waf"]
    if not waf.get("enabled"):
        return {"block_patterns": []}
    out: dict[str, Any] = {"block_patterns": list(waf.get("block_patterns", []))}
    for key in (
        "disabled_endpoints",
        "ssrf_allowed_schemes",
        "ssrf_allowed_hosts",
        "path_traversal_block",
        "sqli_parameterized",
        "ssti_sandbox",
        "pickle_disabled",
    ):
        if key in waf:
            out[key] = waf[key]
    return out


def compile_intent(intent_path: Path, iter_dir: Path) -> dict[str, Path]:
    iter_dir.mkdir(parents=True, exist_ok=True)
    data = yaml.safe_load(intent_path.read_text(encoding='utf-8'))
    pi = data["policy_intent"]

    waf_json = iter_dir / "waf_rules.json"
    waf_json.write_text(json.dumps(_waf_rules(pi), indent=2), encoding='utf-8')

    docker_lines = _docker_run_lines(pi, iter_dir)
    run_sh = iter_dir / "docker_run.sh"
    run_sh.write_text("#!/usr/bin/env bash\nset -euo pipefail\n"
    "docker rm -f "
    + CONTAINER_NAME
    + " >/dev/null 2>&1 || true\n"
    + "\n".join(docker_lines)
    + "\n", encoding='utf-8')
    run_sh.chmod(0o755)

    return {"docker_run": run_sh, "waf_rules": waf_json}
