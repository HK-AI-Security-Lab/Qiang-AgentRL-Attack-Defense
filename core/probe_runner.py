"""Run the white-listed probe scripts and normalise output to ProbeResult JSON."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "probes" / "registry.yaml"

_EVIDENCE_RE = re.compile(r"^EVIDENCE:\s*(.+)$", re.MULTILINE)


def load_registry() -> list[dict[str, Any]]:
    return yaml.safe_load(REGISTRY_PATH.read_text())["probes"]


def _classify(category: str, exit_code: int) -> str:
    if category == "attack_surface":
        return "allowed" if exit_code == 0 else "blocked"
    if category == "regression":
        return "pass" if exit_code == 0 else "fail"
    return "error"


def _evidence_from(stdout: str) -> str:
    m = list(_EVIDENCE_RE.finditer(stdout))
    if m:
        return m[-1].group(1).strip()
    return stdout.strip().splitlines()[-1] if stdout.strip() else ""


def run_one(spec: dict[str, Any], iteration: int) -> dict[str, Any]:
    env = os.environ.copy()
    env.setdefault("TARGET_HOST", "127.0.0.1")
    env.setdefault("TARGET_PORT", os.environ.get("TARGET_PORT", "18080"))
    env.setdefault("TARGET_CONTAINER", os.environ.get("TARGET_CONTAINER", "autopatch-target"))
    script = Path(__file__).resolve().parent.parent / spec["script"]

    t0 = time.time()
    try:
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        rc = proc.returncode
        out = proc.stdout or ""
        err = proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = (e.stdout or b"").decode("utf-8", "ignore") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = "probe timed out"
    duration = round(time.time() - t0, 3)

    actual = _classify(spec["category"], rc) if rc in (0, 1) else "error"

    return {
        "probe_id": spec["id"],
        "category": spec["category"],
        "severity": spec["severity"],
        "expected": spec["expected"],
        "actual": actual,
        "evidence": _evidence_from(out)[:400],
        "raw_stdout": out[-2000:],
        "raw_stderr": err[-1000:],
        "exit_code": rc,
        "iteration": iteration,
        "duration_s": duration,
    }


def run_all(iteration: int) -> list[dict[str, Any]]:
    return [run_one(spec, iteration) for spec in load_registry()]
