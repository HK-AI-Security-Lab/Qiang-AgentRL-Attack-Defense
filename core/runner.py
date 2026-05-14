"""Container lifecycle wrapper.

Deliberately small: we only need start / stop / wait-ready / exec for the
target. The policy_compiler produces a docker_run.sh; we exec it. To stop
we just `docker rm -f`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import urllib.request
import urllib.error

CONTAINER_NAME = os.environ.get("TARGET_CONTAINER", "autopatch-target")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "18080"))
HEALTHZ_URL = f"http://127.0.0.1:{TARGET_PORT}/healthz"


def _resolve_bash() -> str:
    """Find a real POSIX bash, avoiding Windows' WSL launcher (System32\\bash.exe)
    which only relays into a WSL distro and breaks docker_run.sh on machines
    without WSL installed."""
    override = os.environ.get("AUTOPATCH_BASH")
    if override and Path(override).exists():
        return override

    if sys.platform != "win32":
        return "bash"

    # Probe well-known Git for Windows locations first.
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\bin\bash.exe"),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return c

    # Fall back to PATH lookup, but reject the WSL launcher in System32.
    found = shutil.which("bash")
    if found:
        normalized = found.replace("/", "\\").lower()
        if "\\system32\\bash.exe" not in normalized and "\\windowsapps\\" not in normalized:
            return found

    raise RuntimeError(
        "No usable bash found. Install Git for Windows, or set AUTOPATCH_BASH "
        "to the absolute path of a POSIX bash.exe."
    )


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def down(name: str = CONTAINER_NAME) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)


def up(docker_run_script: Path) -> None:
    """Stop any existing container and start a new one from the generated script."""
    down()
    bash = _resolve_bash()
    res = subprocess.run(
        [bash, str(docker_run_script)], capture_output=True, text=True
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"docker run failed (rc={res.returncode}, bash={bash})\n"
            f"stdout: {res.stdout}\nstderr: {res.stderr}"
        )


def wait_ready(timeout: float = 20.0) -> bool:
    """Poll /healthz until 200 or timeout. Return True on ready."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(HEALTHZ_URL, timeout=1.5) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionResetError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def container_logs(tail: int = 50) -> str:
    res = subprocess.run(
        ["docker", "logs", "--tail", str(tail), CONTAINER_NAME],
        capture_output=True,
        text=True,
    )
    return (res.stdout or "") + (res.stderr or "")
