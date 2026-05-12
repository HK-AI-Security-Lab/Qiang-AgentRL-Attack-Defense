# Security Hardening Report: autopatch-target:vuln

## TL;DR

**Starting state:** Misconfigured container running as root with SYS_ADMIN capability, unconfined seccomp, host filesystem mounted at `/host`, and Docker socket exposed at `/var/run/docker.sock`. Attack surface included 6 high-severity application flaws (command injection, SSRF, path traversal, SQLi, SSTI, deserialization RCE) plus 4 container-level escape vectors.

**Iterations:** 2 completed.

**Final policy (iter-001):** Removed all bind mounts; SYS_ADMIN and unconfined seccomp remain. Blocks `probe_host_mount` and `probe_docker_sock` but leaves application vulnerabilities and privilege escalation vectors open.

---

## Iteration-by-iteration

### Iter-000 (Baseline)
Agent observed fully misconfigured baseline. All 6 red-team application probes passed (command injection, SSRF, path traversal, SQLi, SSTI, deserialization RCE). Container-level probes showed: `probe_cmd_injection` allowed, `probe_host_mount` allowed (read `/host/etc/hostname`), `probe_docker_sock` allowed (Docker API reachable), `probe_userns` allowed (unshare -U succeeded). Regression suite passed (health, legit_ping, homepage).

**Probe outcome changes:** N/A (baseline).

**Score:** −1610 (6 high-severity allowed attacks, 2 high-severity mounts exposed, 1 medium-severity userns allowed).

---

### Iter-001 (Remove Mounts)
Agent removed both bind mounts (`/host` and `/var/run/docker.sock`). Rationale: mounts are highest-impact escape vectors requiring no application-level exploitation.

**Probe outcome changes vs. iter-000:**
- `probe_host_mount`: **allowed → blocked** ✓ (mount absent)
- `probe_docker_sock`: **allowed → blocked** ✓ (socket not exposed)
- `probe_cmd_injection`: allowed (unchanged; application flaw)
- `probe_userns`: allowed (unchanged; no seccomp restriction)
- `dyn_path_1`: **blocked → allowed** ✗ (new bypass: `../../../../etc/passwd` now succeeds; previously blocked by `....//` filter)
- All regression tests: **pass** (health, legit_ping, homepage)

**Score delta:** −1610 → −1490 (+120). Gained +200 for blocking 2 high-severity mount probes; lost −80 due to new path traversal bypass.

---

## Final Policy

```yaml
policy_intent:
  name: harden-iter-1-mounts
  target:
    image: autopatch-target:vuln
  controls:
    container_security:
      run_as_non_root: false
      allow_privilege_escalation: true
      read_only_root_fs: false
      no_new_privileges: false
      privileged: false
    capabilities:
      drop: []
      add:
      - SYS_ADMIN
    seccomp:
      profile: Unconfined
    mounts:
      bind: []
    namespace:
      pid_host: false
    app_waf:
      enabled: false
      block_patterns: []
```

**Concrete defenses deployed:**
- **Removed mounts:** `/host` (read-only host filesystem) and `/var/run/docker.sock` (Docker daemon socket).
- **Retained vulnerabilities:** SYS_ADMIN capability, unconfined seccomp, root user, allow_privilege_escalation=true, no WAF.

---

## Residual Risk / Future Work

**Uncovered attack surface:**

1. **Application-layer vulnerabilities (6 high-severity):** Command injection (`probe_cmd_injection`, `dyn_cmd_1`), SSRF (`red_ssrf`, `dyn_ssrf_1`, `dyn_ssrf_2`), path traversal (`red_path_traversal`, `dyn_path_1`), SQLi (`red_sqli`), SSTI (`red_ssti`, `dyn_ssti_1`), deserialization RCE (`red_deserialization`) all remain exploitable. These require WAF rules or application fixes (e.g., parameterized queries, template sandboxing, input validation).

2. **Privilege escalation:** `allow_privilege_escalation=true` + `SYS_ADMIN` capability + unconfined seccomp allow container escape via kernel exploits or capability abuse. `probe_userns` still succeeds.

3. **Root execution:** `run_as_non_root=false` means any RCE (e.g., via deserialization or SSTI) executes as uid=0.

4. **No seccomp filtering:** Unconfined profile permits all syscalls; restricting to a baseline profile (e.g., Docker default) would block namespace creation and kernel module loading.

**Next iteration should address:** (1) Enable WAF with patterns for SQLi (`UNION SELECT`, `--`, `/*`), SSTI (`{{`, `{%`), path traversal (`../`, `%2e%2e`), SSRF (`file://`, `127.0.0.1`, `localhost`); (2) Drop SYS_ADMIN and apply default seccomp; (3) Set `run_as_non_root=true` and `no_new_privileges=true`.