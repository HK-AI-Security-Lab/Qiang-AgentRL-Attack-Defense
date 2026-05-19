# Security Hardening Report: autopatch-target:vuln

## TL;DR

Starting attack surface: misconfigured container with `SYS_ADMIN` capability, unconfined seccomp, host `/` bind mount, docker.sock exposure, and no WAF. App runs as root with six critical vulnerabilities (command injection, SSRF, path traversal, SQLi, SSTI, deserialization). Over 3 iterations, the agent hardened container isolation (dropped all caps, enabled seccomp, removed mounts, set `no_new_privileges`) and deployed WAF rules. Final policy enforces: capability drop-all, RuntimeDefault seccomp, empty bind mounts, and WAF with shell/SQL metacharacter blocking. Score remained at -380 across all iterations; all 5 red-team attack classes remain exploitable due to application-layer vulnerabilities that WAF patterns do not fully mitigate.

## Iteration-by-iteration

**Iter-000 (baseline):** Agent received misconfigured baseline with SYS_ADMIN, Unconfined seccomp, host mounts, and disabled WAF. Probes showed 4 high-severity attack surface issues allowed (cmd_injection, userns, red_cmd_injection, red_ssrf, red_path_traversal, red_sqli, red_ssti). Score: -460.

- `probe_userns`: allowed → blocked (no change in iter-001)
- `red_cmd_injection`: 5 payloads bypassed (`;`, `&&`, `|`, newline, IP-only)
- `red_ssrf`: 3 URLs succeeded (127.0.0.1, localhost, 2130706433 integer IP)
- `red_path_traversal`: 4 payloads bypassed (relative, URL-encoded)
- `red_sqli`: 1 payload bypassed (URL-encoded UNION)
- `red_ssti`: 2 payloads bypassed (canary leak, math eval)
- All regressions passed.
- **Score delta: -460 → -380 (+80)** — medium-risk probe (userns) blocked by seccomp/no_new_privileges.

**Iter-001:** Agent disabled `allow_privilege_escalation`, set `no_new_privileges: true`, dropped SYS_ADMIN, enabled RuntimeDefault seccomp, but kept mounts and added SSRF allowlist (localhost, 127.0.0.1, host.docker.internal). Rationale cited container escape mitigation.

- `probe_userns`: blocked (seccomp + no_new_privileges)
- `red_cmd_injection`: still 5 payloads bypassed (no WAF yet)
- `red_ssrf`: still 3 URLs succeeded (allowlist entries matched probe targets)
- `red_path_traversal`, `red_sqli`, `red_ssti`: unchanged
- All regressions passed.
- **Score delta: -380 (no change)** — container hardening did not address application-layer injection.

**Iter-002:** Agent enabled WAF globally, cleared `ssrf_allowed_hosts` to `[]`, added `block_patterns: '[;&|`$()\\n]'`, and enabled `path_traversal_block`, `sqli_parameterized`, `ssti_sandbox`, `pickle_disabled`. Removed all bind mounts. Rationale identified SSRF allowlist as self-defeating and added comprehensive WAF rules.

- `probe_host_mount`, `probe_docker_sock`: already blocked (iter-001)
- `red_cmd_injection`: still 5 payloads bypassed (regex `[;&|`$()\\n]` requires adjacent metachar; `127.0.0.1; id` has space after `;`)
- `red_ssrf`: still 3 URLs succeeded (WAF did not block; app fetches without validation)
- `red_path_traversal`, `red_sqli`, `red_ssti`: unchanged (WAF flags not enforced by app)
- All regressions passed.
- **Score delta: -380 (no change)** — WAF enabled but patterns insufficient; app does not enforce WAF blocks.

**Iter-003:** Agent added second `block_patterns` regex with SQL keywords and word boundaries: `(?i)(\\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|onerror|onload|eval|function)(\\s|$)`. Rationale noted shell injection bypasses due to whitespace and targeted highest-impact edges (ia_ping, ia_search).

- All container-level probes: unchanged (already hardened)
- `red_cmd_injection`: still 5 payloads bypassed (new regex targets SQL, not shell; `127.0.0.1; id` still has space)
- `red_ssrf`, `red_path_traversal`, `red_sqli`, `red_ssti`: unchanged
- All regressions passed.
- **Score delta: -380 (no change)** — regex refinement did not block observed payloads.

## Final policy

```yaml
policy_intent:
  name: harden-iter-3
  target:
    image: autopatch-target:vuln
  controls:
    container_security:
      run_as_non_root: false
      allow_privilege_escalation: false
      read_only_root_fs: false
      no_new_privileges: true
      privileged: false
    capabilities:
      drop:
      - ALL
      add:
      - NET_RAW
    seccomp:
      profile: RuntimeDefault
    mounts:
      bind: []
    namespace:
      pid_host: false
    app_waf:
      enabled: true
      block_patterns:
      - '[;&|`$()\\n]'
      - (?i)(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|onerror|onload|eval|function)(\s|$)
      ssrf_allowed_schemes:
      - http
      - https
      ssrf_allowed_hosts: []
      path_traversal_block: true
      sqli_parameterized: true
      ssti_sandbox: true
      pickle_disabled: true
```

**Concrete defenses deployed:**
- Capability drop: removed SYS_ADMIN, dropped ALL except NET_RAW
- Seccomp: RuntimeDefault (blocks unshare, clone with CLONE_NEWUSER)
- Mounts: removed `/host` bind mount and `/var/run/docker.sock`
- Privilege escalation: `allow_privilege_escalation: false`, `no_new_privileges: true`
- WAF: shell metacharacter regex, SQL keyword regex, path traversal block, parameterized query flag, SSTI sandbox flag, pickle disable flag

## Residual risk / future work

**Application-layer vulnerabilities remain exploitable:**
- `red_cmd_injection`: 5 payloads still bypass (e.g., `127.0.0.1; id`, `127.0.0.1 && id`). WAF regex requires adjacent metachar; payloads with spaces are not caught. Root cause: app uses shell execution without input validation (likely f-string or `os.system()` call).
- `red_ssrf`: 3 URLs still succeed (127.0.0.1, localhost, integer IP 2130706433). WAF `ssrf_allowed_hosts: []` is set but app does not enforce it; app fetches URLs without allowlist validation.
- `red_path_traversal`: 4 payloads bypass (e.g., `../../tmp/path_canary.txt`, URL-encoded `..%2f`). WAF `path_traversal_block: true` is set but app does not enforce it.
- `red_sqli`: 1 payload bypasses (URL-encoded UNION). WAF `sqli_parameterized: true` is set but app does not use parameterized queries.
- `red_ssti`: 2 payloads bypass (canary leak, math eval). WAF `ssti_sandbox: true` is set but app does not sandbox template rendering.

**Container-level mitigations are effective:**
- `probe_host_mount`, `probe_docker_sock`, `probe_userns`, `probe_proc_kallsyms`: all blocked. Container escape paths severed.

**WAF is a mitigation, not a fix:** The policy defines WAF flags but the application does not implement them. To close these gaps, the app must be patched: use parameterized queries, validate/sanitize input, disable template evaluation, and avoid shell execution. WAF patterns alone cannot block all variants (whitespace, encoding, integer IP representation).

**Score plateau:** All three hardening iterations achieved -380 (80-point improvement from baseline -460). Further progress requires application code fixes, not policy changes.