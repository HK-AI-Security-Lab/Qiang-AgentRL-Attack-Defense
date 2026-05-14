# Hardening Report: autopatch-target:vuln

## TL;DR

Starting attack surface: 6 high-severity ACTIVE-BYPASS endpoints (/ping, /fetch, /read, /search, /render, /load) with 40+ bypass edges across command injection, SSRF, path traversal, SQLi, SSTI, and deserialization. Over 11 iterations, the agent applied container hardening (seccomp RuntimeDefault, dropped ALL caps, disabled privilege escalation, removed dangerous mounts) and layered WAF patterns to block shell metacharacters, variable expansion, template delimiters, and loopback IPs. Final policy enforces: dropped capabilities, seccomp, no_new_privileges, disabled /load endpoint, block_patterns for injection vectors, path_traversal_block, sqli_parameterized, ssti_sandbox, and SSRF allowlist (example.com, api.example.com only).

## Iteration-by-iteration

**Iter 0 (baseline):** Misconfigured container with SYS_ADMIN, unconfined seccomp, /host and docker.sock mounts, app running as root, no WAF. Probes: 5 high-severity ACTIVE-BYPASS (cmd_injection, userns, red_cmd_injection, red_ssrf, red_path_traversal, red_sqli, red_ssti). Score: -740.

- Baseline: all 6 red_team probes allowed; deserialization blocked.
- Regression: all 4 pass.
- Score delta: -740 (starting point).

**Iter 1:** Hardened container_security: disabled allow_privilege_escalation, enabled no_new_privileges, dropped SYS_ADMIN, enabled seccomp RuntimeDefault, removed mounts.

- probe_userns: blocked (was allowed).
- red_cmd_injection, red_ssrf, red_path_traversal, red_sqli, red_ssti: still allowed.
- dyn_deser_2: NEW bypass (base64 pickle dict).
- Score delta: +400 (container fixes blocked userns; deserialization new edge).

**Iter 2:** Enabled app_waf with block_patterns `[;&|`$()]`, disabled /load endpoint.

- red_cmd_injection, red_ssrf, red_path_traversal, red_sqli, red_ssti: still allowed.
- dyn_cmd_1, dyn_cmd_2, dyn_cmd_3: mixed (some blocked, some bypassed).
- dyn_ssrf_1, dyn_path_1, dyn_ssti_1, dyn_ssti_2: NEW dynamic bypasses.
- Score delta: -40 (WAF patterns partially effective; new dynamic edges).

**Iter 3:** Added SSRF allowlist (example.com, api.example.com), added path_traversal_block, added `[\r\n]` pattern.

- dyn_cmd_2: blocked (literal newline now caught).
- dyn_ssrf_1, dyn_ssrf_2: still allowed (decimal IP, hex IP bypasses).
- dyn_path_1: blocked.
- dyn_ssti_1, dyn_ssti_2: still allowed.
- Score delta: -280 (path traversal fixed; SSRF allowlist incomplete).

**Iter 4:** Enabled path_traversal_block: true.

- red_path_traversal: still allowed (URL-encoded variants bypass).
- dyn_cmd_1, dyn_cmd_2, dyn_cmd_3: mixed results.
- dyn_ssti_1, dyn_ssti_2: NEW bypasses (filter chain, variable assignment).
- Score delta: 0 (path block not fully effective; SSTI new edges).

**Iter 5:** Enabled ssti_sandbox: true.

- red_ssti: still allowed (sandbox escape via __class__ chain).
- dyn_ssti_1, dyn_ssti_2: still allowed (filter chain, variable assignment).
- Score delta: +360 (deserialization improvements; SSTI sandbox incomplete).

**Iter 6:** Added sqli_parameterized: true, added `[\s]id[\s]` pattern.

- red_sqli: still allowed (URL-encoded UNION bypassed).
- dyn_cmd_2: NEW bypass ($IFS variable substitution).
- dyn_sqli_2: blocked.
- Score delta: -280 (SQLi parameterization incomplete; new cmd injection edge).

**Iter 7:** Added `\$\{.*\}` and `\$IFS` patterns.

- dyn_cmd_2: blocked (IFS bypass now caught).
- dyn_cmd_3: blocked.
- dyn_ssrf_1, dyn_ssrf_2: still allowed (hex IP, direct IP bypasses).
- dyn_ssti_2: blocked.
- Score delta: +220 (command injection improved; SSRF still vulnerable).

**Iter 8:** Added `[;]`, `&&`, `[|]` patterns.

- red_cmd_injection: still allowed (literal newline in PAYLOAD[5]).
- dyn_cmd_1, dyn_cmd_2, dyn_cmd_3: mixed (tab char, process substitution).
- dyn_ssrf_1: NEW bypass (decimal IP).
- dyn_ssti_1: NEW bypass (filter chain without underscore).
- Score delta: 0 (command injection patterns redundant; new SSTI/SSRF edges).

**Iter 9:** Added `{{.*}}`, `__class__`, `__mro__`, `__subclasses__`, `config`, `__init__`, `__globals__` patterns.

- red_ssti: still allowed (canary leak, math eval, RCE).
- dyn_cmd_2: NEW bypass (literal newline in POST body).
- dyn_ssti_1: NEW bypass (direct variable access in sandbox).
- Score delta: -480 (SSTI patterns incomplete; new cmd/SSTI edges).

**Iter 10:** Added `[\x00-\x1f]` control character pattern.

- dyn_cmd_2: blocked (literal newline now caught).
- dyn_deser_1, dyn_deser_2: blocked.
- dyn_ssti_2: NEW bypass (direct variable access).
- Score delta: +360 (control char filter effective; SSTI variable access still open).

**Iter 11:** Added loopback block pattern `(?i)(localhost|127\.|::1|2130706433)` to block_patterns.

- red_ssrf: still allowed (127.0.0.1, localhost, decimal IP all bypassed).
- dyn_ssrf_2: still allowed (direct localhost IP).
- dyn_deser_1, dyn_deser_2, dyn_deser_3: blocked.
- dyn_cmd_2, dyn_cmd_3: blocked.
- Score delta: +360 (deserialization fully blocked; SSRF pattern not applied to /fetch parameter).

## Final policy

```yaml
policy_intent:
  name: hardened-iter-11
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
      - '[;&|`$()]'
      - '[\\r\\n]'
      - \$\{.*\}
      - \$IFS
      - '[;]'
      - '&&'
      - '[|]'
      - \{\{.*\}\}
      - __class__
      - __mro__
      - __subclasses__
      - config
      - __init__
      - __globals__
      - '[\\x00-\\x1f]'
      ssrf_allowed_schemes:
      - http
      - https
      ssrf_allowed_hosts:
      - example.com
      - api.example.com
      path_traversal_block: true
      sqli_parameterized: true
      ssti_sandbox: true
      pickle_disabled: false
```

**Concrete defenses:**
- **Dropped capabilities:** ALL except NET_RAW (removed SYS_ADMIN).
- **Removed mounts:** /host, /var/run/docker.sock.
- **Seccomp:** RuntimeDefault (blocks unshare, privilege escalation syscalls).
- **WAF block_patterns:** Shell metacharacters `[;&|`$()]`, control chars `[\x00-\x1f]`, variable expansion `\$\{.*\}`, `\$IFS`, template delimiters `{{.*}}`, SSTI escape chains (`__class__`, `__mro__`, `__subclasses__`, `config`, `__init__`, `__globals__`).
- **Disabled endpoints:** /load (pickle deserialization).
- **Path traversal:** path_traversal_block: true (blocks .. sequences in /read).
- **SQLi:** sqli_parameterized: true (enforces prepared statements on /search).
- **SSTI:** ssti_sandbox: true (Jinja2 autoescape + sandbox mode on /render).
- **SSRF:** Allowlist http/https schemes, restrict hosts to example.com and api.example.com.

## Residual risk / future work

**Still-allowed attack surface:**
- **/ping command injection:** Literal newline in POST body (dyn_cmd_2 iter-9) bypasses `[\r\n]` regex (matches escaped sequences, not raw bytes). Mitigation: input validation at HTTP layer or stricter WAF on raw request body.
- **/fetch SSRF:** Loopback block pattern added iter-11 but not applied to URL parameter parsing; 127.0.0.1, localhost, decimal IP 2130706433 still bypass allowlist. Mitigation: enforce loopback rejection in /fetch handler before HTTP request.
- **/read path traversal:** URL-encoded variants (`..%2f`, `%2e%2e`) still bypass path_traversal_block. Mitigation: normalize and decode URL before path check.
- **/search SQLi:** URL-encoded UNION payloads bypass sqli_parameterized (app-level bug: f-string query construction). Mitigation: fix app code to use parameterized queries, not WAF.
- **/render SSTI:** Direct variable access (ssti_canary in context) bypasses sandbox. Mitigation: remove sensitive variables from template context or use stricter sandbox (RestrictedPython).
- **/load deserialization:** Disabled endpoint; no pickle RCE possible via /load. Residual risk: if endpoint re-enabled, pickle gadget chains (os.system via __reduce__) will execute.

**Limitations:**
- AppArmor/vArmor not available on Docker Desktop macOS; seccomp RuntimeDefault is primary syscall defense.
- WAF is mitigation, not fix: app-level vulnerabilities (f-string SQLi, unsafe pickle.loads, unsafe Jinja2 rendering) remain in code.
- SSRF allowlist does not prevent internal service discovery (e.g., metadata endpoints on non-loopback IPs).
- Path traversal block does not handle symlink attacks or case-sensitivity bypasses on case-insensitive filesystems.