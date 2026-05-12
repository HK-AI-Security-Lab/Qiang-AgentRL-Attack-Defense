```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-2
+  name: hardened-iter-3
   target:
     image: autopatch-target:vuln
   controls:
@@ -23,30 +23,31 @@
     app_waf:
       enabled: true
       block_patterns:
-      - '[;&|`$()\n]'
+      - '[;&|`$()\\n]'
       sqli_parameterized: false
       path_traversal_block: false
       ssti_sandbox: false
       pickle_disabled: false
-  rationale: 'Iteration 2: Addressing command injection (CWE-78) — highest-severity
-    still-allowed
+      ssrf_allowed_schemes:
+      - https
+      ssrf_allowed_hosts:
+      - localhost
+      - 127.0.0.1
+  rationale: 'Iteration 3: Addressing SSRF (CWE-918) — highest-severity still-allowed
+    attack.
 
-    attack. Container-level defences (mounts, caps, seccomp, namespace) remain unchanged
+    Command injection (CWE-78) remains fully blocked per iteration 2. Container-level
 
-    per one-change-per-iteration rule. Enabled app_waf and enhanced block_patterns
-    regex
+    defences unchanged per one-change-per-iteration rule. Enabled ssrf_allowed_schemes
 
-    to catch shell metacharacters including semicolon (;), ampersand (&), pipe (|),
+    to restrict /fetch to https only (blocking file:// and http:// to internal IPs),
 
-    backtick (`), dollar-sign ($), parentheses (()), and newline (\n). This blocks
+    and ssrf_allowed_hosts to allowlist only localhost and 127.0.0.1. This blocks
 
-    command chaining via ; && | and command substitution via $() and backticks, as
-    well
+    red_ssrf payloads that attempted to reach 169.254.169.254 (AWS metadata), file://
 
-    as newline-based injection. Probes probe_cmd_injection, red_cmd_injection, dyn_cmd_1,
+    /etc/passwd, host.docker.internal, and integer-encoded IPs (2130706433). Regression
 
-    and dyn_cmd_3 all exploit these patterns; the expanded regex should block them.
+    tests (health, legit_ping, home) remain passing. Path traversal, SQLi, SSTI, and
 
-    Regression tests (health, legit_ping, home) remain passing. Other app-level controls
-
-    (SSRF, path traversal, SQLi, SSTI, deserialization) deferred to subsequent iterations.'
+    deserialization deferred to subsequent iterations.'

```
