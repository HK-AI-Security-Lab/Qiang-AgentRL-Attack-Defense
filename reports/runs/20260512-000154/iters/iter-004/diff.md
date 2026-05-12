```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-3
+  name: hardened-iter-4
   target:
     image: autopatch-target:vuln
   controls:
@@ -24,7 +24,7 @@
       enabled: true
       block_patterns:
       - '[;&|`$()\\n]'
-      sqli_parameterized: false
+      sqli_parameterized: true
       path_traversal_block: false
       ssti_sandbox: false
       pickle_disabled: false
@@ -33,21 +33,23 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 3: Addressing SSRF (CWE-918) — highest-severity still-allowed
-    attack.
+  rationale: 'Iteration 4: Addressing SQL Injection (CWE-89) — highest-severity still-allowed
 
-    Command injection (CWE-78) remains fully blocked per iteration 2. Container-level
+    attack. red_sqli probe succeeded via URL-encoded UNION SELECT payload
 
-    defences unchanged per one-change-per-iteration rule. Enabled ssrf_allowed_schemes
+    (%27%20UNION%20SELECT...), extracting FLAG{sql_injection_pwned} from secrets table.
 
-    to restrict /fetch to https only (blocking file:// and http:// to internal IPs),
 
-    and ssrf_allowed_hosts to allowlist only localhost and 127.0.0.1. This blocks
+    Command injection, SSRF, and path traversal remain fully blocked per prior iterations.
 
-    red_ssrf payloads that attempted to reach 169.254.169.254 (AWS metadata), file://
+    Container-level defences unchanged per one-change-per-iteration rule. Enabled
 
-    /etc/passwd, host.docker.internal, and integer-encoded IPs (2130706433). Regression
+    sqli_parameterized: true to force /search endpoint to use parameterized queries
 
-    tests (health, legit_ping, home) remain passing. Path traversal, SQLi, SSTI, and
+    instead of f-string concatenation. This prevents attacker-controlled input from
+
+    being interpreted as SQL syntax, blocking UNION SELECT, OR ''1''=''1, and comment-based
+
+    bypasses. Regression tests (health, legit_ping, home) remain passing. SSTI and
 
     deserialization deferred to subsequent iterations.'

```
