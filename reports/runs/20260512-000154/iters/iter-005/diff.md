```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-4
+  name: hardened-iter-5
   target:
     image: autopatch-target:vuln
   controls:
@@ -26,30 +26,32 @@
       - '[;&|`$()\\n]'
       sqli_parameterized: true
       path_traversal_block: false
-      ssti_sandbox: false
+      ssti_sandbox: true
       pickle_disabled: false
       ssrf_allowed_schemes:
       - https
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 4: Addressing SQL Injection (CWE-89) — highest-severity still-allowed
+  rationale: 'Iteration 5: Addressing Server-Side Template Injection (CWE-1336) —
+    highest-severity
 
-    attack. red_sqli probe succeeded via URL-encoded UNION SELECT payload
+    still-allowed attack. red_ssti probe succeeded with mathematical expression injection
 
-    (%27%20UNION%20SELECT...), extracting FLAG{sql_injection_pwned} from secrets table.
+    (7*7=49) and class traversal introspection, confirming unsafe template rendering
+    on
+
+    /render endpoint. Enabled ssti_sandbox: true to force Jinja2 autoescape and sandbox
+
+    mode, preventing template expression evaluation and attribute access traversal.
 
 
-    Command injection, SSRF, and path traversal remain fully blocked per prior iterations.
+    Command injection, SSRF, path traversal, and SQL injection remain fully blocked
+    per
 
-    Container-level defences unchanged per one-change-per-iteration rule. Enabled
+    prior iterations. Container-level defences unchanged per one-change-per-iteration
+    rule.
 
-    sqli_parameterized: true to force /search endpoint to use parameterized queries
+    Regression tests (health, legit_ping, home) remain passing. Deserialization (red_deserialization)
 
-    instead of f-string concatenation. This prevents attacker-controlled input from
-
-    being interpreted as SQL syntax, blocking UNION SELECT, OR ''1''=''1, and comment-based
-
-    bypasses. Regression tests (health, legit_ping, home) remain passing. SSTI and
-
-    deserialization deferred to subsequent iterations.'
+    deferred to next iteration as second-highest-severity remaining vulnerability.'

```
