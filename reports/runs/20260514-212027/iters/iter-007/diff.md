```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-6
+  name: hardened-iter-7
   target:
     image: autopatch-target:vuln
   controls:
@@ -25,7 +25,8 @@
       block_patterns:
       - '[;&|`$()]'
       - '[\\r\\n]'
-      - '[\s]id[\s]'
+      - \$\{.*\}
+      - \$IFS
       disabled_endpoints:
       - /load
       ssrf_allowed_schemes:
@@ -38,26 +39,24 @@
       sqli_parameterized: true
       ssti_sandbox: true
       pickle_disabled: false
-  rationale: 'Iteration 5 shows 5 ACTIVE-BYPASS endpoints. Highest-severity still-allowed
+  rationale: 'Iteration 6 shows 5 ACTIVE-BYPASS endpoints. Highest-severity still-allowed
 
-    probes: /ping command injection (semicolon, &&, |, newline all bypassed),
+    probes: /ping command injection via $IFS variable substitution (NEW bypass),
 
-    /fetch SSRF (127.0.0.1, localhost, decimal IP 2130706433 all bypassed),
+    /fetch SSRF via 127.0.0.1/localhost/decimal IP (3 ACTIVE-BYPASS edges),
 
-    /read path traversal (dot-dot, URL-encoded variants bypassed), /search SQLi
+    /render SSTI via __class__ chain sandbox escape, /read path traversal via
 
-    (URL-encoded UNION bypassed), /render SSTI (canary leak, math eval, RCE
+    dot-dot variants, /search SQLi via URL-encoded UNION. Applying ONE-CHANGE-
 
-    bypassed despite ssti_sandbox enabled). Applying ONE-CHANGE-PER-ITERATION to
+    PER-ITERATION to app_waf category. Prioritizing /ping $IFS bypass by adding
 
-    app_waf category. Prioritizing /ping command injection by adding pattern
+    two new block_patterns: ''\$\{.*\}'' to catch variable expansion syntax and
 
-    ''[\s]id[\s]'' to block_patterns to catch the injected `id` command with
+    ''\$IFS'' to block the IFS substitution technique directly. These patterns
 
-    whitespace delimiters. Also enabling sqli_parameterized: true to block
+    complement existing ''[;&|`$()]'' to close the $IFS bypass vector while
 
-    /search SQLi URL-encoded UNION payloads. These two fixes address the most
+    maintaining legitimate ping functionality. Next iteration will tighten SSRF
 
-    active bypasses. Next iteration will tighten SSRF allowlist to exclude
-
-    127.0.0.1, localhost, and decimal IP encodings.'
+    allowlist to exclude 127.0.0.1, localhost, and decimal IP encodings.'

```
