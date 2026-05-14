```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-7
+  name: hardened-iter-8
   target:
     image: autopatch-target:vuln
   controls:
@@ -27,6 +27,9 @@
       - '[\\r\\n]'
       - \$\{.*\}
       - \$IFS
+      - '[;]'
+      - '&&'
+      - '[|]'
       disabled_endpoints:
       - /load
       ssrf_allowed_schemes:
@@ -39,24 +42,26 @@
       sqli_parameterized: true
       ssti_sandbox: true
       pickle_disabled: false
-  rationale: 'Iteration 6 shows 5 ACTIVE-BYPASS endpoints. Highest-severity still-allowed
+  rationale: 'Iteration 7 shows 5 ACTIVE-BYPASS endpoints with 18 active bypass edges.
 
-    probes: /ping command injection via $IFS variable substitution (NEW bypass),
+    Highest-severity still-allowed probes: /ping command injection (semicolon,
 
-    /fetch SSRF via 127.0.0.1/localhost/decimal IP (3 ACTIVE-BYPASS edges),
+    AND, pipe operators bypassing existing block_patterns), /fetch SSRF via
 
-    /render SSTI via __class__ chain sandbox escape, /read path traversal via
+    127.0.0.1/localhost/decimal IP (4 ACTIVE-BYPASS edges), /read path
 
-    dot-dot variants, /search SQLi via URL-encoded UNION. Applying ONE-CHANGE-
+    traversal via dot-dot variants, /render SSTI, /search SQLi. Applying
 
-    PER-ITERATION to app_waf category. Prioritizing /ping $IFS bypass by adding
+    ONE-CHANGE-PER-ITERATION to app_waf category. Prioritizing /ping command
 
-    two new block_patterns: ''\$\{.*\}'' to catch variable expansion syntax and
+    injection by adding three new block_patterns: ''[;]'' to block semicolon
 
-    ''\$IFS'' to block the IFS substitution technique directly. These patterns
+    separator, ''&&'' to block AND chain, ''[|]'' to block pipe operator. These
 
-    complement existing ''[;&|`$()]'' to close the $IFS bypass vector while
+    complement existing patterns to close semicolon, AND, and pipe bypass
 
-    maintaining legitimate ping functionality. Next iteration will tighten SSRF
+    vectors while maintaining legitimate ping functionality. Next iteration
 
-    allowlist to exclude 127.0.0.1, localhost, and decimal IP encodings.'
+    will tighten SSRF allowlist to exclude 127.0.0.1, localhost, and decimal
+
+    IP encodings.'

```
