```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-8
+  name: hardened-iter-9
   target:
     image: autopatch-target:vuln
   controls:
@@ -30,6 +30,13 @@
       - '[;]'
       - '&&'
       - '[|]'
+      - \{\{.*\}\}
+      - __class__
+      - __mro__
+      - __subclasses__
+      - config
+      - __init__
+      - __globals__
       disabled_endpoints:
       - /load
       ssrf_allowed_schemes:
@@ -42,26 +49,23 @@
       sqli_parameterized: true
       ssti_sandbox: true
       pickle_disabled: false
-  rationale: 'Iteration 7 shows 5 ACTIVE-BYPASS endpoints with 18 active bypass edges.
+  rationale: 'Iteration 8 shows 5 ACTIVE-BYPASS endpoints with 18 active bypass edges.
 
-    Highest-severity still-allowed probes: /ping command injection (semicolon,
+    Highest-severity still-allowed probes: /render SSTI (NEW bypass via __class__
 
-    AND, pipe operators bypassing existing block_patterns), /fetch SSRF via
+    chain without underscore prefix), /fetch SSRF (decimal IP notation 2130706433
 
-    127.0.0.1/localhost/decimal IP (4 ACTIVE-BYPASS edges), /read path
+    bypassing host allowlist), /ping command injection (semicolon, AND, pipe still
 
-    traversal via dot-dot variants, /render SSTI, /search SQLi. Applying
+    bypassed despite prior patterns). Applying ONE-CHANGE-PER-ITERATION to app_waf
 
-    ONE-CHANGE-PER-ITERATION to app_waf category. Prioritizing /ping command
+    category. Prioritizing /render SSTI by adding 8 new block_patterns to block
 
-    injection by adding three new block_patterns: ''[;]'' to block semicolon
+    template injection vectors: ''{{.*}}'' for Jinja2 delimiters, ''__class__'',
 
-    separator, ''&&'' to block AND chain, ''[|]'' to block pipe operator. These
+    ''__mro__'', ''__subclasses__'', ''config'', ''__init__'', ''__globals__'' to
+    block
 
-    complement existing patterns to close semicolon, AND, and pipe bypass
+    sandbox escape chains. These complement ssti_sandbox: true to close SSTI RCE
 
-    vectors while maintaining legitimate ping functionality. Next iteration
-
-    will tighten SSRF allowlist to exclude 127.0.0.1, localhost, and decimal
-
-    IP encodings.'
+    and canary leak vectors while maintaining legitimate template rendering.'

```
