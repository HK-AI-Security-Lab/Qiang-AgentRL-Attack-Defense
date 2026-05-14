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
@@ -28,6 +28,7 @@
       - '[\n\t\r]'
       - '&&'
       - '||'
+      - ;
       sqli_parameterized: true
       path_traversal_block: true
       ssti_sandbox: true
@@ -37,24 +38,21 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 3 analysis: probe_cmd_injection and red_cmd_injection still
-    allowed.
+  rationale: 'Iteration 4: probe_cmd_injection and red_cmd_injection still allowed.
 
-    Red team bypassed via dyn_cmd_3 (double ampersand &&) and dyn_cmd_2 (semicolon).
 
-    Current patterns block single &, |, ; but miss && and || operators. Added explicit
+    Root cause: dyn_cmd_2 bypassed via bare semicolon (127.0.0.1; id).
 
-    patterns for && and || to close operator-chaining bypass. Also enabled sqli_parameterized,
+    Current block_patterns include && and || but NOT standalone semicolon.
 
-    path_traversal_block, ssti_sandbox, and ssrf_allowed_schemes/hosts to address
-    other
 
-    high-severity red_team probes (red_ssrf, red_sqli, red_path_traversal, red_ssti)
-    in
+    Fix: Added explicit '';'' pattern to block_patterns. This closes the
 
-    a single WAF update. This is the highest-impact single control category change:
-    app_waf
+    semicolon command separator bypass while maintaining all prior defences
 
-    now blocks all 6 injection vectors at once, addressing the most severe still-allowed
+    (&&, ||, $(), backticks, shell metacharacters, newlines/tabs).
 
-    attack surface across command injection, SSRF, path traversal, SQLi, and SSTI.'
+
+    One-change rule: Only modifying app_waf.block_patterns. All other
+
+    controls remain unchanged from iter-3.'

```
