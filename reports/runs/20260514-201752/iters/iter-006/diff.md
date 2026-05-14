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
@@ -29,6 +29,7 @@
       - '&&'
       - '||'
       - ;
+      - \|
       sqli_parameterized: true
       path_traversal_block: true
       ssti_sandbox: true
@@ -38,21 +39,21 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 4: probe_cmd_injection and red_cmd_injection still allowed.
+  rationale: 'Iteration 5: probe_cmd_injection and red_cmd_injection still allowed.
 
 
-    Root cause: dyn_cmd_2 bypassed via bare semicolon (127.0.0.1; id).
+    Root cause: red_cmd_injection PAYLOAD[1] and PAYLOAD[2] bypass via bare pipe (|).
 
-    Current block_patterns include && and || but NOT standalone semicolon.
+    Current block_patterns include && and || but NOT standalone pipe character.
 
 
-    Fix: Added explicit '';'' pattern to block_patterns. This closes the
+    Fix: Added explicit ''\|'' pattern to block_patterns. This closes the pipe
 
-    semicolon command separator bypass while maintaining all prior defences
+    command separator bypass (127.0.0.1 | id, 127.0.0.1 && id) while maintaining
 
-    (&&, ||, $(), backticks, shell metacharacters, newlines/tabs).
+    all prior defences (semicolon, &&, ||, $(), backticks, shell metacharacters).
 
 
-    One-change rule: Only modifying app_waf.block_patterns. All other
+    One-change rule: Only modifying app_waf.block_patterns. All other controls
 
-    controls remain unchanged from iter-3.'
+    remain unchanged from iter-4.'

```
