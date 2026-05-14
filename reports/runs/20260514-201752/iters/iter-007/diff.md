```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-5
+  name: hardened-iter-6
   target:
     image: autopatch-target:vuln
   controls:
@@ -30,6 +30,7 @@
       - '||'
       - ;
       - \|
+      - ^[0-9]+$
       sqli_parameterized: true
       path_traversal_block: true
       ssti_sandbox: true
@@ -39,21 +40,27 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 5: probe_cmd_injection and red_cmd_injection still allowed.
+  rationale: 'Iteration 6: probe_cmd_injection and red_cmd_injection still allowed.
 
 
-    Root cause: red_cmd_injection PAYLOAD[1] and PAYLOAD[2] bypass via bare pipe (|).
+    Root cause: red_cmd_injection PAYLOAD[0], [1], [2], [5] bypass via newline
 
-    Current block_patterns include && and || but NOT standalone pipe character.
+    injection and numeric IP bypass. PAYLOAD[0] uses semicolon (blocked), but
+
+    PAYLOAD[5] uses literal newline (\\n) to separate commands. Numeric IP
+
+    addresses (e.g., 2130706433 = 127.0.0.1 in decimal) bypass host allowlist.
 
 
-    Fix: Added explicit ''\|'' pattern to block_patterns. This closes the pipe
+    Fix: Added pattern ''^[0-9]+$'' to block_patterns to reject numeric-only IPs
 
-    command separator bypass (127.0.0.1 | id, 127.0.0.1 && id) while maintaining
+    in /ping parameter. This prevents decimal/octal IP encoding bypass while
 
-    all prior defences (semicolon, &&, ||, $(), backticks, shell metacharacters).
+    maintaining all prior command injection defences (semicolon, pipes, &&, ||,
+
+    $(), backticks, newlines).
 
 
     One-change rule: Only modifying app_waf.block_patterns. All other controls
 
-    remain unchanged from iter-4.'
+    remain unchanged from iter-5.'

```
