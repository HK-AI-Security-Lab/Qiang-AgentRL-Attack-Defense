```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-1
+  name: hardened-iter-2
   target:
     image: autopatch-target:vuln
   controls:
@@ -25,4 +25,11 @@
       block_patterns:
       - '[;&|`$()]'
       - \$\(
-  rationale: (heuristic) WAF on, blocking shell metachar
+      - '[\n\t\r]'
+  rationale: probe_cmd_injection and red_cmd_injection still allowed. Analysis shows
+    semicolon (;), newline, and tab bypasses in dyn_cmd_2/dyn_cmd_3. Current block_patterns
+    only covers [;&|`$()], missing whitespace/newline IFS separators. Added regex
+    [\n\t\r] to block newline, tab, carriage return characters used in command injection
+    payloads. This is the single highest-impact fix for the most severe still-allowed
+    attack surface (command injection). Container-level defences already in place;
+    focusing on app_waf injection patterns per one-change-per-iteration rule.

```
