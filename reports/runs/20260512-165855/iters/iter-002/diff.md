```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: harden-iter-1-mounts
+  name: harden-iter-2-app-waf-cmd-injection
   target:
     image: autopatch-target:vuln
   controls:
@@ -20,18 +20,23 @@
     namespace:
       pid_host: false
     app_waf:
-      enabled: false
-      block_patterns: []
-  rationale: 'Iteration 1: Removing dangerous bind mounts (highest-severity container-level
+      enabled: true
+      block_patterns:
+      - '[;&|`$()\n]'
+  rationale: 'Iteration 2: Enabling app-level WAF to block command injection on /ping.
 
-    issue). probe_host_mount and probe_docker_sock are both HIGH severity and
+    probe_cmd_injection, red_cmd_injection, and dyn_cmd_1 are all HIGH severity
 
-    currently allowed. Removing the /host bind mount and /var/run/docker.sock
+    and currently allowed. The red_team analysis shows that semicolon (;), ampersand
 
-    mount eliminates two critical escape/pivot vectors. This is a pure container
+    (&), pipe (|), backtick (`), dollar-paren $(), and newline separators bypass
 
-    hardening fix with no app-level changes, following the one-change-per-iteration
+    the app. Adding a comprehensive block_patterns regex that matches shell
 
-    rule. Regression tests (health, legit_ping, home) should remain passing since
+    metacharacters [;&|`$()\\n] will prevent command chaining. This is the
 
-    they do not depend on host filesystem access or docker.sock.'
+    highest-impact app-level fix and follows one-change-per-iteration by
+
+    addressing only the command injection category. Container-level controls
+
+    remain unchanged from iter-1.'

```
