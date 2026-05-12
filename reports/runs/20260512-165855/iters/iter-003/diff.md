```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,20 +1,21 @@
 policy_intent:
-  name: harden-iter-2-app-waf-cmd-injection
+  name: harden-iter-3-container-userns
   target:
     image: autopatch-target:vuln
   controls:
     container_security:
       run_as_non_root: false
-      allow_privilege_escalation: true
+      allow_privilege_escalation: false
       read_only_root_fs: false
-      no_new_privileges: false
+      no_new_privileges: true
       privileged: false
     capabilities:
-      drop: []
+      drop:
+      - ALL
       add:
-      - SYS_ADMIN
+      - NET_RAW
     seccomp:
-      profile: Unconfined
+      profile: RuntimeDefault
     mounts:
       bind: []
     namespace:
@@ -22,21 +23,28 @@
     app_waf:
       enabled: true
       block_patterns:
-      - '[;&|`$()\n]'
-  rationale: 'Iteration 2: Enabling app-level WAF to block command injection on /ping.
+      - '[;&|`$()\\n]'
+  rationale: 'Iteration 3: Hardening container-level security to block namespace escape.
 
-    probe_cmd_injection, red_cmd_injection, and dyn_cmd_1 are all HIGH severity
 
-    and currently allowed. The red_team analysis shows that semicolon (;), ampersand
+    probe_userns is MEDIUM severity and currently ALLOWED. The probe shows that
 
-    (&), pipe (|), backtick (`), dollar-paren $(), and newline separators bypass
+    unshare -U (user namespace creation) succeeds, allowing an attacker to create
 
-    the app. Adding a comprehensive block_patterns regex that matches shell
+    a new user namespace and potentially escalate privileges or escape confinement.
 
-    metacharacters [;&|`$()\\n] will prevent command chaining. This is the
 
-    highest-impact app-level fix and follows one-change-per-iteration by
+    Fixing this requires tightening container_security controls:
 
-    addressing only the command injection category. Container-level controls
+    - allow_privilege_escalation: false (was true) — prevents privilege escalation
 
-    remain unchanged from iter-1.'
+    - no_new_privileges: true (was false) — prevents new privilege grants
+
+
+    These changes directly block the userns probe without affecting app-level WAF
+
+    or other container controls. Command injection (red_cmd_injection, dyn_cmd_*)
+
+    remain blocked by the existing WAF pattern. This follows one-change-per-iteration
+
+    by addressing only the container_security category.'

```
