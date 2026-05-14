```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -21,22 +21,8 @@
     namespace:
       pid_host: false
     app_waf:
-      enabled: false
-      block_patterns: []
-  rationale: 'Iteration 1: Fixed container-level defences. Highest-severity still-allowed
-
-    probes are command injection (probe_cmd_injection, red_cmd_injection,
-
-    dyn_cmd_2) and user namespace escape (probe_userns). Container hardening
-
-    blocks escape/pivot vectors first. Changes: drop ALL capabilities (was
-
-    SYS_ADMIN), add only NET_RAW; enable RuntimeDefault seccomp (was
-
-    Unconfined); remove dangerous bind mounts (/ and docker.sock); set
-
-    no_new_privileges=true and allow_privilege_escalation=false. Regression
-
-    tests (health, legit_ping, home) remain passing. App-level WAF will be
-
-    enabled in next iteration to address injection vulnerabilities.'
+      enabled: true
+      block_patterns:
+      - '[;&|`$()]'
+      - \$\(
+  rationale: (heuristic) WAF on, blocking shell metachar

```
