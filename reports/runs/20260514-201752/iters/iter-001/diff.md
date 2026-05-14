```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,42 +1,42 @@
 policy_intent:
-  name: baseline-misconfigured
+  name: hardened-iter-1
   target:
     image: autopatch-target:vuln
-
   controls:
     container_security:
       run_as_non_root: false
-      allow_privilege_escalation: true
+      allow_privilege_escalation: false
       read_only_root_fs: false
-      no_new_privileges: false
+      no_new_privileges: true
       privileged: false
-
     capabilities:
-      drop: []
-      add: [SYS_ADMIN]
-
+      drop:
+      - ALL
+      add:
+      - NET_RAW
     seccomp:
-      profile: Unconfined
-
+      profile: RuntimeDefault
     mounts:
-      bind:
-        - host_path: /
-          container_path: /host
-          readonly: true
-        - host_path: /var/run/docker.sock
-          container_path: /var/run/docker.sock
-          readonly: false
-
+      bind: []
     namespace:
       pid_host: false
-
     app_waf:
       enabled: false
       block_patterns: []
+  rationale: 'Iteration 1: Fixed container-level defences. Highest-severity still-allowed
 
-  rationale: |
-    Realistic baseline misconfiguration. Operator added SYS_ADMIN "for a
-    debugging tool", disabled seccomp "to debug a crash", bind-mounted host /
-    "for log forwarding", and exposed docker.sock "for sidecar deployment".
-    App runs as root, no WAF. This is the starting state the agent must harden
-    without breaking the regression suite.
+    probes are command injection (probe_cmd_injection, red_cmd_injection,
+
+    dyn_cmd_2) and user namespace escape (probe_userns). Container hardening
+
+    blocks escape/pivot vectors first. Changes: drop ALL capabilities (was
+
+    SYS_ADMIN), add only NET_RAW; enable RuntimeDefault seccomp (was
+
+    Unconfined); remove dangerous bind mounts (/ and docker.sock); set
+
+    no_new_privileges=true and allow_privilege_escalation=false. Regression
+
+    tests (health, legit_ping, home) remain passing. App-level WAF will be
+
+    enabled in next iteration to address injection vulnerabilities.'

```
