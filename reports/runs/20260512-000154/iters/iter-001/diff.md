```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,42 +1,49 @@
 policy_intent:
-  name: baseline-misconfigured
+  name: hardened-iter-1
   target:
     image: autopatch-target:vuln
-
   controls:
     container_security:
-      run_as_non_root: false
-      allow_privilege_escalation: true
+      run_as_non_root: true
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
+  rationale: 'Iteration 1: Addressing container-level escape/pivot risks (highest
+    severity).
 
-  rationale: |
-    Realistic baseline misconfiguration. Operator added SYS_ADMIN "for a
-    debugging tool", disabled seccomp "to debug a crash", bind-mounted host /
-    "for log forwarding", and exposed docker.sock "for sidecar deployment".
-    App runs as root, no WAF. This is the starting state the agent must harden
-    without breaking the regression suite.
+    Fixed three critical mount and capability issues: (1) removed dangerous bind mounts
+
+    (/host and docker.sock) that allow host filesystem and Docker daemon access,
+
+    enabling container escape; (2) dropped ALL capabilities and added only NET_RAW,
+
+    removing SYS_ADMIN which permits namespace manipulation and privilege escalation;
+
+    (3) enabled RuntimeDefault seccomp profile to block dangerous syscalls. Also
+
+    hardened container_security: set run_as_non_root=true and allow_privilege_escalation=false
+
+    to prevent root execution and privilege escalation. These changes block probe_host_mount,
+
+    probe_docker_sock, and probe_userns. Regression tests remain passing. App-level
+    WAF
+
+    fixes (command injection, SSRF, path traversal, SQLi, SSTI, deserialization) will
+    be
+
+    applied in subsequent iterations, one category per round.'

```
