```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,8 +1,7 @@
 policy_intent:
-  name: baseline-misconfigured
+  name: harden-iter-1-mounts
   target:
     image: autopatch-target:vuln
-
   controls:
     container_security:
       run_as_non_root: false
@@ -10,33 +9,29 @@
       read_only_root_fs: false
       no_new_privileges: false
       privileged: false
-
     capabilities:
       drop: []
-      add: [SYS_ADMIN]
-
+      add:
+      - SYS_ADMIN
     seccomp:
       profile: Unconfined
-
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
+  rationale: 'Iteration 1: Fixing container-level mounts (highest-severity category).
 
-  rationale: |
-    Realistic baseline misconfiguration. Operator added SYS_ADMIN "for a
-    debugging tool", disabled seccomp "to debug a crash", bind-mounted host /
-    "for log forwarding", and exposed docker.sock "for sidecar deployment".
-    App runs as root, no WAF. This is the starting state the agent must harden
-    without breaking the regression suite.
+    Removed both dangerous bind mounts: /host (host root filesystem) and
+
+    /var/run/docker.sock (Docker daemon socket). These enable container
+
+    escape and lateral movement. Probes probe_host_mount and probe_docker_sock
+
+    were both "allowed" with high severity. Removing mounts blocks these
+
+    immediately without breaking regression tests (health, legit_ping, home
+
+    all pass). Next iteration will address capabilities and seccomp.'

```
