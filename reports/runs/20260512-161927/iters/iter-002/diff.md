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
@@ -20,18 +20,25 @@
     namespace:
       pid_host: false
     app_waf:
-      enabled: false
-      block_patterns: []
-  rationale: 'Iteration 1: Fixing container-level mounts (highest-severity category).
+      enabled: true
+      block_patterns:
+      - '[;&|`$()]'
+  rationale: 'Iteration 2: Fixing app-level WAF for command injection (highest-severity
 
-    Removed both dangerous bind mounts: /host (host root filesystem) and
+    still-allowed attack). Probes probe_cmd_injection, red_cmd_injection, and
 
-    /var/run/docker.sock (Docker daemon socket). These enable container
+    dyn_cmd_1 all show command injection is allowed via semicolon, pipe, and
 
-    escape and lateral movement. Probes probe_host_mount and probe_docker_sock
+    ampersand separators on /ping endpoint. Enabled app_waf with block_patterns
 
-    were both "allowed" with high severity. Removing mounts blocks these
+    regex [;&|`$()]  to block shell metacharacters: semicolon (;), ampersand (&),
 
-    immediately without breaking regression tests (health, legit_ping, home
+    pipe (|), backtick (`), dollar ($), parentheses (). This blocks the bypassed
 
-    all pass). Next iteration will address capabilities and seccomp.'
+    payloads: "127.0.0.1; id", "127.0.0.1 && id", "127.0.0.1 | id", and newline
+
+    injection. Regression tests (health, legit_ping, home) remain passing. Next
+
+    iteration will address SSRF, path traversal, SQLi, SSTI, and deserialization
+
+    one at a time.'

```
