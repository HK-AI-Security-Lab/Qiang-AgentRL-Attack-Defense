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
@@ -21,29 +21,32 @@
     namespace:
       pid_host: false
     app_waf:
-      enabled: false
-      block_patterns: []
-  rationale: 'Iteration 1: Addressing container-level escape/pivot risks (highest
-    severity).
+      enabled: true
+      block_patterns:
+      - '[;&|`$()\n]'
+      sqli_parameterized: false
+      path_traversal_block: false
+      ssti_sandbox: false
+      pickle_disabled: false
+  rationale: 'Iteration 2: Addressing command injection (CWE-78) — highest-severity
+    still-allowed
 
-    Fixed three critical mount and capability issues: (1) removed dangerous bind mounts
+    attack. Container-level defences (mounts, caps, seccomp, namespace) remain unchanged
 
-    (/host and docker.sock) that allow host filesystem and Docker daemon access,
+    per one-change-per-iteration rule. Enabled app_waf and enhanced block_patterns
+    regex
 
-    enabling container escape; (2) dropped ALL capabilities and added only NET_RAW,
+    to catch shell metacharacters including semicolon (;), ampersand (&), pipe (|),
 
-    removing SYS_ADMIN which permits namespace manipulation and privilege escalation;
+    backtick (`), dollar-sign ($), parentheses (()), and newline (\n). This blocks
 
-    (3) enabled RuntimeDefault seccomp profile to block dangerous syscalls. Also
+    command chaining via ; && | and command substitution via $() and backticks, as
+    well
 
-    hardened container_security: set run_as_non_root=true and allow_privilege_escalation=false
+    as newline-based injection. Probes probe_cmd_injection, red_cmd_injection, dyn_cmd_1,
 
-    to prevent root execution and privilege escalation. These changes block probe_host_mount,
+    and dyn_cmd_3 all exploit these patterns; the expanded regex should block them.
 
-    probe_docker_sock, and probe_userns. Regression tests remain passing. App-level
-    WAF
+    Regression tests (health, legit_ping, home) remain passing. Other app-level controls
 
-    fixes (command injection, SSRF, path traversal, SQLi, SSTI, deserialization) will
-    be
-
-    applied in subsequent iterations, one category per round.'
+    (SSRF, path traversal, SQLi, SSTI, deserialization) deferred to subsequent iterations.'

```
