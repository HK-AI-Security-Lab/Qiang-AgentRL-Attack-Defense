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
@@ -21,26 +21,31 @@
     namespace:
       pid_host: false
     app_waf:
-      enabled: false
-      block_patterns: []
-  rationale: 'Iteration 0 baseline has 5 ACTIVE-BYPASS endpoints and severe container
+      enabled: true
+      block_patterns:
+      - '[;&|`$()]'
+      disabled_endpoints:
+      - /load
+  rationale: 'Iteration 1 shows 6 ACTIVE-BYPASS endpoints. Applying ONE-CHANGE-PER-ITERATION
 
-    misconfigurations. Applied ONE-CHANGE-PER-ITERATION rule to fix the
+    to app_waf category. Highest-severity still-allowed probes: /ping command
 
-    highest-impact category: container_security. Changes: disabled
+    injection (semicolon, &&, |, newline bypasses), /fetch SSRF (127.0.0.1,
 
-    allow_privilege_escalation (was true), enabled no_new_privileges (was
+    localhost, decimal IP), /read path traversal (../, URL-encoded variants),
 
-    false). This blocks privilege escalation and userns creation probes
+    /search SQLi (URL-encoded UNION), /render SSTI (canary leak, math eval, RCE),
 
-    (probe_userns still allowed but lower priority than app-level injection
+    /load deserialization (base64-encoded pickle dict). Prioritizing /load first
 
-    fixes). Removed dangerous mounts (/host, docker.sock) and dropped SYS_ADMIN
+    because dyn_deser_2 shows a NEW bypass (base64 pickle dict) that is harder to
 
-    capability, replacing with minimal NET_RAW. Enabled seccomp RuntimeDefault.
+    WAF-pattern than injection attacks. Disabling /load entirely via
 
-    These container-level fixes prevent escape/pivot. Next iteration will
+    disabled_endpoints is the most reliable defense against pickle deserialization
 
-    address app-level injection via WAF (command injection on /ping is highest
+    attacks. Enabled block_patterns for /ping command injection (shell metacharacters
 
-    severity ACTIVE-BYPASS).'
+    [;&|`$()]). Next iteration will address /fetch SSRF with ssrf_allowed_schemes
+
+    and ssrf_allowed_hosts constraints.'

```
