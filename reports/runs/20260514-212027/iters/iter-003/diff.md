```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-2
+  name: hardened-iter-3
   target:
     image: autopatch-target:vuln
   controls:
@@ -24,28 +24,39 @@
       enabled: true
       block_patterns:
       - '[;&|`$()]'
+      - '[\r\n]'
       disabled_endpoints:
       - /load
-  rationale: 'Iteration 1 shows 6 ACTIVE-BYPASS endpoints. Applying ONE-CHANGE-PER-ITERATION
+      ssrf_allowed_schemes:
+      - http
+      - https
+      ssrf_allowed_hosts:
+      - example.com
+      - api.example.com
+      path_traversal_block: false
+      sqli_parameterized: false
+      ssti_sandbox: false
+      pickle_disabled: false
+  rationale: 'Iteration 2 shows 5 ACTIVE-BYPASS endpoints. Applying ONE-CHANGE-PER-ITERATION
 
     to app_waf category. Highest-severity still-allowed probes: /ping command
 
     injection (semicolon, &&, |, newline bypasses), /fetch SSRF (127.0.0.1,
 
-    localhost, decimal IP), /read path traversal (../, URL-encoded variants),
+    localhost, decimal IP 2130706433), /render SSTI (canary leak via direct
 
-    /search SQLi (URL-encoded UNION), /render SSTI (canary leak, math eval, RCE),
+    template variable). Prioritizing /fetch SSRF with ssrf_allowed_schemes and
 
-    /load deserialization (base64-encoded pickle dict). Prioritizing /load first
+    ssrf_allowed_hosts constraints. Red probes dyn_ssrf_1 show decimal IP bypass
 
-    because dyn_deser_2 shows a NEW bypass (base64 pickle dict) that is harder to
+    (2130706433 = 127.0.0.1 in decimal). Restricting /fetch to http/https schemes
 
-    WAF-pattern than injection attacks. Disabling /load entirely via
+    only and allowlisting safe external hosts (example.com, api.example.com)
 
-    disabled_endpoints is the most reliable defense against pickle deserialization
+    blocks loopback, localhost, and decimal IP variants. Also strengthening /ping
 
-    attacks. Enabled block_patterns for /ping command injection (shell metacharacters
+    block_patterns to include raw newline/carriage-return [\r\n] to catch literal
 
-    [;&|`$()]). Next iteration will address /fetch SSRF with ssrf_allowed_schemes
+    newline injection (dyn_cmd_2 shows POST body newline bypass). Next iteration
 
-    and ssrf_allowed_hosts constraints.'
+    will address /render SSTI sandbox and /read path traversal.'

```
