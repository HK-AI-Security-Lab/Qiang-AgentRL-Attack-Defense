```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-3
+  name: hardened-iter-4
   target:
     image: autopatch-target:vuln
   controls:
@@ -24,7 +24,7 @@
       enabled: true
       block_patterns:
       - '[;&|`$()]'
-      - '[\r\n]'
+      - '[\\r\\n]'
       disabled_endpoints:
       - /load
       ssrf_allowed_schemes:
@@ -33,30 +33,32 @@
       ssrf_allowed_hosts:
       - example.com
       - api.example.com
-      path_traversal_block: false
+      path_traversal_block: true
       sqli_parameterized: false
       ssti_sandbox: false
       pickle_disabled: false
-  rationale: 'Iteration 2 shows 5 ACTIVE-BYPASS endpoints. Applying ONE-CHANGE-PER-ITERATION
+  rationale: 'Iteration 3 shows 5 ACTIVE-BYPASS endpoints with 20+ active edges. Applying
 
-    to app_waf category. Highest-severity still-allowed probes: /ping command
+    ONE-CHANGE-PER-ITERATION to app_waf category. Highest-severity still-allowed
 
-    injection (semicolon, &&, |, newline bypasses), /fetch SSRF (127.0.0.1,
+    probes: /ping command injection (semicolon, &&, |, newline), /fetch SSRF
 
-    localhost, decimal IP 2130706433), /render SSTI (canary leak via direct
+    (127.0.0.1, localhost, decimal, hex-encoded IPs), /read path traversal
 
-    template variable). Prioritizing /fetch SSRF with ssrf_allowed_schemes and
+    (dot-dot, URL-encoded variants, absolute paths), /render SSTI (canary leak,
 
-    ssrf_allowed_hosts constraints. Red probes dyn_ssrf_1 show decimal IP bypass
+    math eval, RCE), /search SQLi (URL-encoded UNION). Prioritizing /read path
 
-    (2130706433 = 127.0.0.1 in decimal). Restricting /fetch to http/https schemes
+    traversal by enabling path_traversal_block: true. This blocks .. sequences
 
-    only and allowlisting safe external hosts (example.com, api.example.com)
+    and common traversal patterns in the /read ?name= parameter, severing
 
-    blocks loopback, localhost, and decimal IP variants. Also strengthening /ping
+    ACTIVE-BYPASS edges for literal dot-dot, URL-encoded dot-dot, URL-encoded
 
-    block_patterns to include raw newline/carriage-return [\r\n] to catch literal
+    slash, and absolute path attacks. Next iteration will address /ping command
 
-    newline injection (dyn_cmd_2 shows POST body newline bypass). Next iteration
+    injection with stricter block_patterns (semicolon not yet blocked), then
 
-    will address /render SSTI sandbox and /read path traversal.'
+    /fetch SSRF host allowlist tightening, then /render SSTI sandbox, then
+
+    /search SQLi parameterization.'

```
