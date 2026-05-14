```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-4
+  name: hardened-iter-5
   target:
     image: autopatch-target:vuln
   controls:
@@ -35,30 +35,28 @@
       - api.example.com
       path_traversal_block: true
       sqli_parameterized: false
-      ssti_sandbox: false
+      ssti_sandbox: true
       pickle_disabled: false
-  rationale: 'Iteration 3 shows 5 ACTIVE-BYPASS endpoints with 20+ active edges. Applying
+  rationale: 'Iteration 4 shows 5 ACTIVE-BYPASS endpoints. Highest-severity still-allowed
 
-    ONE-CHANGE-PER-ITERATION to app_waf category. Highest-severity still-allowed
+    probes: /render SSTI (2 NEW dynamic bypasses via Jinja2 filter chain and
 
-    probes: /ping command injection (semicolon, &&, |, newline), /fetch SSRF
+    variable assignment), /fetch SSRF (127.0.0.1, localhost, decimal IP), /ping
 
-    (127.0.0.1, localhost, decimal, hex-encoded IPs), /read path traversal
+    command injection (semicolon, &&, |, newline), /read path traversal (dot-dot,
 
-    (dot-dot, URL-encoded variants, absolute paths), /render SSTI (canary leak,
+    URL-encoded variants), /search SQLi (URL-encoded UNION). Applying
 
-    math eval, RCE), /search SQLi (URL-encoded UNION). Prioritizing /read path
+    ONE-CHANGE-PER-ITERATION to app_waf category. Prioritizing /render SSTI by
 
-    traversal by enabling path_traversal_block: true. This blocks .. sequences
+    enabling ssti_sandbox: true. This activates Jinja2 autoescape and sandbox
 
-    and common traversal patterns in the /read ?name= parameter, severing
+    mode, blocking filter chains, variable assignment tricks, and direct access
 
-    ACTIVE-BYPASS edges for literal dot-dot, URL-encoded dot-dot, URL-encoded
+    to __class__, config, and RCE payloads. Severing ACTIVE-BYPASS edges for
 
-    slash, and absolute path attacks. Next iteration will address /ping command
+    canary leak, math eval, RCE, and the two new dynamic filter/assignment
 
-    injection with stricter block_patterns (semicolon not yet blocked), then
+    bypasses. Next iteration will address /fetch SSRF host allowlist tightening
 
-    /fetch SSRF host allowlist tightening, then /render SSTI sandbox, then
-
-    /search SQLi parameterization.'
+    to block 127.0.0.1, localhost, and decimal IP encodings.'

```
