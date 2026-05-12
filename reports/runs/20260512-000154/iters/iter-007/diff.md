```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-6
+  name: hardened-iter-7
   target:
     image: autopatch-target:vuln
   controls:
@@ -24,6 +24,8 @@
       enabled: true
       block_patterns:
       - '[;&|`$()\\n]'
+      - '{{.*}}'
+      - '{%.*%}'
       sqli_parameterized: true
       path_traversal_block: true
       ssti_sandbox: true
@@ -33,29 +35,22 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 6: Addressing Insecure Deserialization (CWE-502) — second-highest-severity
+  rationale: 'Iteration 7: Addressing Server-Side Template Injection (CWE-1336) —
+    the only
 
-    still-allowed attack. red_deserialization probe succeeded with malicious pickle
-    RCE
+    remaining high-severity still-allowed attack. red_ssti probe shows payloads 0,1,3
 
-    via /load endpoint, confirming unsafe pickle.loads() execution. Applied single
-    control:
+    bypass the current ssti_sandbox setting, executing template math and class
 
-    pickle_disabled: true to completely disable the /load endpoint, returning 404
-    for all
+    traversal. Added two new block_patterns to catch Jinja2 template delimiters:
 
-    requests. This is the most direct and safest mitigation for pickle-based RCE.
+    ''{{.*}}'' blocks variable/expression interpolation, ''{%.*%}'' blocks control
+    flow.
 
+    These patterns complement the existing character-based block and sandbox setting,
 
-    SSTI remains the only still-allowed high-severity probe (red_ssti payloads 0,1,3
-    bypass
+    creating defense-in-depth. All other attack categories remain fully blocked.
 
-    ssti_sandbox). Will address in next iteration with stricter template filtering
-    or
+    Regression tests pass. One-change-per-iteration rule observed: only
 
-    endpoint disabling if sandbox proves insufficient. All other attack categories
-    remain
-
-    fully blocked per prior iterations. Regression tests pass. One-change-per-iteration
-
-    rule observed: only app_waf.pickle_disabled changed.'
+    app_waf.block_patterns extended with two new regex entries.'

```
