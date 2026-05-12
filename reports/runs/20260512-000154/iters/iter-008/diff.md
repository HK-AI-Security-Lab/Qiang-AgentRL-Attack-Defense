```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-7
+  name: hardened-iter-8
   target:
     image: autopatch-target:vuln
   controls:
@@ -26,6 +26,9 @@
       - '[;&|`$()\\n]'
       - '{{.*}}'
       - '{%.*%}'
+      - __.*__
+      - globals
+      - builtins
       sqli_parameterized: true
       path_traversal_block: true
       ssti_sandbox: true
@@ -35,22 +38,24 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 7: Addressing Server-Side Template Injection (CWE-1336) —
-    the only
+  rationale: 'Iteration 8: Addressing persistent Server-Side Template Injection (CWE-1336).
 
-    remaining high-severity still-allowed attack. red_ssti probe shows payloads 0,1,3
+    red_ssti probe shows payloads 1 and 3 still succeed via class traversal
 
-    bypass the current ssti_sandbox setting, executing template math and class
+    (SSTI_INTROSPECT), bypassing existing ssti_sandbox and template delimiter
 
-    traversal. Added two new block_patterns to catch Jinja2 template delimiters:
+    blocks. The attack exploits Python dunder attributes (__class__, __globals__)
 
-    ''{{.*}}'' blocks variable/expression interpolation, ''{%.*%}'' blocks control
-    flow.
+    and builtins access to escape the sandbox. Added three new block_patterns:
 
-    These patterns complement the existing character-based block and sandbox setting,
+    ''__.*__'' to block dunder attribute access, ''globals'' to prevent __globals__
 
-    creating defense-in-depth. All other attack categories remain fully blocked.
+    traversal, and ''builtins'' to block builtin function access. These patterns
 
-    Regression tests pass. One-change-per-iteration rule observed: only
+    target the introspection mechanism itself rather than template syntax,
 
-    app_waf.block_patterns extended with two new regex entries.'
+    creating defense-in-depth against class-based escapes. All other attack
+
+    categories remain fully blocked. Regression tests pass. One-change-per-iteration
+
+    rule observed: only app_waf.block_patterns extended with three new regex entries.'

```
