```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: hardened-iter-8
+  name: hardened-iter-9
   target:
     image: autopatch-target:vuln
   controls:
@@ -29,6 +29,7 @@
       - __.*__
       - globals
       - builtins
+      - namespace\s*\(
       sqli_parameterized: true
       path_traversal_block: true
       ssti_sandbox: true
@@ -38,24 +39,26 @@
       ssrf_allowed_hosts:
       - localhost
       - 127.0.0.1
-  rationale: 'Iteration 8: Addressing persistent Server-Side Template Injection (CWE-1336).
+  rationale: 'Iteration 9: Addressing persistent Server-Side Template Injection (CWE-1336).
 
-    red_ssti probe shows payloads 1 and 3 still succeed via class traversal
 
-    (SSTI_INTROSPECT), bypassing existing ssti_sandbox and template delimiter
+    red_ssti probe shows payloads 1 and 3 still succeed via SSTI_INTROSPECT class
 
-    blocks. The attack exploits Python dunder attributes (__class__, __globals__)
+    traversal, bypassing existing dunder and globals/builtins blocks. Analysis of
 
-    and builtins access to escape the sandbox. Added three new block_patterns:
+    dyn_ssti_sandbox_1 reveals the attack vector: Jinja2 namespace() builtin object
 
-    ''__.*__'' to block dunder attribute access, ''globals'' to prevent __globals__
+    allows arithmetic execution without dunder attributes. Added new block_pattern
 
-    traversal, and ''builtins'' to block builtin function access. These patterns
+    ''namespace\s*\('' to prevent instantiation of the namespace() function, which
+    is
 
-    target the introspection mechanism itself rather than template syntax,
+    the root cause of the introspection bypass. This targets the specific Jinja2
 
-    creating defense-in-depth against class-based escapes. All other attack
+    builtin that enables sandbox escape without relying on __class__ or __globals__.
 
-    categories remain fully blocked. Regression tests pass. One-change-per-iteration
+    All other attack categories remain fully blocked. Regression tests pass.
 
-    rule observed: only app_waf.block_patterns extended with three new regex entries.'
+    One-change-per-iteration rule observed: only app_waf.block_patterns extended
+
+    with one new regex entry.'

```
