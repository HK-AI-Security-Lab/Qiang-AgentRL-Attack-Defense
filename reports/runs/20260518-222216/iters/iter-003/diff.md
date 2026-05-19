```diff
--- prev/policy_intent.yaml
+++ curr/policy_intent.yaml
@@ -1,5 +1,5 @@
 policy_intent:
-  name: harden-iter-2
+  name: harden-iter-3
   target:
     image: autopatch-target:vuln
   controls:
@@ -23,7 +23,8 @@
     app_waf:
       enabled: true
       block_patterns:
-      - '[;&|`$()\n]'
+      - '[;&|`$()\\n]'
+      - (?i)(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|onerror|onload|eval|function)(\s|$)
       ssrf_allowed_schemes:
       - http
       - https
@@ -32,15 +33,27 @@
       sqli_parameterized: true
       ssti_sandbox: true
       pickle_disabled: true
-  rationale: 'Self-check warnings identified that ssrf_allowed_hosts contained localhost,
-    127.0.0.1, and host.docker.internal—exactly the targets the red SSRF probe uses.
-    Removing these entries closes the SSRF bypass. Simultaneously, I enabled app_waf
-    globally and added comprehensive defences for all 6 vulnerabilities in a single
-    WAF configuration: (1) block_patterns now includes newline to stop semicolon+newline
-    injection bypasses seen in red_cmd_injection; (2) ssrf_allowed_hosts cleared to
-    block all internal SSRF; (3) path_traversal_block enabled to stop ../ and URL-encoded
-    traversal; (4) sqli_parameterized enabled for /search; (5) ssti_sandbox enabled
-    for /render; (6) pickle_disabled blocks /load. Container-level mounts remain empty
-    (no /host or docker.sock). This single WAF-category change addresses all 5 bypassed
-    edges (ia_ping, ia_fetch, ia_read, ia_search, ia_render) and closes the SSRF self-defeating
-    policy trap.'
+  rationale: 'Five bypassed edges remain at L1→L2: ia_ping, ia_fetch, ia_read, ia_render,
+    ia_search.
+
+    The command injection block_patterns regex `[;&|`$()\\n]` is not catching all
+    bypasses.
+
+    Red team payloads like `127.0.0.1; id` (semicolon+space) and `127.0.0.1 && id`
+    (ampersand+space)
+
+    are bypassing because the regex requires the metachar to be adjacent with no whitespace.
+
+    Adding a second pattern with word boundaries and case-insensitive SQL keywords
+    to catch
+
+    both shell injection variants (with spaces) and SQL injection payloads that slip
+    through
+
+    parameterization checks. This single app_waf block_patterns change targets the
+    highest-impact
+
+    bypassed edges: ia_ping→cap_shell_exec and ia_search→cap_db_read, which feed into
+
+    cc_read_shadow (REACHABLE). Severing these two edges cascades and reduces live
+    paths.'

```
