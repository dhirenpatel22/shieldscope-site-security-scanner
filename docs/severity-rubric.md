# ShieldScope severity rubric

Every finding gets one severity from this table. Rate what the scan actually observed, not the worst case it might lead to.

| Severity | Meaning | Examples |
|---|---|---|
| **Critical** | A confirmed compromise or exposed secret. | A modified WordPress core file; a database or wp-config backup downloadable over HTTP. |
| **High** | A confirmed exploitable misconfiguration: someone can abuse it now, without first finding another flaw. | Open registration with Administrator as the default role; the site served only over HTTP, so passwords travel in clear text. |
| **Medium** | A weakened posture: a protection is missing or out of date, but no exploit has been confirmed. | Core or theme updates pending; automatic updates disabled; errors displayed to visitors; short authentication salts. |
| **Low** | Hardening: a good-practice step that reduces risk on an otherwise sound site. | Missing security headers (CSP, HSTS, X-Frame-Options); WordPress or plugin version disclosed; file editor enabled; XML-RPC enabled. |
| **Info** | Context: worth knowing, no action required. | Default table prefix `wp_`; `DISALLOW_FILE_MODS` not set; WordPress is up to date. |

## Rules

1. Missing security headers, version disclosure and the default table prefix are Low or Info, never higher.
2. A pattern match or heuristic that a person must still confirm is rated by what it shows, and its wording says it needs review.
3. Each issue is reported by one check only. A second check must not repeat it with a different severity or advice.
4. Advice must be safe to follow as written. Every code snippet must be valid PHP that runs on a current WordPress site, and every callback it names must exist. `tests/test-severity.php` lints the snippets of the config, core, themes and database checks.
5. Do not make claims that cannot be sourced (for example "almost certainly", "the most common", time estimates).

## Applied in the config, core, themes and database checks (A-09)

| Finding | Before | Now |
|---|---|---|
| X-Frame-Options, Content-Security-Policy, HSTS missing | Medium | Low (HSTS only checked when the home URL is HTTPS; browsers ignore it over HTTP) |
| X-XSS-Protection missing | Low, advised `1; mode=block` | No finding. Low only when the header enables the legacy filter; advice: send `0` or omit it |
| No login-throttling plugin (config) | Medium | Removed; brute-force protection is checked by the access-control check only |
| `FORCE_SSL_ADMIN` not set (core) | Medium | Low; reported once, by the core check, on HTTPS sites only |
| WordPress core update available | High | Medium |
| Theme update available | High | Medium |
| File editor enabled | Medium | Low |
| `DISALLOW_FILE_MODS` not set | Low | Info |
| Auth keys/salts missing or placeholder | Critical | Low (WordPress then uses random salts stored in the database) |
| Auth keys/salts shorter than 40 characters | Critical | Medium |
| `WP_DEBUG` with errors displayed | High | Medium |
| Default table prefix | Low | Info |
| XML-RPC enabled; REST user list public | Medium | Low |
| Open registration with Administrator default role | Critical | High |
| siteurl and home on different hosts | High | Medium |

Other checks are brought in line with this rubric by their own tickets.

## Applied in the injection and SSRF checks (A-12b)

| Finding | Before | Now |
|---|---|---|
| Request data and a dangerous call in one expression (for example `unserialize( $_POST[...] )`) | Critical or High | High at most; description says it is a pattern match to confirm |
| Variable assigned from request data reaching a sink in the same file (taint) | Critical or High, worded as a confirmed bug | Low, titled "Review: user input near ..." |
| Request data in the same file as `maybe_unserialize()`, or `wp_parse_str()` on request data | Medium or High | Low, "Review" wording |
| `wp_remote_*()`, `file_get_contents()`, cURL, sockets or redirects with request data | Critical, High or Medium | Low, "Review" wording |
| `create_function()`, `preg_replace()` with `/e` | High or Critical | Medium (both are removed from current PHP) |
| oEmbed proxy answered a logged-out request | Medium, described as public by default | Medium; core restricts the proxy to `edit_posts`, so this means something opened it |
| Pingbacks | Medium, read the outbound `default_pingback_flag` | Low, reads `default_ping_status` (inbound pingbacks on new posts) |

Matches in comments, string literals and inline HTML are ignored. `absint()`, `intval()`, `sanitize_key()`, `esc_*()`, `isset()` guards and casts clear taint; values passed as `$wpdb->prepare()` arguments are not treated as SQL. A regex failure on a file is reported as "Could not analyse".

## Confidence labels (S-03)

Every finding carries `confidence` in its context: **Confirmed** (a fact read from the site) or **Needs review** (a pattern match or heuristic; titles start with "Review:" or "Matches pattern"). A finding that needs review is never Critical: `ShieldScope_Check_Base::finding()` caps it at High. Code findings also carry `evidence` (line number and a snippet of up to 160 characters from that line), shown in the report and the PDF.
