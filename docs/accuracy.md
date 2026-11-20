# Accuracy: false-positive corpus

`bin/fp-corpus.php` runs ShieldScope's code rules (code patterns, and the
injection and SSRF rules with Developer review on) over well-known plugins
pinned in `tests/corpus/manifest.json` (versions and sha256 hashes). The CI
workflow `.github/workflows/fp-corpus.yml` fails if any rule reports a
Critical or High finding on them.

## Result, 2026-11-20

Akismet 5.7.2, Classic Editor 1.7.0, Contact Form 7 6.2.5, Elementor 4.4.1,
Jetpack 16.4, WooCommerce 11.3.0, Yoast SEO 28.9, WPForms Lite 2.0.5.1:
14,365 PHP files.

| Severity | Findings |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low ("Needs review") | 9 |
| Info (files not scanned: vendor folders) | 2 |

With the default settings (Developer review off) only the code-pattern rules
run, and they report 1 Low finding on all eight plugins: a 400-character
base64 string in Yoast SEO (a signed JWT constant), which is the kind of
string the rule exists to point at.

The first run found five false positives in the code-pattern rules, now
fixed and covered by `tests/test-s25-fp-fixtures.php`: "require $_GET" in a
comment (Medium), "system (" inside strings and `new Views\System()` (Low),
base64 `data:` URIs and a base64 example in a docblock (Low).

The remaining Low findings in Developer review mode are request data near
`maybe_unserialize()`, `echo`, `wp_redirect()` and `wp_remote_get()`; one,
`wp_redirect( wp_unslash( $_GET['wccom-install-url'] ) )` in WooCommerce's
helper, is worth a human look, which is what "Needs review" means.
