# ShieldScope

A WordPress security audit you run from the admin. It checks core, plugins, themes, users, files and server settings, and produces a report grouped by severity with a recommendation, evidence (file, line, snippet) and a **Confirmed** or **Needs review** label for every finding. The report downloads as PDF, CSV or JSON.

ShieldScope is an audit, not a firewall: it does not block traffic, clean files, use a database of known malicious code, or monitor the site between scans. Pattern-based findings are labelled **Needs review** and are never Critical.

- **What it checks, rule by rule:** [`docs/rules.md`](docs/rules.md) (generated from the source; 16 checks).
- **How severities are chosen:** [`docs/severity-rubric.md`](docs/severity-rubric.md).
- **False-positive testing:** [`docs/accuracy.md`](docs/accuracy.md): the code rules run against pinned versions of WooCommerce, Yoast SEO, Elementor, Jetpack and other popular plugins on every pull request, and fail on any Critical or High finding.

## How a scan runs

- The scan works in short steps (default 2 s each) and saves its place after every step, so it can be paused, resumed and survive a closed tab.
- **Scan pace** (default 20%) is the share of time spent working: after each step the next one waits `work × (100 − pace) / pace` seconds. The wait happens between requests, not inside them, so no PHP worker is held while the scan rests. It is not a CPU limit.
- With the scan page open, the page drives the scan. With **Background scanning** on (default), it also continues through WP-Cron after the page is closed, and an admin notice appears when it finishes. WP-Cron runs on site visits (or a server cron job), so a closed-page scan on a quiet site is slower.
- The report shows **coverage**: which checks completed in full, partly (and why: files skipped, no WPScan key, Developer review off) or with an error.
- **Developer review** (off by default) adds the injection and SSRF code-pattern scans, which only produce findings to review.

## Data and privacy

Scan results stay in the WordPress database. During a scan ShieldScope sends requests to the site itself (headers, HTTPS, files that should not be public) and contacts:

| Service | Sent | When |
|---|---|---|
| `api.wordpress.org/core/checksums` | WordPress version and locale | Core integrity check |
| `api.wordpress.org/plugins/info` | Folder names (slugs) of installed plugins | Plugins check (closed / unmaintained plugins) |
| `wpscan.com` | Plugin and theme slugs | Only with a WPScan API key (free key: 25 requests a day, non-commercial) |

ShieldScope does not change files, settings, users or content. It stores its settings and scan progress (options), cached lookups (transients), a findings table and scheduled tasks; `uninstall.php` removes all of them.

## Using it

1. **ShieldScope → Scan**, then **Start Scan**.
2. **ShieldScope → Report**: verdict, "Fix first" list, findings by severity with evidence, coverage, checks with no findings, and "Method and limits".
3. **Ignore…** under any affected item records a reason (accepted risk, false positive, handled by host or CDN, other; a note is required for Critical). Ignored items leave the counts but stay listed, with their reason, on the page and in every download.
4. **Download PDF / CSV / JSON**. Paths are relative to the WordPress folder; CSV cells that could run as spreadsheet formulas are neutralised.

On multisite only super admins can use ShieldScope.

## Plugin security

- Every admin page, AJAX action and download checks the capability (`manage_options`, or `manage_network_options` on multisite) and a nonce.
- Input is unslashed and sanitised; queries use `$wpdb->prepare()`; output is escaped at render (`esc_html`, `esc_attr`, `esc_url`). Text from scanned files is treated as untrusted everywhere, including the PDF.
- The PDF library (Dompdf 3.1.6) is bundled under the `ShieldScope\Vendor` namespace and runs with remote loading, PHP and JavaScript off and file access limited to its font folder.

## File layout

```
shieldscope-site-security-scanner.php   plugin header, constants, autoloader
uninstall.php                           removes options, transients, cron events, findings table
admin/
  views/scan.php, report.php, settings.php
  js/admin.js, css/admin.css
includes/
  class-shieldscope-core.php            hooks, activation, cron handlers, upgrade
  class-shieldscope-scanner.php         resumable scan engine, tick lock, background scan, per-check progress
  class-shieldscope-throttle.php        scan pace (rest between steps)
  class-shieldscope-logger.php          findings table
  class-shieldscope-coverage.php        per-check coverage of a completed scan
  class-shieldscope-ignore.php          ignored findings
  class-shieldscope-pdf-report.php      PDF download
  class-shieldscope-export.php          CSV and JSON downloads
  class-shieldscope-ajax.php            scan AJAX endpoints
  class-shieldscope-admin.php           menus, settings, notices, shared statements
  class-shieldscope-eol-data.php        dated end-of-life tables (PHP, MySQL, MariaDB, WordPress)
  class-shieldscope-probe.php           requests to the site itself
  checks/class-shieldscope-check-*.php  the 16 checks and their shared base
vendor-prefixed/                        bundled PDF library (built by bin/prefix-vendor.php)
languages/                              translation template
docs/                                   rules, severity rubric, accuracy
tests/                                  PHPUnit tests, Playground smoke run, false-positive corpus manifest
bin/                                    release checks, corpus, rule catalogue, .pot, vendor prefixing
```

## Development

- Tests: `phpunit` (PHPUnit 9.6). Release checks: `bin/verify-release.sh`.
- Real WordPress (Playground, PHP 7.4): `tests/smoke/run.sh` runs a scan, the PDF, and a background (cron-only) scan.
- False-positive corpus: `php bin/fp-corpus.php`.
- After changing a finding: `php bin/rule-catalogue.php` (a test fails if `docs/rules.md` is stale).
- After changing strings: `bin/make-pot.sh`.
- After changing the PDF library: `composer install --no-dev && php bin/prefix-vendor.php`.

## Requirements

WordPress 5.8+, PHP 7.4+. Outbound HTTPS for the WordPress.org checks (and WPScan if used). PDF download needs the PHP `dom` and `mbstring` extensions.

## License

GPL-2.0-or-later. Bundled libraries keep their licences (LGPL-2.1, LGPL-2.1-or-later, LGPL-3.0-or-later, MIT); see `readme.txt`.
