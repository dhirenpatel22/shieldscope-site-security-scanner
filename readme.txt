=== ShieldScope – Site Security Scanner ===

Contributors: dhirenpatel22
Tags: security, scanner, malware, hardening, audit
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.3.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security audit for WordPress: checks core, plugins, themes, users, files and server settings, and reports findings by severity with what to do.

== Description ==

**ShieldScope** is a security audit you run from your WordPress admin. It checks how your site is set up, and produces a report grouped by severity (Critical, High, Medium, Low, Info), with a recommendation for every finding. You can download the report as a PDF to keep or hand to a client.

ShieldScope is an audit, not a firewall: it does not block attacks, clean infected files or monitor your site between scans.

**How a scan runs.** The scan works in short steps with pauses between them and saves its place after each step. With the scan page open it runs at full pace; you can also close the page and it carries on in the background using WP-Cron, with a notice in the admin when it finishes. WP-Cron runs when the site gets visits, so on a quiet site a closed-page scan can take longer. A typical scan takes about 5 to 20 minutes.

**What a finding means.** Configuration, version and file checks report facts about your site. The code checks (code patterns, injection, server-side requests) look for patterns in plugin and theme source code; those findings are titled "Matches pattern" or "Review:" and must be confirmed by reading the code. They are not proof of a vulnerability or of malware.

**Here is what ShieldScope checks:**

= WordPress Core =
WordPress version and support status, debug settings, HTTPS for the admin, and other common setup mistakes.

= Core File Integrity =
Compares WordPress core files with the official WordPress.org checksums for your version and language, and lists modified or unexpected files in the core folders. Also lists PHP files in the WordPress root that are not part of WordPress, drop-ins and other PHP files directly in wp-content, and must-use plugins, which are common places for injected code.

= User Accounts =
Administrator accounts: a user named "admin", the number of administrators, empty passwords and old password hash formats.

= Files & Folders =
File permissions, configuration and backup files that can be downloaded from the web, PHP files in the uploads folder, and directory listings.

= Plugins and Themes =
Pending updates, inactive plugins and themes, plugins that WordPress.org has closed (WordPress itself still shows them as up to date), and plugins with no release on WordPress.org for over two years.

= Code Patterns =
Looks in plugin and theme PHP files for code shapes that need a manual review, such as eval() on decoded data. A match is a pointer for review, not a confirmed infection.

= SSL & HTTPS =
Certificate validity and expiry, older TLS versions, HTTP to HTTPS redirects and mixed content.

= Security Headers =
Browser security headers (for example Content-Security-Policy and X-Frame-Options) and whether the WordPress version is shown publicly.

= Database Settings =
Open registration with a risky default role, site address mismatches and recently created administrators.

= Injection Patterns =
Optional (Settings → Developer review, off by default). Looks in plugin and theme code for request data reaching risky calls (SQL queries, echo, unserialize and others). Matches are findings to review, mostly Low, to confirm by reading the code.

= Access Control =
Usernames exposed through author pages or login error messages, application passwords, login protection and two-factor authentication, plugin REST routes that accept writes without a login, and AJAX handlers that lack capability checks. These checks read settings, code and registered routes inside WordPress; they do not try to log in or send write requests.

= Server Configuration =
PHP version support status, sensitive files reachable from the web (such as .env or debug logs) and server settings that reveal technical details.

= Server-Side Requests (SSRF) =
WordPress features that make the server send requests, such as pingbacks and the oEmbed proxy. With Developer review on, also code patterns where request data may choose a URL the server fetches.

= Vulnerable & Outdated Components =
Database and WordPress versions against end-of-support dates.

= Vulnerability Database =
Without a key, installed plugins are checked against a limited built-in list of widely used plugins. With an optional WPScan API key, each plugin listed on WordPress.org and the active theme are looked up on WPScan (the free key allows 25 requests a day and is for non-commercial use).

**What ShieldScope changes.** ShieldScope does not change your files, settings, users or content. It stores only its own data: its settings and scan progress (options), cached lookups (transients), a findings table, and scheduled tasks (one daily clean-up, plus short-lived ones while a scan runs). Deleting the plugin removes all of it.

== Third-Party Services ==

While a scan runs, ShieldScope sends requests to your own site (to check headers, HTTPS and files that should not be public) and to the services below. No data is sent on regular page loads.

= WordPress.org Core Checksums API =

During the Core Integrity check, the plugin fetches the official file checksums for your exact WordPress version and locale from the WordPress.org API. The only data sent is your WordPress version number and site locale (for example, en_US). No personal data, usernames, or site URLs are transmitted.

* Service: https://api.wordpress.org/core/checksums/1.0/
* Privacy policy: https://automattic.com/privacy/

= WordPress.org Plugin Directory API =

During the Plugins check, the plugin asks the WordPress.org plugin directory whether each installed plugin is listed, closed, or long unmaintained. The only data sent is each plugin's folder name (its slug), the same information WordPress sends when it checks for updates. Answers are cached for 12 hours.

* Service: https://api.wordpress.org/plugins/info/1.2/
* Privacy policy: https://automattic.com/privacy/

= WPScan Vulnerability Database (optional) =

If you enter a WPScan API key in Settings, the Vulnerability Database check sends the slug of each plugin listed on WordPress.org, and of the active theme (and its parent), to wpscan.com to retrieve known vulnerability data. It is **off by default** and needs an API key you provide. WPScan's free key allows 25 requests a day and is licensed for non-commercial use; results are cached for 24 hours.

* Service: https://wpscan.com/api/v3/
* Privacy policy: https://automattic.com/privacy/
* Terms of service: https://wpscan.com/terms/

= Bundled libraries =

The PDF report is built on your server, with no network requests, using Dompdf 3.1.6 (LGPL-2.1) and its dependencies php-font-lib (LGPL-2.1-or-later), php-svg-lib (LGPL-3.0-or-later), masterminds/html5 (MIT) and sabberworm/php-css-parser (MIT), with DejaVu fonts (https://dejavu-fonts.github.io/License.html). They are in the `vendor-prefixed` folder, moved under the ShieldScope\Vendor namespace, with their licence files. Source: https://github.com/dompdf/dompdf

== Installation ==

1. In your WordPress admin, go to **Plugins → Add New**, search for **ShieldScope**, then click **Install Now** and **Activate**.
2. Click **ShieldScope** in the admin menu.
3. Optionally adjust the settings (scan pace, file size limit, WPScan API key) under **ShieldScope → Settings**.
4. Click **Start Scan**. You can keep the page open (fastest) or close it; the scan continues in the background.
5. Open **ShieldScope → Report** to see the results, and use **Download PDF report** to save them.

On multisite, only super admins can run a scan.

== Frequently Asked Questions ==

= Will the scan slow down my site? =

Visitors should not notice on most hosts. The scan works in short steps with pauses between them; the scan pace setting (default 20%) is the share of time spent working, not a CPU limit. Each step uses one PHP process while it runs, so on small shared hosting run large scans at a quiet time.

= Do I have to keep the scan page open? =

No. With background scanning on (the default), the scan continues using WP-Cron after you close the page, and a notice appears in the admin when it finishes. WP-Cron only runs when the site gets visits or from a server cron job, so on a quiet site keep the page open for the fastest scan. If you turn background scanning off in Settings, the scan runs only while the page is open.

= Does it change my site? =

No. ShieldScope does not change your files, settings, users or content. It stores only its own settings, scan progress, cached lookups and findings, and removes them when you delete the plugin.

= Is a finding proof that my site is hacked or vulnerable? =

Not always. Configuration and version findings are facts. Findings titled "Matches pattern" or "Review:" come from code patterns and must be confirmed by reading the code; well-written plugins can match too. A report with no findings does not mean the site is secure.

= Is this a malware scanner or a firewall? =

No. ShieldScope audits configuration, versions and code patterns. It does not use a malware signature database, clean files, block traffic or monitor the site between scans.

= Where do I find the results? =

Go to **ShieldScope → Report**. Findings are grouped by severity so you can start with the most important ones. **Download PDF report** saves them as a PDF.

= What is the WPScan API key for? =

It lets the Vulnerability Database check look up each plugin listed on WordPress.org, and the active theme, on WPScan. The free key allows 25 requests a day and is licensed for non-commercial use, so check WPScan's terms before using it on client sites. Without a key, only a limited built-in list of widely used plugins is checked.

= Is any of my site data sent to external servers? =

During a scan ShieldScope contacts api.wordpress.org (it sends your WordPress version and locale, and the folder names of installed plugins) and, only if you add a WPScan API key, wpscan.com (it sends plugin and theme slugs). It also sends requests to your own site. File contents, passwords, user data and scan results are not sent anywhere. Details are in the Third-Party Services section.

= How long does a scan take? =

About 5 to 20 minutes, depending on the number of plugins, themes and PHP files. The scan saves its place after each step, so a paused scan continues where it stopped.

== Screenshots ==

1. Scan dashboard — start, pause, or resume a scan with a live progress bar and real-time status updates.
2. Security report — findings grouped by severity (Critical through Info) with a plain-English description and a clear action to take for every issue.
3. Settings page — adjust scan speed, file size limits, tab-pause behaviour, and optionally add a WPScan API key.

== Disclaimer ==

ShieldScope uses automated checks to point out potential security issues. Review findings before acting on them, particularly for plugins and themes, where a fix may need the plugin or theme developer.

It is designed to help site owners and developers find security risks on sites they manage. It does not find every vulnerability. For questions, please use the support forum.

== Changelog ==

= 1.4.0 =
* New: Download the report as a PDF, built on your server.
* Changed: Code-pattern, injection and SSRF matches are reported as findings to review (mostly Low) instead of confirmed vulnerabilities; prepared database queries are no longer reported as SQL injection.
* Changed: The scan no longer sends a failed login or a write request to your site; those access-control checks were removed.
* Fixed: TLS checks, password-hash formats, "admin" user wording, wp-config.php and sensitive-file probes, end-of-life dates for PHP, MySQL and MariaDB, and the built-in vulnerability list (wrong CVE references removed).
* Fixed: Pause and Abort now take effect reliably; a step that keeps failing is skipped and reported instead of retrying forever.
* Fixed: The results table is created on network activation and WP-CLI activation, and the last report is no longer deleted after 30 days.
* Changed: On multisite only super admins can use ShieldScope.
* Changed: Plain wording across the plugin: no "malware scanner" or CPU-limit claims, one privacy statement that lists every outbound request, menu item renamed to "Report".
* Correction: the 1.2.0 note below said PHP 8.2 reached end of life in December 2025. PHP 8.2 receives security fixes until 31 December 2026.

= 1.3.2 =
* Fixed: Core file integrity check no longer floods the report with false "modified core file" warnings on WordPress Playground, WordPress Studio, or other SQLite-based installs.
* Improved: If a large share of core files genuinely differ (different WordPress version, locale, or a customised hosting build), the scan now reports one clear summary instead of a wall of individual findings.
* Fixed: User account check no longer flags accounts as using a "non-standard" password hash on WordPress 6.8 and later.
* Fixed: Malicious code, injection, SSRF, access control, and uploads folder scans could skip some files when a scan batch ended partway through a large directory. All files are now scanned reliably.
* Fixed: Plugin activation via WP-CLI or WordPress Playground blueprints no longer silently fails to set up the results table.
* Fixed: Findings report page now loads correctly on SQLite-based WordPress installs.
* Improved: wp-config.php accessibility check downgraded from High to Low severity for the normal case of an empty response — this is expected behaviour, not exposure.
* Added: Twenty Twenty-Six recognised as a default WordPress theme.

= 1.3.1 =
* Fixed: Corrected URL on settings admin page.
* Fixed: Updated language file.

= 1.3.0 =
* New: SSL/TLS check — flags certificates expiring within 30 days, outdated encryption protocols, mixed HTTP/HTTPS content, and missing HSTS headers.
* Improved: All recommendations rewritten to be shorter and more actionable.
* Improved: Scan, Report, and Settings admin pages redesigned with clearer layouts, severity indicators, and FAQ accordions.
* Cleanup: Removed legacy files left over from a previous plugin rename.

= 1.2.0 =
* New: Injection vulnerability scanner — detects SQL injection, XSS, LDAP injection, and other common code-level attack patterns in plugin and theme files.
* New: Access control scanner — tests login protection, two-factor authentication availability, username exposure, and whether admin pages enforce proper permission checks.
* New: Server configuration scanner — flags outdated PHP versions, publicly accessible sensitive files, insecure cron configuration, and dangerous server settings.
* New: SSRF scanner — identifies code patterns that could allow attackers to trigger unauthorised server-side requests.
* New: Vulnerable components check — flags end-of-life database versions, WordPress versions with known critical vulnerabilities, and high-risk plugins.
* New: Vulnerability database — optional WPScan API integration plus a built-in list covering 18+ commonly exploited plugins.
* Fixed: Database version detection now correctly identifies all end-of-life MariaDB versions in the 10.x and 11.x branches.
* Fixed: PHP 8.2 now correctly flagged as end-of-life (went EOL December 2025).

= 1.1.0 =
* New: Core file integrity check — verifies every WordPress core file against official checksums and flags anything that has been modified or does not belong.
* Improved: File size limit setting now uses megabytes instead of raw bytes.
* Improved: Clearer messaging when the scan pauses due to tab switching, including a visible banner and updated browser tab title.
* Added: Full architecture documentation in the GitHub repository.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.4.0 =
Adds PDF download of the report and makes findings more accurate: code-pattern matches are labelled for review, and the scan no longer sends login or write requests to your site.

= 1.3.0 =
Adds SSL/TLS certificate and encryption checks. Improves all recommendation text and redesigns the admin pages.

= 1.2.0 =
Adds six major new scan modules: injection vulnerabilities, access control, server configuration, SSRF, vulnerable components, and a vulnerability database with optional WPScan integration.

= 1.1.0 =
Adds WordPress core file integrity verification and improved scan pause messaging.

= 1.0.0 =
Initial release.