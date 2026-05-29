<?php
/**
 * Scan control view.
 *
 * @package Site_Security_Audit
 *
 * @var array $state Passed in from render_scan_page().
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap ssa-wrap">
	<h1><?php esc_html_e( 'SSA – Site Security Audit, Self-Hosted & Private', 'site-security-audit' ); ?></h1>

	<p class="description">
		<?php esc_html_e( 'Run a comprehensive background scan of your WordPress installation, themes, plugins, users and filesystem. The scan is CPU-throttled and will automatically pause if you leave this tab.', 'site-security-audit' ); ?>
	</p>

	<div id="ssa-scan-panel"
		 data-status="<?php echo esc_attr( $state['status'] ); ?>"
		 data-progress="<?php echo esc_attr( (int) ( ! empty( $state['total_steps'] ) ? floor( ( $state['done_steps'] * 100 ) / $state['total_steps'] ) : 0 ) ); ?>"
		 data-scan-id="<?php echo esc_attr( $state['scan_id'] ); ?>">

		<div id="ssa-blur-banner" class="ssa-blur-banner" role="status" aria-live="polite" hidden>
			<span class="ssa-blur-icon" aria-hidden="true">👋</span>
			<div class="ssa-blur-text">
				<strong id="ssa-blur-title"></strong>
				<span id="ssa-blur-body"></span>
			</div>
		</div>

		<div class="ssa-card">
			<div class="ssa-status-row">
				<span class="ssa-status-label"><?php esc_html_e( 'Status', 'site-security-audit' ); ?>:</span>
				<span class="ssa-status-value" id="ssa-status-text"><?php echo esc_html( ucfirst( $state['status'] ) ); ?></span>
			</div>

			<div class="ssa-progress-wrap">
				<div class="ssa-progress-bar">
					<div class="ssa-progress-fill" id="ssa-progress-fill"></div>
				</div>
				<div class="ssa-progress-meta">
					<span id="ssa-progress-pct">0%</span>
					<span id="ssa-progress-steps">
						<?php
						printf(
							/* translators: 1: done, 2: total */
							esc_html__( '%1$d of %2$d checks', 'site-security-audit' ),
							(int) $state['done_steps'],
							(int) $state['total_steps']
						);
						?>
					</span>
				</div>
			</div>

			<p id="ssa-message" class="ssa-message">
				<?php echo esc_html( $state['last_message'] ); ?>
			</p>

			<div class="ssa-controls">
				<button type="button" class="button button-primary" id="ssa-btn-start">
					<?php esc_html_e( 'Start Scan', 'site-security-audit' ); ?>
				</button>
				<button type="button" class="button" id="ssa-btn-pause" disabled>
					<?php esc_html_e( 'Pause', 'site-security-audit' ); ?>
				</button>
				<button type="button" class="button" id="ssa-btn-resume" disabled>
					<?php esc_html_e( 'Resume', 'site-security-audit' ); ?>
				</button>
				<button type="button" class="button button-link-delete" id="ssa-btn-abort" disabled>
					<?php esc_html_e( 'Abort', 'site-security-audit' ); ?>
				</button>
			</div>
		</div>

		<div class="ssa-card ssa-summary ssa-hidden" id="ssa-summary">
			<h2><?php esc_html_e( 'Live findings', 'site-security-audit' ); ?></h2>
			<ul class="ssa-summary-grid">
				<li class="sev-critical"><span class="count" data-sev="critical">0</span><span class="label"><?php esc_html_e( 'Critical', 'site-security-audit' ); ?></span></li>
				<li class="sev-high"><span class="count" data-sev="high">0</span><span class="label"><?php esc_html_e( 'High', 'site-security-audit' ); ?></span></li>
				<li class="sev-medium"><span class="count" data-sev="medium">0</span><span class="label"><?php esc_html_e( 'Medium', 'site-security-audit' ); ?></span></li>
				<li class="sev-low"><span class="count" data-sev="low">0</span><span class="label"><?php esc_html_e( 'Low', 'site-security-audit' ); ?></span></li>
				<li class="sev-info"><span class="count" data-sev="info">0</span><span class="label"><?php esc_html_e( 'Info', 'site-security-audit' ); ?></span></li>
			</ul>
			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . SSA_SLUG . '-report' ) ); ?>" class="button">
					<?php esc_html_e( 'View full report', 'site-security-audit' ); ?>
				</a>
			</p>
		</div>

		<div class="ssa-card ssa-notice-card">
			<p>
				<strong><?php esc_html_e( 'About the focus-lock:', 'site-security-audit' ); ?></strong>
				<?php esc_html_e( 'To avoid stealing CPU from the rest of your site, the scanner only runs chunks of work while this browser tab is focused. If you switch tabs, minimize the window, or navigate away, the scan pauses automatically and resumes when you return.', 'site-security-audit' ); ?>
			</p>
		</div>
	</div>

	<div class="ssa-card ssa-faq">
		<div class="ssa-faq-header">
			<div class="ssa-faq-header-icon">🛡️</div>
			<div>
				<h2><?php esc_html_e( 'Help &amp; Frequently Asked Questions', 'site-security-audit' ); ?></h2>
				<p class="ssa-faq-header-sub"><?php esc_html_e( 'Everything you need to know about running and understanding scans.', 'site-security-audit' ); ?></p>
			</div>
		</div>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">⚡</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'Running Scans', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'How long does a scan take?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'A typical scan finishes in 2–10 minutes depending on the number of plugins, themes, and PHP files on your site. Sites with many plugins or large codebases take longer. Keep this browser tab open and focused throughout — the scanner pauses automatically if you switch away.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Does the scan slow down my website for visitors?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'No. The scanner is CPU-throttled and only runs while this admin tab is focused. It sleeps between work chunks to stay well under the CPU limit configured in Settings. Front-end visitor traffic is completely unaffected.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Why did my scan pause or stop?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The scan pauses automatically when you switch away from this browser tab. Return to this tab and it resumes from where it left off — no data is lost.', 'site-security-audit' ); ?></p>
				<p><?php esc_html_e( 'If the scan stops without completing, it may have been interrupted by a PHP server timeout. Try increasing the Chunk time budget in Settings, or run the scan during a quiet period on your server.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'How often should I run a scan?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Run a scan:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'After installing or updating plugins and themes', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'After a WordPress core update', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Any time you notice unusual activity on your site', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'As a weekly routine — most scans take only a few minutes', 'site-security-audit' ); ?></li>
				</ul>
			</div>
		</details>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🔍</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'What Gets Checked', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What does the scanner check?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The scanner covers 16 check categories:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'WordPress core version, configuration, and file integrity', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Plugin and theme updates and abandonment', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'User accounts, passwords, and authentication', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'File system permissions and dangerous file types', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Database configuration and suspicious options', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'SSL/TLS certificate health and mixed content', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Exposed sensitive files and directory listings', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'PHP version and dangerous function availability', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Known CVEs via built-in list and WPScan API (if configured)', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Code injection patterns and SSRF vectors', 'site-security-audit' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Will the scan fix issues automatically?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'No — this plugin is a read-only auditor. It never modifies files, settings, or the database. Every finding in the report includes a clear, actionable recommendation describing exactly what to do to fix it.', 'site-security-audit' ); ?></p>
				<div class="ssa-faq-tip">
					<span class="ssa-faq-tip-icon">💡</span>
					<span><?php esc_html_e( 'After fixing an issue, re-run the scan to confirm the finding no longer appears in your report.', 'site-security-audit' ); ?></span>
				</div>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'I found a Critical issue — what should I do first?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Critical findings represent the highest risk and should be addressed immediately. Common critical issues and first steps:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Exposed wp-config.php or backup files — delete or move them outside the webroot right away', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'PHP file in uploads directory — delete it, it\'s almost certainly a backdoor', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Expired SSL certificate — renew it immediately to prevent browser warnings for all visitors', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Weak or missing auth salts — regenerate them via https://api.wordpress.org/secret-key/1.1/salt/', 'site-security-audit' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'Open the full report and click each Critical finding for step-by-step fix instructions.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🌐</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'Compatibility', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Can I use this on a staging or local site?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Yes, but some checks require a publicly accessible HTTPS URL to work correctly:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'SSL/TLS certificate checks will be skipped if the site is on HTTP or uses a self-signed cert', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'HTTP header checks probe the live homepage — localhost URLs are not reachable from the server itself in some configurations', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Directory listing probes and sensitive file checks rely on HTTP responses', 'site-security-audit' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'All code-level checks (file integrity, permissions, user accounts, PHP config) work fully on any environment.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Does the scanner work on WordPress multisite?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Most checks work on multisite. The plugin scans the shared core files, network-activated plugins, and site-wide configuration. Some checks (like per-site plugin status) operate on the context of the site where you run the scan. Install and run the scan from the network admin for the most complete results.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<div class="ssa-faq-footer">
			<span>🔒</span>
			<span><?php esc_html_e( 'No scan data is ever sent to external servers. All analysis runs on your own hosting environment.', 'site-security-audit' ); ?></span>
		</div>
	</div>
</div>
