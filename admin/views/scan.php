<?php
/**
 * Scan control view.
 *
 * @package ShieldScope
 *
 * @var array $state Passed in from render_scan_page().
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap shieldscope-wrap">
	<h1><?php esc_html_e( 'ShieldScope – Site Security Scanner', 'shieldscope-site-security-scanner' ); ?></h1>

	<p class="description">
		<?php esc_html_e( 'Run a comprehensive background scan of your WordPress installation, themes, plugins, users and filesystem. The scan is CPU-throttled and will automatically pause if you leave this tab.', 'shieldscope-site-security-scanner' ); ?>
	</p>

	<div id="shieldscope-scan-panel"
		 data-status="<?php echo esc_attr( $state['status'] ); ?>"
		 data-progress="<?php echo esc_attr( (int) ( ! empty( $state['total_steps'] ) ? floor( ( $state['done_steps'] * 100 ) / $state['total_steps'] ) : 0 ) ); ?>"
		 data-scan-id="<?php echo esc_attr( $state['scan_id'] ); ?>">

		<div id="shieldscope-blur-banner" class="shieldscope-blur-banner" role="status" aria-live="polite" hidden>
			<span class="shieldscope-blur-icon" aria-hidden="true">👋</span>
			<div class="shieldscope-blur-text">
				<strong id="shieldscope-blur-title"></strong>
				<span id="shieldscope-blur-body"></span>
			</div>
		</div>

		<div class="shieldscope-card">
			<div class="shieldscope-status-row">
				<span class="shieldscope-status-label"><?php esc_html_e( 'Status', 'shieldscope-site-security-scanner' ); ?>:</span>
				<span class="shieldscope-status-value" id="shieldscope-status-text"><?php echo esc_html( ucfirst( $state['status'] ) ); ?></span>
			</div>

			<div class="shieldscope-progress-wrap">
				<div class="shieldscope-progress-bar">
					<div class="shieldscope-progress-fill" id="shieldscope-progress-fill"></div>
				</div>
				<div class="shieldscope-progress-meta">
					<span id="shieldscope-progress-pct">0%</span>
					<span id="shieldscope-progress-steps">
						<?php
						printf(
							/* translators: 1: done, 2: total */
							esc_html__( '%1$d of %2$d checks', 'shieldscope-site-security-scanner' ),
							(int) $state['done_steps'],
							(int) $state['total_steps']
						);
						?>
					</span>
				</div>
			</div>

			<p id="shieldscope-message" class="shieldscope-message">
				<?php echo esc_html( $state['last_message'] ); ?>
			</p>

			<div class="shieldscope-controls">
				<button type="button" class="button button-primary" id="shieldscope-btn-start">
					<?php esc_html_e( 'Start Scan', 'shieldscope-site-security-scanner' ); ?>
				</button>
				<button type="button" class="button" id="shieldscope-btn-pause" disabled>
					<?php esc_html_e( 'Pause', 'shieldscope-site-security-scanner' ); ?>
				</button>
				<button type="button" class="button" id="shieldscope-btn-resume" disabled>
					<?php esc_html_e( 'Resume', 'shieldscope-site-security-scanner' ); ?>
				</button>
				<button type="button" class="button button-link-delete" id="shieldscope-btn-abort" disabled>
					<?php esc_html_e( 'Abort', 'shieldscope-site-security-scanner' ); ?>
				</button>
			</div>
		</div>

		<div class="shieldscope-card shieldscope-summary shieldscope-hidden" id="shieldscope-summary">
			<h2><?php esc_html_e( 'Live findings', 'shieldscope-site-security-scanner' ); ?></h2>
			<ul class="shieldscope-summary-grid">
				<li class="sev-critical"><span class="count" data-sev="critical">0</span><span class="label"><?php esc_html_e( 'Critical', 'shieldscope-site-security-scanner' ); ?></span></li>
				<li class="sev-high"><span class="count" data-sev="high">0</span><span class="label"><?php esc_html_e( 'High', 'shieldscope-site-security-scanner' ); ?></span></li>
				<li class="sev-medium"><span class="count" data-sev="medium">0</span><span class="label"><?php esc_html_e( 'Medium', 'shieldscope-site-security-scanner' ); ?></span></li>
				<li class="sev-low"><span class="count" data-sev="low">0</span><span class="label"><?php esc_html_e( 'Low', 'shieldscope-site-security-scanner' ); ?></span></li>
				<li class="sev-info"><span class="count" data-sev="info">0</span><span class="label"><?php esc_html_e( 'Info', 'shieldscope-site-security-scanner' ); ?></span></li>
			</ul>
			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . SHIELDSCOPE_SLUG . '-report' ) ); ?>" class="button">
					<?php esc_html_e( 'View full report', 'shieldscope-site-security-scanner' ); ?>
				</a>
			</p>
		</div>

		<div class="shieldscope-card shieldscope-notice-card">
			<p>
				<strong><?php esc_html_e( 'About the focus-lock:', 'shieldscope-site-security-scanner' ); ?></strong>
				<?php esc_html_e( 'To avoid stealing CPU from the rest of your site, the scanner only runs chunks of work while this browser tab is focused. If you switch tabs, minimize the window, or navigate away, the scan pauses automatically and resumes when you return.', 'shieldscope-site-security-scanner' ); ?>
			</p>
		</div>
	</div>

	<div class="shieldscope-card shieldscope-faq">
		<div class="shieldscope-faq-header">
			<div class="shieldscope-faq-header-icon">🛡️</div>
			<div>
				<h2><?php esc_html_e( 'Help &amp; Frequently Asked Questions', 'shieldscope-site-security-scanner' ); ?></h2>
				<p class="shieldscope-faq-header-sub"><?php esc_html_e( 'Everything you need to know about running and understanding scans.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</div>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">⚡</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'Running Scans', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How long does a scan take?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'A typical scan finishes in 2–10 minutes depending on the number of plugins, themes, and PHP files on your site. Sites with many plugins or large codebases take longer. Keep this browser tab open and focused throughout — the scanner pauses automatically if you switch away.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Does the scan slow down my website for visitors?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'No. The scanner is CPU-throttled and only runs while this admin tab is focused. It sleeps between work chunks to stay well under the CPU limit configured in Settings. Front-end visitor traffic is completely unaffected.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Why did my scan pause or stop?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The scan pauses automatically when you switch away from this browser tab. Return to this tab and it resumes from where it left off — no data is lost.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'If the scan stops without completing, it may have been interrupted by a PHP server timeout. Try increasing the Chunk time budget in Settings, or run the scan during a quiet period on your server.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How often should I run a scan?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Run a scan:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'After installing or updating plugins and themes', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'After a WordPress core update', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Any time you notice unusual activity on your site', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'As a weekly routine — most scans take only a few minutes', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
		</details>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🔍</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'What Gets Checked', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What does the scanner check?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The scanner covers 16 check categories:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'WordPress core version, configuration, and file integrity', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Plugin and theme updates and abandonment', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'User accounts, passwords, and authentication', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'File system permissions and dangerous file types', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Database configuration and suspicious options', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'SSL/TLS certificate health and mixed content', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Exposed sensitive files and directory listings', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'PHP version and dangerous function availability', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Known CVEs via built-in list and WPScan API (if configured)', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Code injection patterns and SSRF vectors', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Will the scan fix issues automatically?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'No — this plugin is a read-only auditor. It never modifies files, settings, or the database. Every finding in the report includes a clear, actionable recommendation describing exactly what to do to fix it.', 'shieldscope-site-security-scanner' ); ?></p>
				<div class="shieldscope-faq-tip">
					<span class="shieldscope-faq-tip-icon">💡</span>
					<span><?php esc_html_e( 'After fixing an issue, re-run the scan to confirm the finding no longer appears in your report.', 'shieldscope-site-security-scanner' ); ?></span>
				</div>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'I found a Critical issue — what should I do first?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Critical findings represent the highest risk and should be addressed immediately. Common critical issues and first steps:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Exposed wp-config.php or backup files — delete or move them outside the webroot right away', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'PHP file in uploads directory — delete it, it\'s almost certainly a backdoor', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Expired SSL certificate — renew it immediately to prevent browser warnings for all visitors', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Weak or missing auth salts — regenerate them via https://api.wordpress.org/secret-key/1.1/salt/', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'Open the full report and click each Critical finding for step-by-step fix instructions.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🌐</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'Compatibility', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Can I use this on a staging or local site?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Yes, but some checks require a publicly accessible HTTPS URL to work correctly:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'SSL/TLS certificate checks will be skipped if the site is on HTTP or uses a self-signed cert', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'HTTP header checks probe the live homepage — localhost URLs are not reachable from the server itself in some configurations', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Directory listing probes and sensitive file checks rely on HTTP responses', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'All code-level checks (file integrity, permissions, user accounts, PHP config) work fully on any environment.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Does the scanner work on WordPress multisite?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Most checks work on multisite. The plugin scans the shared core files, network-activated plugins, and site-wide configuration. Some checks (like per-site plugin status) operate on the context of the site where you run the scan. Install and run the scan from the network admin for the most complete results.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-footer">
			<span>🔒</span>
			<span><?php esc_html_e( 'No scan data is ever sent to external servers. All analysis runs on your own hosting environment.', 'shieldscope-site-security-scanner' ); ?></span>
		</div>
	</div>
</div>
