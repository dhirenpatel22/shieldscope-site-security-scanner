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
	<h1><?php esc_html_e( 'ShieldScope: Scan', 'shieldscope-site-security-scanner' ); ?></h1>

	<p class="description">
		<?php
		printf(
			/* translators: %s: scan time estimate, for example "about 5 to 20 minutes" */
			esc_html__( 'Audit WordPress core, plugins, themes, users, files and server settings. A scan takes %s and runs from this tab in short steps with pauses between them.', 'shieldscope-site-security-scanner' ),
			esc_html( ShieldScope_Admin::scan_time_estimate() )
		);
		?>
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
				<strong><?php esc_html_e( 'Keep this tab open:', 'shieldscope-site-security-scanner' ); ?></strong>
				<?php esc_html_e( 'the scan runs from this browser tab. By default it also pauses while the tab is hidden and continues from the same point when you return; you can turn that off in Settings. If you close the tab, start the page again and press Resume.', 'shieldscope-site-security-scanner' ); ?>
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
				<p>
				<?php
				printf(
					/* translators: %s: scan time estimate, for example "about 5 to 20 minutes" */
					esc_html__( 'A scan usually takes %s, depending on the number of plugins, themes and PHP files. Keep this tab open until it finishes.', 'shieldscope-site-security-scanner' ),
					esc_html( ShieldScope_Admin::scan_time_estimate() )
				);
				?>
				</p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Does the scan slow down my website for visitors?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Visitors should not notice on most hosts. The scan works in short steps with pauses between them (set by the scan pace in Settings), and each step uses one PHP process while it runs. On small shared hosting, run it at a quiet time.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Why did my scan pause or stop?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'By default the scan pauses while this tab is hidden. Return to the tab and it continues from where it stopped; findings so far are kept.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'If the scan stops without finishing, a PHP timeout on the server may have interrupted it. Lower Time per step in Settings, or run the scan at a quiet time.', 'shieldscope-site-security-scanner' ); ?></p>
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
					<li><?php esc_html_e( 'As a regular check, for example once a month', 'shieldscope-site-security-scanner' ); ?></li>
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
					<li><?php esc_html_e( 'Known vulnerabilities: a limited built-in list, or WPScan if you add a key', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Code patterns that need a manual review (injection, server-side requests, eval on decoded data)', 'shieldscope-site-security-scanner' ); ?></li>
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
				<p><?php esc_html_e( 'No. Every finding includes a recommendation; you decide what to change.', 'shieldscope-site-security-scanner' ); ?> <?php echo esc_html( ShieldScope_Admin::footprint_statement() ); ?></p>
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
					<li><?php esc_html_e( 'wp-config.php or a .env file readable from the web — block access to it, then change the database password and any keys it contains', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Backup file in the web root — move it out of the web root or delete it', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'PHP file in the uploads folder — find out what added it; uploads should not contain PHP code, and an unknown file there is a common sign of a compromise', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'User with an empty password — set a strong password or remove the account', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Expired SSL certificate — renew it', 'shieldscope-site-security-scanner' ); ?></li>
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
				<p><?php esc_html_e( 'Yes. On multisite only super admins can run a scan. It checks the shared core files, every installed plugin and theme, and all network users; site settings are read from the site whose dashboard you run it from. There is no separate network admin screen.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-footer">
			<span>🔒</span>
			<span><?php echo esc_html( ShieldScope_Admin::privacy_statement() ); ?></span>
		</div>
	</div>
</div>
