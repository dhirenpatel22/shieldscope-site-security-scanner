<?php
/**
 * Report view.
 *
 * @package ShieldScope
 *
 * @var array  $findings  Passed from render_report_page().
 * @var array  $summary   Passed from render_report_page().
 * @var string $last_scan Passed from render_report_page().
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- included inside a class method, not global scope
$severity_order = array( 'critical', 'high', 'medium', 'low', 'info' );
$severity_label = array(
	'critical' => __( 'Critical', 'shieldscope-site-security-scanner' ),
	'high'     => __( 'High', 'shieldscope-site-security-scanner' ),
	'medium'   => __( 'Medium', 'shieldscope-site-security-scanner' ),
	'low'      => __( 'Low', 'shieldscope-site-security-scanner' ),
	'info'     => __( 'Informational', 'shieldscope-site-security-scanner' ),
);

// Build tabs: severity → { count, groups: issue-title → [findings] }
// Findings with identical titles are the same issue type and are merged so
// the user sees one collapsible row per type, with all affected targets listed
// inside rather than one row per individual finding.
$tabs = array();
foreach ( $severity_order as $sev ) {
	$tabs[ $sev ] = array(
		'count'  => 0,
		'groups' => array(),
	);
}

foreach ( (array) $findings as $f ) {
	$sev   = ( isset( $f['severity'] ) && isset( $tabs[ $f['severity'] ] ) )
	         ? $f['severity'] : 'info';
	$title = ( isset( $f['title'] ) && '' !== trim( (string) $f['title'] ) )
	         ? trim( (string) $f['title'] )
	         : __( 'Unknown issue', 'shieldscope-site-security-scanner' );
	$tabs[ $sev ]['count']++;
	$tabs[ $sev ]['groups'][ $title ][] = $f;
}

// Default active tab: first severity that has findings.
$active_tab = 'info';
foreach ( $severity_order as $sev ) {
	if ( $tabs[ $sev ]['count'] > 0 ) {
		$active_tab = $sev;
		break;
	}
}
?>
<div class="wrap shieldscope-wrap">
	<h1><?php esc_html_e( 'Security Scan Report', 'shieldscope-site-security-scanner' ); ?></h1>

	<?php if ( empty( $last_scan ) ) : ?>
		<div class="notice notice-info">
			<p><?php esc_html_e( 'No completed scan yet. Run a scan first.', 'shieldscope-site-security-scanner' ); ?></p>
		</div>
	<?php else : ?>
		<p class="description">
			<?php
			printf(
				/* translators: %s: scan id */
				esc_html__( 'Scan ID: %s', 'shieldscope-site-security-scanner' ),
				'<code>' . esc_html( $last_scan ) . '</code>'
			);
			?>
		</p>

		<!-- Summary counts — tiles with findings are clickable to jump to that tab -->
		<div class="shieldscope-card">
			<ul class="shieldscope-summary-grid">
				<?php foreach ( $severity_order as $sev ) : ?>
					<li
						class="sev-<?php echo esc_attr( $sev ); ?><?php echo esc_attr( $tabs[ $sev ]['count'] > 0 ? ' is-clickable' : '' ); ?>"
						<?php if ( $tabs[ $sev ]['count'] > 0 ) : ?>
							data-tab="<?php echo esc_attr( $sev ); ?>"
							role="button"
							tabindex="0"
						<?php endif; ?>
					>
						<span class="count"><?php echo (int) ( isset( $summary[ $sev ] ) ? $summary[ $sev ] : 0 ); ?></span>
						<span class="label"><?php echo esc_html( $severity_label[ $sev ] ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		</div>

		<!-- Severity tabs -->
		<div class="shieldscope-tabs">
			<nav class="shieldscope-tab-nav" role="tablist" aria-label="<?php esc_attr_e( 'Findings by severity', 'shieldscope-site-security-scanner' ); ?>">
				<?php foreach ( $severity_order as $sev ) : ?>
					<button
						id="shieldscope-tab-btn-<?php echo esc_attr( $sev ); ?>"
						class="shieldscope-tab-btn sev-<?php echo esc_attr( $sev ); ?><?php echo esc_attr( $sev === $active_tab ? ' is-active' : '' ); ?>"
						data-tab="<?php echo esc_attr( $sev ); ?>"
						role="tab"
						aria-selected="<?php echo esc_attr( $sev === $active_tab ? 'true' : 'false' ); ?>"
						aria-controls="shieldscope-tab-<?php echo esc_attr( $sev ); ?>"
						<?php disabled( 0, $tabs[ $sev ]['count'] ); ?>
					>
						<?php echo esc_html( $severity_label[ $sev ] ); ?>
						<span class="shieldscope-tab-count"><?php echo (int) $tabs[ $sev ]['count']; ?></span>
					</button>
				<?php endforeach; ?>
			</nav>

			<div class="shieldscope-tab-panels">
				<?php foreach ( $severity_order as $sev ) : ?>
					<div
						id="shieldscope-tab-<?php echo esc_attr( $sev ); ?>"
						class="shieldscope-tab-panel<?php echo esc_attr( $sev === $active_tab ? ' is-active' : '' ); ?>"
						role="tabpanel"
						aria-labelledby="shieldscope-tab-btn-<?php echo esc_attr( $sev ); ?>"
					>
						<?php if ( empty( $tabs[ $sev ]['groups'] ) ) : ?>
							<p class="description"><?php esc_html_e( 'No issues at this severity level.', 'shieldscope-site-security-scanner' ); ?></p>
						<?php else : ?>
							<?php foreach ( $tabs[ $sev ]['groups'] as $issue_title => $instances ) :
								$count       = count( $instances );
								$first       = $instances[0];
								$check_id    = isset( $first['check_id'] ) ? (string) $first['check_id'] : '';
								$ctx         = ( ! empty( $first['context'] ) ) ? json_decode( $first['context'], true ) : array();
								$plugin_name = ( is_array( $ctx ) && ! empty( $ctx['plugin_name'] ) ) ? (string) $ctx['plugin_name'] : '';
							?>
								<details class="shieldscope-finding sev-<?php echo esc_attr( $sev ); ?>">
									<summary>
										<span class="shieldscope-finding-title"><?php echo esc_html( $issue_title ); ?></span>
										<?php if ( '' !== $check_id ) : ?>
											<span class="shieldscope-finding-check"><?php echo esc_html( $check_id ); ?></span>
										<?php endif; ?>
										<?php if ( 1 === $count && '' !== $plugin_name ) : ?>
											<span class="shieldscope-issue-badge"><?php echo esc_html( $plugin_name ); ?></span>
										<?php endif; ?>
										<?php if ( $count > 1 ) : ?>
											<span class="shieldscope-issue-badge">
												<?php echo esc_html(
													sprintf(
														/* translators: %d: number of affected items */
														_n( '%d instance', '%d instances', $count, 'shieldscope-site-security-scanner' ),
														$count
													)
												); ?>
											</span>
										<?php endif; ?>
									</summary>
									<div class="shieldscope-finding-body">
										<?php if ( ! empty( $first['description'] ) ) : ?>
											<p><?php echo wp_kses_post( $first['description'] ); ?></p>
										<?php endif; ?>
										<?php if ( ! empty( $first['recommendation'] ) ) : ?>
											<p><strong><?php esc_html_e( 'Recommendation:', 'shieldscope-site-security-scanner' ); ?></strong>
											<?php echo wp_kses_post( $first['recommendation'] ); ?></p>
										<?php endif; ?>
										<?php if ( 1 === $count ) : ?>
											<?php if ( ! empty( $first['target'] ) ) : ?>
												<p><strong><?php esc_html_e( 'Target:', 'shieldscope-site-security-scanner' ); ?></strong>
												<code><?php echo esc_html( $first['target'] ); ?></code></p>
											<?php endif; ?>
										<?php else : ?>
											<div class="shieldscope-instances">
												<p class="shieldscope-instances-label"><?php esc_html_e( 'Affected items:', 'shieldscope-site-security-scanner' ); ?></p>
												<ul class="shieldscope-target-list">
													<?php foreach ( $instances as $inst ) : ?>
														<?php if ( ! empty( $inst['target'] ) ) : ?>
															<li><code><?php echo esc_html( $inst['target'] ); ?></code></li>
														<?php endif; ?>
													<?php endforeach; ?>
												</ul>
											</div>
										<?php endif; ?>
									</div>
								</details>
							<?php endforeach; ?>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
	<?php endif; ?>

	<div class="shieldscope-card shieldscope-faq">
		<div class="shieldscope-faq-header">
			<div class="shieldscope-faq-header-icon">📋</div>
			<div>
				<h2><?php esc_html_e( 'Understanding Your Results', 'shieldscope-site-security-scanner' ); ?></h2>
				<p class="shieldscope-faq-header-sub"><?php esc_html_e( 'A guide to reading your security report and knowing what to do next.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</div>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🚦</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'Severity Levels', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item" open>
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What do the severity levels mean?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p>
					<span class="shieldscope-sev-chip critical">● Critical</span>&nbsp;
					<?php esc_html_e( 'Immediate risk of data breach, site takeover, or credential exposure. Act today.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<span class="shieldscope-sev-chip high">● High</span>&nbsp;
					<?php esc_html_e( 'Significant risk that a motivated attacker could exploit. Address within 24–48 hours.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<span class="shieldscope-sev-chip medium">● Medium</span>&nbsp;
					<?php esc_html_e( 'Notable weaknesses that increase attack surface. Fix during your next maintenance window.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<span class="shieldscope-sev-chip low">● Low</span>&nbsp;
					<?php esc_html_e( 'Hardening recommendations and best practices. Useful to address but not urgent.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<span class="shieldscope-sev-chip info">● Info</span>&nbsp;
					<?php esc_html_e( 'Status details and observations that require no immediate action.', 'shieldscope-site-security-scanner' ); ?>
				</p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Where should I start?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Work through findings in severity order — Critical first, then High, then Medium. Each finding has a Recommendation section with clear steps.', 'shieldscope-site-security-scanner' ); ?></p>
				<ol>
					<li><?php esc_html_e( 'Fix all Critical findings immediately — these are active risks', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Address High findings within 24–48 hours', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Schedule Medium fixes in your next maintenance window', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Work through Low and Info findings as time allows', 'shieldscope-site-security-scanner' ); ?></li>
				</ol>
				<div class="shieldscope-faq-tip">
					<span class="shieldscope-faq-tip-icon">💡</span>
					<span><?php esc_html_e( 'After fixing issues, run a new scan from the Scan page — the report updates only after a fresh scan completes.', 'shieldscope-site-security-scanner' ); ?></span>
				</div>
			</div>
		</details>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🔧</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'Taking Action', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'A finding mentions a plugin I use — what do I do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Check Dashboard → Updates first — an update may already fix the issue. If an update is available, apply it, then re-run the scan to confirm.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'If no update is available, visit the plugin\'s page on wordpress.org, open the Support tab, and post a message to the developer asking for a fix timeline. In the meantime, consider deactivating the plugin if the vulnerability is high-severity and you do not rely on it critically.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How do I fix WordPress core update and integrity issues?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'For outdated core: go to Dashboard → Updates and click "Update Now". This is always safe and takes under 2 minutes.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'For modified or missing core files: go to Dashboard → Updates and click "Re-install now" — this re-downloads all core files without touching your content, plugins, or wp-config.php. It is the safest way to restore a clean WordPress installation.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How do I share this report with my developer?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The simplest way is to give your developer temporary Administrator access to this WordPress dashboard so they can view the report directly. If you prefer not to do that:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Take a screenshot or use your browser\'s print function (Ctrl/Cmd+P) to save the report as a PDF', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Copy the key Critical and High findings and paste them into an email', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
		</details>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">💬</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'About Results', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Could any findings be false positives?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Yes, occasionally. Some examples:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( '"No brute-force protection" may appear even if your host applies firewall-level rate limiting that this plugin cannot detect', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '"Inactive plugin present" fires for all inactive plugins, even ones intentionally kept as backups', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Version disclosure warnings (Low) are informational signals — they are not exploitable on their own', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'Read the description of each finding — it explains why the issue was flagged, giving you the context to judge whether it applies to your setup.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'I fixed an issue — why does it still appear in the report?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The report displays results from the last completed scan — it does not update automatically. Go to Security Audit → Scan, run a new scan, and the updated report will reflect your fixes.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How do I know when my site is properly secured?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'A well-secured WordPress site typically shows:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Zero Critical or High findings in the report', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'WordPress core, all plugins, and all themes up to date', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Valid SSL certificate with plenty of days remaining', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Key security headers (HSTS, CSP, X-Frame-Options) all present', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'Security is an ongoing process, not a one-time task. Regular scans and keeping software updated are the two most effective things you can do.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-footer">
			<span>ℹ️</span>
			<span><?php esc_html_e( 'The scanner is read-only — it never modifies your files, database, or settings.', 'shieldscope-site-security-scanner' ); ?></span>
		</div>
	</div>
</div>
