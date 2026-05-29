<?php
/**
 * Report view.
 *
 * @package Site_Security_Audit
 *
 * @var array  $findings  Passed from render_report_page().
 * @var array  $summary   Passed from render_report_page().
 * @var string $last_scan Passed from render_report_page().
 */

defined( 'ABSPATH' ) || exit;

$severity_order = array( 'critical', 'high', 'medium', 'low', 'info' );
$severity_label = array(
	'critical' => __( 'Critical', 'site-security-audit' ),
	'high'     => __( 'High', 'site-security-audit' ),
	'medium'   => __( 'Medium', 'site-security-audit' ),
	'low'      => __( 'Low', 'site-security-audit' ),
	'info'     => __( 'Informational', 'site-security-audit' ),
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
	         : __( 'Unknown issue', 'site-security-audit' );
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
<div class="wrap ssa-wrap">
	<h1><?php esc_html_e( 'Security Scan Report', 'site-security-audit' ); ?></h1>

	<?php if ( empty( $last_scan ) ) : ?>
		<div class="notice notice-info">
			<p><?php esc_html_e( 'No completed scan yet. Run a scan first.', 'site-security-audit' ); ?></p>
		</div>
	<?php else : ?>
		<p class="description">
			<?php
			printf(
				/* translators: %s: scan id */
				esc_html__( 'Scan ID: %s', 'site-security-audit' ),
				'<code>' . esc_html( $last_scan ) . '</code>'
			);
			?>
		</p>

		<!-- Summary counts — tiles with findings are clickable to jump to that tab -->
		<div class="ssa-card">
			<ul class="ssa-summary-grid">
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
		<div class="ssa-tabs">
			<nav class="ssa-tab-nav" role="tablist" aria-label="<?php esc_attr_e( 'Findings by severity', 'site-security-audit' ); ?>">
				<?php foreach ( $severity_order as $sev ) : ?>
					<button
						id="ssa-tab-btn-<?php echo esc_attr( $sev ); ?>"
						class="ssa-tab-btn sev-<?php echo esc_attr( $sev ); ?><?php echo esc_attr( $sev === $active_tab ? ' is-active' : '' ); ?>"
						data-tab="<?php echo esc_attr( $sev ); ?>"
						role="tab"
						aria-selected="<?php echo esc_attr( $sev === $active_tab ? 'true' : 'false' ); ?>"
						aria-controls="ssa-tab-<?php echo esc_attr( $sev ); ?>"
						<?php disabled( 0, $tabs[ $sev ]['count'] ); ?>
					>
						<?php echo esc_html( $severity_label[ $sev ] ); ?>
						<span class="ssa-tab-count"><?php echo (int) $tabs[ $sev ]['count']; ?></span>
					</button>
				<?php endforeach; ?>
			</nav>

			<div class="ssa-tab-panels">
				<?php foreach ( $severity_order as $sev ) : ?>
					<div
						id="ssa-tab-<?php echo esc_attr( $sev ); ?>"
						class="ssa-tab-panel<?php echo esc_attr( $sev === $active_tab ? ' is-active' : '' ); ?>"
						role="tabpanel"
						aria-labelledby="ssa-tab-btn-<?php echo esc_attr( $sev ); ?>"
					>
						<?php if ( empty( $tabs[ $sev ]['groups'] ) ) : ?>
							<p class="description"><?php esc_html_e( 'No issues at this severity level.', 'site-security-audit' ); ?></p>
						<?php else : ?>
							<?php foreach ( $tabs[ $sev ]['groups'] as $issue_title => $instances ) :
								$count       = count( $instances );
								$first       = $instances[0];
								$check_id    = isset( $first['check_id'] ) ? (string) $first['check_id'] : '';
								$ctx         = ( ! empty( $first['context'] ) ) ? json_decode( $first['context'], true ) : array();
								$plugin_name = ( is_array( $ctx ) && ! empty( $ctx['plugin_name'] ) ) ? (string) $ctx['plugin_name'] : '';
							?>
								<details class="ssa-finding sev-<?php echo esc_attr( $sev ); ?>">
									<summary>
										<span class="ssa-finding-title"><?php echo esc_html( $issue_title ); ?></span>
										<?php if ( '' !== $check_id ) : ?>
											<span class="ssa-finding-check"><?php echo esc_html( $check_id ); ?></span>
										<?php endif; ?>
										<?php if ( 1 === $count && '' !== $plugin_name ) : ?>
											<span class="ssa-issue-badge"><?php echo esc_html( $plugin_name ); ?></span>
										<?php endif; ?>
										<?php if ( $count > 1 ) : ?>
											<span class="ssa-issue-badge">
												<?php echo esc_html(
													sprintf(
														/* translators: %d: number of affected items */
														_n( '%d instance', '%d instances', $count, 'site-security-audit' ),
														$count
													)
												); ?>
											</span>
										<?php endif; ?>
									</summary>
									<div class="ssa-finding-body">
										<?php if ( ! empty( $first['description'] ) ) : ?>
											<p><?php echo wp_kses_post( $first['description'] ); ?></p>
										<?php endif; ?>
										<?php if ( ! empty( $first['recommendation'] ) ) : ?>
											<p><strong><?php esc_html_e( 'Recommendation:', 'site-security-audit' ); ?></strong>
											<?php echo wp_kses_post( $first['recommendation'] ); ?></p>
										<?php endif; ?>
										<?php if ( 1 === $count ) : ?>
											<?php if ( ! empty( $first['target'] ) ) : ?>
												<p><strong><?php esc_html_e( 'Target:', 'site-security-audit' ); ?></strong>
												<code><?php echo esc_html( $first['target'] ); ?></code></p>
											<?php endif; ?>
										<?php else : ?>
											<div class="ssa-instances">
												<p class="ssa-instances-label"><?php esc_html_e( 'Affected items:', 'site-security-audit' ); ?></p>
												<ul class="ssa-target-list">
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

	<div class="ssa-card ssa-faq">
		<div class="ssa-faq-header">
			<div class="ssa-faq-header-icon">📋</div>
			<div>
				<h2><?php esc_html_e( 'Understanding Your Results', 'site-security-audit' ); ?></h2>
				<p class="ssa-faq-header-sub"><?php esc_html_e( 'A guide to reading your security report and knowing what to do next.', 'site-security-audit' ); ?></p>
			</div>
		</div>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🚦</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'Severity Levels', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item" open>
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What do the severity levels mean?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p>
					<span class="ssa-sev-chip critical">● Critical</span>&nbsp;
					<?php esc_html_e( 'Immediate risk of data breach, site takeover, or credential exposure. Act today.', 'site-security-audit' ); ?>
				</p>
				<p>
					<span class="ssa-sev-chip high">● High</span>&nbsp;
					<?php esc_html_e( 'Significant risk that a motivated attacker could exploit. Address within 24–48 hours.', 'site-security-audit' ); ?>
				</p>
				<p>
					<span class="ssa-sev-chip medium">● Medium</span>&nbsp;
					<?php esc_html_e( 'Notable weaknesses that increase attack surface. Fix during your next maintenance window.', 'site-security-audit' ); ?>
				</p>
				<p>
					<span class="ssa-sev-chip low">● Low</span>&nbsp;
					<?php esc_html_e( 'Hardening recommendations and best practices. Useful to address but not urgent.', 'site-security-audit' ); ?>
				</p>
				<p>
					<span class="ssa-sev-chip info">● Info</span>&nbsp;
					<?php esc_html_e( 'Status details and observations that require no immediate action.', 'site-security-audit' ); ?>
				</p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Where should I start?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Work through findings in severity order — Critical first, then High, then Medium. Each finding has a Recommendation section with clear steps.', 'site-security-audit' ); ?></p>
				<ol>
					<li><?php esc_html_e( 'Fix all Critical findings immediately — these are active risks', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Address High findings within 24–48 hours', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Schedule Medium fixes in your next maintenance window', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Work through Low and Info findings as time allows', 'site-security-audit' ); ?></li>
				</ol>
				<div class="ssa-faq-tip">
					<span class="ssa-faq-tip-icon">💡</span>
					<span><?php esc_html_e( 'After fixing issues, run a new scan from the Scan page — the report updates only after a fresh scan completes.', 'site-security-audit' ); ?></span>
				</div>
			</div>
		</details>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🔧</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'Taking Action', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'A finding mentions a plugin I use — what do I do?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Check Dashboard → Updates first — an update may already fix the issue. If an update is available, apply it, then re-run the scan to confirm.', 'site-security-audit' ); ?></p>
				<p><?php esc_html_e( 'If no update is available, visit the plugin\'s page on wordpress.org, open the Support tab, and post a message to the developer asking for a fix timeline. In the meantime, consider deactivating the plugin if the vulnerability is high-severity and you do not rely on it critically.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'How do I fix WordPress core update and integrity issues?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'For outdated core: go to Dashboard → Updates and click "Update Now". This is always safe and takes under 2 minutes.', 'site-security-audit' ); ?></p>
				<p><?php esc_html_e( 'For modified or missing core files: go to Dashboard → Updates and click "Re-install now" — this re-downloads all core files without touching your content, plugins, or wp-config.php. It is the safest way to restore a clean WordPress installation.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'How do I share this report with my developer?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The simplest way is to give your developer temporary Administrator access to this WordPress dashboard so they can view the report directly. If you prefer not to do that:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Take a screenshot or use your browser\'s print function (Ctrl/Cmd+P) to save the report as a PDF', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Copy the key Critical and High findings and paste them into an email', 'site-security-audit' ); ?></li>
				</ul>
			</div>
		</details>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">💬</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'About Results', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Could any findings be false positives?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Yes, occasionally. Some examples:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( '"No brute-force protection" may appear even if your host applies firewall-level rate limiting that this plugin cannot detect', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( '"Inactive plugin present" fires for all inactive plugins, even ones intentionally kept as backups', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Version disclosure warnings (Low) are informational signals — they are not exploitable on their own', 'site-security-audit' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'Read the description of each finding — it explains why the issue was flagged, giving you the context to judge whether it applies to your setup.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'I fixed an issue — why does it still appear in the report?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The report displays results from the last completed scan — it does not update automatically. Go to Security Audit → Scan, run a new scan, and the updated report will reflect your fixes.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'How do I know when my site is properly secured?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'A well-secured WordPress site typically shows:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Zero Critical or High findings in the report', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'WordPress core, all plugins, and all themes up to date', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Valid SSL certificate with plenty of days remaining', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Key security headers (HSTS, CSP, X-Frame-Options) all present', 'site-security-audit' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'Security is an ongoing process, not a one-time task. Regular scans and keeping software updated are the two most effective things you can do.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<div class="ssa-faq-footer">
			<span>ℹ️</span>
			<span><?php esc_html_e( 'The scanner is read-only — it never modifies your files, database, or settings.', 'site-security-audit' ); ?></span>
		</div>
	</div>
</div>
