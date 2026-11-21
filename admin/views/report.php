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

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound,WordPress.WP.GlobalVariablesOverride.Prohibited -- included inside a class method, not global scope; $tabs/$title are local to the render callback, not real WP globals
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
// Ignored findings (S-07) are left out of the counts but listed below.
list( $findings, $shieldscope_ignored ) = ShieldScope_Ignore::split( (array) $findings );
$shieldscope_reasons                    = ShieldScope_Ignore::reasons();
$shieldscope_labels                     = ShieldScope_PDF_Report::check_labels();

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

?>
<div class="wrap shieldscope-wrap">
	<h1><?php esc_html_e( 'ShieldScope: Report', 'shieldscope-site-security-scanner' ); ?></h1>

	<?php
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only status flag set by our own redirect.
	$shieldscope_ignore_msg = isset( $_GET['shieldscope_ignore'] ) ? sanitize_key( wp_unslash( $_GET['shieldscope_ignore'] ) ) : '';
	$shieldscope_notices    = array(
		'ignored'  => array( 'success', __( 'Item ignored. It is listed under Ignored findings and can be restored.', 'shieldscope-site-security-scanner' ) ),
		'restored' => array( 'success', __( 'Item restored.', 'shieldscope-site-security-scanner' ) ),
		'invalid'  => array( 'error', __( 'Not ignored: choose a reason, and add a note for Critical findings or for "Other".', 'shieldscope-site-security-scanner' ) ),
		'notfound' => array( 'error', __( 'Not ignored: that item is not in the latest scan.', 'shieldscope-site-security-scanner' ) ),
	);
	?>
	<?php if ( isset( $shieldscope_notices[ $shieldscope_ignore_msg ] ) ) : ?>
		<div class="notice notice-<?php echo esc_attr( $shieldscope_notices[ $shieldscope_ignore_msg ][0] ); ?> is-dismissible"><p><?php echo esc_html( $shieldscope_notices[ $shieldscope_ignore_msg ][1] ); ?></p></div>
	<?php endif; ?>

	<?php if ( empty( $last_scan ) ) : ?>
		<div class="notice notice-info">
			<p><?php esc_html_e( 'No completed scan yet. Run a scan first.', 'shieldscope-site-security-scanner' ); ?></p>
		</div>
	<?php elseif ( empty( $findings ) && empty( $shieldscope_ignored ) ) : ?>
		<div class="notice notice-<?php echo esc_attr( ShieldScope_Logger::save_failed( $last_scan ) ? 'error' : 'warning' ); ?>">
			<p>
				<?php
				if ( ShieldScope_Logger::save_failed( $last_scan ) ) {
					esc_html_e( 'The results of this scan could not be saved, so no report is available. Run a new scan.', 'shieldscope-site-security-scanner' );
				} else {
					esc_html_e( 'Report expired, run a new scan.', 'shieldscope-site-security-scanner' );
				}
				?>
			</p>
		</div>
	<?php else : ?>
		<?php if ( ShieldScope_Logger::save_failed( $last_scan ) ) : ?>
			<div class="notice notice-error">
				<p><?php esc_html_e( 'The results of this scan could not be saved in full, so this report may be missing findings. Run a new scan.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		<?php endif; ?>
		<?php
		$scan_time = '';
		foreach ( $findings as $f ) {
			if ( ! empty( $f['created_at'] ) && $f['created_at'] > $scan_time ) {
				$scan_time = $f['created_at'];
			}
		}
		?>
		<p class="description">
			<?php
			printf(
				/* translators: %s: scan id */
				esc_html__( 'Scan ID: %s', 'shieldscope-site-security-scanner' ),
				'<code>' . esc_html( $last_scan ) . '</code>'
			);
			if ( '' !== $scan_time ) {
				echo ' &middot; ';
				printf(
					/* translators: %s: date and time the scan finished */
					esc_html__( 'Scan date: %s', 'shieldscope-site-security-scanner' ),
					esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $scan_time . ' UTC' ) ) )
				);
			}
			?>
		</p>

		<div class="shieldscope-export">
			<?php $shieldscope_pdf_reason = ShieldScope_PDF_Report::unavailable_reason(); ?>
			<?php if ( '' === $shieldscope_pdf_reason ) : ?>
				<a class="button button-primary" href="<?php echo esc_url( ShieldScope_PDF_Report::download_url() ); ?>">
					<span class="dashicons dashicons-pdf" aria-hidden="true"></span>
					<?php esc_html_e( 'Download PDF report', 'shieldscope-site-security-scanner' ); ?>
				</a>
			<?php else : ?>
				<p class="description"><?php echo esc_html( $shieldscope_pdf_reason ); ?></p>
			<?php endif; ?>
			<a class="button" href="<?php echo esc_url( ShieldScope_Export::download_url( 'csv' ) ); ?>"><?php esc_html_e( 'Download CSV', 'shieldscope-site-security-scanner' ); ?></a>
			<a class="button" href="<?php echo esc_url( ShieldScope_Export::download_url( 'json' ) ); ?>"><?php esc_html_e( 'Download JSON', 'shieldscope-site-security-scanner' ); ?></a>
			<span class="description"><?php esc_html_e( 'File paths in downloads are shown relative to the WordPress folder.', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<div class="shieldscope-card shieldscope-summary-card">
			<h2 class="shieldscope-verdict"><?php echo esc_html( ShieldScope_PDF_Report::verdict( array_combine( array_keys( $tabs ), array_column( $tabs, 'count' ) ) ) ); ?></h2>
			<ul class="shieldscope-summary-grid">
				<?php foreach ( $severity_order as $sev ) : ?>
					<li class="sev-<?php echo esc_attr( $sev ); ?>">
						<?php if ( $tabs[ $sev ]['count'] > 0 ) : ?>
							<a href="#shieldscope-sev-<?php echo esc_attr( $sev ); ?>">
						<?php endif; ?>
						<span class="count"><?php echo (int) $tabs[ $sev ]['count']; ?></span>
						<span class="label"><?php echo esc_html( $severity_label[ $sev ] ); ?></span>
						<?php if ( $tabs[ $sev ]['count'] > 0 ) : ?>
							</a>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ul>
			<?php
			$shieldscope_top = array();
			foreach ( array( 'critical', 'high' ) as $sev ) {
				foreach ( array_keys( $tabs[ $sev ]['groups'] ) as $shieldscope_title ) {
					$shieldscope_top[] = array( $sev, $shieldscope_title );
				}
			}
			?>
			<?php if ( $shieldscope_top ) : ?>
				<h3><?php esc_html_e( 'Fix first', 'shieldscope-site-security-scanner' ); ?></h3>
				<ol class="shieldscope-top-actions">
					<?php foreach ( array_slice( $shieldscope_top, 0, 5 ) as $shieldscope_item ) : ?>
						<li><span class="shieldscope-sev-chip <?php echo esc_attr( $shieldscope_item[0] ); ?>"><?php echo esc_html( $severity_label[ $shieldscope_item[0] ] ); ?></span> <?php echo esc_html( $shieldscope_item[1] ); ?></li>
					<?php endforeach; ?>
				</ol>
			<?php endif; ?>
		</div>

		<?php $shieldscope_coverage = ShieldScope_Coverage::get( $last_scan ); ?>
		<?php if ( null !== $shieldscope_coverage ) : ?>
			<div class="shieldscope-card shieldscope-coverage">
				<p><strong><?php esc_html_e( 'Coverage:', 'shieldscope-site-security-scanner' ); ?></strong>
				<?php echo esc_html( ShieldScope_Coverage::summary( $shieldscope_coverage ) ); ?></p>
				<details>
					<summary><?php esc_html_e( 'Show every check', 'shieldscope-site-security-scanner' ); ?></summary>
					<table class="widefat striped">
						<thead><tr>
							<th scope="col"><?php esc_html_e( 'Check', 'shieldscope-site-security-scanner' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Result', 'shieldscope-site-security-scanner' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Notes', 'shieldscope-site-security-scanner' ); ?></th>
						</tr></thead>
						<tbody>
						<?php foreach ( $shieldscope_coverage as $shieldscope_check ) : ?>
							<tr class="is-<?php echo esc_attr( $shieldscope_check['status'] ); ?>">
								<td><?php echo esc_html( $shieldscope_check['label'] ); ?></td>
								<td><?php echo esc_html( ShieldScope_Coverage::status_label( $shieldscope_check['status'] ) ); ?></td>
								<td><?php echo esc_html( implode( '; ', (array) $shieldscope_check['notes'] ) ); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				</details>
			</div>
		<?php endif; ?>

		<?php $shieldscope_cmp = ShieldScope_History::compare_with_previous( $last_scan, array_merge( $findings, $shieldscope_ignored ) ); ?>
		<?php if ( null !== $shieldscope_cmp ) : ?>
			<div class="shieldscope-card shieldscope-compare">
				<p><strong><?php esc_html_e( 'Since the previous scan', 'shieldscope-site-security-scanner' ); ?></strong>
				(<?php echo esc_html( wp_date( get_option( 'date_format' ), strtotime( $shieldscope_cmp['previous']['date'] . ' UTC' ) ) ); ?>):
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: new findings, 2: fixed findings, 3: findings still open */
						__( '%1$d new, %2$d fixed, %3$d still open.', 'shieldscope-site-security-scanner' ),
						count( $shieldscope_cmp['new'] ),
						count( $shieldscope_cmp['fixed'] ),
						$shieldscope_cmp['open']
					)
				);
				?>
				</p>
				<?php foreach ( array( 'new' => __( 'New', 'shieldscope-site-security-scanner' ), 'fixed' => __( 'Fixed', 'shieldscope-site-security-scanner' ) ) as $shieldscope_key => $shieldscope_heading ) : ?>
					<?php if ( $shieldscope_cmp[ $shieldscope_key ] ) : ?>
						<details>
							<summary><?php echo esc_html( $shieldscope_heading . ' (' . count( $shieldscope_cmp[ $shieldscope_key ] ) . ')' ); ?></summary>
							<ul>
								<?php foreach ( $shieldscope_cmp[ $shieldscope_key ] as $shieldscope_row ) : ?>
									<li><?php echo esc_html( ( isset( $severity_label[ $shieldscope_row['severity'] ] ) ? $severity_label[ $shieldscope_row['severity'] ] : '' ) . ': ' . $shieldscope_row['title'] . ( ! empty( $shieldscope_row['target'] ) ? ' — ' . $shieldscope_row['target'] : '' ) ); ?></li>
								<?php endforeach; ?>
							</ul>
						</details>
					<?php endif; ?>
				<?php endforeach; ?>
			</div>
		<?php endif; ?>

		<?php if ( $findings ) : ?>
			<div class="shieldscope-filter" role="search">
				<label for="shieldscope-filter-text"><?php esc_html_e( 'Filter findings', 'shieldscope-site-security-scanner' ); ?></label>
				<input type="search" id="shieldscope-filter-text" class="regular-text" placeholder="<?php esc_attr_e( 'Title, file or check', 'shieldscope-site-security-scanner' ); ?>" />
				<label><input type="checkbox" id="shieldscope-filter-review" /> <?php esc_html_e( 'Needs review only', 'shieldscope-site-security-scanner' ); ?></label>
				<span id="shieldscope-filter-count" class="description" aria-live="polite"></span>
			</div>
		<?php endif; ?>

		<?php foreach ( $severity_order as $sev ) : ?>
			<?php
			if ( empty( $tabs[ $sev ]['groups'] ) ) {
				continue;
			}
			?>
			<section class="shieldscope-sev-section sev-<?php echo esc_attr( $sev ); ?>" id="shieldscope-sev-<?php echo esc_attr( $sev ); ?>" aria-labelledby="shieldscope-sev-h-<?php echo esc_attr( $sev ); ?>">
				<h2 id="shieldscope-sev-h-<?php echo esc_attr( $sev ); ?>">
					<?php
					/* translators: 1: severity name, 2: number of findings */
					echo esc_html( sprintf( __( '%1$s (%2$d)', 'shieldscope-site-security-scanner' ), $severity_label[ $sev ], $tabs[ $sev ]['count'] ) );
					?>
				</h2>

				<?php foreach ( $tabs[ $sev ]['groups'] as $issue_title => $instances ) :
					$count       = count( $instances );
					$first       = $instances[0];
					$check_id    = isset( $first['check_id'] ) ? (string) $first['check_id'] : '';
					$ctx         = ( ! empty( $first['context'] ) ) ? json_decode( $first['context'], true ) : array();
					$plugin_name = ( is_array( $ctx ) && ! empty( $ctx['plugin_name'] ) ) ? (string) $ctx['plugin_name'] : '';
					$is_review   = ( is_array( $ctx ) && isset( $ctx['confidence'] ) )
						? ShieldScope_Check_Base::CONFIDENCE_REVIEW === $ctx['confidence']
						: ShieldScope_Check_Base::is_review_title( $issue_title );
				?>
					<details class="shieldscope-finding sev-<?php echo esc_attr( $sev ); ?>">
						<summary>
							<span class="shieldscope-finding-title"><?php echo esc_html( $issue_title ); ?></span>
							<span class="shieldscope-confidence <?php echo esc_attr( $is_review ? 'is-review' : 'is-confirmed' ); ?>">
								<?php echo $is_review ? esc_html__( 'Needs review', 'shieldscope-site-security-scanner' ) : esc_html__( 'Confirmed', 'shieldscope-site-security-scanner' ); ?>
							</span>
							<?php if ( '' !== $check_id ) : ?>
								<span class="shieldscope-finding-check"><?php echo esc_html( isset( $shieldscope_labels[ $check_id ] ) ? $shieldscope_labels[ $check_id ] : $check_id ); ?></span>
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
								<p><?php echo esc_html( wp_strip_all_tags( $first['description'] ) ); ?></p>
							<?php endif; ?>
							<?php if ( ! empty( $first['recommendation'] ) ) : ?>
								<p><strong><?php esc_html_e( 'Recommendation:', 'shieldscope-site-security-scanner' ); ?></strong>
								<?php echo esc_html( wp_strip_all_tags( $first['recommendation'] ) ); ?></p>
							<?php endif; ?>
							<?php if ( $is_review ) : ?>
								<p class="shieldscope-review-note"><?php esc_html_e( 'This is a pattern match. Open the file at the line shown and check whether the flagged code really does what the finding describes before changing anything.', 'shieldscope-site-security-scanner' ); ?></p>
							<?php endif; ?>
							<?php
							$shieldscope_items = array();
							foreach ( $instances as $inst ) {
								$inst_ctx            = ! empty( $inst['context'] ) ? json_decode( $inst['context'], true ) : array();
								$shieldscope_items[] = array(
									'fp'      => ShieldScope_Ignore::fingerprint( $inst ),
									'target'  => isset( $inst['target'] ) ? (string) $inst['target'] : '',
									'line'    => isset( $inst_ctx['evidence']['line'] ) ? (int) $inst_ctx['evidence']['line'] : 0,
									'snippet' => isset( $inst_ctx['evidence']['snippet'] ) ? (string) $inst_ctx['evidence']['snippet'] : '',
								);
							}
							?>
							<?php if ( $shieldscope_items ) : ?>
								<div class="shieldscope-instances">
									<p class="shieldscope-instances-label"><?php echo 1 === count( $shieldscope_items ) ? esc_html__( 'Target:', 'shieldscope-site-security-scanner' ) : esc_html__( 'Affected items:', 'shieldscope-site-security-scanner' ); ?></p>
									<ul class="shieldscope-target-list">
										<?php foreach ( $shieldscope_items as $item ) : ?>
											<li>
												<?php if ( '' !== $item['target'] ) : ?>
													<code><?php echo esc_html( $item['target'] . ( $item['line'] > 0 ? ':' . $item['line'] : '' ) ); ?></code>
												<?php endif; ?>
												<?php if ( '' !== $item['snippet'] ) : ?>
													<pre class="shieldscope-snippet"><?php echo esc_html( $item['snippet'] ); ?></pre>
												<?php endif; ?>
												<details class="shieldscope-ignore">
													<summary><?php esc_html_e( 'Ignore…', 'shieldscope-site-security-scanner' ); ?></summary>
													<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
														<input type="hidden" name="action" value="<?php echo esc_attr( ShieldScope_Ignore::ACTION ); ?>" />
														<input type="hidden" name="do" value="ignore" />
														<input type="hidden" name="fp" value="<?php echo esc_attr( $item['fp'] ); ?>" />
														<?php wp_nonce_field( ShieldScope_Ignore::ACTION ); ?>
														<label><?php esc_html_e( 'Reason', 'shieldscope-site-security-scanner' ); ?>
															<select name="reason" required>
																<?php foreach ( $shieldscope_reasons as $shieldscope_key => $shieldscope_label ) : ?>
																	<option value="<?php echo esc_attr( $shieldscope_key ); ?>"><?php echo esc_html( $shieldscope_label ); ?></option>
																<?php endforeach; ?>
															</select>
														</label>
														<label><?php echo 'critical' === $sev ? esc_html__( 'Note (required)', 'shieldscope-site-security-scanner' ) : esc_html__( 'Note', 'shieldscope-site-security-scanner' ); ?>
															<input type="text" name="note" maxlength="500" class="regular-text" <?php echo 'critical' === $sev ? 'required' : ''; ?> />
														</label>
														<button type="submit" class="button button-small"><?php esc_html_e( 'Ignore this item', 'shieldscope-site-security-scanner' ); ?></button>
													</form>
												</details>
											</li>
										<?php endforeach; ?>
									</ul>
								</div>
							<?php endif; ?>
						</div>
					</details>
				<?php endforeach; ?>
			</section>
		<?php endforeach; ?>

		<?php if ( $shieldscope_ignored ) : ?>
			<div class="shieldscope-card shieldscope-ignored">
				<h2>
					<?php
					/* translators: %d: number of ignored findings */
					echo esc_html( sprintf( _n( 'Ignored finding (%d)', 'Ignored findings (%d)', count( $shieldscope_ignored ), 'shieldscope-site-security-scanner' ), count( $shieldscope_ignored ) ) );
					?>
				</h2>
				<p class="description"><?php esc_html_e( 'Ignored items are left out of the counts above but still appear in the PDF, CSV and JSON downloads with their reason.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<?php foreach ( $shieldscope_ignored as $shieldscope_row ) : ?>
						<li>
							<strong><?php echo esc_html( $severity_label[ isset( $severity_label[ $shieldscope_row['severity'] ] ) ? $shieldscope_row['severity'] : 'info' ] ); ?>:</strong>
							<?php echo esc_html( $shieldscope_row['title'] ); ?>
							<?php if ( ! empty( $shieldscope_row['target'] ) ) : ?>
								<code><?php echo esc_html( $shieldscope_row['target'] ); ?></code>
							<?php endif; ?>
							<br /><span class="description"><?php echo esc_html( ShieldScope_Ignore::describe( $shieldscope_row['ignored'] ) ); ?></span>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="shieldscope-inline-form">
								<input type="hidden" name="action" value="<?php echo esc_attr( ShieldScope_Ignore::ACTION ); ?>" />
								<input type="hidden" name="do" value="restore" />
								<input type="hidden" name="fp" value="<?php echo esc_attr( ShieldScope_Ignore::fingerprint( $shieldscope_row ) ); ?>" />
								<?php wp_nonce_field( ShieldScope_Ignore::ACTION ); ?>
								<button type="submit" class="button-link"><?php esc_html_e( 'Restore', 'shieldscope-site-security-scanner' ); ?></button>
							</form>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
		<?php endif; ?>

		<?php
		$shieldscope_clean = array();
		if ( null !== $shieldscope_coverage ) {
			$shieldscope_with_findings = array_unique( array_column( (array) $findings, 'check_id' ) );
			foreach ( $shieldscope_coverage as $shieldscope_id => $shieldscope_check ) {
				if ( ShieldScope_Coverage::DONE === $shieldscope_check['status'] && ! in_array( $shieldscope_id, $shieldscope_with_findings, true ) ) {
					$shieldscope_clean[] = $shieldscope_check['label'];
				}
			}
		}
		?>
		<?php if ( $shieldscope_clean ) : ?>
			<div class="shieldscope-card">
				<h2><?php esc_html_e( 'Checks with no findings', 'shieldscope-site-security-scanner' ); ?></h2>
				<p><?php echo esc_html( implode( ', ', $shieldscope_clean ) ); ?></p>
			</div>
		<?php endif; ?>

		<div class="shieldscope-card shieldscope-method">
			<h2><?php esc_html_e( 'Method and limits', 'shieldscope-site-security-scanner' ); ?></h2>
			<p><?php echo esc_html( ShieldScope_Admin::method_statement() ); ?></p>
			<p><?php echo esc_html( ShieldScope_Admin::footprint_statement() ); ?></p>
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
					<li><?php esc_html_e( 'Use Download PDF report at the top of this page (or Download CSV / JSON for a spreadsheet or another tool)', 'shieldscope-site-security-scanner' ); ?></li>
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
				<p><?php esc_html_e( 'The report displays results from the last completed scan — it does not update automatically. Go to ShieldScope → Scan, run a new scan, and the updated report will reflect your fixes.', 'shieldscope-site-security-scanner' ); ?></p>
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
			<span><?php esc_html_e( 'ShieldScope does not change your files, settings, users or content. It stores only its own scan data.', 'shieldscope-site-security-scanner' ); ?></span>
		</div>
	</div>
</div>
