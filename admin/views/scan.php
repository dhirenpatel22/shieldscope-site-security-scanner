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
	<h1><?php esc_html_e( 'Site Security Audit', 'site-security-audit' ); ?></h1>

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
</div>
