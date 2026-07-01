<?php
/**
 * Admin UI registration.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Admin
 */
class ShieldScope_Admin {

	/**
	 * Hook suffix for our top-level page.
	 *
	 * @var string
	 */
	private $hook_suffix = '';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_filter( 'plugin_action_links_' . SHIELDSCOPE_PLUGIN_BASENAME, array( $this, 'action_links' ) );
	}

	/**
	 * Add the menu page.
	 *
	 * @return void
	 */
	public function register_menu() {
		$this->hook_suffix = add_menu_page(
			__( 'ShieldScope', 'shieldscope-site-security-scanner' ),
			__( 'ShieldScope', 'shieldscope-site-security-scanner' ),
			SHIELDSCOPE_MIN_CAP,
			SHIELDSCOPE_SLUG,
			array( $this, 'render_scan_page' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			SHIELDSCOPE_SLUG,
			__( 'Scan', 'shieldscope-site-security-scanner' ),
			__( 'Scan', 'shieldscope-site-security-scanner' ),
			SHIELDSCOPE_MIN_CAP,
			SHIELDSCOPE_SLUG,
			array( $this, 'render_scan_page' )
		);

		add_submenu_page(
			SHIELDSCOPE_SLUG,
			__( 'Last Report', 'shieldscope-site-security-scanner' ),
			__( 'Last Report', 'shieldscope-site-security-scanner' ),
			SHIELDSCOPE_MIN_CAP,
			SHIELDSCOPE_SLUG . '-report',
			array( $this, 'render_report_page' )
		);

		add_submenu_page(
			SHIELDSCOPE_SLUG,
			__( 'Settings', 'shieldscope-site-security-scanner' ),
			__( 'Settings', 'shieldscope-site-security-scanner' ),
			SHIELDSCOPE_MIN_CAP,
			SHIELDSCOPE_SLUG . '-settings',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Enqueue admin JS/CSS only on our pages.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( false === strpos( $hook, SHIELDSCOPE_SLUG ) ) {
			return;
		}

		wp_enqueue_style(
			'shieldscope-admin',
			SHIELDSCOPE_PLUGIN_URL . 'admin/css/admin.css',
			array(),
			SHIELDSCOPE_VERSION
		);

		wp_enqueue_script(
			'shieldscope-admin',
			SHIELDSCOPE_PLUGIN_URL . 'admin/js/admin.js',
			array( 'jquery' ),
			SHIELDSCOPE_VERSION,
			true
		);

		$settings = (array) get_option( 'shieldscope_settings', array() );

		wp_localize_script(
			'shieldscope-admin',
			'ShieldScope',
			array(
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'shieldscope_scan' ),
				'pauseOnBlur'   => ! empty( $settings['pause_on_blur'] ),
				'tickInterval'  => 1500, // ms between chunk requests when running.
				'pollInterval'  => 5000, // ms while paused.
				'i18n'          => array(
					'starting'     => __( 'Starting scan…', 'shieldscope-site-security-scanner' ),
					'paused'       => __( 'Paused (tab not focused). Return to this tab to resume.', 'shieldscope-site-security-scanner' ),
					'resumed'      => __( 'Resumed. Scanning again.', 'shieldscope-site-security-scanner' ),
					'finished'     => __( 'Scan complete.', 'shieldscope-site-security-scanner' ),
					'aborted'      => __( 'Scan aborted.', 'shieldscope-site-security-scanner' ),
					'leaveWarn'    => __( "Hey, the scan is still running! If you close this tab it'll pause — but don't worry, it'll pick up right where it left off when you come back.", 'shieldscope-site-security-scanner' ),
					'error'        => __( 'Network error. Retrying…', 'shieldscope-site-security-scanner' ),
					// Funny / friendly banner copy for tab blur.
					'blurTitle'    => __( '👋 Pssst — scan paused!', 'shieldscope-site-security-scanner' ),
					'blurBody'     => __( "We noticed you wandered off to another tab, so we politely paused the scan. Your server says thank you. Come back whenever — we'll pick up right where we left off.", 'shieldscope-site-security-scanner' ),
					'titleActive'  => __( '🛡️ Scanning… — Security Scan', 'shieldscope-site-security-scanner' ),
					'titlePaused'  => __( '⏸ Scan paused — come back!', 'shieldscope-site-security-scanner' ),
					'titleDone'    => __( '✅ Scan complete — Security Scan', 'shieldscope-site-security-scanner' ),
				),
			)
		);
	}

	/**
	 * Plugin action links (Settings on plugins screen).
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function action_links( $links ) {
		$url   = admin_url( 'admin.php?page=' . SHIELDSCOPE_SLUG );
		$links = array_merge(
			array( '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Scan', 'shieldscope-site-security-scanner' ) . '</a>' ),
			(array) $links
		);
		return $links;
	}

	/**
	 * Render scan page.
	 *
	 * @return void
	 */
	public function render_scan_page() {
		if ( ! current_user_can( SHIELDSCOPE_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ) );
		}
		$scanner = new ShieldScope_Scanner();
		$state   = $scanner->get_state();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/scan.php';
		$this->render_disclaimer();
	}

	/**
	 * Render report page.
	 *
	 * @return void
	 */
	public function render_report_page() {
		if ( ! current_user_can( SHIELDSCOPE_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ) );
		}
		$logger      = new ShieldScope_Logger();
		$last_scan   = get_option( 'shieldscope_last_scan', '' );
		$findings    = $last_scan ? $logger->get_findings( $last_scan ) : array();
		$summary     = $last_scan ? $logger->get_summary( $last_scan ) : array();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/report.php';
		$this->render_disclaimer();
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings_page() {
		if ( ! current_user_can( SHIELDSCOPE_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ) );
		}
		$this->maybe_save_settings();

		$settings = wp_parse_args(
			(array) get_option( 'shieldscope_settings', array() ),
			array(
				'cpu_limit'          => 20,
				'chunk_time_limit'   => 2,
				'max_scan_file_size' => 2 * MB_IN_BYTES,
				'pause_on_blur'      => 1,
			)
		);
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/settings.php';
		$this->render_disclaimer();
	}

	/**
	 * Handle settings form POST.
	 *
	 * @return void
	 */
	private function maybe_save_settings() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce is verified on the very next line.
		if ( empty( $_POST['shieldscope_settings_submit'] ) ) {
			return;
		}
		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'shieldscope_save_settings' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'shieldscope-site-security-scanner' ) );
		}
		if ( ! current_user_can( SHIELDSCOPE_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ) );
		}

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each key in $raw is individually sanitized/cast in the $clean array below.
		$raw = isset( $_POST['shieldscope_settings'] ) && is_array( $_POST['shieldscope_settings'] )
			? wp_unslash( $_POST['shieldscope_settings'] )
			: array();
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// Max file size: the form submits MB (1-20); we store bytes internally so every
		// consumer can continue to reason in bytes without change.
		$mb = 2;
		if ( isset( $raw['max_scan_file_size_mb'] ) ) {
			$mb = max( 1, min( 20, (int) $raw['max_scan_file_size_mb'] ) );
		} elseif ( isset( $raw['max_scan_file_size'] ) ) {
			// Backwards compat with old byte-based submissions.
			$mb = max( 1, min( 20, (int) round( (int) $raw['max_scan_file_size'] / MB_IN_BYTES ) ) );
		}

		// WPScan API key — preserve existing value if the field was submitted blank
		// (browser password fields submit empty when not changed by user).
		$existing     = (array) get_option( 'shieldscope_settings', array() );
		$wpscan_key   = isset( $raw['wpscan_api_key'] ) ? sanitize_text_field( $raw['wpscan_api_key'] ) : '';
		if ( '' === $wpscan_key && ! empty( $existing['wpscan_api_key'] ) ) {
			$wpscan_key = $existing['wpscan_api_key'];
		}

		$clean = array(
			'cpu_limit'          => isset( $raw['cpu_limit'] ) ? max( 5, min( 80, (int) $raw['cpu_limit'] ) ) : 20,
			'chunk_time_limit'   => isset( $raw['chunk_time_limit'] ) ? max( 1, min( 10, (int) $raw['chunk_time_limit'] ) ) : 2,
			'max_scan_file_size' => $mb * MB_IN_BYTES,
			'pause_on_blur'      => ! empty( $raw['pause_on_blur'] ) ? 1 : 0,
			'wpscan_api_key'     => $wpscan_key,
		);
		update_option( 'shieldscope_settings', $clean );

		add_settings_error(
			'shieldscope_settings',
			'saved',
			__( 'Settings saved.', 'shieldscope-site-security-scanner' ),
			'updated'
		);
	}

	/**
	 * Render the shared disclaimer footer shown on all admin pages.
	 *
	 * @return void
	 */
	private function render_disclaimer() {
		?>
		<div class="shieldscope-disclaimer">
			<div class="shieldscope-disclaimer__icon">&#9432;</div>
			<div class="shieldscope-disclaimer__body">
				<strong><?php esc_html_e( 'Disclaimer', 'shieldscope-site-security-scanner' ); ?></strong>
				<p>
					<?php esc_html_e( 'Results produced by this plugin are based on automated pattern analysis and heuristic checks. Each scan module runs independently — findings related to third-party plugins or themes are indicative only. Please verify with the respective plugin or theme developer before making any changes, and contact them directly if a fix is required.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<?php esc_html_e( 'This plugin is intended to help developers and website owners identify potential security issues. It does not guarantee complete coverage of all vulnerabilities.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<?php esc_html_e( 'No scan data, site information, or personal data is stored on external servers or shared with any third party or individual. All analysis is performed locally on your own server.', 'shieldscope-site-security-scanner' ); ?>
					<?php
					printf(
						/* translators: %s: support link */
						esc_html__( 'For any concerns or questions, please %s.', 'shieldscope-site-security-scanner' ),
						'<a href="https://wordpress.org/support/plugin/shieldscope-site-security-scanner/" target="_blank" rel="noopener noreferrer">' . esc_html__( 'reach out via the support forum', 'shieldscope-site-security-scanner' ) . '</a>'
					);
					?>
				</p>
			</div>
		</div>
		<?php
	}
}
