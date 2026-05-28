<?php
/**
 * Admin UI registration.
 *
 * @package Site_Security_Audit
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class SSA_Admin
 */
class SSA_Admin {

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
		add_filter( 'plugin_action_links_' . SSA_PLUGIN_BASENAME, array( $this, 'action_links' ) );
	}

	/**
	 * Add the menu page.
	 *
	 * @return void
	 */
	public function register_menu() {
		$this->hook_suffix = add_menu_page(
			__( 'Security Scan', 'site-security-audit' ),
			__( 'Security Scan', 'site-security-audit' ),
			SSA_MIN_CAP,
			SSA_SLUG,
			array( $this, 'render_scan_page' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			SSA_SLUG,
			__( 'Scan', 'site-security-audit' ),
			__( 'Scan', 'site-security-audit' ),
			SSA_MIN_CAP,
			SSA_SLUG,
			array( $this, 'render_scan_page' )
		);

		add_submenu_page(
			SSA_SLUG,
			__( 'Last Report', 'site-security-audit' ),
			__( 'Last Report', 'site-security-audit' ),
			SSA_MIN_CAP,
			SSA_SLUG . '-report',
			array( $this, 'render_report_page' )
		);

		add_submenu_page(
			SSA_SLUG,
			__( 'Settings', 'site-security-audit' ),
			__( 'Settings', 'site-security-audit' ),
			SSA_MIN_CAP,
			SSA_SLUG . '-settings',
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
		if ( false === strpos( $hook, SSA_SLUG ) ) {
			return;
		}

		wp_enqueue_style(
			'ssa-admin',
			SSA_PLUGIN_URL . 'admin/css/admin.css',
			array(),
			SSA_VERSION
		);

		wp_enqueue_script(
			'ssa-admin',
			SSA_PLUGIN_URL . 'admin/js/admin.js',
			array( 'jquery' ),
			SSA_VERSION,
			true
		);

		$settings = (array) get_option( 'ssa_settings', array() );

		wp_localize_script(
			'ssa-admin',
			'SSA',
			array(
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'ssa_scan' ),
				'pauseOnBlur'   => ! empty( $settings['pause_on_blur'] ),
				'tickInterval'  => 1500, // ms between chunk requests when running.
				'pollInterval'  => 5000, // ms while paused.
				'i18n'          => array(
					'starting'     => __( 'Starting scan…', 'site-security-audit' ),
					'paused'       => __( 'Paused (tab not focused). Return to this tab to resume.', 'site-security-audit' ),
					'resumed'      => __( 'Resumed. Scanning again.', 'site-security-audit' ),
					'finished'     => __( 'Scan complete.', 'site-security-audit' ),
					'aborted'      => __( 'Scan aborted.', 'site-security-audit' ),
					'leaveWarn'    => __( "Hey, the scan is still running! If you close this tab it'll pause — but don't worry, it'll pick up right where it left off when you come back.", 'site-security-audit' ),
					'error'        => __( 'Network error. Retrying…', 'site-security-audit' ),
					// Funny / friendly banner copy for tab blur.
					'blurTitle'    => __( '👋 Pssst — scan paused!', 'site-security-audit' ),
					'blurBody'     => __( "We noticed you wandered off to another tab, so we politely paused the scan. Your server says thank you. Come back whenever — we'll pick up right where we left off.", 'site-security-audit' ),
					'titleActive'  => __( '🛡️ Scanning… — Security Scan', 'site-security-audit' ),
					'titlePaused'  => __( '⏸ Scan paused — come back!', 'site-security-audit' ),
					'titleDone'    => __( '✅ Scan complete — Security Scan', 'site-security-audit' ),
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
		$url   = admin_url( 'admin.php?page=' . SSA_SLUG );
		$links = array_merge(
			array( '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Scan', 'site-security-audit' ) . '</a>' ),
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
		if ( ! current_user_can( SSA_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'site-security-audit' ) );
		}
		$scanner = new SSA_Scanner();
		$state   = $scanner->get_state();
		include SSA_PLUGIN_DIR . 'admin/views/scan.php';
	}

	/**
	 * Render report page.
	 *
	 * @return void
	 */
	public function render_report_page() {
		if ( ! current_user_can( SSA_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'site-security-audit' ) );
		}
		$logger      = new SSA_Logger();
		$last_scan   = get_option( 'ssa_last_scan', '' );
		$findings    = $last_scan ? $logger->get_findings( $last_scan ) : array();
		$summary     = $last_scan ? $logger->get_summary( $last_scan ) : array();
		include SSA_PLUGIN_DIR . 'admin/views/report.php';
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings_page() {
		if ( ! current_user_can( SSA_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'site-security-audit' ) );
		}
		$this->maybe_save_settings();

		$settings = wp_parse_args(
			(array) get_option( 'ssa_settings', array() ),
			array(
				'cpu_limit'          => 20,
				'chunk_time_limit'   => 2,
				'max_scan_file_size' => 2 * MB_IN_BYTES,
				'pause_on_blur'      => 1,
			)
		);
		include SSA_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Handle settings form POST.
	 *
	 * @return void
	 */
	private function maybe_save_settings() {
		if ( empty( $_POST['ssa_settings_submit'] ) ) {
			return;
		}
		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'ssa_save_settings' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'site-security-audit' ) );
		}
		if ( ! current_user_can( SSA_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'site-security-audit' ) );
		}

		$raw = isset( $_POST['ssa_settings'] ) && is_array( $_POST['ssa_settings'] )
			? wp_unslash( $_POST['ssa_settings'] )
			: array();

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
		$existing     = (array) get_option( 'ssa_settings', array() );
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
		update_option( 'ssa_settings', $clean );

		add_settings_error(
			'ssa_settings',
			'saved',
			__( 'Settings saved.', 'site-security-audit' ),
			'updated'
		);
	}
}
