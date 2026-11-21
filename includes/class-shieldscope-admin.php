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
	 * Capability needed to open the ShieldScope pages and call its AJAX actions.
	 *
	 * On multisite the scan reads network-wide data (all users, every installed
	 * plugin, server paths), so only super admins may run it.
	 *
	 * @return string
	 */
	public static function required_capability() {
		return is_multisite() ? 'manage_network_options' : SHIELDSCOPE_MIN_CAP;
	}

	/**
	 * Server-load presets (S-15): key => array( label, pace %, seconds per step ).
	 *
	 * @return array
	 */
	public static function load_presets() {
		return array(
			'gentle' => array( __( 'Gentle (busy shared hosting)', 'shieldscope-site-security-scanner' ), 10, 1 ),
			'normal' => array( __( 'Normal (most sites)', 'shieldscope-site-security-scanner' ), 20, 2 ),
			'fast'   => array( __( 'Fast (VPS or managed hosting)', 'shieldscope-site-security-scanner' ), 40, 3 ),
		);
	}

	/**
	 * Which preset the current values match, or "custom".
	 *
	 * @param array $settings Settings.
	 * @return string
	 */
	public static function current_preset( array $settings ) {
		foreach ( self::load_presets() as $key => $p ) {
			if ( (int) $settings['cpu_limit'] === $p[1] && (int) $settings['chunk_time_limit'] === $p[2] ) {
				return $key;
			}
		}
		return 'custom';
	}

	/**
	 * Last four characters of a secret, for display (B-08).
	 *
	 * @param string $key Secret.
	 * @return string
	 */
	public static function key_tail( $key ) {
		$key = (string) $key;
		return strlen( $key ) > 4 ? '…' . substr( $key, -4 ) : '…';
	}

	/**
	 * Support forum URL.
	 */
	const SUPPORT_URL = 'https://wordpress.org/support/plugin/shieldscope-site-security-scanner/';

	/**
	 * The one scan-time estimate used in every screen. Change it here only
	 * after measuring real scans. 2026-11-21: 17 s of work on a small site,
	 * 19 s for 14,365 plugin PHP files; at the default 20% pace about 1.5
	 * minutes with the page open, more on slow hosting.
	 *
	 * @return string
	 */
	public static function scan_time_estimate() {
		return __( 'a few minutes', 'shieldscope-site-security-scanner' );
	}

	/**
	 * The one statement of what leaves the server, used in every screen.
	 *
	 * @return string
	 */
	public static function privacy_statement() {
		return __( 'Scan results stay in your WordPress database. During a scan ShieldScope sends requests to your own site (to check headers, HTTPS and files that should not be public) and contacts api.wordpress.org (it sends your WordPress version and locale, and the folder names of installed plugins to check whether they are closed or unmaintained) and downloads.wordpress.org (plugin folder names and versions, to compare plugin files with the official release). If you add a WPScan API key it also sends plugin and theme slugs to wpscan.com.', 'shieldscope-site-security-scanner' );
	}

	/**
	 * What the scan tests and its limits, used in the report and the PDF.
	 *
	 * @return string
	 */
	public static function method_statement() {
		return __( 'ShieldScope checks WordPress configuration, versions, users, file permissions, server settings and plugin and theme code from inside the site. Findings labelled "Needs review" are pattern matches or heuristics that a person must confirm by reading the code; they are not confirmed vulnerabilities. Known-vulnerability results depend on the data source used (a limited built-in list, or WPScan with an API key). It does not test the site from outside like an attacker, does not compare files with a database of known malicious code, and does not monitor the site between scans. A report with no findings does not mean the site is secure.', 'shieldscope-site-security-scanner' );
	}

	/**
	 * The developer's contact page, linked from the plugin screens and
	 * (optionally) the PDF footer. A plain link: nothing is loaded from or
	 * sent to it unless the user clicks, and no referral tracking (WordPress.org
	 * plugin guidelines 7 and 11).
	 */
	const HELP_URL = 'https://www.dhirenpatel.me/contact/';

	/**
	 * The box offering the developer's help, shown on ShieldScope's
	 * own screens only (Scan, Report, Settings), never elsewhere in wp-admin.
	 *
	 * @return void
	 */
	public static function render_help_box() {
		?>
		<div class="shieldscope-card shieldscope-help-box">
			<span class="shieldscope-help-icon" aria-hidden="true"><span class="dashicons dashicons-shield-alt"></span></span>
			<div class="shieldscope-help-body">
				<h2><?php esc_html_e( 'Need a deeper review, or help fixing what ShieldScope found?', 'shieldscope-site-security-scanner' ); ?></h2>
				<p><?php esc_html_e( 'ShieldScope checks the most common security problems automatically. For anything beyond that, you can contact me, Dhiren Patel, the developer of ShieldScope.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul class="shieldscope-help-points">
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span><?php esc_html_e( 'A detailed audit of your site', 'shieldscope-site-security-scanner' ); ?></li>
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span><?php esc_html_e( 'Fixes for the issues ShieldScope found', 'shieldscope-site-security-scanner' ); ?></li>
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span><?php esc_html_e( 'Advice on keeping the site secure', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
			<div class="shieldscope-help-action">
				<a class="button button-primary shieldscope-help-button" href="<?php echo esc_url( self::HELP_URL ); ?>" target="_blank" rel="noopener noreferrer">
					<?php esc_html_e( 'Contact the developer', 'shieldscope-site-security-scanner' ); ?>
					<span class="dashicons dashicons-external" aria-hidden="true"></span>
					<span class="screen-reader-text"><?php esc_html_e( '(opens in a new tab)', 'shieldscope-site-security-scanner' ); ?></span>
				</a>
				<span class="shieldscope-help-note"><?php esc_html_e( 'Opens dhirenpatel.me in a new tab', 'shieldscope-site-security-scanner' ); ?></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Show the developer's contact link in downloaded reports (PDF footer,
	 * last CSV row, JSON "help")? On by default; Settings → Downloaded reports.
	 *
	 * @return bool
	 */
	public static function report_help_link() {
		$settings = (array) get_option( 'shieldscope_settings', array() );
		return ! isset( $settings['report_help_link'] ) || ! empty( $settings['report_help_link'] );
	}

	/**
	 * The contact line used in the PDF footer and the CSV and JSON downloads.
	 *
	 * @return string
	 */
	public static function help_line() {
		/* translators: %s: web address of the developer's contact page */
		return sprintf( __( 'Detailed audit or help with fixes: %s', 'shieldscope-site-security-scanner' ), self::HELP_URL );
	}

	/**
	 * The one statement of what ShieldScope writes, used in every screen.
	 *
	 * @return string
	 */
	public static function footprint_statement() {
		return __( 'ShieldScope does not change your files, settings, users or content. It stores only its own data: its settings and scan progress (options), cached lookups (transients), a findings table, and scheduled tasks (one daily clean-up, plus short-lived ones while a scan runs). Deleting the plugin removes all of it.', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		if ( is_multisite() ) {
			// Super admins can also open ShieldScope from Network Admin (S-17).
			add_action( 'network_admin_menu', array( $this, 'register_menu' ) );
		}
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'completion_notice' ) );
		add_action( 'admin_post_' . ShieldScope_PDF_Report::ACTION, array( 'ShieldScope_PDF_Report', 'handle' ) );
		add_action( 'admin_post_' . ShieldScope_Export::ACTION, array( 'ShieldScope_Export', 'handle' ) );
		add_action( 'admin_post_' . ShieldScope_Ignore::ACTION, array( 'ShieldScope_Ignore', 'handle' ) );
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
			self::required_capability(),
			SHIELDSCOPE_SLUG,
			array( $this, 'render_scan_page' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			SHIELDSCOPE_SLUG,
			__( 'Scan', 'shieldscope-site-security-scanner' ),
			__( 'Scan', 'shieldscope-site-security-scanner' ),
			self::required_capability(),
			SHIELDSCOPE_SLUG,
			array( $this, 'render_scan_page' )
		);

		add_submenu_page(
			SHIELDSCOPE_SLUG,
			__( 'Report', 'shieldscope-site-security-scanner' ),
			__( 'Report', 'shieldscope-site-security-scanner' ),
			self::required_capability(),
			SHIELDSCOPE_SLUG . '-report',
			array( $this, 'render_report_page' )
		);

		add_submenu_page(
			SHIELDSCOPE_SLUG,
			__( 'Settings', 'shieldscope-site-security-scanner' ),
			__( 'Settings', 'shieldscope-site-security-scanner' ),
			self::required_capability(),
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
				// Pausing on a hidden tab only applies when the scan depends on the tab.
				'pauseOnBlur'   => ! empty( $settings['pause_on_blur'] ) && ! ShieldScope_Scanner::background_enabled(),
				'background'    => ShieldScope_Scanner::background_enabled(),
				'tickInterval'  => 1500, // ms between chunk requests when running.
				'pollInterval'  => 5000, // ms while paused.
				'i18n'          => array(
					'starting'     => __( 'Starting scan…', 'shieldscope-site-security-scanner' ),
					'paused'       => __( 'Paused (tab not focused). Return to this tab to resume.', 'shieldscope-site-security-scanner' ),
					'resumed'      => __( 'Resumed. Scanning again.', 'shieldscope-site-security-scanner' ),
					'finished'     => __( 'Scan complete.', 'shieldscope-site-security-scanner' ),
					'aborted'      => __( 'Scan aborted.', 'shieldscope-site-security-scanner' ),
					'leaveWarn'    => __( 'A scan is running. If you leave, it stops until you come back to this page.', 'shieldscope-site-security-scanner' ),
					'error'        => __( 'Could not reach the server. Trying again…', 'shieldscope-site-security-scanner' ),
					/* translators: 1: findings shown, 2: all findings */
					'filterCount'  => __( 'Showing %1$d of %2$d findings', 'shieldscope-site-security-scanner' ),
					'confirmAbort' => __( 'Abort this scan? Its findings so far will be discarded.', 'shieldscope-site-security-scanner' ),
					'gaveUp'       => __( 'Could not reach the server after several tries, so this page stopped sending scan steps. Reload the page to check the scan.', 'shieldscope-site-security-scanner' ),
					'expired'      => __( 'Your session has expired. Reload the page (you may need to log in again); the scan keeps its place.', 'shieldscope-site-security-scanner' ),
					'stalled'      => __( 'The scan has not made progress for over two minutes. WordPress runs background tasks when the site gets visits; press Resume to continue from this page.', 'shieldscope-site-security-scanner' ),
					/* translators: 1: steps done, 2: total steps */
					'stepsOf'      => __( '%1$d of %2$d steps', 'shieldscope-site-security-scanner' ),
					'checkStatus'  => array(
						'waiting' => __( 'Waiting', 'shieldscope-site-security-scanner' ),
						'running' => __( 'Running', 'shieldscope-site-security-scanner' ),
						'done'    => __( 'Done', 'shieldscope-site-security-scanner' ),
						'partial' => __( 'Partly done', 'shieldscope-site-security-scanner' ),
						'error'   => __( 'Error', 'shieldscope-site-security-scanner' ),
						'not_run' => __( 'Did not run', 'shieldscope-site-security-scanner' ),
					),
					'blurTitle'    => __( 'Scan paused', 'shieldscope-site-security-scanner' ),
					'blurBody'     => __( 'The scan pauses while this tab is hidden and continues from the same point when you return. You can turn this off in Settings.', 'shieldscope-site-security-scanner' ),
					'titleActive'  => __( 'Scanning… – ShieldScope', 'shieldscope-site-security-scanner' ),
					'titlePaused'  => __( 'Scan paused – ShieldScope', 'shieldscope-site-security-scanner' ),
					'titleDone'    => __( 'Scan complete – ShieldScope', 'shieldscope-site-security-scanner' ),
				),
			)
		);
	}

	/**
	 * One-time notice that a scan finished (S-10): shown on admin screens
	 * until the report is opened.
	 *
	 * @return void
	 */
	public function completion_notice() {
		if ( ! current_user_can( self::required_capability() ) ) {
			return;
		}
		$last = (string) get_option( 'shieldscope_last_scan', '' );
		if ( '' === $last || get_option( 'shieldscope_last_seen', '' ) === $last ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false !== strpos( (string) $screen->id, SHIELDSCOPE_SLUG ) ) {
			return; // The scan and report pages show the result themselves.
		}
		$summary = ShieldScope_Ignore::active_summary( $last );
		printf(
			'<div class="notice notice-info"><p>%s <a href="%s">%s</a></p></div>',
			esc_html( __( 'ShieldScope scan finished.', 'shieldscope-site-security-scanner' ) . ' ' . ShieldScope_PDF_Report::verdict( $summary ) ),
			esc_url( admin_url( 'admin.php?page=' . SHIELDSCOPE_SLUG . '-report' ) ),
			esc_html__( 'View the report', 'shieldscope-site-security-scanner' )
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
		if ( ! current_user_can( self::required_capability() ) ) {
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
		if ( ! current_user_can( self::required_capability() ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ) );
		}
		$logger      = new ShieldScope_Logger();
		$last_scan   = get_option( 'shieldscope_last_scan', '' );
		update_option( 'shieldscope_last_seen', $last_scan, false );
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
		if ( ! current_user_can( self::required_capability() ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ) );
		}
		$this->maybe_save_settings();

		$settings = wp_parse_args(
			(array) get_option( 'shieldscope_settings', array() ),
			array(
				'cpu_limit'          => 20,
				'chunk_time_limit'   => 2,
				'max_scan_file_size' => 2 * MB_IN_BYTES,
				'pause_on_blur'      => 0,
				'background_scan'    => 1,
				'developer_review'   => 0,
				'report_help_link'     => 1,
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
		if ( ! current_user_can( self::required_capability() ) ) {
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
		$wpscan_key   = isset( $raw['wpscan_api_key'] ) ? trim( sanitize_text_field( $raw['wpscan_api_key'] ) ) : '';
		if ( '' === $wpscan_key && ! empty( $existing['wpscan_api_key'] ) ) {
			$wpscan_key = $existing['wpscan_api_key'];
		}
		if ( ! empty( $raw['wpscan_api_key_remove'] ) ) {
			$wpscan_key = '';
		}

		// A preset sets pace and step time together (S-15); "custom" keeps the fields.
		// If the pace or step fields were changed and do not match the chosen
		// preset, the typed values win (SC2-06).
		$presets = self::load_presets();
		if ( isset( $raw['load_preset'], $presets[ $raw['load_preset'] ] ) ) {
			$preset = $presets[ $raw['load_preset'] ];
			$posted = array(
				isset( $raw['cpu_limit'] ) ? (int) $raw['cpu_limit'] : $preset[1],
				isset( $raw['chunk_time_limit'] ) ? (int) $raw['chunk_time_limit'] : $preset[2],
			);
			$before = array(
				isset( $existing['cpu_limit'] ) ? (int) $existing['cpu_limit'] : 20,
				isset( $existing['chunk_time_limit'] ) ? (int) $existing['chunk_time_limit'] : 2,
			);
			$edited = $posted !== $before && $posted !== array( $preset[1], $preset[2] );
			if ( ! $edited ) {
				$raw['cpu_limit']        = $preset[1];
				$raw['chunk_time_limit'] = $preset[2];
			}
		}

		$clean = array(
			'cpu_limit'          => isset( $raw['cpu_limit'] ) ? max( 5, min( 80, (int) $raw['cpu_limit'] ) ) : 20,
			'chunk_time_limit'   => isset( $raw['chunk_time_limit'] ) ? max( 1, min( 10, (int) $raw['chunk_time_limit'] ) ) : 2,
			'max_scan_file_size' => $mb * MB_IN_BYTES,
			'pause_on_blur'      => ! empty( $raw['pause_on_blur'] ) ? 1 : 0,
			'background_scan'    => ! empty( $raw['background_scan'] ) ? 1 : 0,
			'developer_review'   => ! empty( $raw['developer_review'] ) ? 1 : 0,
			'report_help_link'     => ! empty( $raw['report_help_link'] ) ? 1 : 0,
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
					<?php esc_html_e( 'This plugin is intended to help developers and website owners identify potential security issues. It does not find every vulnerability, and a report with no findings does not mean the site is secure.', 'shieldscope-site-security-scanner' ); ?>
				</p>
				<p>
					<?php echo esc_html( self::privacy_statement() ); ?>
					<?php
					printf(
						/* translators: %s: support link */
						esc_html__( 'For any concerns or questions, please %s.', 'shieldscope-site-security-scanner' ),
						'<a href="' . esc_url( self::SUPPORT_URL ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'reach out via the support forum', 'shieldscope-site-security-scanner' ) . '</a>'
					);
					?>
				</p>
			</div>
		</div>
		<?php
	}
}
