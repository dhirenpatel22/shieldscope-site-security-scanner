<?php
/**
 * WordPress core configuration checks.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Core
 */
class ShieldScope_Check_Core extends ShieldScope_Check_Base {

	/**
	 * Check ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'core';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'WordPress Core', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array(
			'version',
			'constants',
			'salts',
			'debug',
			'prefix',
			'ssl',
			'xmlrpc',
			'rest_enum',
		);
	}

	/**
	 * Run a step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'version':
				$this->check_version();
				break;
			case 'constants':
				$this->check_constants();
				break;
			case 'salts':
				$this->check_salts();
				break;
			case 'debug':
				$this->check_debug();
				break;
			case 'prefix':
				$this->check_table_prefix();
				break;
			case 'ssl':
				$this->check_ssl();
				break;
			case 'xmlrpc':
				$this->check_xmlrpc();
				break;
			case 'rest_enum':
				$this->check_rest_user_enum();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * WordPress version freshness.
	 *
	 * @return void
	 */
	private function check_version() {
		global $wp_version;

		$update = get_site_transient( 'update_core' );
		if ( $update && isset( $update->updates ) && is_array( $update->updates ) ) {
			foreach ( $update->updates as $u ) {
				if ( isset( $u->response ) && 'upgrade' === $u->response ) {
					$this->finding(
						ShieldScope_Logger::SEVERITY_HIGH,
						__( 'WordPress core is out of date', 'shieldscope-site-security-scanner' ),
						sprintf(
							/* translators: 1: current version, 2: new version */
							__( 'You are running WordPress %1$s; version %2$s is available.', 'shieldscope-site-security-scanner' ),
							$wp_version,
							isset( $u->current ) ? $u->current : 'latest'
						),
						__( 'Back up your site first (use your host\'s backup tool or export a database dump), then go to Dashboard → Updates and click "Update Now". Core updates are safe and usually take under 2 minutes.', 'shieldscope-site-security-scanner' ),
						'wordpress-core'
					);
					return;
				}
			}
		}

		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			__( 'WordPress core is up to date', 'shieldscope-site-security-scanner' ),
			sprintf(
				/* translators: %s: version string */
				__( 'Running WordPress %s.', 'shieldscope-site-security-scanner' ),
				$wp_version
			)
		);
	}

	/**
	 * Hardening constants.
	 *
	 * @return void
	 */
	private function check_constants() {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Theme/plugin file editor is enabled', 'shieldscope-site-security-scanner' ),
				__( 'The built-in editor lets administrators run arbitrary PHP from the dashboard. If an admin account is compromised, the entire site can be backdoored.', 'shieldscope-site-security-scanner' ),
				__( "Add to wp-config.php: define('DISALLOW_FILE_EDIT', true);", 'shieldscope-site-security-scanner' ),
				'wp-config.php'
			);
		}

		if ( ! defined( 'DISALLOW_FILE_MODS' ) || ! DISALLOW_FILE_MODS ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'File modifications from the dashboard are allowed', 'shieldscope-site-security-scanner' ),
				__( 'DISALLOW_FILE_MODS is not set. Consider disabling plugin/theme installation and updates via the dashboard in strict environments.', 'shieldscope-site-security-scanner' ),
				__( "Add to wp-config.php: define('DISALLOW_FILE_MODS', true); — note this also blocks automatic updates.", 'shieldscope-site-security-scanner' ),
				'wp-config.php'
			);
		}

		if ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'FORCE_SSL_ADMIN is not enabled', 'shieldscope-site-security-scanner' ),
				__( 'Admin logins and cookies can be sent over HTTP without this constant.', 'shieldscope-site-security-scanner' ),
				__( "Add to wp-config.php: define('FORCE_SSL_ADMIN', true);", 'shieldscope-site-security-scanner' ),
				'wp-config.php'
			);
		}

		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Automatic updates are fully disabled', 'shieldscope-site-security-scanner' ),
				__( 'Automatic minor/security updates are disabled. Unpatched vulnerabilities will stay unpatched.', 'shieldscope-site-security-scanner' ),
				__( 'In wp-config.php, remove the line or change it to: define(\'AUTOMATIC_UPDATER_DISABLED\', false); This re-enables automatic security patch updates for minor releases. If intentionally disabled, commit to a regular manual update schedule.', 'shieldscope-site-security-scanner' )
			);
		}
	}

	/**
	 * Auth salts sanity check.
	 *
	 * @return void
	 */
	private function check_salts() {
		$keys = array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);

		$bad = array();
		foreach ( $keys as $k ) {
			if ( ! defined( $k ) ) {
				$bad[] = $k . ' (missing)';
				continue;
			}
			$v = constant( $k );
			if ( ! is_string( $v ) || strlen( $v ) < 40 || false !== stripos( $v, 'put your unique phrase here' ) ) {
				$bad[] = $k . ' (weak/placeholder)';
			}
		}

		if ( $bad ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'Weak or missing authentication salts', 'shieldscope-site-security-scanner' ),
				__( 'One or more AUTH/NONCE keys in wp-config.php are missing, short, or still set to their placeholder value. An attacker who learns a weak salt may forge cookies.', 'shieldscope-site-security-scanner' ),
				__( 'Visit https://api.wordpress.org/secret-key/1.1/salt/ to generate 8 fresh random keys, then replace all AUTH_KEY / SALT lines in wp-config.php with the generated block. All active sessions will be logged out — this is expected and safe.', 'shieldscope-site-security-scanner' ),
				'wp-config.php',
				array( 'failed_keys' => $bad )
			);
		}
	}

	/**
	 * Debug mode checks.
	 *
	 * @return void
	 */
	private function check_debug() {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$display = defined( 'WP_DEBUG_DISPLAY' ) ? WP_DEBUG_DISPLAY : true;
			if ( $display ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_HIGH,
					__( 'WP_DEBUG is enabled and errors are displayed', 'shieldscope-site-security-scanner' ),
					__( 'Error messages leak path and software version information to visitors and attackers.', 'shieldscope-site-security-scanner' ),
					__( 'In production, set WP_DEBUG to false, or at minimum set WP_DEBUG_DISPLAY to false and log to a file with WP_DEBUG_LOG.', 'shieldscope-site-security-scanner' ),
					'wp-config.php'
				);
			} else {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					__( 'WP_DEBUG is enabled (errors hidden)', 'shieldscope-site-security-scanner' ),
					__( 'Debug logging is on. If debug.log is inside wp-content and not blocked by the webserver, it may be publicly readable.', 'shieldscope-site-security-scanner' ),
					__( 'Disable WP_DEBUG in production and make sure debug.log is not accessible via HTTP.', 'shieldscope-site-security-scanner' )
				);
			}
		}
	}

	/**
	 * Default table prefix detection.
	 *
	 * @return void
	 */
	private function check_table_prefix() {
		global $wpdb;
		if ( 'wp_' === $wpdb->prefix ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( "Default database prefix 'wp_' in use", 'shieldscope-site-security-scanner' ),
				__( 'Using the default prefix is not itself a vulnerability, but can make blind SQL injection exploitation marginally easier.', 'shieldscope-site-security-scanner' ),
				__( 'Low priority — only attempt with a full database backup. Rename all tables to a custom prefix via your host\'s phpMyAdmin or database tool, then update $table_prefix in wp-config.php to match. Do not attempt manual SQL renaming without a current backup.', 'shieldscope-site-security-scanner' )
			);
		}
	}

	/**
	 * SSL configuration.
	 *
	 * @return void
	 */
	private function check_ssl() {
		$home    = get_home_url();
		$siteurl = get_site_url();
		if ( 0 !== stripos( $home, 'https://' ) || 0 !== stripos( $siteurl, 'https://' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Site URL is not HTTPS', 'shieldscope-site-security-scanner' ),
				__( 'The home or site URL is configured over HTTP. Traffic, including login credentials, can be intercepted.', 'shieldscope-site-security-scanner' ),
				__( 'Get a free SSL certificate via your hosting panel (cPanel, Plesk, or similar) using Let\'s Encrypt. Once installed, update both WordPress Address and Site Address in Settings → General to https://, and add define(\'FORCE_SSL_ADMIN\', true); to wp-config.php.', 'shieldscope-site-security-scanner' )
			);
		}
	}

	/**
	 * XML-RPC exposure.
	 *
	 * @return void
	 */
	private function check_xmlrpc() {
		if ( apply_filters( 'xmlrpc_enabled', true ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reading WP core filter
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'XML-RPC is enabled', 'shieldscope-site-security-scanner' ),
				__( 'XML-RPC is commonly abused for password brute-force (system.multicall) and pingback-based DDoS. If you do not use Jetpack, the mobile app, or XML-RPC-based clients, disable it.', 'shieldscope-site-security-scanner' ),
				__( 'Add to your theme\'s functions.php or a must-use plugin: add_filter(\'xmlrpc_enabled\', \'__return_false\'); Or block it at the webserver level: Apache .htaccess — <Files xmlrpc.php> deny from all </Files>. Skip this if you use Jetpack or the WordPress mobile app.', 'shieldscope-site-security-scanner' ),
				'/xmlrpc.php'
			);
		}
	}

	/**
	 * REST API user enumeration.
	 *
	 * @return void
	 */
	private function check_rest_user_enum() {
		// Unauthenticated request to /wp/v2/users — does it return usernames?
		$url      = rest_url( 'wp/v2/users' );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( 200 === $code && $body ) {
			$decoded = json_decode( $body, true );
			if ( is_array( $decoded ) && ! empty( $decoded ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_MEDIUM,
					__( 'REST API exposes user list to unauthenticated requests', 'shieldscope-site-security-scanner' ),
					__( 'GET /wp/v2/users returns usernames without authentication, aiding targeted brute-force attempts.', 'shieldscope-site-security-scanner' ),
					__( 'Block the endpoint in functions.php or a must-use plugin: add_filter(\'rest_endpoints\', function($e){ if(!is_user_logged_in()){ unset($e[\'/wp/v2/users\']); unset($e[\'/wp/v2/users/(?P<id>[\\d]+)\']); } return $e; });', 'shieldscope-site-security-scanner' ),
					'/wp-json/wp/v2/users'
				);
			}
		}
	}
}
