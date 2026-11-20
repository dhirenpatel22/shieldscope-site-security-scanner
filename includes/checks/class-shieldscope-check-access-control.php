<?php
/**
 * Access control vulnerability checks.
 *
 * Detects missing or inadequate restrictions on authenticated actions:
 * application passwords, author enumeration, unprotected login page, and
 * AJAX handlers lacking nonce or capability checks.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Access_Control
 */
class ShieldScope_Check_Access_Control extends ShieldScope_Check_Base {

	/**
	 * Max file size to scan.
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param ShieldScope_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, ShieldScope_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$settings            = (array) get_option( 'shieldscope_settings', array() );
		$this->max_file_size = isset( $settings['max_scan_file_size'] )
			? (int) $settings['max_scan_file_size']
			: 2 * MB_IN_BYTES;
	}

	/** @return string */
	public function get_id() {
		return 'access_control';
	}

	/** @return string */
	public function get_label() {
		return __( 'Access Control', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps a quick scan skips.
	 *
	 * @return string[]
	 */
	public function get_slow_steps() {
		return array( 'scan_plugins' );
	}

	/** @return array */
	public function get_steps() {
		return array(
			'app_passwords',
			'author_enum',
			'login_page',
			'login_errors',
			'rest_routes',
			'scan_plugins',
		);
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'app_passwords':
				$this->check_application_passwords();
				break;
			case 'author_enum':
				$this->check_author_enumeration();
				break;
			case 'login_page':
				$this->check_login_page();
				break;
			case 'login_errors':
				$this->check_login_errors();
				break;
			case 'rest_routes':
				$this->check_rest_write_routes();
				break;
			case 'scan_plugins':
				return $this->scan_plugins_for_auth( $cursor );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * REST namespaces that belong to WordPress core.
	 */
	const CORE_REST_PREFIXES = array( '/wp/', '/oembed/', '/wp-site-health/', '/wp-block-editor/', '/batch/', '/wp-abilities/' );

	/**
	 * Do failed-login messages reveal whether a username exists?
	 *
	 * Passive: runs the site's login_errors filter on WordPress's own
	 * "wrong password for this username" message, in this request. No login
	 * is attempted.
	 *
	 * @return void
	 */
	private function check_login_errors() {
		$probe   = 'shieldscope-probe-user';
		$message = sprintf(
			/* translators: %s: user name (mirrors the WordPress core login error) */
			__( '<strong>Error:</strong> The password you entered for the username %s is incorrect.', 'shieldscope-site-security-scanner' ),
			'<strong>' . $probe . '</strong>'
		);
		$filtered = (string) apply_filters( 'login_errors', $message ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reading a core filter.

		if ( false === strpos( $filtered, $probe ) ) {
			return;
		}
		$this->finding(
			ShieldScope_Logger::SEVERITY_LOW,
			__( 'Login error messages reveal whether a username exists', 'shieldscope-site-security-scanner' ),
			__( 'After a failed login, WordPress says whether the username exists ("The password you entered for the username ... is incorrect"). Nothing on this site changes that message, so an attacker can confirm usernames before guessing passwords. Checked by running the site\'s login_errors filter on WordPress\'s own message; no login was attempted.', 'shieldscope-site-security-scanner' ),
			__( 'Use a security or login-protection plugin that shows one generic message for every failed login, or add a login_errors filter that returns a generic message. Limiting login attempts matters more than hiding usernames.', 'shieldscope-site-security-scanner' ),
			'wp-login.php'
		);
	}

	/**
	 * REST routes added by plugins that accept writes from anyone.
	 *
	 * Passive: reads the registered routes and their permission callbacks in
	 * this request. Reported as Low "Review" findings, one per namespace,
	 * because public write routes are sometimes intended (forms, webhooks).
	 *
	 * @return void
	 */
	private function check_rest_write_routes() {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return;
		}
		$server = rest_get_server();
		if ( ! is_object( $server ) || ! method_exists( $server, 'get_routes' ) ) {
			return;
		}

		$by_namespace = array();
		foreach ( (array) $server->get_routes() as $route => $endpoints ) {
			if ( self::is_core_route( $route ) ) {
				continue;
			}
			foreach ( (array) $endpoints as $endpoint ) {
				if ( ! is_array( $endpoint ) ) {
					continue;
				}
				$methods = isset( $endpoint['methods'] ) ? array_keys( array_filter( (array) $endpoint['methods'] ) ) : array();
				$writes  = array_intersect( array_map( 'strtoupper', $methods ), array( 'POST', 'PUT', 'PATCH', 'DELETE' ) );
				if ( ! $writes ) {
					continue;
				}
				$cb = array_key_exists( 'permission_callback', $endpoint ) ? $endpoint['permission_callback'] : null;
				if ( null !== $cb && '__return_true' !== $cb ) {
					continue;
				}
				$namespace                    = self::route_namespace( $route );
				$by_namespace[ $namespace ][] = implode( '/', $writes ) . ' ' . $route . ( null === $cb ? ' ' . __( '(no permission check)', 'shieldscope-site-security-scanner' ) : ' (__return_true)' );
			}
		}

		foreach ( $by_namespace as $namespace => $routes ) {
			$routes = array_values( array_unique( $routes ) );
			$shown  = array_slice( $routes, 0, 10 );
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				/* translators: %s: REST namespace, for example "myplugin/v1" */
				sprintf( __( 'Review: REST routes in %s accept writes without a login', 'shieldscope-site-security-scanner' ), $namespace ),
				sprintf(
					/* translators: 1: number of routes, 2: list of routes */
					__( '%1$d route(s) accept POST, PUT, PATCH or DELETE requests from anyone: %2$s. This is normal for contact forms or webhooks that check their own input, but a route that changes data without a permission check is a vulnerability. Checked by reading the registered routes; no request was sent.', 'shieldscope-site-security-scanner' ),
					count( $routes ),
					implode( '; ', $shown ) . ( count( $routes ) > 10 ? ' …' : '' )
				),
				__( 'Check what each route does. If it should not be public, ask the plugin developer to add a permission_callback that checks current_user_can(); if it is meant to be public, confirm it validates input and uses a nonce or signature where it can.', 'shieldscope-site-security-scanner' ),
				'/wp-json/' . $namespace
			);
		}
	}

	/**
	 * Is this route in a WordPress core namespace?
	 *
	 * @param string $route Route.
	 * @return bool
	 */
	private static function is_core_route( $route ) {
		foreach ( self::CORE_REST_PREFIXES as $prefix ) {
			if ( 0 === strpos( $route, $prefix ) ) {
				return true;
			}
		}
		return '/' === $route;
	}

	/**
	 * Namespace part of a route ("/myplugin/v1/items" => "myplugin/v1").
	 *
	 * @param string $route Route.
	 * @return string
	 */
	private static function route_namespace( $route ) {
		$parts = array_values( array_filter( explode( '/', (string) $route ), 'strlen' ) );
		return implode( '/', array_slice( $parts, 0, 2 ) );
	}

	/**
	 * Audit Application Passwords usage.
	 *
	 * @return void
	 */
	private function check_application_passwords() {
		if ( ! function_exists( 'wp_is_application_passwords_available' ) ) {
			return;
		}
		if ( ! wp_is_application_passwords_available() || ! class_exists( 'WP_Application_Passwords' ) ) {
			return;
		}

		$users_with_app_pw = get_users(
			array(
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- meta_key is indexed; required to identify users with application passwords.
				'meta_key'     => '_application_passwords',
				'meta_compare' => 'EXISTS',
				'number'       => 20,
				'fields'       => array( 'ID', 'user_login', 'roles' ),
			)
		);

		// The meta row stays (as an empty array) after every password is revoked.
		$users_with_app_pw = array_values(
			array_filter(
				(array) $users_with_app_pw,
				static function ( $u ) {
					return ! empty( WP_Application_Passwords::get_user_application_passwords( $u->ID ) );
				}
			)
		);

		if ( empty( $users_with_app_pw ) ) {
			return;
		}

		$admin_logins = array();
		foreach ( $users_with_app_pw as $u ) {
			if ( user_can( $u->ID, 'manage_options' ) ) {
				$admin_logins[] = $u->user_login;
			}
		}

		if ( ! empty( $admin_logins ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Administrator accounts have Application Passwords configured', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: comma-separated list of usernames */
					__( 'The following administrator accounts have application passwords: %s. Each app password is an independent credential — if leaked it grants full API access with no 2FA challenge.', 'shieldscope-site-security-scanner' ),
					implode( ', ', $admin_logins )
				),
				__( 'Review and revoke unused application passwords via Users → Profile. Apply the principle of least privilege — avoid granting admin-level app passwords.', 'shieldscope-site-security-scanner' ),
				'',
				array( 'admin_users' => $admin_logins )
			);
		} else {
			$logins = wp_list_pluck( $users_with_app_pw, 'user_login' );
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Application Passwords are active on user accounts', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: comma-separated list of usernames */
					__( 'Users with application passwords configured: %s. Review and revoke any that are unused or unrecognised.', 'shieldscope-site-security-scanner' ),
					implode( ', ', $logins )
				),
				__( 'Audit application passwords in Users → Profile and remove any that are no longer needed.', 'shieldscope-site-security-scanner' ),
				'',
				array( 'users' => $logins )
			);
		}
	}

	/**
	 * Check if the ?author=N redirect leaks usernames.
	 *
	 * @return void
	 */
	private function check_author_enumeration() {
		$url      = home_url( '/?author=1' );
		$response = wp_remote_head(
			$url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code     = wp_remote_retrieve_response_code( $response );
		$location = wp_remote_retrieve_header( $response, 'location' );

		if ( in_array( $code, array( 301, 302 ), true ) && false !== strpos( (string) $location, '/author/' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Username exposed via author archive redirect', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: redirect URL */
					__( '/?author=1 redirects to %s, leaking a username to unauthenticated visitors and aiding brute-force targeting.', 'shieldscope-site-security-scanner' ),
					$location
				),
				__( 'In Users → All Users, set each author\'s "Display name publicly as" to a first name or nickname that differs from their login. To also block the redirect itself, add to functions.php: add_action(\'template_redirect\', function(){ if(is_author()){ wp_redirect(home_url(\'/\'), 301); exit; } });', 'shieldscope-site-security-scanner' ),
				'/?author=1',
				array( 'redirect' => $location )
			);
		}
	}

	/**
	 * Check login page exposure and brute-force protection.
	 *
	 * @return void
	 */
	private function check_login_page() {
		$login_url = wp_login_url();
		$response  = wp_remote_get(
			$login_url,
			array(
				'timeout'     => 5,
				'redirection' => 3,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return;
		}

		// Login page is accessible — check for recognised brute-force protection.
		$bf_plugins = array(
			'wordfence/wordfence.php',
			'better-wp-security/better-wp-security.php',
			'ithemes-security/ithemes-security.php',
			'loginizer/loginizer.php',
			'wp-cerber/wp-cerber.php',
			'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
			'wps-hide-login/wps-hide-login.php',
			'rename-wp-login/rename-wp-login.php',
			'solid-security-basic/solid-security-basic.php',
			'all-in-one-wp-security-and-firewall/wp-security.php',
		);

		$active_bf = false;
		foreach ( $bf_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$active_bf = true;
				break;
			}
		}

		if ( ! $active_bf ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Login page is publicly accessible without brute-force protection', 'shieldscope-site-security-scanner' ),
				__( 'wp-login.php is reachable and no recognised login-protection plugin is active. Bots continuously run credential-stuffing attacks against WordPress login pages.', 'shieldscope-site-security-scanner' ),
				__( 'Protect your login page by enabling rate limiting at the webserver or firewall level, or by moving wp-login.php to a custom URL (so bots cannot find the default path). Check your hosting dashboard — many managed hosts include brute-force protection built in.', 'shieldscope-site-security-scanner' ),
				$login_url
			);
		}

		// Check for 2FA plugin.
		$twofa_plugins = array(
			'two-factor/two-factor.php',
			'google-authenticator/google-authenticator.php',
			'wp-2fa/wp-2fa.php',
			'miniOrange-2-factor-authentication/miniorange_2_factor_authentication.php',
			'wordfence/wordfence.php',
		);

		$has_2fa = false;
		foreach ( $twofa_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$has_2fa = true;
				break;
			}
		}

		if ( ! $has_2fa ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'No two-factor authentication plugin detected', 'shieldscope-site-security-scanner' ),
				__( 'No recognised 2FA plugin is active. Without a second factor, a stolen password is sufficient to compromise any account.', 'shieldscope-site-security-scanner' ),
				__( 'Enable two-factor authentication for all administrator accounts. With 2FA, a stolen password alone is not enough to access an account. Search for "two-factor" on wordpress.org/plugins to find a suitable option, or check whether your hosting provider includes 2FA tools in their dashboard.', 'shieldscope-site-security-scanner' )
			);
		}
	}

	/**
	 * Scan plugin PHP files for AJAX handlers without proper authorisation.
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function scan_plugins_for_auth( array $cursor ) {
		$root = SHIELDSCOPE_WP_PLUGINS_DIR;
		return $this->walk_php_files_step(
			$root,
			$cursor,
			function ( $full ) {
				$this->scan_file_for_auth( $full );
			}
		);
	}

	/**
	 * Check one file for AJAX handlers lacking auth.
	 *
	 * @param string $path File path.
	 * @return void
	 */
	private function scan_file_for_auth( $path ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size || 0 === $size ) {
			return;
		}
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || '' === $contents ) {
			return;
		}

		// wp_ajax_nopriv_ hooks without any nonce verification in the same file.
		$nopriv_count = preg_match_all(
			"/add_action\s*\(\s*['\"]wp_ajax_nopriv_/i",
			$contents
		);
		if ( $nopriv_count > 0 ) {
			$has_nonce = (bool) preg_match( '/check_ajax_referer|wp_verify_nonce|check_admin_referer/i', $contents );
			if ( ! $has_nonce ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					__( 'Needs review: public AJAX handler with no nonce check in the same file', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: %d: number of hooks found */
						_n(
							'Found %d wp_ajax_nopriv_ hook in a file that contains no nonce check. This is a file-level pattern match: the check may live in another file, and some public handlers do not need one. Review the handler to confirm.',
							'Found %d wp_ajax_nopriv_ hooks in a file that contains no nonce check. This is a file-level pattern match: the check may live in another file, and some public handlers do not need one. Review the handlers to confirm.',
							$nopriv_count,
							'shieldscope-site-security-scanner'
						),
						$nopriv_count
					),
					__( 'If the handler changes data, it should call check_ajax_referer() or wp_verify_nonce() to prevent cross-site request forgery.', 'shieldscope-site-security-scanner' ),
					$path
				);
			}
		}

		// wp_ajax_ (logged-in) hooks without capability or nonce check.
		$priv_count = preg_match_all(
			"/add_action\s*\(\s*['\"]wp_ajax_(?!nopriv_)/i",
			$contents
		);
		if ( $priv_count > 0 ) {
			$has_auth = (bool) preg_match( '/current_user_can|check_ajax_referer|wp_verify_nonce|check_admin_referer/i', $contents );
			if ( ! $has_auth ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					__( 'Needs review: AJAX handler with no capability or nonce check in the same file', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: %d: number of hooks found */
						_n(
							'Found %d wp_ajax_ hook in a file that contains no current_user_can() or nonce check. This is a file-level pattern match: the checks may live in another file. If they are missing, any logged-in user could trigger the action.',
							'Found %d wp_ajax_ hooks in a file that contains no current_user_can() or nonce check. This is a file-level pattern match: the checks may live in another file. If they are missing, any logged-in user could trigger the actions.',
							$priv_count,
							'shieldscope-site-security-scanner'
						),
						$priv_count
					),
					__( 'Call current_user_can() with the required capability and use check_ajax_referer() or wp_verify_nonce() to prevent CSRF.', 'shieldscope-site-security-scanner' ),
					$path
				);
			}
		}
	}
}
