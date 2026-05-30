<?php
/**
 * Security (Mis)Configuration checks.
 *
 * Detects insecure or default server and WordPress configuration:
 * EOL PHP, server/PHP version disclosure, publicly accessible sensitive files,
 * WP-Cron HTTP exposure, cookie security, and enabled dangerous PHP functions.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Security_Config
 */
class ShieldScope_Check_Security_Config extends ShieldScope_Check_Base {

	/** @return string */
	public function get_id() {
		return 'security_config';
	}

	/** @return string */
	public function get_label() {
		return __( 'Security Misconfiguration', 'shieldscope-site-security-scanner' );
	}

	/** @return array */
	public function get_steps() {
		return array(
			'php_version',
			'server_info',
			'sensitive_files',
			'wp_cron',
			'cookie_security',
			'php_functions',
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
			case 'php_version':
				$this->check_php_version();
				break;
			case 'server_info':
				$this->check_server_info();
				break;
			case 'sensitive_files':
				$this->check_sensitive_files();
				break;
			case 'wp_cron':
				$this->check_wp_cron();
				break;
			case 'cookie_security':
				$this->check_cookie_security();
				break;
			case 'php_functions':
				$this->check_php_dangerous_functions();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * PHP version end-of-life check.
	 *
	 * EOL dates: 7.x and below — EOL. 8.0 — Nov 2023. 8.1 — Dec 2024.
	 * 8.2 — Dec 2025. 8.3 — Dec 2026 (active). 8.4 — Dec 2027 (current).
	 *
	 * @return void
	 */
	private function check_php_version() {
		$version = PHP_VERSION;
		$major   = PHP_MAJOR_VERSION;
		$minor   = PHP_MINOR_VERSION;

		if ( $major < 8 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'PHP version is end-of-life and receives no security updates', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: PHP version string */
					__( 'PHP %s no longer receives security patches. Known vulnerabilities in this version will never be fixed.', 'shieldscope-site-security-scanner' ),
					$version
				),
				__( 'Upgrade to PHP 8.3 via your hosting control panel — look for "PHP Version" or "PHP Selector" under Software or Domain settings (cPanel, Plesk, or your managed host\'s dashboard). Always test on a staging copy first to check plugin compatibility.', 'shieldscope-site-security-scanner' ),
				'php.ini',
				array( 'php_version' => $version, 'minimum_recommended' => '8.3' )
			);
			return;
		}

		if ( 8 === $major && 0 === $minor ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'PHP 8.0 is end-of-life (EOL November 2023)', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: PHP version string */
					__( 'PHP %s reached end-of-life in November 2023 and no longer receives security patches.', 'shieldscope-site-security-scanner' ),
					$version
				),
				__( 'Upgrade to PHP 8.3 via your hosting control panel — look for "PHP Version" or "PHP Selector" under Software settings (cPanel/Plesk). Test on a staging copy first to check plugin compatibility.', 'shieldscope-site-security-scanner' ),
				'php.ini',
				array( 'php_version' => $version )
			);
			return;
		}

		if ( 8 === $major && 1 === $minor ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'PHP 8.1 is end-of-life (EOL December 2024)', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: PHP version string */
					__( 'PHP %s reached end-of-life in December 2024. No further security updates are available.', 'shieldscope-site-security-scanner' ),
					$version
				),
				__( 'Upgrade to PHP 8.3 via your hosting control panel — look for "PHP Version" or "PHP Selector" under Software settings (cPanel/Plesk). Test on a staging copy first to check plugin compatibility.', 'shieldscope-site-security-scanner' ),
				'php.ini',
				array( 'php_version' => $version )
			);
			return;
		}

		if ( 8 === $major && 2 === $minor ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'PHP 8.2 is end-of-life (EOL December 2025)', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: PHP version string */
					__( 'PHP %s reached end-of-life in December 2025. No further security updates are available.', 'shieldscope-site-security-scanner' ),
					$version
				),
				__( 'Upgrade to PHP 8.3 or later.', 'shieldscope-site-security-scanner' ),
				'php.ini',
				array( 'php_version' => $version )
			);
			return;
		}

		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			sprintf(
				/* translators: %s: PHP version string */
				__( 'PHP %s is a currently supported version', 'shieldscope-site-security-scanner' ),
				$version
			),
			'',
			'',
			'php.ini',
			array( 'php_version' => $version )
		);
	}

	/**
	 * Check for software version disclosure in response headers.
	 *
	 * @return void
	 */
	private function check_server_info() {
		$response = wp_remote_head(
			home_url( '/' ),
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$server  = wp_remote_retrieve_header( $response, 'server' );
		$x_power = wp_remote_retrieve_header( $response, 'x-powered-by' );

		if ( $server && preg_match( '/(?:Apache|nginx|IIS|LiteSpeed)[\/\s][\d.]+/i', $server ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Web server version disclosed in Server header', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: Server header value */
					__( 'The Server response header reveals the exact server software and version: "%s". This helps attackers target known CVEs for that specific version.', 'shieldscope-site-security-scanner' ),
					$server
				),
				__( 'Suppress version info: Apache — ServerTokens Prod; Nginx — server_tokens off; LiteSpeed — check Server Signature in admin.', 'shieldscope-site-security-scanner' ),
				'web-server-config',
				array( 'server_header' => $server )
			);
		}

		if ( $x_power ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'PHP/framework version disclosed in X-Powered-By header', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: X-Powered-By header value */
					__( 'The X-Powered-By response header reveals the server technology: "%s". Attackers use this to target specific PHP or framework CVEs.', 'shieldscope-site-security-scanner' ),
					$x_power
				),
				__( 'Set expose_php = Off in php.ini to suppress this header.', 'shieldscope-site-security-scanner' ),
				'php.ini',
				array( 'x_powered_by' => $x_power )
			);
		}
	}

	/**
	 * Probe for commonly-exposed sensitive files.
	 *
	 * @return void
	 */
	private function check_sensitive_files() {
		$base = trailingslashit( home_url() );

		$files = array(
			'wp-config-sample.php'   => array(
				'severity' => ShieldScope_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'wp-config-sample.php is publicly accessible', 'shieldscope-site-security-scanner' ),
				'desc'     => __( 'The sample config file is readable via HTTP. While it contains no real credentials it confirms WordPress is installed and reveals config structure to attackers.', 'shieldscope-site-security-scanner' ),
				'rec'      => __( 'Delete wp-config-sample.php from the server.', 'shieldscope-site-security-scanner' ),
			),
			'.env'                   => array(
				'severity' => ShieldScope_Logger::SEVERITY_CRITICAL,
				'title'    => __( '.env file is publicly accessible', 'shieldscope-site-security-scanner' ),
				'desc'     => __( 'A .env file responded with HTTP 200. These files typically contain database credentials, API keys, and other secrets.', 'shieldscope-site-security-scanner' ),
				'rec'      => __( 'Move .env above the webroot or add a deny rule in your webserver config to block access to .env files.', 'shieldscope-site-security-scanner' ),
			),
			'.git/config'            => array(
				'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				'title'    => __( '.git/config is publicly accessible', 'shieldscope-site-security-scanner' ),
				'desc'     => __( 'The git repository configuration is publicly readable. This exposes repository metadata and may allow full source code download.', 'shieldscope-site-security-scanner' ),
				'rec'      => __( 'Block access to the .git directory at the webserver level (deny all .git paths).', 'shieldscope-site-security-scanner' ),
			),
			'wp-content/debug.log'   => array(
				'severity' => ShieldScope_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'WordPress debug.log is publicly accessible', 'shieldscope-site-security-scanner' ),
				'desc'     => __( 'The debug.log file is readable via HTTP and may contain stack traces, file paths, database errors, and user data.', 'shieldscope-site-security-scanner' ),
				'rec'      => __( 'Block access to debug.log via the webserver or move WP_DEBUG_LOG path outside the webroot.', 'shieldscope-site-security-scanner' ),
			),
			'phpinfo.php'            => array(
				'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				'title'    => __( 'phpinfo.php is publicly accessible', 'shieldscope-site-security-scanner' ),
				'desc'     => __( 'A phpinfo() file was found. It discloses PHP configuration, loaded extensions, environment variables, and server internals to any visitor.', 'shieldscope-site-security-scanner' ),
				'rec'      => __( 'Delete phpinfo.php immediately.', 'shieldscope-site-security-scanner' ),
			),
			'info.php'               => array(
				'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				'title'    => __( 'info.php is publicly accessible (possible phpinfo)', 'shieldscope-site-security-scanner' ),
				'desc'     => __( 'A PHP file at info.php was found. If it calls phpinfo(), it discloses sensitive server configuration to any visitor.', 'shieldscope-site-security-scanner' ),
				'rec'      => __( 'Delete or restrict info.php.', 'shieldscope-site-security-scanner' ),
			),
		);

		foreach ( $files as $file => $meta ) {
			$response = wp_remote_get(
				$base . ltrim( $file, '/' ),
				array(
					'timeout'   => 5,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
				)
			);
			if ( is_wp_error( $response ) ) {
				continue;
			}
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				$this->finding(
					$meta['severity'],
					$meta['title'],
					$meta['desc'],
					$meta['rec'],
					'/' . $file
				);
			}
		}
	}

	/**
	 * Assess WP-Cron HTTP vs server cron configuration.
	 *
	 * @return void
	 */
	private function check_wp_cron() {
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'WP-Cron is disabled — verify a real server cron is running', 'shieldscope-site-security-scanner' ),
				__( 'DISABLE_WP_CRON is set (recommended for production). Ensure a system cron job calls wp-cron.php on a schedule, otherwise scheduled tasks will not fire.', 'shieldscope-site-security-scanner' ),
				__( 'Example cron entry: */5 * * * * wget -q -O - https://yoursite.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1', 'shieldscope-site-security-scanner' )
			);
		} else {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'WP-Cron fires on page load (default behaviour)', 'shieldscope-site-security-scanner' ),
				__( "WP-Cron is triggered on every visitor request. On high-traffic or heavily-attacked sites this wastes resources and can amplify the impact of a request flood.", 'shieldscope-site-security-scanner' ),
				__( "Add define( 'DISABLE_WP_CRON', true ); to wp-config.php and schedule a real server cron job to call wp-cron.php every 5–15 minutes.", 'shieldscope-site-security-scanner' ),
				'wp-config.php'
			);
		}
	}

	/**
	 * Check cookie security configuration.
	 *
	 * @return void
	 */
	private function check_cookie_security() {
		$is_https = ( 0 === stripos( get_site_url(), 'https://' ) );

		if ( $is_https && ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'FORCE_SSL_ADMIN not set — auth cookies may lack the Secure flag', 'shieldscope-site-security-scanner' ),
				__( 'Without FORCE_SSL_ADMIN, WordPress may issue authentication cookies without the Secure attribute, allowing them to be transmitted over HTTP and intercepted by a network attacker.', 'shieldscope-site-security-scanner' ),
				__( "Add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php.", 'shieldscope-site-security-scanner' ),
				'wp-config.php'
			);
		}

		// COOKIE_DOMAIN = '' disables domain scoping — only flag if explicitly set to empty.
		if ( defined( 'COOKIE_DOMAIN' ) && '' === COOKIE_DOMAIN ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'COOKIE_DOMAIN is set to an empty string', 'shieldscope-site-security-scanner' ),
				__( "Defining COOKIE_DOMAIN as '' removes the domain restriction from WordPress auth cookies. This is sometimes intentional in multisite setups but widens cookie scope unexpectedly.", 'shieldscope-site-security-scanner' ),
				__( 'Set COOKIE_DOMAIN to your actual domain or remove the definition to use the WordPress default.', 'shieldscope-site-security-scanner' ),
				'wp-config.php'
			);
		}

		// Warn if WordPress is served over HTTP on the login URL.
		if ( $is_https ) {
			$login_url = wp_login_url();
			if ( 0 !== stripos( $login_url, 'https://' ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_HIGH,
					__( 'Login URL is not HTTPS despite site using HTTPS', 'shieldscope-site-security-scanner' ),
					__( 'The wp_login_url() value does not begin with https://. Credentials can be transmitted in plaintext.', 'shieldscope-site-security-scanner' ),
					__( 'Ensure home_url and site_url both use https://, and that FORCE_SSL_ADMIN is set.', 'shieldscope-site-security-scanner' ),
					$login_url
				);
			}
		}
	}

	/**
	 * Check whether dangerous PHP functions are available.
	 *
	 * @return void
	 */
	private function check_php_dangerous_functions() {
		$dangerous    = array( 'exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen', 'pcntl_exec' );
		$not_disabled = array();
		foreach ( $dangerous as $fn ) {
			if ( function_exists( $fn ) ) {
				$not_disabled[] = $fn;
			}
		}

		if ( ! empty( $not_disabled ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Dangerous PHP functions are not disabled', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: comma-separated list of PHP function names */
					__( 'The following PHP functions are callable: %s. If a plugin or theme has a code injection bug, these can be used for OS command execution.', 'shieldscope-site-security-scanner' ),
					implode( ', ', $not_disabled )
				),
					__( 'Add to php.ini: disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec. If you cannot edit php.ini directly, create a .user.ini file in your WordPress root with the same line, or ask your host to apply it at the server level.', 'shieldscope-site-security-scanner' ),
				'php.ini',
				array( 'available_functions' => $not_disabled )
			);
		} else {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Dangerous PHP execution functions are all disabled', 'shieldscope-site-security-scanner' ),
				__( 'exec, passthru, shell_exec, system, proc_open, popen, and pcntl_exec are disabled via disable_functions.', 'shieldscope-site-security-scanner' )
			);
		}
	}
}
