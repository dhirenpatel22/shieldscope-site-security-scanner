<?php
/**
 * Vulnerable and Outdated Components checks.
 *
 * Assesses the patch level of core infrastructure components: database server
 * version (MySQL/MariaDB EOL), WordPress known-CVE version windows and
 * HTTP-to-HTTPS redirect enforcement.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Components
 */
class ShieldScope_Check_Components extends ShieldScope_Check_Base {

	/** @return string */
	public function get_id() {
		return 'components';
	}

	/** @return string */
	public function get_label() {
		return __( 'Vulnerable & Outdated Components', 'shieldscope-site-security-scanner' );
	}

	/** @return array */
	public function get_steps() {
		return array(
			'database_version',
			'wp_vuln_ranges',
			'http_redirect',
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
			case 'database_version':
				$this->check_database_version();
				break;
			case 'wp_vuln_ranges':
				$this->check_wp_vuln_ranges();
				break;
			case 'http_redirect':
				$this->check_http_to_https_redirect();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Check MySQL / MariaDB version against EOL dates.
	 *
	 * @return void
	 */
	private function check_database_version() {
		global $wpdb;

		$full_version = $wpdb->get_var( 'SELECT VERSION()' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( ! $full_version ) {
			return;
		}

		$is_mariadb = ( false !== stripos( $full_version, 'mariadb' ) );
		$engine     = $is_mariadb ? 'MariaDB' : 'MySQL';
		$ver        = preg_match( '/\d+\.\d+\.\d+/', $full_version, $m ) ? $m[0] : $full_version;
		$eol        = ShieldScope_EOL_Data::lookup( $is_mariadb ? 'mariadb' : 'mysql', $ver );
		$context    = array( 'version' => $ver, 'engine' => $engine, 'eol_date' => $eol['eol_date'], 'eol_data_reviewed' => ShieldScope_EOL_Data::LAST_REVIEWED );

		if ( ShieldScope_EOL_Data::STATUS_EOL === $eol['status'] ) {
			if ( null !== $eol['eol_date'] ) {
				$description = sprintf(
					/* translators: 1: database engine (MySQL or MariaDB), 2: version, 3: end-of-life date */
					__( '%1$s %2$s reached end of life on %3$s and no longer receives security patches. Known CVEs will remain permanently unpatched.', 'shieldscope-site-security-scanner' ),
					$engine,
					$ver,
					ShieldScope_EOL_Data::format_date( $eol['eol_date'] )
				);
			} else {
				$description = sprintf(
					/* translators: 1: database engine (MySQL or MariaDB), 2: version */
					__( '%1$s %2$s is an old or short-term release that a newer release has replaced. It no longer receives security patches. Known CVEs will remain permanently unpatched.', 'shieldscope-site-security-scanner' ),
					$engine,
					$ver
				);
			}

			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				sprintf(
					/* translators: %s: database engine (MySQL or MariaDB) */
					__( '%s version is end-of-life', 'shieldscope-site-security-scanner' ),
					$engine
				),
				$description,
				$is_mariadb
					? __( 'Upgrade to a supported MariaDB long-term release such as 10.11 or 11.4. Contact your hosting provider or upgrade via your database control panel.', 'shieldscope-site-security-scanner' )
					: __( 'Upgrade to a supported MySQL LTS release such as 8.4. Contact your hosting provider.', 'shieldscope-site-security-scanner' ),
				'database',
				$context
			);
			return;
		}

		if ( ShieldScope_EOL_Data::STATUS_SUPPORTED === $eol['status'] ) {
			$description = null !== $eol['eol_date']
				? sprintf(
					/* translators: 1: end-of-life date, 2: date the end-of-life data was last reviewed */
					__( 'Security support until %1$s (end-of-life data last reviewed %2$s).', 'shieldscope-site-security-scanner' ),
					ShieldScope_EOL_Data::format_date( $eol['eol_date'] ),
					ShieldScope_EOL_Data::format_date( ShieldScope_EOL_Data::LAST_REVIEWED )
				)
				: sprintf(
					/* translators: %s: date the end-of-life data was last reviewed */
					__( 'Supported, with no end-of-life date announced (end-of-life data last reviewed %s).', 'shieldscope-site-security-scanner' ),
					ShieldScope_EOL_Data::format_date( ShieldScope_EOL_Data::LAST_REVIEWED )
				);

			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				sprintf(
					/* translators: 1: database engine (MySQL or MariaDB), 2: version */
					__( '%1$s %2$s is a supported version', 'shieldscope-site-security-scanner' ),
					$engine,
					$ver
				),
				$description,
				'',
				'database',
				$context
			);
			return;
		}

		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			sprintf(
				/* translators: 1: database engine (MySQL or MariaDB), 2: version */
				__( '%1$s %2$s support status could not be determined', 'shieldscope-site-security-scanner' ),
				$engine,
				$ver
			),
			sprintf(
				/* translators: 1: version, 2: date the end-of-life data was last reviewed */
				__( 'Version %1$s is not in ShieldScope\'s end-of-life table (last reviewed %2$s). Check the vendor\'s lifecycle page to confirm it still receives security patches.', 'shieldscope-site-security-scanner' ),
				$ver,
				ShieldScope_EOL_Data::format_date( ShieldScope_EOL_Data::LAST_REVIEWED )
			),
			'',
			'database',
			$context
		);
	}

	/**
	 * Flag WordPress version ranges with critical known CVEs.
	 *
	 * This supplements the core check that flags available updates — it
	 * specifically calls out versions with publicly-documented RCE/auth-bypass CVEs.
	 *
	 * @return void
	 */
	private function check_wp_vuln_ranges() {
		global $wp_version;

		$eol = ShieldScope_EOL_Data::lookup( 'wordpress', $wp_version );

		if ( ShieldScope_EOL_Data::STATUS_EOL === $eol['status'] ) {
			$no_updates = null !== $eol['eol_date']
				? sprintf(
					/* translators: 1: WordPress version, 2: date security backports ended */
					__( 'WordPress %1$s no longer receives security updates: the WordPress Security Team stopped backporting fixes to this branch on %2$s.', 'shieldscope-site-security-scanner' ),
					$wp_version,
					ShieldScope_EOL_Data::format_date( $eol['eol_date'] )
				)
				: sprintf(
					/* translators: %s: WordPress version */
					__( 'WordPress %s no longer receives security updates.', 'shieldscope-site-security-scanner' ),
					$wp_version
				);

			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'WordPress version contains critical publicly-known CVEs', 'shieldscope-site-security-scanner' ),
				$no_updates . ' ' . __( 'Publicly known vulnerabilities remain unpatched, for example CVE-2017-1000600 (remote code execution by an authenticated user through PHAR deserialisation in thumbnail processing).', 'shieldscope-site-security-scanner' ),
				__( 'Update WordPress immediately via Dashboard → Updates. Back up your database and files first.', 'shieldscope-site-security-scanner' ),
				'wordpress-core',
				array( 'version' => $wp_version, 'eol_date' => $eol['eol_date'], 'eol_data_reviewed' => ShieldScope_EOL_Data::LAST_REVIEWED )
			);
			return;
		}

		if ( version_compare( $wp_version, '5.0', '<' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'WordPress version is significantly out of date with known high-severity CVEs', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: WordPress version */
					__( 'WordPress %s is well below the current major version and within a range with multiple documented high-severity vulnerabilities.', 'shieldscope-site-security-scanner' ),
					$wp_version
				),
				__( 'Update WordPress via Dashboard → Updates.', 'shieldscope-site-security-scanner' ),
				'wordpress-core',
				array( 'version' => $wp_version )
			);
		}
		// Current update availability is already reported by ShieldScope_Check_Core.
	}

	/**
	 * Verify that HTTP requests are redirected to HTTPS.
	 *
	 * @return void
	 */
	private function check_http_to_https_redirect() {
		$site_url = get_site_url();
		if ( 0 !== stripos( $site_url, 'https://' ) ) {
			return; // Site not on HTTPS — ShieldScope_Check_Core already flags this.
		}

		$http_url = 'http://' . preg_replace( '/^https:\/\//i', '', $site_url ) . '/';

		$response = wp_remote_head(
			$http_url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'sslverify'   => false,
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code     = wp_remote_retrieve_response_code( $response );
		$location = wp_remote_retrieve_header( $response, 'location' );

		$redirects_to_https = (
			in_array( $code, array( 301, 302, 307, 308 ), true ) &&
			0 === stripos( (string) $location, 'https://' )
		);

		if ( ! $redirects_to_https ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'HTTP requests are not redirected to HTTPS', 'shieldscope-site-security-scanner' ),
				__( 'The site uses HTTPS but plain HTTP requests are not automatically redirected. Visitors who type the address without "https://" will have an unencrypted connection.', 'shieldscope-site-security-scanner' ),
				__( 'Add a permanent HTTP-to-HTTPS redirect in your webserver config (.htaccess RewriteRule for Apache, return 301 for Nginx). This is separate from FORCE_SSL_ADMIN.', 'shieldscope-site-security-scanner' ),
				$http_url
			);
		} elseif ( ! in_array( $code, array( 301, 308 ), true ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'HTTP-to-HTTPS redirect uses a non-permanent status code', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'The HTTP-to-HTTPS redirect uses a %d (temporary) status code instead of 301. Browsers will not cache it and search engines will not pass full link equity.', 'shieldscope-site-security-scanner' ),
					$code
				),
				__( 'Change the redirect to a 301 Permanent in your webserver configuration.', 'shieldscope-site-security-scanner' ),
				$http_url
			);
		}
	}
}
