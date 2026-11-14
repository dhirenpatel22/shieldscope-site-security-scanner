<?php
/**
 * Tests for ticket A-05: date-driven end-of-life data and the component /
 * security-config findings that use it.
 *
 * Expected dates were checked on 2026-11-14 against php.net, the Oracle
 * Lifetime Support Policy, mariadb.org and make.wordpress.org, with
 * endoflife.date as a cross-check.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

// Stubs this ticket needs that tests/wp-stubs.php does not provide (yet).
if ( ! function_exists( 'wp_date' ) ) {
	function wp_date( $format, $timestamp = null, $timezone = null ) {
		return gmdate( $format, null === $timestamp ? time() : $timestamp );
	}
}
if ( ! function_exists( 'get_site_url' ) ) {
	function get_site_url() {
		list( $hit, $result ) = ss_tests_maybe_override( 'get_site_url', array() );
		return $hit ? $result : 'https://example.test';
	}
}
if ( ! function_exists( 'wp_login_url' ) ) {
	function wp_login_url() {
		return get_site_url() . '/wp-login.php';
	}
}
if ( ! function_exists( 'get_plugins' ) ) {
	function get_plugins() {
		list( $hit, $result ) = ss_tests_maybe_override( 'get_plugins', array() );
		return $hit ? $result : array();
	}
}
if ( ! function_exists( 'wp_remote_head' ) ) {
	function wp_remote_head( $url, $args = array() ) {
		list( $hit, $result ) = ss_tests_maybe_override( 'wp_remote_head', array( $url, $args ) );
		return $hit ? $result : new WP_Error( 'no_network', 'Network disabled in tests' );
	}
}
if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
	function wp_remote_retrieve_header( $response, $header ) {
		return isset( $response['headers'][ $header ] ) ? $response['headers'][ $header ] : '';
	}
}

if ( ! class_exists( 'SS_EOL_Fake_WPDB' ) ) {
	/**
	 * wpdb double that only answers SELECT VERSION().
	 */
	class SS_EOL_Fake_WPDB {
		/** @var string */
		public $version;

		public function __construct( $version ) {
			$this->version = $version;
		}

		public function get_var( $sql ) {
			return $this->version;
		}

		public function db_version() {
			return $this->version;
		}
	}
}

/**
 * Class Test_EOL_Data
 */
class Test_EOL_Data extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->logger = new SS_Fake_Logger();
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wpdb'] );
	}

	private static function utc( $datetime ) {
		return strtotime( $datetime . ' UTC' );
	}

	// -----------------------------------------------------------------------
	// Data table
	// -----------------------------------------------------------------------

	public function test_last_reviewed_is_not_older_than_six_months() {
		$reviewed = strtotime( ShieldScope_EOL_Data::LAST_REVIEWED . ' 00:00:00 UTC' );
		$this->assertNotFalse( $reviewed );
		$this->assertGreaterThanOrEqual(
			time(),
			strtotime( '+6 months', $reviewed ),
			'EOL data was last reviewed on ' . ShieldScope_EOL_Data::LAST_REVIEWED . '. Re-check every date in includes/class-shieldscope-eol-data.php against its source, then update LAST_REVIEWED.'
		);
	}

	public function test_every_table_entry_is_a_valid_date_or_null() {
		foreach ( ShieldScope_EOL_Data::table() as $product => $releases ) {
			$this->assertNotEmpty( $releases, $product );
			foreach ( $releases as $branch => $date ) {
				$this->assertMatchesRegularExpression( '/^\d+\.\d+$/', (string) $branch, "$product $branch" );
				if ( null !== $date ) {
					$parsed = DateTime::createFromFormat( '!Y-m-d', $date );
					$this->assertNotFalse( $parsed, "$product $branch" );
					$this->assertSame( $date, $parsed->format( 'Y-m-d' ), "$product $branch" );
				}
			}
		}
	}

	public function test_php_82_is_not_eol_before_end_of_2026() {
		$on_last_day = ShieldScope_EOL_Data::lookup( 'php', '8.2.29', self::utc( '2026-12-31 18:00:00' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_SUPPORTED, $on_last_day['status'] );
		$this->assertSame( '2026-12-31', $on_last_day['eol_date'] );

		$today = ShieldScope_EOL_Data::lookup( 'php', '8.2.29', self::utc( '2026-11-14 12:00:00' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_SUPPORTED, $today['status'] );

		$after = ShieldScope_EOL_Data::lookup( 'php', '8.2.29', self::utc( '2027-01-01 00:00:01' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, $after['status'] );
	}

	public function test_php_81_is_eol_after_end_of_2025() {
		$result = ShieldScope_EOL_Data::lookup( 'php', '8.1.34', self::utc( '2026-01-01 00:00:01' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, $result['status'] );
		$this->assertSame( '2025-12-31', $result['eol_date'] );
	}

	public function test_php_versions_older_than_the_table_are_eol_and_newer_are_unknown() {
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, ShieldScope_EOL_Data::lookup( 'php', '5.4.45' )['status'] );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_UNKNOWN, ShieldScope_EOL_Data::lookup( 'php', '9.0.0' )['status'] );
	}

	public function test_mysql_80_is_eol_after_30_april_2026() {
		$result = ShieldScope_EOL_Data::lookup( 'mysql', '8.0.43', self::utc( '2026-05-01 00:00:01' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, $result['status'] );
		$this->assertSame( '2026-04-30', $result['eol_date'] );
	}

	public function test_mariadb_106_is_eol_after_6_july_2026() {
		$result = ShieldScope_EOL_Data::lookup( 'mariadb', '10.6.23-MariaDB', self::utc( '2026-07-07 00:00:01' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, $result['status'] );
		$this->assertSame( '2026-07-06', $result['eol_date'] );
	}

	/**
	 * @dataProvider superseded_short_term_releases
	 */
	public function test_superseded_innovation_and_short_term_releases_are_eol( $product, $version ) {
		$result = ShieldScope_EOL_Data::lookup( $product, $version, self::utc( '2026-11-14 12:00:00' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, $result['status'] );
	}

	public static function superseded_short_term_releases() {
		return array(
			'MySQL 8.1'     => array( 'mysql', '8.1.0' ),
			'MySQL 8.3'     => array( 'mysql', '8.3.0' ),
			'MySQL 9.0'     => array( 'mysql', '9.0.1' ),
			'MySQL 9.6'     => array( 'mysql', '9.6.0' ),
			'MySQL 26.7'    => array( 'mysql', '26.7.1' ),
			'MariaDB 10.7'  => array( 'mariadb', '10.7.8-MariaDB' ),
			'MariaDB 10.10' => array( 'mariadb', '10.10.7-MariaDB' ),
			'MariaDB 11.0'  => array( 'mariadb', '11.0.6-MariaDB' ),
			'MariaDB 11.7'  => array( 'mariadb', '11.7.2-MariaDB' ),
			'MariaDB 12.0'  => array( 'mariadb', '12.0.2-MariaDB' ),
			'MariaDB 12.2'  => array( 'mariadb', '12.2.1-MariaDB' ),
		);
	}

	/**
	 * @dataProvider supported_releases
	 */
	public function test_supported_releases_are_not_eol( $product, $version ) {
		$result = ShieldScope_EOL_Data::lookup( $product, $version, self::utc( '2026-11-14 12:00:00' ) );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_SUPPORTED, $result['status'] );
	}

	public static function supported_releases() {
		return array(
			'PHP 8.3'       => array( 'php', '8.3.27' ),
			'PHP 8.5'       => array( 'php', '8.5.0' ),
			'MySQL 8.4'     => array( 'mysql', '8.4.6' ),
			'MySQL 9.7'     => array( 'mysql', '9.7.0' ),
			'MySQL 26.10'   => array( 'mysql', '26.10.0' ),
			'MariaDB 10.11' => array( 'mariadb', '10.11.14-MariaDB' ),
			'MariaDB 11.4'  => array( 'mariadb', '11.4.8-MariaDB' ),
			'MariaDB 11.8'  => array( 'mariadb', '11.8.3-MariaDB' ),
			'MariaDB 12.3'  => array( 'mariadb', '12.3.1-MariaDB' ),
		);
	}

	public function test_version_comparison_is_not_float_based() {
		$this->assertSame( '4.10', ShieldScope_EOL_Data::branch( '4.10.2' ) );
		$this->assertSame( '10.11', ShieldScope_EOL_Data::branch( '10.11.5-MariaDB-1:10.11.5+maria~ubu2204' ) );

		// "4.10" must not be read as 4.1 (EOL); it is newer than every listed WordPress branch.
		$this->assertSame( ShieldScope_EOL_Data::STATUS_UNKNOWN, ShieldScope_EOL_Data::lookup( 'wordpress', '4.10' )['status'] );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, ShieldScope_EOL_Data::lookup( 'wordpress', '4.1.40' )['status'] );
		// MariaDB 10.11 must not be read as 10.1 (EOL).
		$this->assertSame( ShieldScope_EOL_Data::STATUS_SUPPORTED, ShieldScope_EOL_Data::lookup( 'mariadb', '10.11.5', self::utc( '2026-11-14 12:00:00' ) )['status'] );
	}

	public function test_wordpress_branches_without_backports_are_eol() {
		$this->assertSame( '2022-12-01', ShieldScope_EOL_Data::lookup( 'wordpress', '4.0.38' )['eol_date'] );
		$this->assertSame( '2025-07-31', ShieldScope_EOL_Data::lookup( 'wordpress', '4.6.29' )['eol_date'] );
		$this->assertSame( ShieldScope_EOL_Data::STATUS_EOL, ShieldScope_EOL_Data::lookup( 'wordpress', '3.5.2' )['status'] );
		$this->assertNotSame( ShieldScope_EOL_Data::STATUS_EOL, ShieldScope_EOL_Data::lookup( 'wordpress', '6.8.1' )['status'] );
	}

	// -----------------------------------------------------------------------
	// Components check
	// -----------------------------------------------------------------------

	private function run_components_step( $step ) {
		$check = new ShieldScope_Check_Components( 'scan_t', $this->logger );
		$check->run_step( $step );
	}

	private function titles() {
		return array_column( $this->logger->findings, 'title' );
	}

	public function test_mysql_80_is_reported_end_of_life_with_its_date() {
		$GLOBALS['wpdb'] = new SS_EOL_Fake_WPDB( '8.0.43' );
		$this->run_components_step( 'database_version' );

		$high = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $high );
		$this->assertStringContainsString( 'MySQL', $high[0]['title'] );
		$this->assertStringContainsString( '30 April 2026', $high[0]['description'] );
		$this->assertCount( 1, $this->logger->findings );
	}

	public function test_mariadb_106_is_reported_end_of_life_with_its_date() {
		$GLOBALS['wpdb'] = new SS_EOL_Fake_WPDB( '10.6.23-MariaDB-log' );
		$this->run_components_step( 'database_version' );

		$high = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $high );
		$this->assertStringContainsString( 'MariaDB', $high[0]['title'] );
		$this->assertStringContainsString( '6 July 2026', $high[0]['description'] );
	}

	public function test_superseded_mariadb_short_term_release_is_reported_end_of_life() {
		$GLOBALS['wpdb'] = new SS_EOL_Fake_WPDB( '12.0.2-MariaDB' );
		$this->run_components_step( 'database_version' );

		$this->assertCount( 1, $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH ) );
	}

	public function test_supported_mariadb_is_info_and_quotes_its_end_date() {
		$GLOBALS['wpdb'] = new SS_EOL_Fake_WPDB( '10.11.14-MariaDB' );
		$this->run_components_step( 'database_version' );

		$info = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_INFO );
		$this->assertCount( 1, $info );
		$this->assertCount( 1, $this->logger->findings );
		$this->assertStringContainsString( '16 February 2028', $info[0]['description'] );
	}

	public function test_old_wordpress_cve_text_is_accurate() {
		$GLOBALS['wp_version'] = '4.6.1';
		$this->run_components_step( 'wp_vuln_ranges' );

		$critical = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_CRITICAL );
		$this->assertCount( 1, $critical );
		$this->assertStringNotContainsString( 'unauthenticated', $critical[0]['description'] );
		$this->assertStringContainsString( 'CVE-2017-1000600', $critical[0]['description'] );
		$this->assertStringContainsString( 'authenticated', $critical[0]['description'] );
		$this->assertStringContainsString( '31 July 2025', $critical[0]['description'] );
	}

	public function test_wordpress_4_10_is_not_compared_as_float() {
		// (float) '4.10' is 4.1, which the old code placed below 4.7.
		$GLOBALS['wp_version'] = '4.10';
		$this->run_components_step( 'wp_vuln_ranges' );

		$this->assertCount( 0, $this->logger->of_severity( ShieldScope_Logger::SEVERITY_CRITICAL ) );
		$this->assertCount( 1, $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH ) );
	}

	public function test_current_wordpress_gets_no_version_range_finding() {
		$GLOBALS['wp_version'] = '6.8.1';
		$this->run_components_step( 'wp_vuln_ranges' );

		$this->assertCount( 0, $this->logger->findings );
	}

	public function test_historical_cve_count_rule_is_removed() {
		ss_tests_override(
			'get_plugins',
			function () {
				return array(
					'woocommerce/woocommerce.php'           => array( 'Version' => '10.3.0' ),
					'contact-form-7/wp-contact-form-7.php' => array( 'Version' => '6.1' ),
				);
			}
		);
		$check = new ShieldScope_Check_Components( 'scan_t', $this->logger );
		$this->assertNotContains( 'high_risk_plugins', $check->get_steps() );
		foreach ( $check->get_steps() as $step ) {
			if ( 'database_version' === $step ) {
				continue;
			}
			$check->run_step( $step );
		}
		$check->run_step( 'high_risk_plugins' );

		foreach ( $this->titles() as $title ) {
			$this->assertStringNotContainsString( 'historical', $title );
		}
	}

	private function redirect_response( $code ) {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => array( 'location' => 'https://example.test/' ),
		);
	}

	public function test_308_redirect_is_not_reported_as_temporary() {
		ss_tests_override(
			'wp_remote_head',
			function () {
				return $this->redirect_response( 308 );
			}
		);
		$this->run_components_step( 'http_redirect' );

		$this->assertCount( 0, $this->logger->findings );
	}

	public function test_302_redirect_is_still_reported_as_temporary() {
		ss_tests_override(
			'wp_remote_head',
			function () {
				return $this->redirect_response( 302 );
			}
		);
		$this->run_components_step( 'http_redirect' );

		$low = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_LOW );
		$this->assertCount( 1, $low );
		$this->assertStringContainsString( '302', $low[0]['description'] );
	}


	// -----------------------------------------------------------------------
	// Security-config check
	// -----------------------------------------------------------------------

	public function test_php_version_finding_quotes_a_date_and_not_the_old_wrong_ones() {
		$check = new ShieldScope_Check_Security_Config( 'scan_t', $this->logger );
		$check->run_step( 'php_version' );

		$this->assertCount( 1, $this->logger->findings );
		$finding = $this->logger->findings[0];
		$text    = $finding['title'] . ' ' . $finding['description'];
		$this->assertStringContainsString( PHP_VERSION, $text );
		$this->assertStringNotContainsString( 'December 2025', $finding['title'] );
		$this->assertStringNotContainsString( 'December 2024', $finding['title'] );
		$this->assertMatchesRegularExpression( '/\d{1,2} [A-Z][a-z]+ \d{4}/', $text );

		if ( 8 === PHP_MAJOR_VERSION && 2 === PHP_MINOR_VERSION && time() <= strtotime( '2026-12-31 23:59:59 UTC' ) ) {
			$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $finding['severity'] );
		}
	}

	public function test_force_ssl_admin_is_not_reported_by_security_config() {
		// ShieldScope_Check_Core reports FORCE_SSL_ADMIN; this check must not duplicate it.
		$this->assertFalse( defined( 'FORCE_SSL_ADMIN' ) );
		$check = new ShieldScope_Check_Security_Config( 'scan_t', $this->logger );
		$check->run_step( 'cookie_security' );

		foreach ( $this->titles() as $title ) {
			$this->assertStringNotContainsString( 'FORCE_SSL_ADMIN', $title );
		}
	}
}
