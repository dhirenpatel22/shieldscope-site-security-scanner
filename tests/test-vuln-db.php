<?php
/**
 * Tests for ShieldScope_Check_Vuln_DB (ticket A-04).
 *
 * Regressions covered:
 *  - The built-in list cited CVEs for other products (e.g. a WooCommerce
 *    Payments CVE flagged every WooCommerce store below 7.8.2 as Critical).
 *  - Any non-200 WPScan response was cached as "no vulnerabilities" and
 *    nothing was reported, so a quota hit or a bad key looked like a clean scan.
 *  - A vulnerability with no CVSS score was reported as High.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Vuln_DB
 */
class Test_Vuln_DB extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var string[] URLs requested from WPScan. */
	private $requests = array();

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->logger                      = new SS_Fake_Logger();
		$this->requests                    = array();
	}

	// ---------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------

	/**
	 * Install plugins; all are listed in the WP.org update transient unless $not_on_org.
	 */
	private function install( array $plugins, array $not_on_org = array() ) {
		$no_update = array();
		foreach ( $plugins as $file => $version ) {
			$slug                                   = explode( '/', $file )[0];
			$GLOBALS['ss_test_plugins'][ $file ]     = array( 'Name' => ucfirst( $slug ), 'Version' => $version );
			if ( ! in_array( $file, $not_on_org, true ) ) {
				$no_update[ $file ] = (object) array( 'slug' => $slug );
			}
		}
		$GLOBALS['ss_test_site_transients']['update_plugins'] = (object) array(
			'response'  => array(),
			'no_update' => $no_update,
		);
	}

	private function set_key() {
		update_option( 'shieldscope_settings', array( 'wpscan_api_key' => 'test-key' ) );
	}

	/**
	 * Mock WPScan: $responder( $slug ) returns array( code, body ) or a WP_Error.
	 */
	private function mock_wpscan( callable $responder ) {
		$test = $this;
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( $responder, $test ) {
				$test->record_request( $url );
				$slug   = rawurldecode( substr( $url, strrpos( $url, '/' ) + 1 ) );
				$result = $responder( $slug );
				if ( $result instanceof WP_Error ) {
					return $result;
				}
				return array(
					'response' => array( 'code' => $result[0] ),
					'body'     => $result[1],
				);
			}
		);
	}

	public function record_request( $url ) {
		$this->requests[] = $url;
	}

	private static function vuln_body( $slug, array $vulns ) {
		return json_encode( array( $slug => array( 'vulnerabilities' => $vulns ) ) );
	}

	/**
	 * Run the check to completion; return the number of run_step calls.
	 */
	private function run_check() {
		$check  = new ShieldScope_Check_Vuln_DB( 'scan1', $this->logger );
		$calls  = 0;
		foreach ( $check->get_steps() as $step ) {
			$cursor = array();
			do {
				$result = $check->run_step( $step, $cursor );
				$cursor = $result['cursor'];
				$calls++;
				$this->assertLessThan( 100, $calls, 'Check did not terminate.' );
			} while ( ! empty( $result['continue'] ) );
		}
		return $calls;
	}

	private function findings_matching( $needle ) {
		return array_values(
			array_filter(
				$this->logger->findings,
				static function ( $f ) use ( $needle ) {
					return false !== strpos( $f['title'], $needle );
				}
			)
		);
	}

	// ---------------------------------------------------------------------
	// Built-in list contents
	// ---------------------------------------------------------------------

	public function test_built_in_list_contains_only_verified_entries() {
		$expected = array(
			'contact-form-7'                      => array( array( 'CVE-2020-35489', '5.3.2', 'critical' ) ),
			'duplicator'                          => array( array( 'CVE-2020-11738', '1.3.28', 'high' ) ),
			'wp-file-manager'                     => array( array( 'CVE-2020-25213', '6.9', 'critical' ) ),
			'wp-gdpr-compliance'                  => array( array( 'CVE-2018-19207', '1.4.3', 'critical' ) ),
			'wp-fastest-cache'                    => array( array( 'CVE-2023-6063', '1.2.2', 'high' ) ),
			'essential-addons-for-elementor-lite' => array( array( 'CVE-2023-32243', '5.7.2', 'critical' ) ),
			'advanced-custom-fields'              => array( array( 'CVE-2023-30777', '6.1.6', 'medium' ) ),
			'advanced-custom-fields-pro'          => array( array( 'CVE-2023-30777', '6.1.6', 'medium' ) ),
			'elementor'                           => array( array( 'CVE-2022-29455', '3.5.6', 'medium' ) ),
			'jetpack'                             => array( array( 'CVE-2023-2996', '12.1.1', 'high' ) ),
			'wp-statistics'                       => array( array( 'CVE-2022-25148', '13.1.6', 'high' ) ),
		);

		$actual = array();
		foreach ( ShieldScope_Check_Vuln_DB::get_built_in_vuln_db() as $slug => $entries ) {
			foreach ( $entries as $entry ) {
				$actual[ $slug ][] = array( $entry['cve'], $entry['fixed_in'], $entry['severity'] );
			}
		}
		ksort( $expected );
		ksort( $actual );
		$this->assertSame( $expected, $actual );
	}

	public function test_built_in_plugin_count_is_exposed() {
		$this->assertSame( 11, ShieldScope_Check_Vuln_DB::built_in_plugin_count() );
	}

	public function test_woocommerce_is_no_longer_flagged_with_a_woocommerce_payments_cve() {
		$this->install( array( 'woocommerce/woocommerce.php' => '7.0.0' ) );
		$this->run_check();
		$this->assertCount( 0, $this->logger->of_severity( ShieldScope_Logger::SEVERITY_CRITICAL ) );
		$this->assertCount( 0, $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH ) );
	}

	public function test_built_in_match_cites_nvd_link_and_corrected_type() {
		$this->install( array( 'elementor/elementor.php' => '3.5.5' ) );
		$this->run_check();
		$hits = $this->findings_matching( 'CVE-2022-29455' );
		$this->assertCount( 1, $hits );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $hits[0]['severity'] );
		$this->assertStringContainsString( 'Cross-Site Scripting', $hits[0]['title'] );
		$this->assertStringContainsString( 'https://nvd.nist.gov/vuln/detail/CVE-2022-29455', $hits[0]['description'] );
		$this->assertStringContainsString( 'limited built-in list (11 plugins, last reviewed 2026-11-14)', $hits[0]['description'] );
	}

	public function test_fixed_version_is_not_flagged() {
		$this->install( array( 'elementor/elementor.php' => '3.5.6' ) );
		$this->run_check();
		$this->assertCount( 0, $this->findings_matching( 'CVE-' ) );
	}

	public function test_versions_before_the_affected_range_are_not_flagged() {
		$this->install( array( 'essential-addons-for-elementor-lite/essential_adons_elementor.php' => '5.3.9' ) );
		$this->run_check();
		$this->assertCount( 0, $this->findings_matching( 'CVE-2023-32243' ) );

		$this->setUp();
		$this->install( array( 'essential-addons-for-elementor-lite/essential_adons_elementor.php' => '5.7.1' ) );
		$this->run_check();
		$this->assertCount( 1, $this->findings_matching( 'CVE-2023-32243' ) );
	}

	// ---------------------------------------------------------------------
	// Honest coverage wording
	// ---------------------------------------------------------------------

	public function test_clean_result_states_limited_coverage_and_never_claims_no_vulnerabilities() {
		$this->install( array( 'hello/hello.php' => '1.0' ) );
		$this->run_check();

		$info = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_INFO );
		$this->assertCount( 1, $info );
		$this->assertStringContainsString( 'limited built-in list (11 plugins, last reviewed 2026-11-14)', $info[0]['title'] );

		foreach ( $this->logger->findings as $f ) {
			$text = strtolower( $f['title'] . ' ' . $f['description'] . ' ' . $f['recommendation'] );
			$this->assertStringNotContainsString( 'no known vulnerabilities', $text );
		}
	}

	public function test_one_plugin_per_cursor_step() {
		$this->install(
			array(
				'a/a.php' => '1.0',
				'b/b.php' => '1.0',
				'c/c.php' => '1.0',
			)
		);
		$this->assertSame( 3, $this->run_check() );
	}

	// ---------------------------------------------------------------------
	// WPScan HTTP status handling
	// ---------------------------------------------------------------------

	public function test_status_200_reports_vulnerability() {
		$this->set_key();
		$this->install( array( 'acme/acme.php' => '1.0' ) );
		$this->mock_wpscan(
			function ( $slug ) {
				return array(
					200,
					self::vuln_body(
						$slug,
						array(
							array(
								'title'      => 'Acme < 1.1 - SQLi',
								'fixed_in'   => '1.1',
								'references' => array( 'cve' => array( '2099-0001' ) ),
								'cvss'       => array( 'score' => 9.8 ),
							),
						)
					),
				);
			}
		);
		$this->run_check();

		$this->assertCount( 1, $this->requests );
		$hits = $this->findings_matching( 'CVE-2099-0001' );
		$this->assertCount( 1, $hits );
		$this->assertSame( ShieldScope_Logger::SEVERITY_CRITICAL, $hits[0]['severity'] );
		$this->assertCount( 0, $this->findings_matching( 'incomplete' ) );
	}

	public function test_status_404_counts_as_checked() {
		$this->set_key();
		$this->install( array( 'acme/acme.php' => '1.0' ) );
		$this->mock_wpscan(
			function () {
				return array( 404, '{"error":"Not found"}' );
			}
		);
		$this->run_check();
		$this->assertCount( 1, $this->requests );
		$this->assertCount( 0, $this->findings_matching( 'incomplete' ) );
	}

	public function test_status_401_stops_lookups_and_reports_incomplete() {
		$this->set_key();
		$this->install( array( 'a/a.php' => '1.0', 'b/b.php' => '1.0' ) );
		$this->mock_wpscan(
			function () {
				return array( 401, '{"status":"error"}' );
			}
		);
		$this->run_check();

		$this->assertCount( 1, $this->requests, 'A rejected key must not be retried for every plugin.' );
		$hits = $this->findings_matching( 'Vulnerability lookup incomplete' );
		$this->assertCount( 1, $hits );
		$this->assertSame( 'Vulnerability lookup incomplete: 0 of 2 components checked (WPScan rejected the API key, HTTP 401)', $hits[0]['title'] );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $hits[0]['severity'] );
		$this->assertFalse( get_transient( 'shieldscope_wpscan_' . md5( 'pluginsa' ) ), 'A failure must not be cached.' );
	}

	public function test_status_429_stops_lookups_and_reports_quota() {
		$this->set_key();
		$this->install( array( 'a/a.php' => '1.0', 'b/b.php' => '1.0', 'c/c.php' => '1.0' ) );
		$this->mock_wpscan(
			function ( $slug ) {
				return 'a' === $slug ? array( 200, self::vuln_body( $slug, array() ) ) : array( 429, '' );
			}
		);
		$this->run_check();

		$this->assertCount( 2, $this->requests );
		$hits = $this->findings_matching( 'Vulnerability lookup incomplete' );
		$this->assertCount( 1, $hits );
		$this->assertSame( 'Vulnerability lookup incomplete: 1 of 3 components checked (WPScan daily request limit reached, HTTP 429)', $hits[0]['title'] );
	}

	public function test_status_5xx_reports_incomplete_without_caching() {
		$this->set_key();
		$this->install( array( 'a/a.php' => '1.0', 'b/b.php' => '1.0' ) );
		$this->mock_wpscan(
			function ( $slug ) {
				return 'a' === $slug ? array( 503, 'Service Unavailable' ) : array( 200, self::vuln_body( $slug, array() ) );
			}
		);
		$this->run_check();

		$this->assertCount( 2, $this->requests, 'A server error on one plugin must not stop the others.' );
		$hits = $this->findings_matching( 'Vulnerability lookup incomplete' );
		$this->assertCount( 1, $hits );
		$this->assertSame( 'Vulnerability lookup incomplete: 1 of 2 components checked (WPScan error, HTTP 503)', $hits[0]['title'] );

		// Next scan retries the failed plugin instead of trusting a cached empty result.
		$this->requests = array();
		$this->logger   = new SS_Fake_Logger();
		$this->run_check();
		$this->assertCount( 1, $this->requests );
		$this->assertStringEndsWith( '/plugins/a', $this->requests[0] );
	}

	public function test_connection_error_reports_incomplete() {
		$this->set_key();
		$this->install( array( 'a/a.php' => '1.0' ) );
		$this->mock_wpscan(
			function () {
				return new WP_Error( 'http_request_failed', 'cURL error 28: timed out' );
			}
		);
		$this->run_check();
		$hits = $this->findings_matching( 'Vulnerability lookup incomplete' );
		$this->assertCount( 1, $hits );
		$this->assertSame( 'Vulnerability lookup incomplete: 0 of 1 components checked (could not connect to WPScan)', $hits[0]['title'] );
	}

	public function test_invalid_json_on_200_reports_incomplete() {
		$this->set_key();
		$this->install( array( 'a/a.php' => '1.0' ) );
		$this->mock_wpscan(
			function () {
				return array( 200, '<html>not json</html>' );
			}
		);
		$this->run_check();
		$this->assertCount( 1, $this->findings_matching( 'Vulnerability lookup incomplete: 0 of 1' ) );
	}

	// ---------------------------------------------------------------------
	// Quota counter and slug eligibility
	// ---------------------------------------------------------------------

	public function test_daily_counter_stops_at_free_quota() {
		$this->set_key();
		set_transient( 'shieldscope_wpscan_requests_' . gmdate( 'Ymd' ), 24, DAY_IN_SECONDS );
		$this->install( array( 'a/a.php' => '1.0', 'b/b.php' => '1.0', 'c/c.php' => '1.0' ) );
		$this->mock_wpscan(
			function ( $slug ) {
				return array( 200, self::vuln_body( $slug, array() ) );
			}
		);
		$this->run_check();

		$this->assertCount( 1, $this->requests );
		$this->assertSame( 25, get_transient( 'shieldscope_wpscan_requests_' . gmdate( 'Ymd' ) ) );
		$this->assertSame(
			array( 'Vulnerability lookup incomplete: 1 of 3 components checked (WPScan daily request limit reached)' ),
			$this->titles_matching( 'incomplete' )
		);
	}

	public function test_cached_responses_do_not_use_quota() {
		$this->set_key();
		set_transient( 'shieldscope_wpscan_requests_' . gmdate( 'Ymd' ), 25, DAY_IN_SECONDS );
		set_transient( 'shieldscope_wpscan_' . md5( 'pluginsa' ), array( 'a' => array( 'vulnerabilities' => array() ) ), DAY_IN_SECONDS );
		$this->install( array( 'a/a.php' => '1.0' ) );
		$this->mock_wpscan(
			function () {
				return array( 500, '' );
			}
		);
		$this->run_check();
		$this->assertCount( 0, $this->requests );
		$this->assertCount( 0, $this->findings_matching( 'incomplete' ) );
	}

	public function test_plugins_not_on_wordpress_org_are_not_looked_up() {
		$this->set_key();
		$this->install( array( 'a/a.php' => '1.0', 'premium/premium.php' => '1.0' ), array( 'premium/premium.php' ) );
		$this->mock_wpscan(
			function ( $slug ) {
				return array( 200, self::vuln_body( $slug, array() ) );
			}
		);
		$this->run_check();
		$this->assertCount( 1, $this->requests );
		$this->assertStringEndsWith( '/plugins/a', $this->requests[0] );
	}

	public function test_active_theme_is_looked_up_when_on_wordpress_org() {
		$this->set_key();
		$GLOBALS['ss_test_theme']                            = new SS_Test_Theme( 'twentytwenty', array( 'Name' => 'Twenty Twenty', 'Version' => '1.0' ) );
		$GLOBALS['ss_test_site_transients']['update_themes'] = (object) array(
			'response'  => array(),
			'no_update' => array( 'twentytwenty' => array( 'theme' => 'twentytwenty' ) ),
		);
		$this->mock_wpscan(
			function ( $slug ) {
				return array( 200, self::vuln_body( $slug, array() ) );
			}
		);
		$this->run_check();
		$this->assertCount( 1, $this->requests );
		$this->assertStringEndsWith( '/themes/twentytwenty', $this->requests[0] );
	}

	// ---------------------------------------------------------------------
	// CVSS
	// ---------------------------------------------------------------------

	public function test_unknown_cvss_is_unrated_medium_not_high() {
		$this->set_key();
		$this->install( array( 'acme/acme.php' => '1.0' ) );
		$this->mock_wpscan(
			function ( $slug ) {
				return array(
					200,
					self::vuln_body( $slug, array( array( 'title' => 'Acme - CSRF', 'fixed_in' => '1.1' ) ) ),
				);
			}
		);
		$this->run_check();
		$hits = $this->findings_matching( 'Acme - CSRF' );
		$this->assertCount( 1, $hits );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $hits[0]['severity'] );
		$this->assertStringContainsString( 'Unrated', $hits[0]['description'] );
	}

	private function titles_matching( $needle ) {
		return array_map(
			static function ( $f ) {
				return $f['title'];
			},
			$this->findings_matching( $needle )
		);
	}
}
