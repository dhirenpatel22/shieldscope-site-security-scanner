<?php
/**
 * Review 2 fixes: IM2-01 (CSV breakout) and IM2-06 (privacy: user-agent, oEmbed target).
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_R2_CSV_Privacy
 */
class Test_R2_CSV_Privacy extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	public function test_backslash_quote_cannot_break_out_of_a_cell() {
		$payload = '<script>x\\",=SUM(1+1),</script>';
		$report  = array(
			'site_url' => 'https://s.example/', 'scan_id' => 's', 'scan_date' => '', 'generated' => '', 'version' => SHIELDSCOPE_VERSION,
			'save_failed' => false, 'check_labels' => array(), 'root' => '/w/',
			'findings' => array(
				array(
					'severity' => 'low', 'check_id' => 'database', 'title' => 'T', 'target' => 'post:1', 'description' => '', 'recommendation' => '',
					'context'  => wp_json_encode( array( 'evidence' => array( 'line' => 1, 'snippet' => $payload ) ) ),
				),
			),
		);
		$lines = explode( "\n", trim( substr( ShieldScope_Export::to_csv( $report ), 3 ) ) );
		$row   = str_getcsv( $lines[1], ',', '"', '' );
		$this->assertCount( 10, $row, 'The payload must stay inside one cell.' );
		$this->assertSame( $payload, $row[6] );
		foreach ( $row as $cell ) {
			$this->assertNotSame( '=SUM(1+1)', $cell );
		}
	}

	public function test_leading_whitespace_does_not_hide_a_formula() {
		$this->assertSame( "' =1+1", ShieldScope_Export::csv_cell( ' =1+1' ) );
		$this->assertSame( "'\n@x", ShieldScope_Export::csv_cell( "\n@x" ) );
	}

	public function test_wordpress_org_requests_send_shieldscope_user_agent() {
		$seen = array();
		ss_tests_override(
			'wp_remote_get',
			function ( $url, $args ) use ( &$seen ) {
				$seen[] = array( $url, isset( $args['user-agent'] ) ? $args['user-agent'] : '' );
				return new WP_Error( 'http', 'offline' );
			}
		);
		$GLOBALS['ss_test_plugins'] = array( 'p/p.php' => array( 'Name' => 'P', 'Version' => '1.0' ) );
		$logger = new SS_Fake_Logger();
		( new ShieldScope_Check_Plugins( 's', $logger ) )->run_step( 'abandoned' );
		( new ShieldScope_Check_Core_Integrity( 's', $logger ) )->run_step( 'fetch' );
		$this->assertNotEmpty( $seen );
		foreach ( $seen as $call ) {
			$this->assertSame( 'ShieldScope/' . SHIELDSCOPE_VERSION, $call[1], $call[0] );
		}
	}

	public function test_oembed_probe_asks_for_the_own_site_and_detects_open_proxy_by_404() {
		$asked = '';
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( &$asked ) {
				$asked = $url;
				return array( 'response' => array( 'code' => 404 ), 'body' => '{"code":"oembed_invalid_url"}' );
			}
		);
		$logger = new SS_Fake_Logger();
		( new ShieldScope_Check_SSRF( 's', $logger ) )->run_step( 'wp_features' );
		$this->assertStringNotContainsString( 'example.com%2F%22', $asked );
		$this->assertStringContainsString( rawurlencode( rawurlencode( home_url( '/' ) ) ), $asked );
		$this->assertContains( 'oEmbed proxy answered a logged-out request', array_column( $logger->findings, 'title' ) );

		ss_tests_override(
			'wp_remote_get',
			function () {
				return array( 'response' => array( 'code' => 401 ), 'body' => '{"code":"rest_forbidden"}' );
			}
		);
		$logger = new SS_Fake_Logger();
		( new ShieldScope_Check_SSRF( 's', $logger ) )->run_step( 'wp_features' );
		$this->assertNotContains( 'oEmbed proxy answered a logged-out request', array_column( $logger->findings, 'title' ) );
	}
}
