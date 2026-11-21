<?php
/**
 * Tests for B-10 and S-20: closed and long-unmaintained plugins from WordPress.org.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S20_WPOrg_Plugin_Status
 */
class Test_S20_WPOrg_Plugin_Status extends TestCase {

	/** @var array slug => array( code, body ) */
	private $api = array();

	/** @var int */
	private $calls = 0;

	protected function setUp(): void {
		ss_tests_reset_state();
		$GLOBALS['ss_test_plugins'] = array(
			'closed-sec/closed-sec.php' => array( 'Name' => 'Closed Sec' ),
			'closed-req/closed-req.php' => array( 'Name' => 'Closed Req' ),
			'old/old.php'               => array( 'Name' => 'Old One' ),
			'fresh/fresh.php'           => array( 'Name' => 'Fresh' ),
			'custom/custom.php'         => array( 'Name' => 'Custom' ),
			'single.php'                => array( 'Name' => 'Single file' ),
		);
		// WordPress lists these as WordPress.org plugins (IM2-03).
		$GLOBALS['ss_test_site_transients']['update_plugins'] = (object) array( 'no_update' => array_fill_keys( array_keys( $GLOBALS['ss_test_plugins'] ), (object) array() ) );
		$this->api = array(
			'closed-sec' => array( 200, array( 'error' => 'closed', 'closed' => true, 'closed_date' => '2021-01-30', 'reason' => 'security-issue', 'reason_text' => 'Security Issue' ) ),
			'closed-req' => array( 200, array( 'error' => 'closed', 'closed' => true, 'closed_date' => '2024-05-01', 'reason' => 'author-request', 'reason_text' => 'Author Request' ) ),
			'old'        => array( 200, array( 'slug' => 'old', 'last_updated' => gmdate( 'Y-m-d g:ia', time() - 3 * YEAR_IN_SECONDS ) . ' GMT' ) ),
			'fresh'      => array( 200, array( 'slug' => 'fresh', 'last_updated' => gmdate( 'Y-m-d g:ia', time() - 30 * DAY_IN_SECONDS ) . ' GMT' ) ),
			'custom'     => array( 404, array( 'error' => 'Plugin not found.' ) ),
		);
		$this->calls = 0;
		$api         = &$this->api;
		$calls       = &$this->calls;
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( &$api, &$calls ) {
				++$calls;
				preg_match( '/request%5Bslug%5D=([^&]+)|request\[slug\]=([^&]+)/', $url, $m );
				$slug = urldecode( ! empty( $m[1] ) ? $m[1] : ( isset( $m[2] ) ? $m[2] : '' ) );
				if ( ! isset( $api[ $slug ] ) ) {
					return new WP_Error( 'http', 'down' );
				}
				return array( 'response' => array( 'code' => $api[ $slug ][0] ), 'body' => json_encode( $api[ $slug ][1] ) );
			}
		);
	}

	private function run_step() {
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Plugins( 's', $logger );
		$cursor = array();
		$notes  = array();
		do {
			$r      = $check->run_step( 'abandoned', $cursor );
			$cursor = $r['cursor'];
			$notes  = array_merge( $notes, $check->take_coverage_notes() );
		} while ( ! empty( $r['continue'] ) );
		return array( $logger->findings, $notes );
	}

	public function test_closed_old_and_unlisted_plugins() {
		list( $findings, $notes ) = $this->run_step();
		$by_title = array_column( $findings, 'severity', 'title' );
		$this->assertSame(
			array(
				'Plugin closed on WordPress.org: Closed Sec'                     => 'high',
				'Plugin closed on WordPress.org: Closed Req'                     => 'medium',
				'Plugin not updated on WordPress.org for over 2 years: Old One' => 'medium',
			),
			$by_title
		);
		$this->assertStringContainsString( '2021-01-30', $findings[0]['description'] );
		$this->assertStringContainsString( 'Security Issue', $findings[0]['description'] );
		$this->assertSame( array(), $notes );
		$this->assertSame( 5, $this->calls, 'Single-file plugins are not looked up.' );
	}

	public function test_results_are_cached() {
		$this->run_step();
		$this->run_step();
		$this->assertSame( 5, $this->calls );
	}

	public function test_failed_lookup_is_noted_and_cached_briefly() {
		unset( $this->api['fresh'] );
		list( , $notes ) = $this->run_step();
		$this->assertSame( array( '1 plugin(s) could not be looked up on WordPress.org' ), $notes );
		list( , $notes ) = $this->run_step();
		$this->assertSame( 5, $this->calls, 'SC2-03: a failed lookup is not repeated within 15 minutes.' );
		$this->assertSame( array( '1 plugin(s) could not be looked up on WordPress.org' ), $notes, 'It is still reported as not looked up.' );
	}

	public function test_no_file_dates_are_used() {
		$source = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'includes/checks/class-shieldscope-check-plugins.php' );
		$this->assertStringNotContainsString( 'filemtime', $source );
	}

	public function test_privacy_statement_mentions_plugin_slugs() {
		$this->assertStringContainsString( 'folder names of installed plugins', ShieldScope_Admin::privacy_statement() );
	}
}
