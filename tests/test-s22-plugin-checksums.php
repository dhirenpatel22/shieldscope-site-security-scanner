<?php
/**
 * Tests for S-22: plugin files against WordPress.org checksums.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S22_Plugin_Checksums
 */
class Test_S22_Plugin_Checksums extends TestCase {

	/** @var array url-substring => response */
	private $responses = array();

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$dir = SHIELDSCOPE_WP_PLUGINS_DIR . '/good';
		mkdir( "$dir/inc", 0777, true );
		file_put_contents( "$dir/good.php", "<?php // main\n" );
		file_put_contents( "$dir/inc/a.php", "<?php // changed\n" );
		file_put_contents( "$dir/readme.txt", 'readme' );
		file_put_contents( "$dir/inc/shell.php", "<?php // not in release\n" );
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR . '/premium', 0777, true );
		$GLOBALS['ss_test_plugins'] = array(
			'good/good.php'       => array( 'Name' => 'Good', 'Version' => '1.0' ),
			'premium/premium.php' => array( 'Name' => 'Premium', 'Version' => '2.0' ),
		);
		$sum = function ( $text ) {
			return array( 'md5' => md5( $text ), 'sha256' => hash( 'sha256', $text ) );
		};
		// WordPress lists these as WordPress.org plugins (IM2-03).
		$GLOBALS['ss_test_site_transients']['update_plugins'] = (object) array( 'no_update' => array_fill_keys( array_keys( $GLOBALS['ss_test_plugins'] ), (object) array() ) );
		$this->responses = array(
			'request%5Bslug%5D=good'    => array( 200, array( 'slug' => 'good', 'last_updated' => gmdate( 'Y-m-d' ) . ' 1:00am GMT' ) ),
			'request%5Bslug%5D=premium' => array( 404, array( 'error' => 'Plugin not found.' ) ),
			'plugin-checksums/good/1.0' => array(
				200,
				array(
					'files' => array(
						'good.php'   => $sum( "<?php // main\n" ),
						'inc/a.php'  => $sum( "<?php // original\n" ),
						'readme.txt' => array( 'md5' => array( 'x', md5( 'readme' ) ), 'sha256' => array( 'y', hash( 'sha256', 'readme' ) ) ),
						'gone.php'   => $sum( 'gone' ),
					),
				),
			),
		);
		$responses = &$this->responses;
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( &$responses ) {
				foreach ( $responses as $needle => $r ) {
					if ( false !== strpos( $url, $needle ) ) {
						return array( 'response' => array( 'code' => $r[0] ), 'body' => json_encode( $r[1] ) );
					}
				}
				return new WP_Error( 'http', 'unexpected ' . $url );
			}
		);
	}

	private function run_step() {
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Plugins( 's', $logger );
		$cursor = array();
		$notes  = array();
		do {
			$r      = $check->run_step( 'checksums', $cursor );
			$cursor = $r['cursor'];
			$notes  = array_merge( $notes, $check->take_coverage_notes() );
		} while ( ! empty( $r['continue'] ) );
		return array( $logger->findings, $notes );
	}

	public function test_modified_and_unexpected_files() {
		list( $findings, $notes ) = $this->run_step();
		$got = array();
		foreach ( $findings as $f ) {
			$got[] = $f['severity'] . ' ' . $f['title'] . ' ' . basename( $f['target'] );
		}
		sort( $got );
		$this->assertSame(
			array(
				'high Plugin file differs from the WordPress.org release: Good a.php',
				'medium Review: PHP file not in the WordPress.org release: Good shell.php',
			),
			$got
		);
		$this->assertSame( array( '1 plugin(s) not verified against WordPress.org checksums (not listed there, or no checksums for the installed version)' ), $notes );
	}

	public function test_many_differences_are_reported_once() {
		$files = array();
		for ( $i = 0; $i < 40; $i++ ) {
			file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . "/good/f$i.php", "<?php // local $i\n" );
			$files[ "f$i.php" ] = array( 'sha256' => hash( 'sha256', "official $i" ) );
		}
		$this->responses['plugin-checksums/good/1.0'] = array( 200, array( 'files' => $files ) );
		list( $findings ) = $this->run_step();
		$titles = array_column( $findings, 'title' );
		$this->assertContains( 'Most files of Good differ from WordPress.org', $titles );
		$this->assertNotContains( 'Plugin file differs from the WordPress.org release: Good', $titles );
	}

	public function test_no_checksums_for_version_is_unverified() {
		$this->responses['plugin-checksums/good/1.0'] = array( 404, array() );
		list( $findings, $notes ) = $this->run_step();
		$this->assertSame( array(), $findings );
		$this->assertStringStartsWith( '2 plugin(s) not verified', $notes[0] );
	}

	public function test_many_unexpected_php_files_are_reported_once() {
		for ( $i = 0; $i < 15; $i++ ) {
			file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . "/good/inc/extra$i.php", "<?php\n" );
		}
		list( $findings ) = $this->run_step();
		$titles = array_column( $findings, 'title' );
		$this->assertContains( 'Review: many PHP files not in the WordPress.org release: Good', $titles );
		$this->assertNotContains( 'Review: PHP file not in the WordPress.org release: Good', $titles );
	}

	public function test_own_folder_is_skipped() {
		$self = basename( rtrim( SHIELDSCOPE_PLUGIN_DIR, '/' ) );
		$GLOBALS['ss_test_plugins'] = array( "$self/x.php" => array( 'Name' => 'Self', 'Version' => '1.0' ) );
		list( $findings, $notes ) = $this->run_step();
		$this->assertSame( array(), $findings );
		$this->assertSame( array(), $notes );
	}

	public function test_privacy_statement_names_downloads_host() {
		$this->assertStringContainsString( 'downloads.wordpress.org', ShieldScope_Admin::privacy_statement() );
	}
}
