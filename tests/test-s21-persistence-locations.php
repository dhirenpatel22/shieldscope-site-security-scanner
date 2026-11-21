<?php
/**
 * Tests for S-21: WordPress root, wp-content root, drop-ins and must-use plugins.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S21_Persistence_Locations
 */
class Test_S21_Persistence_Locations extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		@mkdir( SHIELDSCOPE_WP_CONTENT_DIR . '/mu-plugins', 0777, true );
		set_transient(
			ShieldScope_Check_Core_Integrity::CHECKSUMS_TRANSIENT,
			array( 'version' => '7.1', 'locale' => 'en_US', 'checksums' => array( 'index.php' => 'x', 'wp-load.php' => 'y' ) )
		);
		foreach ( array( 'index.php', 'wp-load.php', 'wp-config.php', 'wordfence-waf.php' ) as $f ) {
			file_put_contents( ABSPATH . $f, "<?php\n" );
		}
		file_put_contents( ABSPATH . 'x1.php', "<?php\n\n@eval( base64_decode( 'ZWNobyAxOw==' ) );\n" );
		file_put_contents( SHIELDSCOPE_WP_CONTENT_DIR . '/index.php', "<?php\n" );
		file_put_contents( SHIELDSCOPE_WP_CONTENT_DIR . '/object-cache.php', "<?php\n" );
		file_put_contents( SHIELDSCOPE_WP_CONTENT_DIR . '/stray.php', "<?php\n" );
		file_put_contents( SHIELDSCOPE_WP_CONTENT_DIR . '/readme.txt', 'x' );
		file_put_contents( SHIELDSCOPE_WP_CONTENT_DIR . '/mu-plugins/host-helper.php', "<?php\n" );
	}

	private function run_step() {
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Core_Integrity( 's', $logger );
		$check->run_step( 'persistence' );
		return array( $logger, $check->take_coverage_notes() );
	}

	public function test_step_is_registered() {
		$this->assertContains( 'persistence', ( new ShieldScope_Check_Core_Integrity( 's', new SS_Fake_Logger() ) )->get_steps() );
	}

	public function test_locations_are_reported() {
		list( $logger, $notes ) = $this->run_step();
		$titles                  = array_column( $logger->findings, 'title' );
		sort( $titles );
		$this->assertSame(
			array(
				'Drop-in in use',
				'Matches pattern: eval() on encoded data',
				'Must-use plugin present',
				'Review: unknown PHP file in the WordPress root: wordfence-waf.php',
				'Review: unknown PHP file in the WordPress root: x1.php',
				'Review: unknown PHP file in wp-content: stray.php',
			),
			$titles
		);
		$this->assertSame( array(), $notes );
	}

	public function test_eval_finding_has_evidence_and_is_review() {
		list( $logger ) = $this->run_step();
		foreach ( $logger->findings as $f ) {
			if ( 'Matches pattern: eval() on encoded data' === $f['title'] ) {
				$this->assertSame( 'high', $f['severity'] );
				$this->assertSame( 3, $f['context']['evidence']['line'] );
				$this->assertSame( 'review', $f['context']['confidence'] );
				return;
			}
		}
		$this->fail( 'eval finding missing' );
	}

	public function test_without_checksums_root_is_noted_not_guessed() {
		delete_transient( ShieldScope_Check_Core_Integrity::CHECKSUMS_TRANSIENT );
		list( $logger, $notes ) = $this->run_step();
		$this->assertSame( array( 'WordPress root not checked for unknown PHP files: core checksums unavailable' ), $notes );
		foreach ( array_column( $logger->findings, 'title' ) as $t ) {
			$this->assertStringNotContainsString( 'WordPress root:', $t );
		}
	}
}
