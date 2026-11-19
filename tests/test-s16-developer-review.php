<?php
/**
 * Tests for S-16: injection and SSRF code scans are off by default.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S16_Developer_Review
 */
class Test_S16_Developer_Review extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR . '/p', 0777, true );
		file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . '/p/main.php', "<?php\n\$d = unserialize( \$_POST['d'] );\nwp_remote_get( \$_GET['u'] );\n" );
	}

	private function scan( $class ) {
		$logger = new SS_Fake_Logger();
		$check  = new $class( 's', $logger );
		$notes  = array();
		foreach ( array( 'scan_plugins' ) as $step ) {
			$cursor = array();
			do {
				$r      = $check->run_step( $step, $cursor );
				$cursor = $r['cursor'];
				$notes  = array_merge( $notes, $check->take_coverage_notes() );
			} while ( ! empty( $r['continue'] ) );
		}
		return array( $logger->findings, $notes );
	}

	public function test_off_by_default_no_code_findings_and_one_note() {
		foreach ( array( 'ShieldScope_Check_Injection', 'ShieldScope_Check_SSRF' ) as $class ) {
			list( $findings, $notes ) = $this->scan( $class );
			$this->assertSame( array(), $findings, $class );
			$this->assertSame( array( 'plugin and theme code not scanned: Developer review is off in Settings' ), $notes, $class );
		}
	}

	public function test_on_scans_code() {
		update_option( 'shieldscope_settings', array( 'developer_review' => 1 ) );
		list( $findings ) = $this->scan( 'ShieldScope_Check_Injection' );
		$this->assertContains( 'PHP Object Injection: deserialization of direct user input', array_column( $findings, 'title' ) );
		list( $findings ) = $this->scan( 'ShieldScope_Check_SSRF' );
		$this->assertNotEmpty( $findings );
	}

	public function test_other_steps_still_run_when_off() {
		update_option( 'default_ping_status', 'open' );
		$logger = new SS_Fake_Logger();
		( new ShieldScope_Check_SSRF( 's', $logger ) )->run_step( 'wp_features' );
		$this->assertContains( 'Pingbacks are allowed on new posts', array_column( $logger->findings, 'title' ) );
	}

	public function test_settings_page_has_the_option_and_it_defaults_off() {
		$view = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'admin/views/settings.php' );
		$this->assertStringContainsString( 'shieldscope_settings[developer_review]', $view );
		$this->assertFalse( ShieldScope_Check_Base::developer_review_enabled() );
	}
}
