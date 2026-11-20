<?php
/**
 * Tests for S-11: quick scan.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S11_Quick_Scan
 */
class Test_S11_Quick_Scan extends TestCase {

	public function test_slow_steps_are_real_steps() {
		$found = 0;
		foreach ( ( new ShieldScope_Scanner() )->get_check_classes() as $class ) {
			$check = new $class( '', new SS_Fake_Logger() );
			$extra = array_diff( $check->get_slow_steps(), $check->get_steps() );
			$this->assertSame( array(), array_values( $extra ), $class );
			$found += count( $check->get_slow_steps() );
		}
		$this->assertGreaterThanOrEqual( 10, $found );
	}

	public function test_scan_page_has_quick_button_and_help() {
		$view = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'admin/views/scan.php' );
		$this->assertStringContainsString( 'id="shieldscope-btn-quick"', $view );
		$this->assertStringContainsString( 'aria-describedby="shieldscope-quick-help"', $view );
	}
}
