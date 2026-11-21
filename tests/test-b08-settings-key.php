<?php
/**
 * Tests for B-08: the WPScan key is never printed and can be removed.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_B08_Settings_Key
 */
class Test_B08_Settings_Key extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		$_POST = array();
	}

	protected function tearDown(): void {
		$_POST = array();
	}

	private function save( array $settings ) {
		$_POST['shieldscope_settings_submit'] = '1';
		$_POST['_wpnonce']                    = 'test-nonce';
		$_POST['shieldscope_settings']        = $settings;
		$method = new ReflectionMethod( ShieldScope_Admin::class, 'maybe_save_settings' );
		$method->setAccessible( true );
		$method->invoke( new ShieldScope_Admin() );
	}

	private function render( array $settings ) {
		ob_start();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/settings.php';
		return ob_get_clean();
	}

	public function test_saved_key_is_not_printed() {
		$html = $this->render( array( 'cpu_limit' => 20, 'chunk_time_limit' => 2, 'max_scan_file_size' => 2097152, 'pause_on_blur' => 0, 'wpscan_api_key' => 'SECRETKEY1234wxyz' ) );
		$this->assertStringNotContainsString( 'SECRETKEY1234', $html );
		$this->assertStringContainsString( '…wxyz', $html );
		$this->assertStringContainsString( 'wpscan_api_key_remove', $html );
	}

	public function test_no_remove_option_without_a_key() {
		$html = $this->render( array( 'cpu_limit' => 20, 'chunk_time_limit' => 2, 'max_scan_file_size' => 2097152, 'pause_on_blur' => 0 ) );
		$this->assertStringNotContainsString( 'wpscan_api_key_remove', $html );
	}

	public function test_remove_clears_the_key() {
		update_option( 'shieldscope_settings', array( 'wpscan_api_key' => 'OLDKEY' ) );
		$this->save( array( 'wpscan_api_key' => '', 'wpscan_api_key_remove' => '1' ) );
		$saved = get_option( 'shieldscope_settings' );
		$this->assertSame( '', $saved['wpscan_api_key'] );
	}

	public function test_key_tail() {
		$this->assertSame( '…wxyz', ShieldScope_Admin::key_tail( 'abcdwxyz' ) );
		$this->assertSame( '…', ShieldScope_Admin::key_tail( 'abc' ) );
	}
}
