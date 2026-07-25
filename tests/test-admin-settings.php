<?php
/**
 * Tests for ShieldScope_Admin::maybe_save_settings() input clamping.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Admin_Settings
 */
class Test_Admin_Settings extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		$_POST = array();
	}

	protected function tearDown(): void {
		$_POST = array();
	}

	/**
	 * Invoke the private maybe_save_settings() with a simulated POST.
	 *
	 * @param array $settings Posted shieldscope_settings array.
	 */
	private function save( array $settings ) {
		$_POST['shieldscope_settings_submit'] = '1';
		$_POST['_wpnonce']                    = 'test-nonce';
		$_POST['shieldscope_settings']        = $settings;

		$admin  = new ShieldScope_Admin();
		$method = new ReflectionMethod( ShieldScope_Admin::class, 'maybe_save_settings' );
		$method->setAccessible( true );
		$method->invoke( $admin );

		return get_option( 'shieldscope_settings' );
	}

	public function test_values_within_range_are_saved_as_is() {
		$saved = $this->save(
			array(
				'cpu_limit'             => 30,
				'chunk_time_limit'      => 3,
				'max_scan_file_size_mb' => 5,
				'pause_on_blur'         => '1',
			)
		);

		$this->assertSame( 30, $saved['cpu_limit'] );
		$this->assertSame( 3, $saved['chunk_time_limit'] );
		$this->assertSame( 5 * MB_IN_BYTES, $saved['max_scan_file_size'] );
		$this->assertSame( 1, $saved['pause_on_blur'] );
	}

	public function test_out_of_range_values_are_clamped() {
		$saved = $this->save(
			array(
				'cpu_limit'             => 999,
				'chunk_time_limit'      => 99,
				'max_scan_file_size_mb' => 500,
			)
		);

		$this->assertSame( 80, $saved['cpu_limit'], 'CPU limit must be clamped to 80%.' );
		$this->assertSame( 10, $saved['chunk_time_limit'], 'Chunk time must be clamped to 10s.' );
		$this->assertSame( 20 * MB_IN_BYTES, $saved['max_scan_file_size'], 'File size must be clamped to 20 MB.' );
	}

	public function test_lower_bounds_are_enforced() {
		$saved = $this->save(
			array(
				'cpu_limit'             => 0,
				'chunk_time_limit'      => 0,
				'max_scan_file_size_mb' => 0,
			)
		);

		$this->assertSame( 5, $saved['cpu_limit'] );
		$this->assertSame( 1, $saved['chunk_time_limit'] );
		$this->assertSame( 1 * MB_IN_BYTES, $saved['max_scan_file_size'] );
	}

	public function test_blank_wpscan_key_preserves_existing_value() {
		update_option( 'shieldscope_settings', array( 'wpscan_api_key' => 'existing-secret' ) );

		$saved = $this->save( array( 'wpscan_api_key' => '' ) );

		$this->assertSame( 'existing-secret', $saved['wpscan_api_key'], 'A blank field must not wipe the stored key.' );
	}

	public function test_new_wpscan_key_replaces_existing_value() {
		update_option( 'shieldscope_settings', array( 'wpscan_api_key' => 'old' ) );
		$saved = $this->save( array( 'wpscan_api_key' => 'brand-new-key' ) );
		$this->assertSame( 'brand-new-key', $saved['wpscan_api_key'] );
	}

	public function test_pause_on_blur_unchecked_saves_zero() {
		$saved = $this->save( array( 'cpu_limit' => 20 ) );
		$this->assertSame( 0, $saved['pause_on_blur'] );
	}

	public function test_nothing_is_saved_without_the_submit_marker() {
		$_POST = array( 'shieldscope_settings' => array( 'cpu_limit' => 50 ) );

		$admin  = new ShieldScope_Admin();
		$method = new ReflectionMethod( ShieldScope_Admin::class, 'maybe_save_settings' );
		$method->setAccessible( true );
		$method->invoke( $admin );

		$this->assertFalse( get_option( 'shieldscope_settings' ) );
	}
}
