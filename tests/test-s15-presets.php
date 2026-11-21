<?php
/**
 * Tests for S-15: server-load presets.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S15_Presets
 */
class Test_S15_Presets extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		$_POST = array();
	}

	protected function tearDown(): void {
		$_POST = array();
	}

	private function save( array $settings ) {
		$_POST = array( 'shieldscope_settings_submit' => '1', '_wpnonce' => 'n', 'shieldscope_settings' => $settings );
		$m     = new ReflectionMethod( ShieldScope_Admin::class, 'maybe_save_settings' );
		$m->setAccessible( true );
		$m->invoke( new ShieldScope_Admin() );
		return get_option( 'shieldscope_settings' );
	}

	public function test_preset_applies_when_the_fields_were_not_edited() {
		update_option( 'shieldscope_settings', array( 'cpu_limit' => 70, 'chunk_time_limit' => 9 ) );
		$saved = $this->save( array( 'load_preset' => 'gentle', 'cpu_limit' => 70, 'chunk_time_limit' => 9 ) );
		$this->assertSame( array( 10, 1 ), array( $saved['cpu_limit'], $saved['chunk_time_limit'] ) );
	}

	public function test_custom_keeps_fields() {
		$saved = $this->save( array( 'load_preset' => 'custom', 'cpu_limit' => 33, 'chunk_time_limit' => 4 ) );
		$this->assertSame( array( 33, 4 ), array( $saved['cpu_limit'], $saved['chunk_time_limit'] ) );
	}

	public function test_edited_fields_win_over_an_untouched_preset() {
		update_option( 'shieldscope_settings', array( 'cpu_limit' => 20, 'chunk_time_limit' => 2 ) );
		$saved = $this->save( array( 'load_preset' => 'normal', 'cpu_limit' => 5, 'chunk_time_limit' => 2 ) );
		$this->assertSame( array( 5, 2 ), array( $saved['cpu_limit'], $saved['chunk_time_limit'] ), 'SC2-06' );
	}

	public function test_changing_only_the_preset_applies_it() {
		update_option( 'shieldscope_settings', array( 'cpu_limit' => 20, 'chunk_time_limit' => 2 ) );
		$saved = $this->save( array( 'load_preset' => 'fast', 'cpu_limit' => 20, 'chunk_time_limit' => 2 ) );
		$this->assertSame( array( 40, 3 ), array( $saved['cpu_limit'], $saved['chunk_time_limit'] ) );
	}

	public function test_current_preset() {
		$this->assertSame( 'normal', ShieldScope_Admin::current_preset( array( 'cpu_limit' => 20, 'chunk_time_limit' => 2 ) ) );
		$this->assertSame( 'custom', ShieldScope_Admin::current_preset( array( 'cpu_limit' => 25, 'chunk_time_limit' => 2 ) ) );
	}
}
