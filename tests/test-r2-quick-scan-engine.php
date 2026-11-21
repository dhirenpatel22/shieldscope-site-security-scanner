<?php
/**
 * SC2-11: the scanner itself skips slow steps in a quick scan.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Fake check with one slow step.
 */
class SS_R2_Quick_Check extends ShieldScope_Check_Base {
	/** @var string[] */
	public static $ran = array();
	public function get_id() {
		return 'r2quick';
	}
	public function get_label() {
		return 'R2 quick';
	}
	public function get_steps() {
		return array( 'fast_a', 'slow', 'fast_b' );
	}
	public function get_slow_steps() {
		return array( 'slow' );
	}
	public function run_step( $step, array $cursor = array() ) {
		self::$ran[] = $step;
		return array( 'continue' => false, 'cursor' => array() );
	}
}

/**
 * Scanner with only the fake check.
 */
class SS_R2_Quick_Scanner extends ShieldScope_Scanner {
	public function get_check_classes() {
		return array( 'SS_R2_Quick_Check' );
	}
}

/**
 * Class Test_R2_Quick_Scan_Engine
 */
class Test_R2_Quick_Scan_Engine extends TestCase {

	/** @var mixed */
	private $saved;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->saved           = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb']       = new SS_Test_WPDB();
		SS_R2_Quick_Check::$ran = array();
		update_option( 'shieldscope_settings', array( 'background_scan' => 0 ) );
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->saved;
	}

	private function run_scan( $quick ) {
		$scanner = new SS_R2_Quick_Scanner();
		$state   = $scanner->start( $quick );
		for ( $i = 0; $i < 20 && 'running' === $state['status']; $i++ ) {
			$state = $scanner->run_chunk( false );
		}
		return $state;
	}

	public function test_quick_scan_skips_slow_steps_and_says_so() {
		$state = $this->run_scan( true );
		$this->assertSame( 'completed', $state['status'] );
		$this->assertSame( array( 'fast_a', 'fast_b' ), SS_R2_Quick_Check::$ran );
		$this->assertSame( 'partial', $state['check_status']['r2quick']['status'] );
		$this->assertSame( array( 'step "slow" skipped in a quick scan' ), $state['check_status']['r2quick']['notes'] );
	}

	public function test_full_scan_runs_every_step() {
		$state = $this->run_scan( false );
		$this->assertSame( 'completed', $state['status'] );
		$this->assertSame( array( 'fast_a', 'slow', 'fast_b' ), SS_R2_Quick_Check::$ran );
	}
}
