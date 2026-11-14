<?php
/**
 * Tests for ShieldScope_Scanner state machine and progress accounting.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Scanner_State
 */
class Test_Scanner_State extends TestCase {

	/** @var ShieldScope_Scanner */
	private $scanner;

	/** @var mixed $wpdb before this test. */
	private $saved_wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->saved_wpdb = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb']  = new SS_Test_WPDB();
		$this->scanner    = new ShieldScope_Scanner();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->saved_wpdb;
	}

	public function test_default_state_is_idle() {
		$state = $this->scanner->get_state();
		$this->assertSame( ShieldScope_Scanner::STATUS_IDLE, $state['status'] );
		$this->assertSame( '', $state['scan_id'] );
		$this->assertSame( 0, $state['done_steps'] );
	}

	public function test_start_creates_running_state_with_unique_scan_id_and_step_total() {
		$state = $this->scanner->start();

		$this->assertSame( ShieldScope_Scanner::STATUS_RUNNING, $state['status'] );
		$this->assertStringStartsWith( 'scan_', $state['scan_id'] );
		$this->assertGreaterThan( 0, $state['total_steps'], 'Total steps must be counted from registered checks.' );
		$this->assertSame( 0, $state['done_steps'] );

		// Started state must be persisted.
		$persisted = $this->scanner->get_state();
		$this->assertSame( $state['scan_id'], $persisted['scan_id'] );

		// A second start produces a different scan id.
		$second = $this->scanner->start();
		$this->assertNotSame( $state['scan_id'], $second['scan_id'] );
	}

	public function test_all_registered_check_classes_exist_and_have_steps() {
		foreach ( $this->scanner->get_check_classes() as $cls ) {
			$this->assertTrue( class_exists( $cls ), "$cls must be loadable." );
			$check = new $cls( 'scan_x', new SS_Fake_Logger() );
			$this->assertInstanceOf( ShieldScope_Check_Base::class, $check );
			$this->assertNotEmpty( $check->get_id() );
			$this->assertNotEmpty( $check->get_label() );
			$this->assertIsArray( $check->get_steps() );
			$this->assertNotEmpty( $check->get_steps(), "$cls must declare at least one step." );
		}
	}

	public function test_check_ids_are_unique() {
		$ids = array();
		foreach ( $this->scanner->get_check_classes() as $cls ) {
			$check = new $cls( 'scan_x', new SS_Fake_Logger() );
			$ids[] = $check->get_id();
		}
		$this->assertSame( $ids, array_unique( $ids ), 'Every check module needs a unique id.' );
	}

	public function test_pause_and_resume_transitions() {
		$this->scanner->start();

		$paused = $this->scanner->pause();
		$this->assertSame( ShieldScope_Scanner::STATUS_PAUSED, $paused['status'] );

		$resumed = $this->scanner->resume();
		$this->assertSame( ShieldScope_Scanner::STATUS_RUNNING, $resumed['status'] );
	}

	public function test_pause_is_ignored_when_idle() {
		$state = $this->scanner->pause();
		$this->assertSame( ShieldScope_Scanner::STATUS_IDLE, $state['status'] );
	}

	public function test_resume_is_ignored_when_not_paused() {
		$this->scanner->start();
		$state = $this->scanner->resume(); // Running, not paused.
		$this->assertSame( ShieldScope_Scanner::STATUS_RUNNING, $state['status'] );
	}

	public function test_abort_from_running_and_from_paused() {
		$this->scanner->start();
		$aborted = $this->scanner->abort();
		$this->assertSame( ShieldScope_Scanner::STATUS_ABORTED, $aborted['status'] );

		$this->scanner->start();
		$this->scanner->pause();
		$aborted = $this->scanner->abort();
		$this->assertSame( ShieldScope_Scanner::STATUS_ABORTED, $aborted['status'] );
	}

	public function test_run_chunk_is_a_noop_unless_running() {
		$before = $this->scanner->get_state();
		$after  = $this->scanner->run_chunk();
		$this->assertSame( $before['status'], $after['status'] );
		$this->assertSame( 0, $after['done_steps'] );
	}

	public function test_progress_calculation() {
		$this->assertSame( 0, $this->scanner->get_progress( array( 'total_steps' => 0, 'done_steps' => 0 ) ) );
		$this->assertSame( 50, $this->scanner->get_progress( array( 'total_steps' => 10, 'done_steps' => 5 ) ) );
		$this->assertSame( 100, $this->scanner->get_progress( array( 'total_steps' => 10, 'done_steps' => 10 ) ) );
		// Never exceeds 100 even with bad accounting.
		$this->assertSame( 100, $this->scanner->get_progress( array( 'total_steps' => 10, 'done_steps' => 99 ) ) );
	}

	public function test_corrupt_persisted_state_falls_back_to_defaults() {
		update_option( ShieldScope_Scanner::STATE_OPTION, 'not-an-array' );
		$state = $this->scanner->get_state();
		$this->assertSame( ShieldScope_Scanner::STATUS_IDLE, $state['status'] );
	}
}
