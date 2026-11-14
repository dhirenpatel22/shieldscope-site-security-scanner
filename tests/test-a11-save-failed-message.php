<?php
/**
 * A-11 / A-15 follow-up: the scan-progress message must not say
 * "Scan complete." when findings could not be saved.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/test-a11a-scanner-pause-abort-lock.php';

/**
 * Class Test_A11_Save_Failed_Message
 */
class Test_A11_Save_Failed_Message extends TestCase {

	/** @var SS_A11a_WPDB */
	private $wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->wpdb      = new SS_A11a_WPDB();
		$GLOBALS['wpdb'] = $this->wpdb;
		update_option( 'shieldscope_settings', array( 'cpu_limit' => 100, 'chunk_time_limit' => 0.25 ) );
		SS_A11a_Fake_Check::$during = array();
		SS_A11a_Fake_Check::$ran    = array();
	}

	private function envelope( array $state ) {
		$method = new ReflectionMethod( 'ShieldScope_Ajax', 'envelope' );
		if ( PHP_VERSION_ID < 80100 ) {
			$method->setAccessible( true );
		}
		return $method->invoke( new ShieldScope_Ajax(), $state, new SS_A11a_Scanner() );
	}

	public function test_completed_scan_with_unsaved_findings_says_so() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		$this->wpdb->fail_inserts = true;

		$state = $scanner->run_chunk();

		$this->assertSame( 'completed', $state['status'] );
		$this->assertSame( 'Scan finished, but some results could not be saved. This report is incomplete.', $state['last_message'] );
		$envelope = $this->envelope( $state );
		$this->assertTrue( $envelope['save_failed'] );
		$this->assertSame( 'Scan finished, but some results could not be saved. This report is incomplete.', $envelope['message'] );
	}

	public function test_completed_scan_with_saved_findings_says_complete() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();

		$state = $scanner->run_chunk();

		$this->assertSame( 'Scan complete.', $state['last_message'] );
		$this->assertFalse( $this->envelope( $state )['save_failed'] );
	}

	public function test_failure_recorded_for_another_scan_does_not_affect_this_one() {
		update_option( 'shieldscope_save_failed', 'scan_older' );
		$scanner = new SS_A11a_Scanner();
		$scanner->start();

		$state = $scanner->run_chunk();

		$this->assertSame( 'Scan complete.', $state['last_message'] );
	}
}
