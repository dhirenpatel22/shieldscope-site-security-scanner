<?php
/**
 * Tests for S-10 (background scan) and S-12 (per-check progress).
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S10_Background_Scan
 */
class Test_S10_Background_Scan extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
	}

	public function test_background_is_on_by_default_and_can_be_turned_off() {
		$this->assertTrue( ShieldScope_Scanner::background_enabled() );
		update_option( 'shieldscope_settings', array( 'background_scan' => 0 ) );
		$this->assertFalse( ShieldScope_Scanner::background_enabled() );
	}

	public function test_kick_schedules_and_spawns_only_when_running_in_background() {
		$scanner = new ShieldScope_Scanner();
		$scanner->kick_background( array( 'status' => 'running' ) );
		$this->assertSame( array( array( time(), 'shieldscope_run_scan_chunk' ) ), $GLOBALS['ss_test_cron'] );
		$this->assertSame( 1, $GLOBALS['ss_test_spawned'] );

		ss_tests_reset_state();
		$scanner->kick_background( array( 'status' => 'paused' ) );
		$this->assertSame( array(), $GLOBALS['ss_test_cron'] );

		update_option( 'shieldscope_settings', array( 'background_scan' => 0 ) );
		$scanner->kick_background( array( 'status' => 'running' ) );
		$this->assertSame( 0, $GLOBALS['ss_test_spawned'] );
	}

	public function test_kick_does_not_queue_twice() {
		ss_tests_override(
			'wp_next_scheduled',
			function () {
				return time() + 5;
			}
		);
		( new ShieldScope_Scanner() )->kick_background( array( 'status' => 'running' ) );
		$this->assertSame( array(), $GLOBALS['ss_test_cron'] );
		$this->assertSame( 1, $GLOBALS['ss_test_spawned'] );
	}

	public function test_stalled() {
		$this->assertTrue( ShieldScope_Scanner::is_stalled( array( 'status' => 'running', 'updated_at' => time() - 300 ) ) );
		$this->assertFalse( ShieldScope_Scanner::is_stalled( array( 'status' => 'running', 'updated_at' => time() - 30 ) ) );
		$this->assertFalse( ShieldScope_Scanner::is_stalled( array( 'status' => 'paused', 'updated_at' => time() - 300 ) ) );
	}

	public function test_check_progress_states() {
		$scanner = new ShieldScope_Scanner();
		$state   = $scanner->get_state();
		$state   = array_merge(
			$state,
			array(
				'status'       => 'running',
				'scan_id'      => 's',
				'check_index'  => 2,
				'check_status' => array( 'core_integrity' => array( 'status' => 'partial', 'notes' => array( 'n' ) ) ),
			)
		);
		$list = $scanner->check_progress( $state );
		$this->assertCount( 16, $list );
		$this->assertSame( array( 'done', 'partial', 'running', 'waiting' ), array_slice( array_column( $list, 'status' ), 0, 4 ) );
		$this->assertSame( array( 'n' ), $list[1]['notes'] );

		$idle = $scanner->check_progress( $scanner->get_state() );
		$this->assertSame( array( 'waiting' ), array_values( array_unique( array_column( $idle, 'status' ) ) ) );
	}

	public function test_completion_notice_once_until_report_opened() {
		update_option( 'shieldscope_last_scan', 'scan_n' );
		$admin = new ShieldScope_Admin();
		ob_start();
		$admin->completion_notice();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'ShieldScope scan finished.', $html );
		$this->assertStringContainsString( 'page=shieldscope-report', $html );

		update_option( 'shieldscope_last_seen', 'scan_n' );
		ob_start();
		$admin->completion_notice();
		$this->assertSame( '', ob_get_clean() );
	}

	public function test_completion_notice_not_on_shieldscope_pages() {
		update_option( 'shieldscope_last_scan', 'scan_n' );
		ss_tests_override(
			'get_current_screen',
			function () {
				return (object) array( 'id' => 'toplevel_page_shieldscope' );
			}
		);
		ob_start();
		( new ShieldScope_Admin() )->completion_notice();
		$this->assertSame( '', ob_get_clean() );
	}
}
