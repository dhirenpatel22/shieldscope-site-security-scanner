<?php
/**
 * Review 2 engine fixes: SC2-02 (cron chain), SC2-03 (lock timeout), IM2-11 (counts).
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_R2_Engine
 */
class Test_R2_Engine extends TestCase {

	/** @var mixed */
	private $saved_wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->saved_wpdb = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb']  = new SS_Test_WPDB();
		$GLOBALS['ss_test_next_cron'] = false;
		ss_tests_override(
			'wp_next_scheduled',
			function () {
				return $GLOBALS['ss_test_next_cron'];
			}
		);
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->saved_wpdb;
	}

	public function test_queue_cron_adds_or_moves_earlier_never_later() {
		ShieldScope_Scanner::queue_cron( 30 );
		$this->assertSame( array( array( time() + 30, 'shieldscope_run_scan_chunk' ) ), $GLOBALS['ss_test_cron'] );

		$GLOBALS['ss_test_cron']      = array();
		$GLOBALS['ss_test_next_cron'] = time() + 20;
		ShieldScope_Scanner::queue_cron( 60 );
		$this->assertSame( array(), $GLOBALS['ss_test_cron'], 'An earlier event is kept.' );

		$GLOBALS['ss_test_next_cron'] = time() + 90;
		ShieldScope_Scanner::queue_cron( 10 );
		$this->assertSame( array( array( time() + 10, 'shieldscope_run_scan_chunk' ) ), $GLOBALS['ss_test_cron'], 'A later event is moved earlier.' );
	}

	public function test_busy_cron_chunk_leaves_a_watchdog_queued() {
		update_option( 'shieldscope_scan_state', array( 'status' => 'running', 'scan_id' => 's', 'total_steps' => 1 ) );
		// Another tick holds the lock.
		$GLOBALS['ss_test_options']['shieldscope_tick_lock'] = time() . ':tab';
		$GLOBALS['wpdb'] = new class() extends SS_Test_WPDB {
			public function query( $sql ) {
				return 0; // INSERT IGNORE finds the row: lock busy.
			}
			public function get_var( $sql = null ) {
				return time() . ':tab';
			}
		};
		$state = ( new ShieldScope_Scanner() )->run_chunk( true );
		$this->assertTrue( ! empty( $state['busy'] ) );
		$this->assertSame( 'shieldscope_run_scan_chunk', $GLOBALS['ss_test_cron'][0][1], 'SC2-02: the chain survives a busy chunk.' );
		$this->assertGreaterThan( time(), $GLOBALS['ss_test_cron'][0][0] );
	}

	public function test_lock_timeout_follows_max_execution_time() {
		$saved = ini_get( 'max_execution_time' );
		ini_set( 'max_execution_time', '0' );
		$this->assertSame( 600, ShieldScope_Scanner::lock_timeout() );
		ini_set( 'max_execution_time', '120' );
		$this->assertSame( 135, ShieldScope_Scanner::lock_timeout() );
		ini_set( 'max_execution_time', '30' );
		$this->assertSame( 60, ShieldScope_Scanner::lock_timeout() );
		ini_set( 'max_execution_time', (string) $saved );
	}

	public function test_active_summary_leaves_out_ignored() {
		$rows = array(
			array( 'check_id' => 'c', 'title' => 'A', 'target' => 'a', 'severity' => 'critical' ),
			array( 'check_id' => 'c', 'title' => 'B', 'target' => 'b', 'severity' => 'high' ),
		);
		$GLOBALS['wpdb'] = new class( $rows ) extends SS_Test_WPDB {
			private $rows;
			public function __construct( $rows ) {
				$this->rows = $rows;
			}
			public function get_results( $sql = null, $output = null ) {
				return $this->rows;
			}
		};
		ShieldScope_Ignore::add( $rows[0], 'accepted', 'note' );
		$this->assertSame( array( 'critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 0, 'info' => 0 ), ShieldScope_Ignore::active_summary( 's' ) );
	}
}
