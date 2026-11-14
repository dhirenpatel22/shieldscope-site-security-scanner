<?php
/**
 * A-11a: Pause/Abort correctness and the tick lock.
 *
 * A fake check pauses, aborts or restarts the scan from "another request"
 * in the middle of a step, the way the Pause/Abort buttons race an in-flight
 * tick on a real site.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}

/**
 * wpdb double backed by the stub options table, with a findings table.
 * Understands only the queries the scanner and logger send.
 */
class SS_A11a_WPDB {
	public $prefix    = 'wp_';
	public $options   = 'wp_options';
	public $insert_id = 0;
	public $findings  = array();

	public function prepare( $sql, ...$args ) {
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%[sd]/', is_int( $a ) ? (string) $a : "'" . addslashes( (string) $a ) . "'", $sql, 1 );
		}
		return $sql;
	}

	public function insert( $table, $data ) {
		$this->insert_id++;
		$this->findings[ $this->insert_id ] = $data;
		return 1;
	}

	public function query( $sql ) {
		$opts = &$GLOBALS['ss_test_options'];
		if ( preg_match( "/^INSERT IGNORE INTO `wp_options` .* VALUES \\( '([^']*)', '([^']*)'/", $sql, $m ) ) {
			if ( array_key_exists( $m[1], $opts ) ) {
				return 0;
			}
			$opts[ $m[1] ] = $m[2];
			return 1;
		}
		if ( preg_match( "/^UPDATE `wp_options` SET `option_value` = '([^']*)' WHERE `option_name` = '([^']*)' AND `option_value` = '([^']*)'/", $sql, $m ) ) {
			if ( isset( $opts[ $m[2] ] ) && (string) $opts[ $m[2] ] === $m[3] ) {
				$opts[ $m[2] ] = $m[1];
				return 1;
			}
			return 0;
		}
		if ( preg_match( "/^DELETE FROM `wp_options` WHERE `option_name` = '([^']*)' AND `option_value` = '([^']*)'/", $sql, $m ) ) {
			if ( isset( $opts[ $m[1] ] ) && (string) $opts[ $m[1] ] === $m[2] ) {
				unset( $opts[ $m[1] ] );
				return 1;
			}
			return 0;
		}
		if ( preg_match( "/^DELETE FROM wp_shieldscope_findings WHERE scan_id = '([^']*)'/", $sql, $m ) ) {
			$before         = count( $this->findings );
			$this->findings = array_filter(
				$this->findings,
				static function ( $row ) use ( $m ) {
					return $row['scan_id'] !== $m[1];
				}
			);
			return $before - count( $this->findings );
		}
		throw new RuntimeException( 'Unexpected query: ' . $sql );
	}

	public function get_var( $sql ) {
		if ( preg_match( "/^SELECT `option_value` FROM `wp_options` WHERE `option_name` = '([^']*)'/", $sql, $m ) ) {
			return array_key_exists( $m[1], $GLOBALS['ss_test_options'] ) ? (string) $GLOBALS['ss_test_options'][ $m[1] ] : null;
		}
		throw new RuntimeException( 'Unexpected query: ' . $sql );
	}

	public function get_results( $sql, $output = ARRAY_A ) {
		return array();
	}

	public function findings_for( $scan_id ) {
		return array_values(
			array_filter(
				$this->findings,
				static function ( $row ) use ( $scan_id ) {
					return $row['scan_id'] === $scan_id;
				}
			)
		);
	}
}

/**
 * Fake check with three quick steps. Tests hook into a step to simulate
 * what another request does while that step runs.
 */
class SS_A11a_Fake_Check extends ShieldScope_Check_Base {

	/** @var array<string,callable> Step id => callback run inside that step. */
	public static $during = array();

	/** @var string[] Steps that ran, in order. */
	public static $ran = array();

	public function get_id() {
		return 'a11a_fake';
	}

	public function get_label() {
		return 'A-11a fake check';
	}

	public function get_steps() {
		return array( 'one', 'two', 'three' );
	}

	public function run_step( $step, array $cursor = array() ) {
		self::$ran[] = $step;
		if ( isset( self::$during[ $step ] ) ) {
			call_user_func( self::$during[ $step ] );
		}
		$this->logger->record( $this->scan_id, $this->get_id(), ShieldScope_Logger::SEVERITY_LOW, 'Finding from step ' . $step );
		return array( 'continue' => false, 'cursor' => array() );
	}
}

/**
 * Scanner that runs only the fake check.
 */
class SS_A11a_Scanner extends ShieldScope_Scanner {
	public function get_check_classes() {
		return array( 'SS_A11a_Fake_Check' );
	}
}

/**
 * Class Test_A11a_Scanner_Pause_Abort_Lock
 */
class Test_A11a_Scanner_Pause_Abort_Lock extends TestCase {

	/** @var SS_A11a_WPDB */
	private $wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->wpdb      = new SS_A11a_WPDB();
		$GLOBALS['wpdb'] = $this->wpdb;
		// No throttle sleeps, shortest chunk.
		update_option( 'shieldscope_settings', array( 'cpu_limit' => 100, 'chunk_time_limit' => 0.25 ) );
		SS_A11a_Fake_Check::$during = array();
		SS_A11a_Fake_Check::$ran    = array();
	}

	private function other_request( $method ) {
		return ss_tests_in_other_request(
			static function () use ( $method ) {
				$scanner = new SS_A11a_Scanner();
				return $scanner->$method();
			}
		);
	}

	private function db_state() {
		return $GLOBALS['ss_test_options'][ ShieldScope_Scanner::STATE_OPTION ];
	}

	public function test_full_tick_without_interference_completes_and_releases_lock() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();

		$state = $scanner->run_chunk();

		$this->assertSame( 'completed', $state['status'] );
		$this->assertSame( array( 'one', 'two', 'three' ), SS_A11a_Fake_Check::$ran );
		$this->assertSame( 'completed', $this->db_state()['status'] );
		$this->assertArrayNotHasKey( 'shieldscope_tick_lock', $GLOBALS['ss_test_options'] );
	}

	public function test_pause_during_a_step_stays_paused_after_the_tick() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		SS_A11a_Fake_Check::$during['two'] = function () {
			$this->other_request( 'pause' );
		};

		$state = $scanner->run_chunk();

		$this->assertSame( 'paused', $state['status'] );
		$this->assertSame( 'paused', $this->db_state()['status'] );
		$this->assertSame( array( 'one', 'two' ), SS_A11a_Fake_Check::$ran, 'No step may start after the pause.' );
		$this->assertSame( 2, $this->db_state()['step_index'], 'Progress made before the pause is kept.' );

		// Resume picks up at step three.
		$this->other_request( 'resume' );
		SS_A11a_Fake_Check::$ran = array();
		$state = ( new SS_A11a_Scanner() )->run_chunk();
		$this->assertSame( array( 'three' ), SS_A11a_Fake_Check::$ran );
		$this->assertSame( 'completed', $state['status'] );
	}

	public function test_pause_during_the_last_step_does_not_complete_the_scan() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		SS_A11a_Fake_Check::$during['three'] = function () {
			$this->other_request( 'pause' );
		};

		$scanner->run_chunk();

		$this->assertSame( 'paused', $this->db_state()['status'] );
		$this->assertFalse( get_option( 'shieldscope_last_scan', false ) );
	}

	public function test_abort_during_a_step_stays_aborted_and_leaves_no_findings() {
		$scanner = new SS_A11a_Scanner();
		$state   = $scanner->start();
		SS_A11a_Fake_Check::$during['two'] = function () {
			$this->other_request( 'abort' );
		};

		$after = $scanner->run_chunk();

		$this->assertSame( 'aborted', $after['status'] );
		$this->assertSame( 'aborted', $this->db_state()['status'] );
		$this->assertSame( array( 'one', 'two' ), SS_A11a_Fake_Check::$ran );
		$this->assertSame( array(), $this->wpdb->findings_for( $state['scan_id'] ), 'Findings written after the abort must be removed too.' );
	}

	public function test_abort_removes_that_scans_partial_findings_only() {
		$scanner = new SS_A11a_Scanner();
		$state   = $scanner->start();
		$logger  = new ShieldScope_Logger();
		$logger->record( $state['scan_id'], 'a11a_fake', ShieldScope_Logger::SEVERITY_HIGH, 'Partial' );
		$logger->record( 'scan_older_completed', 'a11a_fake', ShieldScope_Logger::SEVERITY_HIGH, 'Kept' );

		$aborted = $scanner->abort();

		$this->assertSame( 'aborted', $aborted['status'] );
		$this->assertSame( array(), $this->wpdb->findings_for( $state['scan_id'] ) );
		$this->assertCount( 1, $this->wpdb->findings_for( 'scan_older_completed' ) );
	}

	public function test_new_scan_started_during_a_tick_is_not_overwritten() {
		$scanner = new SS_A11a_Scanner();
		$old     = $scanner->start();
		$new     = null;
		SS_A11a_Fake_Check::$during['one'] = function () use ( &$new ) {
			$new = $this->other_request( 'start' );
			SS_A11a_Fake_Check::$during = array();
		};

		$scanner->run_chunk();

		$this->assertNotSame( $old['scan_id'], $new['scan_id'] );
		$this->assertSame( $new['scan_id'], $this->db_state()['scan_id'] );
		$this->assertSame( 'running', $this->db_state()['status'] );
		$this->assertSame( 0, $this->db_state()['done_steps'], 'The old tick must not write its progress into the new scan.' );
		$this->assertSame( array(), $this->wpdb->findings_for( $old['scan_id'] ), 'The replaced scan leaves no orphan findings.' );
	}

	public function test_second_tick_while_one_is_in_flight_is_busy_and_does_nothing() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		$second = null;
		SS_A11a_Fake_Check::$during['one'] = function () use ( &$second ) {
			SS_A11a_Fake_Check::$during = array();
			$second = $this->other_request( 'run_chunk' );
		};

		$first = $scanner->run_chunk();

		$this->assertTrue( ! empty( $second['busy'] ), 'The overlapping tick reports busy.' );
		$this->assertSame( array( 'one', 'two', 'three' ), SS_A11a_Fake_Check::$ran, 'Each step ran exactly once.' );
		$this->assertSame( 'completed', $first['status'] );
		$this->assertTrue( empty( $first['busy'] ) );
	}

	public function test_held_lock_makes_a_tick_busy_without_changing_state() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		$GLOBALS['ss_test_options']['shieldscope_tick_lock'] = time() . ':other';

		$state = $scanner->run_chunk();

		$this->assertTrue( $state['busy'] );
		$this->assertSame( 'running', $state['status'] );
		$this->assertSame( array(), SS_A11a_Fake_Check::$ran );
		$this->assertSame( 0, $this->db_state()['done_steps'] );
		$this->assertArrayNotHasKey( 'busy', $this->db_state(), 'Busy is a response flag, never saved.' );
		$this->assertSame( time() . ':other', (string) $GLOBALS['ss_test_options']['shieldscope_tick_lock'], 'Another holder\'s lock is left alone.' );
	}

	public function test_expired_lock_is_taken_over() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		$GLOBALS['ss_test_options']['shieldscope_tick_lock'] = ( time() - ShieldScope_Scanner::LOCK_TIMEOUT - 1 ) . ':crashed';

		$state = $scanner->run_chunk();

		$this->assertTrue( empty( $state['busy'] ) );
		$this->assertSame( 'completed', $state['status'] );
		$this->assertArrayNotHasKey( 'shieldscope_tick_lock', $GLOBALS['ss_test_options'] );
	}

	public function test_lock_is_released_when_a_tick_has_nothing_to_do() {
		$scanner = new SS_A11a_Scanner();

		$state = $scanner->run_chunk();

		$this->assertSame( 'idle', $state['status'] );
		$this->assertArrayNotHasKey( 'shieldscope_tick_lock', $GLOBALS['ss_test_options'] );
	}
}
