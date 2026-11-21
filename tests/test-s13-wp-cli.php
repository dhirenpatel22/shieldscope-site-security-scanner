<?php
/**
 * Tests for S-13: WP-CLI exit status logic and registration.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S13_WP_CLI
 */
class Test_S13_WP_CLI extends TestCase {

	private function rows( array $sevs, $ignored_index = -1 ) {
		$rows = array();
		foreach ( $sevs as $i => $sev ) {
			$rows[] = array( 'severity' => $sev, 'ignored' => $i === $ignored_index ? 'Accepted risk (a, 2026-11-20)' : '' );
		}
		return $rows;
	}

	public function test_counts_leave_out_ignored_findings() {
		$counts = ShieldScope_CLI::active_counts( $this->rows( array( 'critical', 'high', 'high', 'low' ), 0 ) );
		$this->assertSame( array( 'critical' => 0, 'high' => 2, 'medium' => 0, 'low' => 1, 'info' => 0 ), $counts );
	}

	public function test_fail_on_threshold() {
		$counts = array( 'critical' => 0, 'high' => 2, 'medium' => 0, 'low' => 1, 'info' => 0 );
		$this->assertFalse( ShieldScope_CLI::should_fail( $counts, 'critical' ) );
		$this->assertTrue( ShieldScope_CLI::should_fail( $counts, 'high' ) );
		$this->assertTrue( ShieldScope_CLI::should_fail( $counts, 'low' ) );
		$this->assertFalse( ShieldScope_CLI::should_fail( $counts, 'none' ) );
	}

	public function test_plain_strips_terminal_control_characters() {
		$this->assertSame( '[31mred[0m title', ShieldScope_CLI::plain( "\x1b[31mred\x1b[0m title" ) );
		$this->assertSame( "a\tb", ShieldScope_CLI::plain( "a\tb" ) );
	}

	public function test_foreground_scan_does_not_start_or_queue_cron() {
		ss_tests_reset_state();
		$saved           = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb'] = new SS_Test_WPDB();
		$scanner         = ( new ShieldScope_Scanner() )->foreground_only();
		$state           = $scanner->start();
		$scanner->run_chunk( false );
		$GLOBALS['wpdb'] = $saved;
		$this->assertSame( 0, $GLOBALS['ss_test_spawned'] );
		$this->assertSame( array(), $GLOBALS['ss_test_cron'] );
		$this->assertSame( 'running', $state['status'] );
	}

	public function test_abort_subcommand_exists() {
		$this->assertTrue( method_exists( 'ShieldScope_CLI', 'abort' ) );
	}

	public function test_command_is_registered_only_under_wp_cli() {
		$main = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'shieldscope-site-security-scanner.php' );
		$this->assertMatchesRegularExpression( "/if \( defined\( 'WP_CLI' \) && WP_CLI \) \{\s*WP_CLI::add_command\( 'shieldscope', 'ShieldScope_CLI' \);/", $main );
	}
}
