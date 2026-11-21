<?php
/**
 * Ticket A-15: fail-open fixes (table creation, pruning, report empty state).
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * wpdb double for A-15: records SQL, simulates a missing table and failed inserts.
 */
class SS_A15_WPDB {
	public $prefix        = 'wp_';
	public $options       = 'wp_options';
	public $insert_id     = 0;
	public $insert_result = 1;
	public $tables        = array();
	public $queries       = array();

	public function insert( $table, $data ) {
		if ( $this->insert_result ) {
			$this->insert_id++;
		}
		return $this->insert_result;
	}
	public function prepare( $sql, ...$args ) {
		// Like wpdb::prepare(), accept the values as one array too.
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%[sd]/', is_int( $a ) ? (string) $a : "'" . $a . "'", $sql, 1 );
		}
		return $sql;
	}
	public function esc_like( $text ) {
		return addcslashes( $text, '_%\\' );
	}
	public function get_var( $sql ) {
		$this->queries[] = $sql;
		foreach ( $this->tables as $table ) {
			if ( false !== strpos( $sql, "'" . $this->esc_like( $table ) . "'" ) ) {
				return $table;
			}
		}
		return null;
	}
	public function get_results( $sql, $output = 'ARRAY_A' ) {
		$this->queries[] = $sql;
		return array();
	}
	public function query( $sql ) {
		$this->queries[] = $sql;
		return 0;
	}
	public function get_charset_collate() {
		return '';
	}
}

/**
 * Class Test_Activation
 */
class Test_Activation extends TestCase {

	/** @var SS_A15_WPDB */
	private $wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->wpdb      = new SS_A15_WPDB();
		$GLOBALS['wpdb'] = $this->wpdb;

		// dbDelta() lives in wp-admin/includes/upgrade.php, which create_table() requires.
		if ( ! is_dir( ABSPATH . 'wp-admin/includes' ) ) {
			mkdir( ABSPATH . 'wp-admin/includes', 0777, true );
		}
		file_put_contents(
			ABSPATH . 'wp-admin/includes/upgrade.php',
			"<?php if ( ! function_exists( 'dbDelta' ) ) { function dbDelta( \$sql ) { \$GLOBALS['ss_a15_dbdelta'][] = \$sql; return array(); } }"
		);
		$GLOBALS['ss_a15_dbdelta'] = array();
	}

	private function created_tables() {
		$names = array();
		foreach ( $GLOBALS['ss_a15_dbdelta'] as $sql ) {
			if ( preg_match( '/CREATE TABLE (\S+)/', $sql, $m ) ) {
				$names[] = $m[1];
			}
		}
		return $names;
	}

	public function test_activation_creates_table_without_a_capable_user() {
		ss_tests_override( 'current_user_can', function () { return false; } );

		ShieldScope_Core::on_activate();

		$this->assertSame( array( 'wp_shieldscope_findings' ), $this->created_tables() );
		$this->assertSame( SHIELDSCOPE_VERSION, get_option( 'shieldscope_version' ) );
	}

	public function test_maybe_upgrade_skips_when_version_current_and_table_present() {
		update_option( 'shieldscope_version', SHIELDSCOPE_VERSION );
		$this->wpdb->tables = array( 'wp_shieldscope_findings' );

		ShieldScope_Core::instance()->maybe_upgrade();

		$this->assertSame( array(), $this->created_tables() );
	}

	public function test_maybe_upgrade_creates_table_when_version_stale() {
		update_option( 'shieldscope_version', '1.0.0' );
		$this->wpdb->tables = array( 'wp_shieldscope_findings' );

		ShieldScope_Core::instance()->maybe_upgrade();

		$this->assertSame( array( 'wp_shieldscope_findings' ), $this->created_tables() );
		$this->assertSame( SHIELDSCOPE_VERSION, get_option( 'shieldscope_version' ) );
	}

	public function test_maybe_upgrade_creates_table_when_missing_even_if_version_current() {
		update_option( 'shieldscope_version', SHIELDSCOPE_VERSION );

		ShieldScope_Core::instance()->maybe_upgrade();

		$this->assertSame( array( 'wp_shieldscope_findings' ), $this->created_tables() );
	}

	public function test_maybe_upgrade_creates_table_for_the_current_sub_site() {
		// Network activation: sub-site 2 has the version option but never got its own table.
		update_option( 'shieldscope_version', SHIELDSCOPE_VERSION );
		$this->wpdb->prefix = 'wp_2_';
		$this->wpdb->tables = array( 'wp_shieldscope_findings' );

		ShieldScope_Core::instance()->maybe_upgrade();

		$this->assertSame( array( 'wp_2_shieldscope_findings' ), $this->created_tables() );
	}

	public function test_failed_insert_marks_scan_results_unsaved() {
		$this->wpdb->insert_result = false;
		$logger                    = new ShieldScope_Logger();

		$this->assertFalse( $logger->record( 'scan_a', 'core', 'high', 'Title' ) );
		$this->assertTrue( ShieldScope_Logger::save_failed( 'scan_a' ) );
		$this->assertFalse( ShieldScope_Logger::save_failed( 'scan_b' ) );
	}

	public function test_successful_insert_does_not_mark_scan_unsaved() {
		$logger = new ShieldScope_Logger();

		$this->assertSame( 1, $logger->record( 'scan_a', 'core', 'high', 'Title' ) );
		$this->assertFalse( ShieldScope_Logger::save_failed( 'scan_a' ) );
	}

	public function test_prune_never_deletes_the_last_completed_scan() {
		update_option( 'shieldscope_last_scan', 'scan_last' );
		$logger = new ShieldScope_Logger();

		$logger->prune_old( 30 * DAY_IN_SECONDS );

		$sql = end( $this->wpdb->queries );
		$this->assertStringContainsString( 'DELETE FROM wp_shieldscope_findings WHERE created_at <', $sql );
		$this->assertStringContainsString( "scan_id NOT IN ('scan_last')", $sql );
	}

	private function render_report( $last_scan, array $findings ) {
		$summary = array();
		ob_start();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/report.php';
		return ob_get_clean();
	}

	public function test_report_with_no_rows_says_expired_not_clean() {
		$html = $this->render_report( 'scan_old', array() );

		$this->assertStringContainsString( 'Report expired, run a new scan.', $html );
		$this->assertStringNotContainsString( 'No issues at this severity level.', $html );
	}

	public function test_report_with_failed_save_says_results_not_saved() {
		update_option( 'shieldscope_save_failed', 'scan_x' );

		$html = $this->render_report( 'scan_x', array() );

		$this->assertStringContainsString( 'The results of this scan could not be saved', $html );
		$this->assertStringNotContainsString( 'No issues at this severity level.', $html );
		$this->assertStringNotContainsString( 'Report expired', $html );
	}

	public function test_report_with_partially_failed_save_warns_above_findings() {
		update_option( 'shieldscope_save_failed', 'scan_x' );
		$row = array(
			'severity'       => 'info',
			'title'          => 'WordPress core is up to date',
			'check_id'       => 'core',
			'description'    => 'Running WordPress 6.8.1.',
			'recommendation' => '',
			'target'         => '',
			'context'        => '',
			'created_at'     => '2026-11-01 09:30:00',
		);

		$html = $this->render_report( 'scan_x', array( $row ) );

		$this->assertStringContainsString( 'The results of this scan could not be saved', $html );
	}

	public function test_report_shows_scan_date() {
		update_option( 'date_format', 'Y-m-d' );
		update_option( 'time_format', 'H:i' );
		$rows = array(
			array( 'severity' => 'info', 'title' => 'A', 'created_at' => '2026-11-01 09:30:00' ),
			array( 'severity' => 'low', 'title' => 'B', 'created_at' => '2026-11-01 09:42:00' ),
		);

		$html = $this->render_report( 'scan_y', $rows );

		$this->assertStringContainsString( 'Scan date: 2026-11-01 09:42', $html );
		$this->assertStringNotContainsString( 'Report expired', $html );
	}

	public function test_uninstall_deletes_tick_lock_and_save_failed_options() {
		update_option( 'shieldscope_tick_lock', 123 );
		update_option( 'shieldscope_save_failed', 'scan_x' );
		update_option( 'shieldscope_last_scan', 'scan_x' );
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'shieldscope-site-security-scanner/shieldscope-site-security-scanner.php' );
		}

		include SHIELDSCOPE_PLUGIN_DIR . 'uninstall.php';

		$this->assertFalse( get_option( 'shieldscope_tick_lock' ) );
		$this->assertFalse( get_option( 'shieldscope_save_failed' ) );
		$this->assertFalse( get_option( 'shieldscope_last_scan' ) );
		$this->assertContains( 'DROP TABLE IF EXISTS wp_shieldscope_findings', $this->wpdb->queries );
	}
}
