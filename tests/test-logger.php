<?php
/**
 * Tests for ShieldScope_Logger input validation and query portability.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Minimal wpdb double capturing inserts and queries.
 */
class SS_Fake_WPDB {
	public $prefix    = 'wp_';
	public $options   = 'wp_options';
	public $users     = 'wp_users';
	public $inserts   = array();
	public $last_sql  = '';
	public $insert_id = 0;

	public function insert( $table, $data ) {
		$this->inserts[] = array( 'table' => $table, 'data' => $data );
		$this->insert_id = count( $this->inserts );
		return 1;
	}
	public function prepare( $sql, ...$args ) {
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%[sd]/', is_int( $a ) ? (string) $a : "'" . $a . "'", $sql, 1 );
		}
		return $sql;
	}
	public function get_results( $sql, $output = ARRAY_A ) {
		$this->last_sql = $sql;
		return array();
	}
	public function query( $sql ) {
		$this->last_sql = $sql;
		return 0;
	}
	public function get_charset_collate() {
		return '';
	}
}

if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}

/**
 * Class Test_Logger
 */
class Test_Logger extends TestCase {

	/** @var SS_Fake_WPDB */
	private $wpdb;

	/** @var ShieldScope_Logger */
	private $logger;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->wpdb      = new SS_Fake_WPDB();
		$GLOBALS['wpdb'] = $this->wpdb;
		$this->logger    = new ShieldScope_Logger();
	}

	public function test_record_persists_all_fields() {
		$id = $this->logger->record( 'scan_1', 'core', ShieldScope_Logger::SEVERITY_HIGH, 'Title', 'Desc', 'Fix it', 'wp-config.php', array( 'k' => 'v' ) );

		$this->assertSame( 1, $id );
		$row = $this->wpdb->inserts[0]['data'];
		$this->assertSame( 'scan_1', $row['scan_id'] );
		$this->assertSame( 'core', $row['check_id'] );
		$this->assertSame( 'high', $row['severity'] );
		$this->assertSame( 'Title', $row['title'] );
		$this->assertSame( '{"k":"v"}', $row['context'] );
		$this->assertSame( 'wp_shieldscope_findings', $this->wpdb->inserts[0]['table'] );
	}

	public function test_invalid_severity_is_coerced_to_low() {
		$this->logger->record( 'scan_1', 'core', 'catastrophic-doom', 'T' );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->wpdb->inserts[0]['data']['severity'] );
	}

	public function test_overlong_fields_are_truncated_to_column_limits() {
		$this->logger->record(
			str_repeat( 'a', 100 ),   // scan_id VARCHAR(64)
			str_repeat( 'b', 200 ),   // check_id VARCHAR(100)
			ShieldScope_Logger::SEVERITY_INFO,
			str_repeat( 'c', 300 ),   // title VARCHAR(255)
			'',
			'',
			str_repeat( 'd', 600 )    // target VARCHAR(500)
		);
		$row = $this->wpdb->inserts[0]['data'];
		$this->assertSame( 64, strlen( $row['scan_id'] ) );
		$this->assertSame( 100, strlen( $row['check_id'] ) );
		$this->assertSame( 255, strlen( $row['title'] ) );
		$this->assertSame( 500, strlen( $row['target'] ) );
	}

	public function test_findings_query_does_not_use_mysql_only_field_function() {
		// Regression: ORDER BY FIELD(...) breaks on SQLite-backed installs
		// (WordPress Playground / Studio). The query must use portable SQL.
		$this->logger->get_findings( 'scan_1' );
		$this->assertStringNotContainsString( 'FIELD(', $this->wpdb->last_sql );
		$this->assertStringContainsString( 'ORDER BY CASE severity', $this->wpdb->last_sql );
	}

	public function test_summary_returns_all_severities_zeroed_when_empty() {
		$summary = $this->logger->get_summary( 'scan_1' );
		$this->assertSame(
			array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 ),
			$summary
		);
	}
}
