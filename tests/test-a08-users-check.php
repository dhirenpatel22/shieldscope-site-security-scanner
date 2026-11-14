<?php
/**
 * A-08: users check covers every user (cursor pagination), flags md5/empty
 * hashes, accepts every modern WordPress hash format, and uses accurate
 * wording for the default 'admin' finding.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}

/**
 * In-memory wp_users table that honours `ID > n ORDER BY ID LIMIT n`.
 */
class SS_A08_Fake_Users_DB {
	public $users   = 'wp_users';
	public $rows    = array();
	public $queries = array();

	public function prepare( $sql, ...$args ) {
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%[sd]/', is_int( $a ) ? (string) $a : "'" . $a . "'", $sql, 1 );
		}
		return $sql;
	}

	public function get_results( $sql, $output = ARRAY_A ) {
		$this->queries[] = $sql;
		$rows            = $this->rows;
		if ( false !== strpos( $sql, "user_pass = ''" ) ) {
			$rows = array_filter(
				$rows,
				static function ( $r ) {
					return '' === $r['user_pass'] || null === $r['user_pass'];
				}
			);
		}
		if ( preg_match( '/\bID\s*>\s*(\d+)/', $sql, $m ) ) {
			$after = (int) $m[1];
			$rows  = array_filter(
				$rows,
				static function ( $r ) use ( $after ) {
					return $r['ID'] > $after;
				}
			);
		}
		usort(
			$rows,
			static function ( $a, $b ) {
				return $a['ID'] - $b['ID'];
			}
		);
		if ( preg_match( '/LIMIT\s+(\d+)/', $sql, $m ) ) {
			$rows = array_slice( $rows, 0, (int) $m[1] );
		}
		return array_values( $rows );
	}
}

/**
 * Class Test_A08_Users_Check
 */
class Test_A08_Users_Check extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var mixed */
	private $saved_wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->logger     = new SS_Fake_Logger();
		$this->saved_wpdb = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb']  = new SS_A08_Fake_Users_DB();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->saved_wpdb;
	}

	private function add_user( $id, $hash ) {
		$GLOBALS['wpdb']->rows[] = array(
			'ID'         => $id,
			'user_login' => 'user' . $id,
			'user_pass'  => $hash,
		);
	}

	private function run_to_completion( $check, $step ) {
		$cursor = array();
		$guard  = 0;
		do {
			$result = $check->run_step( $step, $cursor );
			$cursor = $result['cursor'];
			$this->assertLessThan( 100, ++$guard, 'Step never finished.' );
		} while ( ! empty( $result['continue'] ) );
		return $guard;
	}

	private function flagged_targets() {
		return array_column( $this->logger->findings, 'target' );
	}

	public function test_all_1200_users_are_checked_in_batches_of_500() {
		$bcrypt = '$wp$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
		for ( $id = 1; $id <= 1200; $id++ ) {
			$this->add_user( $id, $bcrypt );
		}
		// Legacy md5 hashes placed in each batch, including past the old 500 cap.
		$GLOBALS['wpdb']->rows[0]['user_pass']    = '5f4dcc3b5aa765d61d8327deb882cf99';
		$GLOBALS['wpdb']->rows[750]['user_pass']  = '5f4dcc3b5aa765d61d8327deb882cf99';
		$GLOBALS['wpdb']->rows[1199]['user_pass'] = '5f4dcc3b5aa765d61d8327deb882cf99';

		$check = new ShieldScope_Check_Users( 'scan_t', $this->logger );
		$calls = $this->run_to_completion( $check, 'weak_hashes' );

		$this->assertSame( array( 'user:1', 'user:751', 'user:1200' ), $this->flagged_targets() );
		$this->assertSame( 3, $calls, '1,200 users at 500 per call need three calls.' );
		foreach ( $GLOBALS['wpdb']->queries as $sql ) {
			$this->assertMatchesRegularExpression( '/ID > \d+ ORDER BY ID LIMIT 500/', $sql );
		}
	}

	public function test_exactly_500_users_finishes_after_an_empty_batch() {
		for ( $id = 1; $id <= 500; $id++ ) {
			$this->add_user( $id, '$P$BDMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21' );
		}
		$check = new ShieldScope_Check_Users( 'scan_t', $this->logger );
		$this->run_to_completion( $check, 'weak_hashes' );
		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_no_users_produces_no_findings() {
		$check  = new ShieldScope_Check_Users( 'scan_t', $this->logger );
		$result = $check->run_step( 'weak_hashes', array() );
		$this->assertFalse( $result['continue'] );
		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_modern_formats_are_accepted_and_md5_is_flagged_high() {
		$hashes = array(
			1 => '$wp$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
			2 => '$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
			3 => '$2b$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
			4 => '$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
			5 => '$P$BDMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21',
			6 => '$H$9DMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21',
			7 => '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$hash',
			8 => '5f4dcc3b5aa765d61d8327deb882cf99',
		);
		foreach ( $hashes as $id => $hash ) {
			$this->add_user( $id, $hash );
		}
		$check = new ShieldScope_Check_Users( 'scan_t', $this->logger );
		$this->run_to_completion( $check, 'weak_hashes' );

		$this->assertSame( array( 'user:8' ), $this->flagged_targets() );
		$this->assertSame( ShieldScope_Logger::SEVERITY_HIGH, $this->logger->findings[0]['severity'] );
	}

	public function test_empty_password_is_flagged_critical() {
		$this->add_user( 1, '$P$BDMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21' );
		$this->add_user( 2, '' );
		$check = new ShieldScope_Check_Users( 'scan_t', $this->logger );
		$this->run_to_completion( $check, 'empty_passwords' );

		$this->assertSame( array( 'user:2' ), $this->flagged_targets() );
		$this->assertSame( ShieldScope_Logger::SEVERITY_CRITICAL, $this->logger->findings[0]['severity'] );
	}

	public function test_admin_username_finding_uses_accurate_wording() {
		ss_tests_override(
			'get_user_by',
			static function ( $field, $value ) {
				return ( 'login' === $field && 'admin' === $value ) ? (object) array( 'ID' => 1 ) : false;
			}
		);
		ss_tests_override(
			'user_can',
			static function () {
				return true;
			}
		);
		$check = new ShieldScope_Check_Users( 'scan_t', $this->logger );
		$check->run_step( 'admin_user', array() );

		$this->assertCount( 1, $this->logger->findings );
		$description = $this->logger->findings[0]['description'];
		$this->assertStringContainsString( "Attackers often try the username 'admin' first.", $description );
		$this->assertStringNotContainsString( 'halves', $description );
	}
}
