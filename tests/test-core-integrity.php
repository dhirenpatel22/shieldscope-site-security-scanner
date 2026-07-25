<?php
/**
 * Tests for ShieldScope_Check_Core_Integrity.
 *
 * Covers the WordPress Playground false-positive regression: on non-standard
 * builds the check must skip (or aggregate) instead of flooding the report
 * with per-file HIGH findings.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Exposes protected members for testing.
 */
class SS_Testable_Core_Integrity extends ShieldScope_Check_Core_Integrity {
	public function detect_env() {
		return $this->detect_nonstandard_environment();
	}
}

/**
 * Class Test_Core_Integrity
 */
class Test_Core_Integrity extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var SS_Testable_Core_Integrity */
	private $check;

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$this->logger = new SS_Fake_Logger();
		$this->check  = new SS_Testable_Core_Integrity( 'scan_test', $this->logger );
	}

	// -- helpers ------------------------------------------------------------

	/**
	 * Write core files under ABSPATH and return their real checksums map.
	 *
	 * @param int $count    Number of files.
	 * @param int $tampered How many of them to modify after hashing.
	 * @return array path => md5 map of the ORIGINAL content.
	 */
	private function make_core_files( $count, $tampered ) {
		mkdir( ABSPATH . 'wp-includes', 0777, true );
		$checksums = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$rel  = "wp-includes/file-$i.php";
			$body = "<?php // original content $i\n";
			file_put_contents( ABSPATH . $rel, $body );
			$checksums[ $rel ] = md5( $body );
		}
		for ( $i = 0; $i < $tampered; $i++ ) {
			file_put_contents( ABSPATH . "wp-includes/file-$i.php", "<?php // TAMPERED $i\n" );
		}
		return $checksums;
	}

	private function seed_checksums( array $checksums ) {
		set_transient(
			ShieldScope_Check_Core_Integrity::CHECKSUMS_TRANSIENT,
			array(
				'version'   => '6.8.1',
				'locale'    => 'en_US',
				'checksums' => $checksums,
			),
			3600
		);
	}

	/**
	 * Drive a resumable step until it reports completion.
	 *
	 * @param string $step Step id.
	 */
	private function run_step_to_completion( $step ) {
		$cursor = array();
		$guard  = 0;
		do {
			$result = $this->check->run_step( $step, $cursor );
			$cursor = $result['cursor'];
			$this->assertLessThan( 1000, ++$guard, 'Step never completed — infinite loop?' );
		} while ( ! empty( $result['continue'] ) );
	}

	// -- environment detection (the Playground fix) --------------------------

	public function test_detects_wordpress_playground_via_server_software() {
		$_SERVER['SERVER_SOFTWARE'] = 'PHP.wasm';
		$this->assertNotSame( '', $this->check->detect_env() );
	}

	public function test_detects_playground_via_server_software_case_insensitive() {
		$_SERVER['SERVER_SOFTWARE'] = 'WordPress Playground Server';
		$this->assertNotSame( '', $this->check->detect_env() );
	}

	public function test_detects_sqlite_via_db_engine_filter_hook() {
		add_filter( 'shieldscope_skip_core_integrity', '__return_true_ss' );
		$this->assertNotSame( '', $this->check->detect_env() );
	}

	public function test_standard_environment_is_not_flagged() {
		$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.58 (Ubuntu)';
		$this->assertSame( '', $this->check->detect_env() );
	}

	public function test_fetch_skips_with_single_info_finding_on_playground() {
		$_SERVER['SERVER_SOFTWARE'] = 'PHP.wasm';
		$this->seed_checksums( array( 'wp-includes/x.php' => 'abc' ) ); // stale cache must be busted.

		$this->check->run_step( 'fetch', array() );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $this->logger->findings[0]['severity'] );
		$this->assertFalse(
			get_transient( ShieldScope_Check_Core_Integrity::CHECKSUMS_TRANSIENT ),
			'Cached checksums must be deleted so verify/extras no-op.'
		);

		// Verify + extras must then produce zero findings.
		$this->run_step_to_completion( 'verify' );
		$this->run_step_to_completion( 'extras' );
		$this->assertCount( 1, $this->logger->findings, 'No per-file findings may be emitted on Playground.' );
	}

	// -- mass-mismatch aggregation (threshold safety net) ---------------------

	public function test_mass_mismatch_produces_one_medium_summary_not_per_file_highs() {
		// 40 core files, 30 tampered (75% > 30% ratio, 30 >= 20 minimum).
		$this->seed_checksums( $this->make_core_files( 40, 30 ) );

		$this->run_step_to_completion( 'verify' );

		$highs   = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$mediums = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_MEDIUM );

		$this->assertCount( 0, $highs, 'Mass mismatch must NOT emit per-file HIGH findings.' );
		$this->assertCount( 1, $mediums, 'Exactly one aggregated summary finding expected.' );
		$this->assertStringContainsString( 'en masse', $mediums[0]['title'] );
		$this->assertSame( 30, $mediums[0]['context']['differing'] );
		$this->assertSame( 40, $mediums[0]['context']['total'] );
	}

	public function test_small_mismatch_still_emits_individual_high_findings() {
		// 40 files, 3 tampered — below both thresholds.
		$this->seed_checksums( $this->make_core_files( 40, 3 ) );

		$this->run_step_to_completion( 'verify' );

		$highs = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 3, $highs );
		foreach ( $highs as $f ) {
			$this->assertSame( 'Modified WordPress core file', $f['title'] );
			$this->assertNotEmpty( $f['context']['expected'] );
			$this->assertNotEmpty( $f['context']['actual'] );
			$this->assertNotSame( $f['context']['expected'], $f['context']['actual'] );
		}
	}

	public function test_missing_core_file_emits_medium_finding() {
		$checksums = $this->make_core_files( 10, 0 );
		$checksums['wp-includes/ghost.php'] = md5( 'never written to disk' );
		$this->seed_checksums( $checksums );

		$this->run_step_to_completion( 'verify' );

		$mediums = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_MEDIUM );
		$this->assertCount( 1, $mediums );
		$this->assertSame( 'Missing WordPress core file', $mediums[0]['title'] );
		$this->assertSame( 'wp-includes/ghost.php', $mediums[0]['target'] );
	}

	public function test_clean_install_emits_no_findings() {
		$this->seed_checksums( $this->make_core_files( 25, 0 ) );
		$this->run_step_to_completion( 'verify' );
		$this->assertCount( 0, $this->logger->findings );
	}

	public function test_wp_content_and_doc_files_are_excluded_from_verification() {
		$checksums = array(
			'wp-content/plugins/foo/foo.php' => md5( 'x' ), // user content — never policed.
			'readme.html'                    => md5( 'y' ),
			'license.txt'                    => md5( 'z' ),
			'wp-config-sample.php'           => md5( 'w' ),
		);
		$this->seed_checksums( $checksums );
		$this->run_step_to_completion( 'verify' );
		$this->assertCount( 0, $this->logger->findings );
	}

	// -- extras step (unknown files in core dirs) -----------------------------

	public function test_unknown_php_file_in_core_dir_is_flagged() {
		$checksums = $this->make_core_files( 5, 0 );
		$this->seed_checksums( $checksums );

		file_put_contents( ABSPATH . 'wp-includes/evil-backdoor.php', "<?php // rogue\n" );
		file_put_contents( ABSPATH . 'wp-includes/legit-image.png', 'png' ); // non-PHP — must be ignored.

		$this->run_step_to_completion( 'extras' );

		$highs = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $highs );
		$this->assertSame( 'wp-includes/evil-backdoor.php', $highs[0]['target'] );
	}

	public function test_known_core_files_are_not_flagged_by_extras() {
		$this->seed_checksums( $this->make_core_files( 5, 0 ) );
		$this->run_step_to_completion( 'extras' );
		$this->assertCount( 0, $this->logger->findings );
	}

	// -- fetch step -----------------------------------------------------------

	public function test_fetch_caches_checksums_on_success() {
		ss_tests_override(
			'wp_remote_get',
			function () {
				return array(
					'response' => array( 'code' => 200 ),
					'body'     => json_encode( array( 'checksums' => array( 'wp-includes/a.php' => 'deadbeef' ) ) ),
				);
			}
		);

		$this->check->run_step( 'fetch', array() );

		$cached = get_transient( ShieldScope_Check_Core_Integrity::CHECKSUMS_TRANSIENT );
		$this->assertIsArray( $cached );
		$this->assertSame( 'deadbeef', $cached['checksums']['wp-includes/a.php'] );
		$this->assertCount( 0, $this->logger->findings );
	}

	public function test_fetch_failure_emits_info_and_verify_noops() {
		// Default wp_remote_get stub returns WP_Error.
		$this->check->run_step( 'fetch', array() );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $this->logger->findings[0]['severity'] );

		$this->run_step_to_completion( 'verify' );
		$this->assertCount( 1, $this->logger->findings, 'Verify must be a no-op when fetch failed.' );
	}
}

/**
 * Helper used as a filter callback (stub apply_filters passes value through).
 *
 * @return bool
 */
function __return_true_ss() {
	return true;
}
