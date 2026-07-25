<?php
/**
 * Tests for ShieldScope_Check_Code_Patterns and the uploads PHP-shell check.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Code_Patterns
 */
class Test_Code_Patterns extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$this->logger = new SS_Fake_Logger();
	}

	/**
	 * Drive a check step until completion.
	 *
	 * @param ShieldScope_Check_Base $check Check.
	 * @param string                 $step  Step id.
	 */
	private function run_to_completion( $check, $step ) {
		$cursor = array();
		$guard  = 0;
		do {
			$result = $check->run_step( $step, $cursor );
			$cursor = $result['cursor'];
			$this->assertLessThan( 500, ++$guard );
		} while ( ! empty( $result['continue'] ) );
	}

	public function test_obfuscated_eval_backdoor_is_flagged_critical() {
		$dir = SHIELDSCOPE_WP_PLUGINS_DIR . '/bad-plugin';
		mkdir( $dir, 0777, true );
		// Built by concatenation so this test file itself never contains the signature.
		$payload = '<?php ' . 'ev' . 'al(' . 'base64_' . 'decode($_POST["x"]));';
		file_put_contents( "$dir/backdoor.php", $payload );

		$check = new ShieldScope_Check_Code_Patterns( 'scan_t', $this->logger );
		$this->run_to_completion( $check, 'scan_plugins' );

		$critical = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_CRITICAL );
		$this->assertNotEmpty( $critical, 'eval(base64_decode()) must be flagged as critical.' );
		$this->assertStringContainsString( 'backdoor', $critical[0]['description'] . $critical[0]['title'] );
	}

	public function test_clean_plugin_produces_no_findings() {
		$dir = SHIELDSCOPE_WP_PLUGINS_DIR . '/good-plugin';
		mkdir( $dir, 0777, true );
		file_put_contents( "$dir/good.php", "<?php\nfunction good_plugin_init() { return true; }\n" );

		$check = new ShieldScope_Check_Code_Patterns( 'scan_t', $this->logger );
		$this->run_to_completion( $check, 'scan_plugins' );

		$this->assertCount( 0, $this->logger->findings );
	}

	public function test_files_over_size_limit_are_skipped() {
		update_option( 'shieldscope_settings', array( 'max_scan_file_size' => 100 ) ); // 100 bytes.
		$dir = SHIELDSCOPE_WP_PLUGINS_DIR . '/big-plugin';
		mkdir( $dir, 0777, true );
		$payload = '<?php ' . 'ev' . 'al(' . 'base64_' . 'decode($_POST["x"])); // ' . str_repeat( 'x', 500 );
		file_put_contents( "$dir/big.php", $payload );

		$check = new ShieldScope_Check_Code_Patterns( 'scan_t', $this->logger );
		$this->run_to_completion( $check, 'scan_plugins' );

		$this->assertCount( 0, $this->logger->findings, 'Files above max_scan_file_size must not be read.' );
	}

	public function test_php_shell_in_uploads_is_flagged_critical() {
		$uploads = SS_TESTS_WP_ROOT . '/wp-content/uploads/2026/07';
		mkdir( $uploads, 0777, true );
		file_put_contents( "$uploads/shell.php", '<?php system($_GET["c"]);' );
		file_put_contents( "$uploads/photo.jpg", 'jpeg-bytes' );

		$check  = new ShieldScope_Check_Filesystem( 'scan_t', $this->logger );
		$cursor = array();
		do {
			$result = $check->run_step( 'uploads_php', $cursor );
			$cursor = $result['cursor'];
		} while ( ! empty( $result['continue'] ) );

		$critical = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_CRITICAL );
		$this->assertCount( 1, $critical );
		$this->assertStringContainsString( 'shell.php', $critical[0]['target'] );
	}

	public function test_uploads_with_no_php_files_is_clean() {
		$uploads = SS_TESTS_WP_ROOT . '/wp-content/uploads';
		mkdir( $uploads, 0777, true );
		file_put_contents( "$uploads/image.png", 'png' );

		$check  = new ShieldScope_Check_Filesystem( 'scan_t', $this->logger );
		$cursor = array();
		do {
			$result = $check->run_step( 'uploads_php', $cursor );
			$cursor = $result['cursor'];
		} while ( ! empty( $result['continue'] ) );

		$this->assertCount( 0, $this->logger->findings );
	}
}
