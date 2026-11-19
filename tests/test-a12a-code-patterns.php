<?php
/**
 * A-12a: code-patterns check accuracy and wording.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_A12a_Code_Patterns
 */
class Test_A12a_Code_Patterns extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var array<string,string|false> */
	private $saved_ini = array();

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$this->logger    = new SS_Fake_Logger();
		$this->saved_ini = array(
			'pcre.backtrack_limit' => ini_get( 'pcre.backtrack_limit' ),
			'pcre.jit'             => ini_get( 'pcre.jit' ),
		);
	}

	protected function tearDown(): void {
		foreach ( $this->saved_ini as $key => $value ) {
			if ( false !== $value ) {
				ini_set( $key, $value );
			}
		}
	}

	/**
	 * Write a file under a fake plugin directory.
	 *
	 * @param string $relative Path relative to the plugins dir.
	 * @param string $contents File contents.
	 * @return string Full path.
	 */
	private function plugin_file( $relative, $contents ) {
		$full = SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $relative;
		if ( ! is_dir( dirname( $full ) ) ) {
			mkdir( dirname( $full ), 0777, true );
		}
		file_put_contents( $full, $contents );
		return $full;
	}

	/**
	 * Scan the fake plugins dir to completion.
	 */
	private function scan_plugins() {
		$check  = new ShieldScope_Check_Code_Patterns( 'scan_t', $this->logger );
		$cursor = array();
		$guard  = 0;
		do {
			$result = $check->run_step( 'scan_plugins', $cursor );
			$cursor = $result['cursor'];
			$this->assertLessThan( 500, ++$guard );
		} while ( ! empty( $result['continue'] ) );
	}

	/**
	 * The eval-on-decoded-data signature, built by concatenation so this file never contains it.
	 *
	 * @return string
	 */
	private function eval_payload() {
		return '<?php ' . 'ev' . 'al(' . 'base64_' . 'decode($_POST["x"]));';
	}

	/**
	 * One file that triggers every pattern rule.
	 *
	 * @return string
	 */
	private function all_rules_payload() {
		return $this->eval_payload() . "\n"
			. "shell_exec( \$cmd );\n"
			. "include \$_GET['page'];\n"
			. "\$wpdb->query( \"DELETE FROM t WHERE id = \$_GET[id]\" );\n"
			. "echo \$_GET['q'];\n"
			. "file_put_contents( \$f, \$_POST['data'] );\n"
			. '$blob = "' . str_repeat( 'QUJD', 120 ) . "\";\n";
	}

	/**
	 * Bug: eval(base64_decode()) was Critical, titled as a confirmed backdoor.
	 */
	public function test_eval_on_decoded_data_gives_one_high_pattern_match() {
		$this->plugin_file( 'bad-plugin/backdoor.php', $this->eval_payload() );

		$this->scan_plugins();

		$this->assertCount( 1, $this->logger->findings );
		$finding = $this->logger->findings[0];
		$this->assertSame( ShieldScope_Logger::SEVERITY_HIGH, $finding['severity'] );
		$this->assertSame( 'Matches pattern: eval() on encoded data', $finding['title'] );
		$this->assertStringContainsString( 'not been confirmed', $finding['description'] );
	}

	/**
	 * Bug: other pattern matches were Critical or High and worded as confirmed.
	 */
	public function test_every_rule_is_capped_and_worded_as_a_pattern_match() {
		$this->plugin_file( 'all-rules/all.php', $this->all_rules_payload() );

		$this->scan_plugins();

		$by_title = array();
		foreach ( $this->logger->findings as $finding ) {
			$by_title[ $finding['title'] ] = $finding['severity'];
			$this->assertStringStartsWith( 'Matches pattern: ', $finding['title'] );
			$this->assertStringContainsString( 'not been confirmed', $finding['description'], $finding['title'] );
			foreach ( array( $finding['description'], $finding['recommendation'] ) as $text ) {
				$this->assertDoesNotMatchRegularExpression( '/\bis a\b|very likely|almost certainly/i', $text, $finding['title'] );
			}
		}

		$this->assertSame(
			array(
				'Matches pattern: eval() on encoded data'                   => ShieldScope_Logger::SEVERITY_HIGH,
				'Matches pattern: shell command function'                   => ShieldScope_Logger::SEVERITY_LOW,
				'Matches pattern: include/require of request data'          => ShieldScope_Logger::SEVERITY_MEDIUM,
				'Matches pattern: request data in a database query string'  => ShieldScope_Logger::SEVERITY_MEDIUM,
				'Matches pattern: echo of request data'                     => ShieldScope_Logger::SEVERITY_MEDIUM,
				'Matches pattern: file_put_contents() with request data'    => ShieldScope_Logger::SEVERITY_MEDIUM,
				'Matches pattern: long encoded string'                      => ShieldScope_Logger::SEVERITY_LOW,
			),
			$by_title
		);
	}

	/**
	 * Bug: the shell regex matched comments, method calls and method definitions.
	 */
	public function test_shell_rule_ignores_comments_methods_and_definitions() {
		$this->plugin_file(
			'fs-plugin/fs.php',
			"<?php\n"
			. "// Uses the file system (WP_Filesystem) to write.\n"
			. "/* popen( \$x ) is not used here */\n"
			. "# shell_exec( 'ls' );\n"
			. "/** Calls system( on purpose? No. */\n"
			. "\$this->system( 'x' );\n"
			. "\$obj?->popen( 'x' );\n"
			. "Foo::passthru( 'x' );\n"
			. "\$system( 'x' );\n"
			. "class A { public function system( \$x ) { return \$x; } }\n"
			. "my_shell_exec( 'x' );\n"
		);

		$this->scan_plugins();

		$this->assertCount( 0, $this->logger->findings );
	}

	public function test_shell_rule_still_matches_a_real_call() {
		$this->plugin_file( 'cmd-plugin/run.php', "<?php\n\$out = \\shell_exec( \$cmd );\n" );

		$this->scan_plugins();

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->logger->findings[0]['severity'] );
	}

	/**
	 * A well-built plugin in the WooCommerce style gives no finding at all.
	 */
	public function test_prepared_woocommerce_style_plugin_gives_no_finding() {
		$this->plugin_file(
			'shop-plugin/includes/class-orders.php',
			"<?php\n"
			. "defined( 'ABSPATH' ) || exit;\n"
			. "class Shop_Orders {\n"
			. "\t/** Reads the order through the WP file system (WP_Filesystem) cache. */\n"
			. "\tpublic function get( \$wpdb ) {\n"
			. "\t\t\$id  = absint( \$_GET['order_id'] );\n"
			. "\t\t\$row = \$wpdb->get_row( \$wpdb->prepare( \"SELECT * FROM {\$wpdb->prefix}wc_orders WHERE id = %d\", \$id ) );\n"
			. "\t\techo esc_html( wp_unslash( \$_GET['note'] ?? '' ) );\n"
			. "\t\t\$this->system( 'status' );\n"
			. "\t\treturn \$row;\n"
			. "\t}\n"
			. "}\n"
		);
		$this->plugin_file( 'shop-plugin/vendor/autoload.php', "<?php\nreturn require __DIR__ . '/composer/autoload_real.php';\n" );

		$this->scan_plugins();

		$this->assertCount( 0, $this->logger->findings );
	}

	/**
	 * Regression guard: a folder whose name contains "shieldscope" is still scanned.
	 */
	public function test_folder_named_like_this_plugin_is_scanned() {
		$this->plugin_file( 'shieldscope-cache/x.php', $this->eval_payload() );

		$this->scan_plugins();

		$high = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $high );
		$this->assertStringContainsString( 'shieldscope-cache', $high[0]['target'] );
	}

	/**
	 * Bug: vendor/ was skipped entirely, so the eval/decode shape could hide there.
	 */
	public function test_vendor_is_scanned_for_eval_shape_only() {
		$this->plugin_file( 'lib-plugin/vendor/acme/lib/hidden.php', $this->eval_payload() );
		$this->plugin_file( 'lib-plugin/vendor/acme/lib/process.php', "<?php\nproc_open( \$cmd, \$spec, \$pipes );\necho \$_GET['q'];\n" );

		$this->scan_plugins();

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_HIGH, $this->logger->findings[0]['severity'] );
		$this->assertStringContainsString( 'hidden.php', $this->logger->findings[0]['target'] );
	}

	/**
	 * Bug: a regex failure (backtrack limit) was treated as "no match".
	 */
	public function test_regex_failure_reports_could_not_analyse() {
		$path = $this->plugin_file( 'pad-plugin/padded.php', $this->all_rules_payload() );
		ini_set( 'pcre.jit', '0' );
		ini_set( 'pcre.backtrack_limit', '1' );

		$this->scan_plugins();

		ini_set( 'pcre.backtrack_limit', (string) $this->saved_ini['pcre.backtrack_limit'] );
		$titles = array_column( $this->logger->findings, 'title' );
		$this->assertContains( 'Could not analyse: ' . $path, $titles );
		$this->assertSame( 1, count( array_keys( $titles, 'Could not analyse: ' . $path, true ) ) );
	}

	/**
	 * Bug: files skipped for size were not counted in the walker's skipped-files Info finding.
	 */
	public function test_file_skipped_for_size_is_counted_by_the_walker() {
		update_option( 'shieldscope_settings', array( 'max_scan_file_size' => 100 ) );
		$this->plugin_file( 'big-plugin/big.php', $this->eval_payload() . ' // ' . str_repeat( 'x', 500 ) );
		$this->plugin_file( 'big-plugin/small.php', "<?php\nreturn 1;\n" );

		$this->scan_plugins();

		$this->assertCount( 1, $this->logger->findings );
		$info = $this->logger->findings[0];
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $info['severity'] );
		$this->assertStringContainsString( 'Files skipped (too large or unreadable): 1.', $info['description'] );
	}
}
