<?php
/**
 * Tests for ticket A-12b: injection and SSRF checks.
 *
 * Regressions covered:
 * - absint()/intval()/sanitize_key() results were tainted, and a value passed
 *   as a $wpdb->prepare() argument was reported as Critical "SQL Injection".
 * - Matches inside comments and string literals produced findings.
 * - Taint and co-occurrence findings were Critical/High/Medium and worded as
 *   confirmed vulnerabilities.
 * - Wrong advice: XXE advice recommended LIBXML_NOENT and the deprecated
 *   libxml_disable_entity_loader(); the pingback finding read a different
 *   option than the one it told the user to change; the oEmbed text called the
 *   proxy unauthenticated and its snippet named a function that does not exist;
 *   a co-occurrence finding cited a CVE for an unrelated product.
 * - preg_* failures were ignored, so a file could silently evade every rule.
 * - Files skipped for size were not counted by the walker's skipped-files note.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_A12b_Injection_SSRF
 */
class Test_A12b_Injection_SSRF extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var array */
	private $saved_ini = array();

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		update_option( 'shieldscope_settings', array( 'developer_review' => 1 ) );
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR, 0777, true );
		$this->logger = new SS_Fake_Logger();
	}

	protected function tearDown(): void {
		foreach ( $this->saved_ini as $key => $value ) {
			ini_set( $key, $value );
		}
		$this->saved_ini = array();
	}

	/**
	 * Write a plugin file under the fake plugins directory.
	 *
	 * @param string $name Plugin folder.
	 * @param string $code File contents.
	 */
	private function plugin_file( $name, $code ) {
		$dir = SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $name;
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0777, true );
		}
		file_put_contents( "$dir/main.php", $code );
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

	private function scan_injection() {
		$this->run_to_completion( new ShieldScope_Check_Injection( 'scan_t', $this->logger ), 'scan_plugins' );
	}

	private function scan_ssrf() {
		$this->run_to_completion( new ShieldScope_Check_SSRF( 'scan_t', $this->logger ), 'scan_plugins' );
	}

	/**
	 * Findings that are not the walker's "Some files were not scanned" note.
	 *
	 * @return array[]
	 */
	private function code_findings() {
		return array_values(
			array_filter(
				$this->logger->findings,
				static function ( $f ) {
					return 'Some files were not scanned' !== $f['title'];
				}
			)
		);
	}

	private function titles() {
		return array_column( $this->code_findings(), 'title' );
	}

	private function all_text() {
		$text = '';
		foreach ( $this->logger->findings as $f ) {
			$text .= $f['title'] . "\n" . $f['description'] . "\n" . $f['recommendation'] . "\n";
		}
		return $text;
	}

	// -----------------------------------------------------------------------
	// Taint logic
	// -----------------------------------------------------------------------

	public function test_absint_then_prepared_query_gives_no_finding() {
		$this->plugin_file(
			'prepared',
			"<?php\n\$id = absint( \$_GET['id'] );\n\$row = \$wpdb->get_row( \$wpdb->prepare( \"SELECT * FROM {\$wpdb->posts} WHERE ID = %d\", \$id ) );\n"
		);
		$this->scan_injection();
		$this->assertSame( array(), $this->titles() );
	}

	public function test_raw_input_as_prepare_argument_gives_no_sql_finding() {
		$this->plugin_file(
			'prepared-raw',
			"<?php\n\$name = wp_unslash( \$_POST['name'] );\n\$wpdb->query( \$wpdb->prepare( \"DELETE FROM t WHERE name = %s\", \$name ) );\n"
		);
		$this->scan_injection();
		$this->assertSame( array(), $this->titles() );
	}

	public function test_intval_and_sanitize_key_clear_taint() {
		$this->plugin_file(
			'casts',
			"<?php\n\$page = intval( \$_GET['page'] );\n\$tab_key = sanitize_key( \$_GET['tab'] );\n\$wpdb->get_results( \"SELECT * FROM t LIMIT \$page\" );\necho \$tab_key;\n"
		);
		$this->scan_injection();
		$this->assertSame( array(), $this->titles() );
	}

	public function test_ternary_with_absint_clears_taint() {
		$this->plugin_file(
			'ternary',
			"<?php\n\$post_id = isset( \$_GET['post'] ) ? absint( \$_GET['post'] ) : 0;\necho \$post_id;\n"
		);
		$this->scan_injection();
		$this->assertSame( array(), $this->titles() );
	}

	public function test_raw_input_interpolated_into_query_is_low_review_finding() {
		$this->plugin_file(
			'raw',
			"<?php\n\$order = sanitize_text_field( \$_GET['order'] );\n\$wpdb->get_results( \"SELECT * FROM t ORDER BY \$order\" );\n"
		);
		$this->scan_injection();
		$findings = $this->code_findings();
		$this->assertCount( 1, $findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $findings[0]['severity'] );
		$this->assertSame( 'Review: user input near a $wpdb query ($order)', $findings[0]['title'] );
	}

	public function test_tainted_var_in_prepare_query_string_is_still_reported() {
		$this->plugin_file(
			'prepare-misuse',
			"<?php\n\$order = wp_unslash( \$_GET['order'] );\n\$wpdb->get_results( \$wpdb->prepare( \"SELECT * FROM t WHERE a = %d ORDER BY \$order\", 1 ) );\n"
		);
		$this->scan_injection();
		$this->assertSame( array( 'Review: user input near a $wpdb query ($order)' ), $this->titles() );
	}

	// -----------------------------------------------------------------------
	// Comments and string literals
	// -----------------------------------------------------------------------

	public function test_matches_in_comments_and_string_literals_are_skipped() {
		$code = "<?php\n"
			. "// \$wpdb->query( \"SELECT * FROM t WHERE id = \$_GET[id]\" );\n"
			. "# unserialize( \$_POST['x'] );\n"
			. "/* extract( \$_POST ); wp_remote_get( \$_GET['url'] ); */\n"
			. "\$help = 'Never call unserialize( \$_POST[\"data\"] ) or file_get_contents( \$_GET[\"f\"] )';\n"
			. "\$doc = <<<'TXT'\ncall_user_func( \$_GET['cb'] ); it's fine\nTXT;\n"
			. "?>\n<p>Don't echo \"\$_GET[x]\" or wp_redirect( \$_GET['to'] ).</p>\n<?php\n"
			. "return \$help . \$doc;\n";
		$this->plugin_file( 'commented', $code );
		$this->scan_injection();
		$this->scan_ssrf();
		$this->assertSame( array(), $this->titles() );
	}

	public function test_real_code_after_apostrophe_in_html_is_still_scanned() {
		$code = "<p>Don't do this.</p>\n<?php\n\$data = unserialize( \$_POST['data'] );\n";
		$this->plugin_file( 'html-first', $code );
		$this->scan_injection();
		$this->assertContains( 'PHP Object Injection: deserialization of direct user input', $this->titles() );
	}

	public function test_code_view_keeps_interpolated_variables() {
		$view = ShieldScope_Check_Injection::code_view( "<?php \$a = \"id = \$_GET[id]\"; // \$_POST\n\$b = 'x\$_COOKIE(';" );
		$this->assertStringContainsString( '$_GET[id]', $view );
		$this->assertStringNotContainsString( '$_POST', $view );
		$this->assertStringNotContainsString( '$_COOKIE', $view );
	}

	// -----------------------------------------------------------------------
	// Caps and wording
	// -----------------------------------------------------------------------

	public function test_taint_findings_are_capped_at_low_with_review_wording() {
		$this->plugin_file(
			'taint-all',
			"<?php\n"
			. "\$payload = \$_POST['payload'];\n"
			. "maybe_unserialize( \$payload );\n"
			. "eval( \$payload );\n"
			. "shell_exec( \$payload );\n"
			. "include \$payload;\n"
			. "echo \$payload;\n"
			. "call_user_func( \$payload );\n"
			. "\$wpdb->query( \$payload );\n"
		);
		$this->scan_injection();
		$findings = $this->code_findings();
		// Seven sinks plus the "user input near maybe_unserialize()" co-occurrence.
		$this->assertCount( 8, $findings );
		foreach ( $findings as $f ) {
			$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $f['severity'], $f['title'] );
			$this->assertStringStartsWith( 'Review: user input near ', $f['title'] );
			$this->assertStringContainsString( 'not a confirmed vulnerability', $f['description'] );
		}
	}

	public function test_cooccurrence_findings_are_capped_at_low_with_review_wording() {
		$cases = array(
			'nopriv' => "<?php\nadd_action( 'wp_ajax_nopriv_x', 'cb' );\nfunction cb() { return maybe_unserialize( \$GLOBALS['v'] ); }\n",
			'input'  => "<?php\n\$k = \$_POST['k'] ?? '';\n\$v = maybe_unserialize( \$value );\n",
			'ajax'   => "<?php\nadd_action( 'wp_ajax_x', 'cb' );\nfunction cb() { return maybe_unserialize( \$value ); }\n",
			'parse'  => "<?php\nwp_parse_str( \$_POST['form'], \$fields );\n",
		);
		foreach ( $cases as $name => $code ) {
			$this->plugin_file( "co-$name", $code );
		}
		$this->scan_injection();
		$findings = $this->code_findings();
		$this->assertCount( 4, $findings );
		foreach ( $findings as $f ) {
			$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $f['severity'], $f['title'] );
			$this->assertStringStartsWith( 'Review: user input near ', $f['title'] );
		}
	}

	public function test_no_cve_is_cited_in_injection_check_text() {
		$source = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'includes/checks/class-shieldscope-check-injection.php' );
		$this->assertStringNotContainsString( 'CVE-2023-3681', $source );
		$this->assertDoesNotMatchRegularExpression( '/CVE-\d{4}-\d+/', $source );
	}

	// -----------------------------------------------------------------------
	// Advice
	// -----------------------------------------------------------------------

	public function test_xxe_advice_does_not_recommend_noent_or_deprecated_loader() {
		$this->plugin_file( 'xxe', "<?php\n\$xml = simplexml_load_string( \$_POST['xml'] );\n" );
		$this->scan_injection();
		$xxe = $this->code_findings();
		$this->assertCount( 1, $xxe );
		$advice = $xxe[0]['recommendation'];
		$this->assertStringNotContainsString( 'libxml_disable_entity_loader', $advice );
		$this->assertMatchesRegularExpression( '/Do not pass LIBXML_NOENT/', $advice );
		$this->assertDoesNotMatchRegularExpression( '/(?<!not pass )LIBXML_NOENT/', $advice );
	}

	public function test_pingback_finding_reads_and_names_default_ping_status() {
		update_option( 'default_pingback_flag', '1' );
		update_option( 'default_ping_status', 'closed' );
		$this->run_to_completion( new ShieldScope_Check_SSRF( 'scan_t', $this->logger ), 'wp_features' );
		$this->assertNotContains( 'Pingbacks are allowed on new posts', $this->titles(), 'Outbound pingback flag is not the inbound pingback setting.' );

		$this->logger = new SS_Fake_Logger();
		update_option( 'default_pingback_flag', '0' );
		update_option( 'default_ping_status', 'open' );
		$this->run_to_completion( new ShieldScope_Check_SSRF( 'scan_t', $this->logger ), 'wp_features' );
		$ping = array_values(
			array_filter(
				$this->logger->findings,
				static function ( $f ) {
					return 'Pingbacks are allowed on new posts' === $f['title'];
				}
			)
		);
		$this->assertCount( 1, $ping );
		$this->assertStringContainsString( 'Allow link notifications from other blogs (pingbacks and trackbacks) on new posts', $ping[0]['recommendation'] );
	}

	public function test_oembed_text_says_edit_posts_and_snippet_names_real_function() {
		ss_tests_override(
			'wp_remote_get',
			function () {
				return array( 'response' => array( 'code' => 200 ), 'body' => '{}' );
			}
		);
		$this->run_to_completion( new ShieldScope_Check_SSRF( 'scan_t', $this->logger ), 'wp_features' );
		$oembed = array_values(
			array_filter(
				$this->logger->findings,
				static function ( $f ) {
					return false !== strpos( $f['title'], 'oEmbed' );
				}
			)
		);
		$this->assertCount( 1, $oembed );
		$this->assertStringContainsString( 'edit_posts', $oembed[0]['description'] );
		$this->assertStringContainsString( "remove_action( 'rest_api_init', 'wp_oembed_register_route' );", $oembed[0]['recommendation'] );
		$this->assertStringNotContainsString( 'wp_oembed_register_routes', $oembed[0]['recommendation'] );
	}

	public function test_code_snippets_in_advice_lint() {
		ss_tests_override(
			'wp_remote_get',
			function () {
				return array( 'response' => array( 'code' => 200 ), 'body' => '{}' );
			}
		);
		$this->run_to_completion( new ShieldScope_Check_SSRF( 'scan_t', $this->logger ), 'wp_features' );
		$snippet = "remove_action( 'rest_api_init', 'wp_oembed_register_route' );";
		$tmp     = tempnam( sys_get_temp_dir(), 'ss-lint' );
		file_put_contents( $tmp, "<?php\n" . $snippet . "\n" );
		exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $tmp ) . ' 2>&1', $out, $code );
		unlink( $tmp );
		$this->assertSame( 0, $code, implode( "\n", $out ) );
		$this->assertStringContainsString( $snippet, $this->all_text() );
	}

	// -----------------------------------------------------------------------
	// preg_last_error() and skipped-file counting
	// -----------------------------------------------------------------------

	private function force_regex_failure() {
		foreach ( array( 'pcre.jit' => '0', 'pcre.backtrack_limit' => '50' ) as $key => $value ) {
			$this->saved_ini[ $key ] = ini_get( $key );
			ini_set( $key, $value );
		}
	}

	/**
	 * A call padded after the request data, so the rule has to backtrack over
	 * all the filler to find it: the evasion this guards against.
	 *
	 * @param string $call Function name.
	 * @return string
	 */
	private function padded_call( $call ) {
		return "<?php\n\$x = $call( \$_POST['p']" . str_repeat( ' . $a', 200 ) . " );\n";
	}

	public function test_padded_call_matches_without_a_limit() {
		$this->plugin_file( 'huge', $this->padded_call( 'unserialize' ) );
		$this->scan_injection();
		$this->assertContains( 'PHP Object Injection: deserialization of direct user input', $this->titles() );
	}

	public function test_regex_failure_reports_could_not_analyse_in_injection_check() {
		$this->plugin_file( 'huge', $this->padded_call( 'unserialize' ) );
		$this->force_regex_failure();
		$this->scan_injection();
		$this->assertContains( 'Could not analyse: ' . SHIELDSCOPE_WP_PLUGINS_DIR . '/huge/main.php', $this->titles() );
	}

	public function test_regex_failure_reports_could_not_analyse_in_ssrf_check() {
		$this->plugin_file( 'huge', $this->padded_call( 'wp_remote_get' ) );
		$this->force_regex_failure();
		$this->scan_ssrf();
		$this->assertContains( 'Could not analyse: ' . SHIELDSCOPE_WP_PLUGINS_DIR . '/huge/main.php', $this->titles() );
	}

	public function test_oversized_files_are_counted_as_skipped_by_both_checks() {
		update_option( 'shieldscope_settings', array( 'max_scan_file_size' => 100, 'developer_review' => 1 ) );
		$this->plugin_file( 'big', "<?php\n// " . str_repeat( 'x', 500 ) . "\n" );
		foreach ( array( 'ShieldScope_Check_Injection', 'ShieldScope_Check_SSRF' ) as $class ) {
			$this->logger = new SS_Fake_Logger();
			$this->run_to_completion( new $class( 'scan_t', $this->logger ), 'scan_plugins' );
			$this->assertCount( 1, $this->logger->findings, $class );
			$this->assertSame( 'Some files were not scanned', $this->logger->findings[0]['title'], $class );
			$this->assertStringContainsString( 'Files skipped (too large or unreadable): 1.', $this->logger->findings[0]['description'], $class );
		}
	}

	// -----------------------------------------------------------------------
	// Well-built plugin fixture
	// -----------------------------------------------------------------------

	public function test_well_built_plugin_gives_no_critical_or_high() {
		$code = <<<'PHP'
<?php
/**
 * Example of careful code. Never do $wpdb->query( "... $_GET[id]" ) or
 * unserialize( $_POST['x'] ); see the docs.
 */
defined( 'ABSPATH' ) || exit;

add_action( 'wp_ajax_wb_save', 'wb_save' );
add_action( 'wp_ajax_nopriv_wb_view', 'wb_view' );

function wb_save() {
	check_ajax_referer( 'wb_save' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_send_json_error( null, 403 );
	}
	global $wpdb;
	$post_id = isset( $_POST['post_id'] ) ? absint( $_POST['post_id'] ) : 0;
	$count   = intval( $_POST['count'] );
	$status  = sanitize_key( $_POST['status'] );
	$title   = sanitize_text_field( wp_unslash( $_POST['title'] ) );
	$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->posts} SET post_title = %s WHERE ID = %d", $title, $post_id ) );
	$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d AND post_status = %s LIMIT %d", $post_id, $status, $count ) );
	$meta = maybe_unserialize( get_post_meta( $post_id, 'wb', true ) );
	wp_send_json_success( array( 'row' => $row, 'meta' => $meta ) );
}

function wb_view() {
	$id = absint( $_GET['id'] );
	echo esc_html( get_the_title( $id ) );
	printf( '<p>%s</p>', esc_html( wp_unslash( $_GET['q'] ) ) );
	echo $id;
	$redirect = wp_validate_redirect( wp_unslash( $_GET['to'] ), home_url() );
	wp_safe_redirect( $redirect );
	exit;
}
PHP;
		$this->plugin_file( 'well-built', $code );
		$this->scan_injection();
		$this->scan_ssrf();
		$this->assertSame( array(), $this->logger->of_severity( ShieldScope_Logger::SEVERITY_CRITICAL ), implode( "\n", $this->titles() ) );
		$this->assertSame( array(), $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH ), implode( "\n", $this->titles() ) );
	}
}
