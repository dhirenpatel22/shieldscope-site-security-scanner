<?php
/**
 * Tests for S-03: line, snippet and Confirmed / Needs review on findings.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Check that records whatever finding it is told to, for base-class tests.
 */
class SS_Test_Echo_Check extends ShieldScope_Check_Base {
	public function get_id() {
		return 'echo';
	}
	public function get_label() {
		return 'Echo';
	}
	public function get_steps() {
		return array();
	}
	public function run_step( $step, array $cursor = array() ) {
		return array( 'continue' => false, 'cursor' => array() );
	}
	public function emit( $severity, $title, $context = array() ) {
		$this->finding( $severity, $title, 'd', 'r', 't', $context );
	}
}

/**
 * Class Test_S03_Finding_Evidence
 */
class Test_S03_Finding_Evidence extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR, 0777, true );
		$this->logger = new SS_Fake_Logger();
	}

	private function plugin_file( $code ) {
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR . '/ev', 0777, true );
		file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . '/ev/main.php', $code );
	}

	private function run_check( $class ) {
		$check  = new $class( 'scan_t', $this->logger );
		$cursor = array();
		do {
			$r      = $check->run_step( 'scan_plugins', $cursor );
			$cursor = $r['cursor'];
		} while ( ! empty( $r['continue'] ) );
	}

	private function finding_titled( $prefix ) {
		foreach ( $this->logger->findings as $f ) {
			if ( 0 === strpos( $f['title'], $prefix ) ) {
				return $f;
			}
		}
		$this->fail( "No finding starting with $prefix" );
	}

	public function test_code_view_keeps_line_breaks() {
		$src = "<?php\n/* one\ntwo */\n\$a = 'x\ny';\n// c\n\$b = 1;\n?>\n<p>\nhtml\n</p>\n<?php \$c = 2;\n";
		$this->assertSame( substr_count( $src, "\n" ), substr_count( ShieldScope_Check_Base::code_view( $src ), "\n" ) );
		$this->assertSame( substr_count( $src, "\n" ), substr_count( ShieldScope_Check_Base::code_view( $src, true ), "\n" ) );
	}

	public function test_injection_evidence_points_at_the_right_line() {
		$this->plugin_file( "<?php\n/**\n * Doc block\n * over lines\n */\n\$help = 'multi\nline';\n\n\$data = unserialize( \$_POST['d'] );\n" );
		$this->run_check( 'ShieldScope_Check_Injection' );
		$f = $this->finding_titled( 'PHP Object Injection' );
		$this->assertSame( 9, $f['context']['evidence']['line'] );
		$this->assertSame( "\$data = unserialize( \$_POST['d'] );", $f['context']['evidence']['snippet'] );
		$this->assertSame( 'review', $f['context']['confidence'] );
	}

	public function test_taint_evidence_is_the_sink_line() {
		$this->plugin_file( "<?php\n\$order = wp_unslash( \$_GET['o'] );\n\$x = absint(\n  \$_GET['n']\n);\n\$wpdb->get_results( \"SELECT * FROM t ORDER BY \$order\" );\n" );
		$this->run_check( 'ShieldScope_Check_Injection' );
		$f = $this->finding_titled( 'Review: user input near a $wpdb query' );
		$this->assertSame( 6, $f['context']['evidence']['line'] );
		$this->assertSame( '$order', $f['context']['tainted_var'] );
	}

	public function test_code_pattern_evidence_after_comments() {
		$this->plugin_file( "<?php\n// system( 'x' );\n/*\n shell_exec( 'y' );\n*/\nsystem( \$cmd );\n" );
		$this->run_check( 'ShieldScope_Check_Code_Patterns' );
		$f = $this->finding_titled( 'Matches pattern: shell command function' );
		$this->assertSame( 6, $f['context']['evidence']['line'] );
		$this->assertSame( 'system( $cmd );', $f['context']['evidence']['snippet'] );
	}

	public function test_ssrf_evidence() {
		$this->plugin_file( "<?php\n\n\$r = wp_remote_get( \$_GET['u'] );\n" );
		$this->run_check( 'ShieldScope_Check_SSRF' );
		$f = $this->finding_titled( 'Review: user input near wp_remote_*()' );
		$this->assertSame( 3, $f['context']['evidence']['line'] );
	}

	public function test_long_snippet_is_truncated() {
		$ev = ShieldScope_Check_Base::evidence( str_repeat( 'a', 500 ), str_repeat( 'a', 500 ), 10 );
		$this->assertSame( 1, $ev['evidence']['line'] );
		$this->assertLessThanOrEqual( 160, mb_strlen( $ev['evidence']['snippet'] ) );
		$this->assertSame( array(), ShieldScope_Check_Base::evidence( 'x', 'x', -1 ) );
	}

	public function test_confidence_defaults_and_critical_cap() {
		$check = new SS_Test_Echo_Check( 'scan_t', $this->logger );
		$check->emit( ShieldScope_Logger::SEVERITY_CRITICAL, 'wp-config.php is readable' );
		$check->emit( ShieldScope_Logger::SEVERITY_CRITICAL, 'Matches pattern: something' );
		$check->emit( ShieldScope_Logger::SEVERITY_CRITICAL, 'Plain title', array( 'confidence' => 'review' ) );
		$f = $this->logger->findings;
		$this->assertSame( array( 'critical', 'confirmed' ), array( $f[0]['severity'], $f[0]['context']['confidence'] ) );
		$this->assertSame( array( 'high', 'review' ), array( $f[1]['severity'], $f[1]['context']['confidence'] ) );
		$this->assertSame( array( 'high', 'review' ), array( $f[2]['severity'], $f[2]['context']['confidence'] ) );
	}

	public function test_pdf_shows_line_snippet_and_label_escaped() {
		$report = array(
			'site_name'    => 'S',
			'site_url'     => 'https://s.example/',
			'scan_id'      => 's',
			'scan_date'    => '',
			'generated'    => '',
			'version'      => SHIELDSCOPE_VERSION,
			'save_failed'  => false,
			'check_labels' => array(),
			'root'         => '/w/',
			'findings'     => array(
				array(
					'check_id' => 'injection',
					'severity' => 'low',
					'title'    => 'Review: user input near echo ($q)',
					'target'   => '/w/wp-content/plugins/p/a.php',
					'context'  => wp_json_encode(
						array(
							'confidence' => 'review',
							'evidence'   => array(
								'line'    => 42,
								'snippet' => 'echo "<script>" . $q;',
							),
						)
					),
				),
			),
		);
		$html = ShieldScope_PDF_Report::build_html( $report );
		$this->assertStringContainsString( 'wp-content/plugins/p/a.php:42', $html );
		$this->assertStringContainsString( 'echo &quot;&lt;script&gt;&quot; . $q;', $html );
		$this->assertStringContainsString( 'Needs review', $html );
		$this->assertStringNotContainsString( '<script>', $html );
	}
}
