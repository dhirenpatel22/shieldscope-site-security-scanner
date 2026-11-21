<?php
/**
 * Review 2, SC2-01: large or dense files must not exhaust memory.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Check exposing the protected views() helper.
 */
class SS_R2_Views_Check extends ShieldScope_Check_Base {
	public function get_id() {
		return 'r2views';
	}
	public function get_label() {
		return 'R2 views';
	}
	public function get_steps() {
		return array();
	}
	public function run_step( $step, array $cursor = array() ) {
		return array( 'continue' => false, 'cursor' => array() );
	}
	public function views_for( $contents ) {
		return $this->views( $contents );
	}
}

/**
 * Class Test_R2_Memory
 */
class Test_R2_Memory extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	public function test_bytes_from_ini() {
		$this->assertSame( 134217728, ShieldScope_Check_Base::bytes_from_ini( '128M' ) );
		$this->assertSame( 1073741824, ShieldScope_Check_Base::bytes_from_ini( '1G' ) );
		$this->assertSame( 65536, ShieldScope_Check_Base::bytes_from_ini( '64k' ) );
		$this->assertSame( -1, ShieldScope_Check_Base::bytes_from_ini( '-1' ) );
	}

	public function test_size_threshold() {
		$this->assertTrue( ShieldScope_Check_Base::can_tokenize( 100000 ) );
		$this->assertFalse( ShieldScope_Check_Base::can_tokenize( ShieldScope_Check_Base::TOKENIZE_MAX_BYTES + 1 ) );
	}

	public function test_careful_mode_uses_raw_text_and_notes_it() {
		$check = new SS_R2_Views_Check( 's', new SS_Fake_Logger() );
		$src   = "<?php\n// comment\n\$a = 'x';\n";
		$this->assertNotSame( array( $src, $src ), $check->views_for( $src ) );
		$this->assertSame( array(), $check->take_coverage_notes() );
		$check->set_careful( true );
		$this->assertSame( array( $src, $src ), $check->views_for( $src ) );
		$this->assertCount( 1, $check->take_coverage_notes() );
	}

	public function test_one_pass_gives_both_views() {
		list( $code, $keep ) = ShieldScope_Check_Base::code_views( "<?php\n// c\n\$a = 'str';\n" );
		$this->assertSame( ShieldScope_Check_Base::code_view( "<?php\n// c\n\$a = 'str';\n" ), $code );
		$this->assertStringContainsString( "'str'", $keep );
		$this->assertStringNotContainsString( '// c', $keep );
	}

	public function test_dense_file_does_not_exhaust_96m() {
		$script = tempnam( sys_get_temp_dir(), 'ss-mem' ) . '.php';
		file_put_contents(
			$script,
			'<?php require ' . var_export( SHIELDSCOPE_PLUGIN_DIR . 'tests/bootstrap.php', true ) . ';
			ss_tests_reset_state(); ss_tests_reset_wp_root();
			update_option( "shieldscope_settings", array( "developer_review" => 1, "max_scan_file_size" => 4194304 ) );
			mkdir( SHIELDSCOPE_WP_PLUGINS_DIR . "/dense", 0777, true );
			file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . "/dense/d.php", "<?php\n" . str_repeat( "\$a=1;\$b=2;\$c=\$a+\$b;", 100000 ) . "\n\$d = unserialize( \$_POST[\"x\"] );\n" );
			$n = 0;
			foreach ( array( "ShieldScope_Check_Code_Patterns", "ShieldScope_Check_Injection", "ShieldScope_Check_SSRF", "ShieldScope_Check_Access_Control" ) as $c ) {
				$l = new SS_Fake_Logger(); $k = new $c( "s", $l ); $cur = array();
				do { $r = $k->run_step( "scan_plugins", $cur ); $cur = $r["cursor"]; } while ( ! empty( $r["continue"] ) );
				$n += count( $l->findings );
			}
			echo "OK " . $n;'
		);
		exec( escapeshellarg( PHP_BINARY ) . ' -d memory_limit=96M ' . escapeshellarg( $script ) . ' 2>&1', $out, $code );
		unlink( $script );
		$text = implode( "\n", $out );
		$this->assertSame( 0, $code, $text );
		$this->assertMatchesRegularExpression( '/OK [1-9]/', $text, 'The real match at the end of the file is still found.' );
	}
}
