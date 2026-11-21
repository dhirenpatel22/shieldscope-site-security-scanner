<?php
/**
 * Fixture tests for false positives found by the S-25 corpus, and the true
 * positives the same rules must still find.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S25_FP_Fixtures
 */
class Test_S25_FP_Fixtures extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR . '/fx', 0777, true );
	}

	private function titles_for( $code ) {
		file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . '/fx/main.php', $code );
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Code_Patterns( 's', $logger );
		$cursor = array();
		do {
			$r      = $check->run_step( 'scan_plugins', $cursor );
			$cursor = $r['cursor'];
		} while ( ! empty( $r['continue'] ) );
		return array_column( $logger->findings, 'title' );
	}

	/**
	 * @dataProvider false_positives
	 */
	public function test_no_finding( $code ) {
		$this->assertSame( array(), $this->titles_for( $code ) );
	}

	public function false_positives() {
		$b64 = str_repeat( 'QUJD', 120 );
		return array(
			'require in a comment (wpforms-lite)'   => array( "<?php\n// For dynamic population we require \$_GET.\n" ),
			'system as array key (wpforms-lite)'    => array( "<?php\n\$v = array( 'system' => new Views\\System() );\n" ),
			'system in a string (woocommerce)'      => array( "<?php\n\$l = __( 'File system (default)', 'x' );\n" ),
			'System in a description (woocommerce)' => array( "<?php\n\$d = 'Identifies the Virtual File System (VFS)';\n" ),
			'data URI icon (woocommerce)'           => array( "<?php\n\$i = 'data:image/svg+xml;base64,$b64';\n" ),
			'base64 in a docblock (jetpack)'        => array( "<?php\n/**\n * $b64\n */\n" ),
			'echo of request data in a string'      => array( "<?php\n\$h = 'echo \$_GET[x]';\n" ),
			'method named system'                   => array( "<?php\n\$x->system( 1 ); Foo::system( 2 );\n" ),
		);
	}

	/**
	 * @dataProvider true_positives
	 */
	public function test_still_found( $code, $title ) {
		$this->assertContains( $title, $this->titles_for( $code ) );
	}

	public function true_positives() {
		return array(
			'shell call'       => array( "<?php\nsystem( \$cmd );\n", 'Matches pattern: shell command function' ),
			'include request'  => array( "<?php\ninclude \$_GET['f'];\n", 'Matches pattern: include/require of request data' ),
			'echo request'     => array( "<?php\necho \$_GET['q'];\n", 'Matches pattern: echo of request data' ),
			'long base64 blob' => array( "<?php\n\$p = '" . str_repeat( 'QUJD', 120 ) . "';\n", 'Matches pattern: long encoded string' ),
			'wpdb string'      => array( "<?php\n\$wpdb->query( \"DELETE FROM t WHERE id = \$_GET[id]\" );\n", 'Matches pattern: request data in a database query string' ),
		);
	}
}
