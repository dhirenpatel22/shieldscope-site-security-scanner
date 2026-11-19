<?php
/**
 * Tests for S-06 (CSV/JSON): rows, formula neutralising, access.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S06b_CSV_JSON_Export
 */
class Test_S06b_CSV_JSON_Export extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	private function report() {
		return array(
			'site_url'     => 'https://shop.example.com/',
			'scan_id'      => 'scan_1',
			'scan_date'    => 'd',
			'generated'    => 'g',
			'version'      => SHIELDSCOPE_VERSION,
			'save_failed'  => false,
			'check_labels' => array( 'injection' => 'Injection Vulnerabilities' ),
			'coverage'     => array( 'injection' => array( 'label' => 'Injection Vulnerabilities', 'status' => 'done', 'notes' => array() ) ),
			'root'         => '/srv/site/',
			'findings'     => array(
				array(
					'severity'       => 'low',
					'check_id'       => 'injection',
					'title'          => '=HYPERLINK("http://evil.example","x")',
					'target'         => '/srv/site/wp-content/plugins/p/a.php',
					'description'    => 'Desc <b>x</b>, with "quotes"',
					'recommendation' => '+cmd',
					'context'        => wp_json_encode( array( 'confidence' => 'review', 'evidence' => array( 'line' => 7, 'snippet' => '@eval($x);' ) ) ),
				),
			),
		);
	}

	public function test_formula_cells_are_neutralised() {
		foreach ( array( '=1+1', '+1', '-1', '@SUM(A1)', "\tx", "\rx" ) as $v ) {
			$this->assertSame( "'" . $v, ShieldScope_Export::csv_cell( $v ), $v );
		}
		$this->assertSame( 'plain', ShieldScope_Export::csv_cell( 'plain' ) );
		$this->assertSame( '', ShieldScope_Export::csv_cell( '' ) );
	}

	public function test_csv_content() {
		$csv  = ShieldScope_Export::to_csv( $this->report() );
		$this->assertStringStartsWith( "\xEF\xBB\xBF" . 'severity,confidence,check,title,target,line,snippet,description,recommendation', $csv );
		$rows = array_map( 'str_getcsv', explode( "\n", trim( substr( $csv, 3 ) ) ) );
		$this->assertCount( 2, $rows );
		$this->assertSame(
			array( 'low', 'review', 'Injection Vulnerabilities', "'=HYPERLINK(\"http://evil.example\",\"x\")", 'wp-content/plugins/p/a.php', '7', "'@eval(\$x);", 'Desc x, with "quotes"', "'+cmd" ),
			$rows[1]
		);
	}

	public function test_json_content() {
		$data = json_decode( ShieldScope_Export::to_json( $this->report() ), true );
		$this->assertSame( 'ShieldScope', $data['tool'] );
		$this->assertTrue( $data['complete'] );
		$this->assertSame( 'done', $data['coverage']['injection']['status'] );
		$this->assertSame( 7, $data['findings'][0]['line'] );
		$this->assertSame( '=HYPERLINK("http://evil.example","x")', $data['findings'][0]['title'], 'JSON keeps values as they are.' );
	}

	public function test_handler_requires_capability_and_nonce() {
		ss_tests_override(
			'current_user_can',
			function () {
				return false;
			}
		);
		try {
			ShieldScope_Export::handle();
			$this->fail( 'Expected exit' );
		} catch ( SS_Test_Exit $e ) {
			$this->assertSame( 'Insufficient permissions.', $e->getMessage() );
		}
		ss_tests_reset_state();
		ss_tests_override(
			'check_admin_referer',
			function () {
				return false;
			}
		);
		$this->expectException( SS_Test_Exit::class );
		$this->expectExceptionMessage( 'bad nonce' );
		ShieldScope_Export::handle();
	}

	public function test_unknown_format_is_rejected() {
		$_GET['format'] = 'xml';
		try {
			$this->expectException( SS_Test_Exit::class );
			$this->expectExceptionMessage( 'Unknown export format.' );
			ShieldScope_Export::handle();
		} finally {
			unset( $_GET['format'] );
		}
	}
}
