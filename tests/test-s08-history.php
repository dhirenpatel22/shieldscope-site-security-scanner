<?php
/**
 * Tests for S-08: scan history and comparison.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S08_History
 */
class Test_S08_History extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	private function row( $title, $target = 'a.php', $sev = 'low' ) {
		return array( 'check_id' => 'c', 'title' => $title, 'target' => $target, 'severity' => $sev );
	}

	public function test_record_keeps_newest_five_without_duplicates() {
		for ( $i = 1; $i <= 7; $i++ ) {
			ShieldScope_History::record( "s$i", array( 'high' => $i ) );
		}
		ShieldScope_History::record( 's7', array( 'high' => 9 ) );
		$this->assertSame( array( 's7', 's6', 's5', 's4', 's3' ), ShieldScope_History::ids() );
		$this->assertSame( 9, ShieldScope_History::all()[0]['counts']['high'] );
		$this->assertSame( 's6', ShieldScope_History::previous( 's7' )['scan_id'] );
		$this->assertNull( ShieldScope_History::previous( 's3' ) );
	}

	public function test_compare_new_fixed_open() {
		$cmp = ShieldScope_History::compare(
			array( $this->row( 'A' ), $this->row( 'B' ), $this->row( 'C', 'c.php' ) ),
			array( $this->row( 'A' ), $this->row( 'D' ) )
		);
		$this->assertSame( array( 'B', 'C' ), array_column( $cmp['new'], 'title' ) );
		$this->assertSame( array( 'D' ), array_column( $cmp['fixed'], 'title' ) );
		$this->assertSame( 1, $cmp['open'] );
	}

	public function test_pdf_shows_comparison_line() {
		$report = array(
			'site_name' => 'S', 'site_url' => 'https://s.example/', 'scan_id' => 's', 'scan_date' => '', 'generated' => '',
			'version' => SHIELDSCOPE_VERSION, 'save_failed' => false, 'check_labels' => array(), 'root' => '/w/',
			'findings' => array( $this->row( 'A' ) ),
			'comparison' => array( 'previous' => array( 'date' => '2026-11-01 10:00:00' ), 'new' => array( 1 ), 'fixed' => array( 1, 2 ), 'open' => 3 ),
		);
		$this->assertStringContainsString( 'Since the previous scan (2026-11-01): 1 new, 2 fixed, 3 still open.', ShieldScope_PDF_Report::build_html( $report ) );
	}
}
