<?php
/**
 * Tests for S-07: ignore a finding with a reason.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S07_Ignore
 */
class Test_S07_Ignore extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	private function row( $severity, $title, $target = 'a.php' ) {
		return array(
			'severity'       => $severity,
			'title'          => $title,
			'check_id'       => 'code_patterns',
			'description'    => 'D',
			'recommendation' => 'R',
			'target'         => $target,
			'context'        => '',
			'created_at'     => '2026-11-01 09:30:00',
		);
	}

	public function test_fingerprint_is_stable_and_ignores_line_changes() {
		$a = $this->row( 'low', 'T' );
		$b = $this->row( 'low', 'T' );
		$b['context'] = '{"evidence":{"line":99}}';
		$this->assertSame( ShieldScope_Ignore::fingerprint( $a ), ShieldScope_Ignore::fingerprint( $b ) );
		$this->assertNotSame( ShieldScope_Ignore::fingerprint( $a ), ShieldScope_Ignore::fingerprint( $this->row( 'low', 'T', 'b.php' ) ) );
	}

	public function test_add_validates_reason_and_required_notes() {
		$this->assertSame( 'Choose a reason.', ShieldScope_Ignore::add( $this->row( 'low', 'T' ), 'nope', '' ) );
		$this->assertStringStartsWith( 'Add a note', ShieldScope_Ignore::add( $this->row( 'critical', 'C' ), 'accepted', '  ' ) );
		$this->assertStringStartsWith( 'Add a note', ShieldScope_Ignore::add( $this->row( 'low', 'T' ), 'other', '' ) );
		$this->assertSame( '', ShieldScope_Ignore::add( $this->row( 'low', 'T' ), 'false_positive', '<b>Vendor</b> library' ) );
		$entry = current( ShieldScope_Ignore::all() );
		$this->assertSame( 'Vendor library', $entry['note'] );
		$this->assertSame( 'auditor', $entry['user'] );
	}

	public function test_split_and_restore() {
		$rows = array( $this->row( 'low', 'T' ), $this->row( 'high', 'H' ) );
		ShieldScope_Ignore::add( $rows[0], 'accepted', '' );
		list( $active, $ignored ) = ShieldScope_Ignore::split( $rows );
		$this->assertSame( array( 'H' ), array_column( $active, 'title' ) );
		$this->assertSame( 'T', $ignored[0]['title'] );
		$this->assertStringStartsWith( 'Accepted risk (auditor, ', ShieldScope_Ignore::describe( $ignored[0]['ignored'] ) );
		ShieldScope_Ignore::restore( ShieldScope_Ignore::fingerprint( $rows[0] ) );
		list( $active ) = ShieldScope_Ignore::split( $rows );
		$this->assertCount( 2, $active );
	}

	public function test_report_page_hides_counts_but_lists_ignored() {
		$critical = $this->row( 'critical', 'Crit A' );
		ShieldScope_Ignore::add( $critical, 'handled', 'WAF at the CDN blocks this' );
		$findings  = array( $critical, $this->row( 'low', 'Low A' ) );
		$last_scan = 'scan_s07';
		$summary   = array();
		ob_start();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/report.php';
		$html = ob_get_clean();
		$this->assertStringContainsString( 'No critical or high findings.', $html );
		$this->assertStringContainsString( 'Ignored finding (1)', $html );
		$this->assertStringContainsString( 'WAF at the CDN blocks this', $html );
		$this->assertStringContainsString( 'name="do" value="restore"', $html );
		$this->assertStringNotContainsString( 'id="shieldscope-sev-critical"', $html );
	}

	public function test_all_ignored_is_not_reported_as_expired() {
		$row = $this->row( 'low', 'Only' );
		ShieldScope_Ignore::add( $row, 'accepted', '' );
		$findings  = array( $row );
		$last_scan = 'scan_s07';
		$summary   = array();
		ob_start();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/report.php';
		$html = ob_get_clean();
		$this->assertStringNotContainsString( 'Report expired', $html );
		$this->assertStringContainsString( 'Ignored finding (1)', $html );
	}

	public function test_pdf_and_csv_show_ignored_items_with_reason() {
		$crit = $this->row( 'critical', 'Crit A' );
		ShieldScope_Ignore::add( $crit, 'accepted', 'Owner accepts' );
		$report = array(
			'site_name' => 'S', 'site_url' => 'https://s.example/', 'scan_id' => 's', 'scan_date' => '', 'generated' => '',
			'version' => SHIELDSCOPE_VERSION, 'save_failed' => false, 'check_labels' => array(), 'root' => '/w/',
			'findings' => array( $crit, $this->row( 'low', 'Low A' ) ),
		);
		$html = ShieldScope_PDF_Report::build_html( $report );
		$this->assertStringContainsString( 'No critical or high findings.', $html );
		$this->assertStringContainsString( 'Ignored findings', $html );
		$this->assertStringContainsString( 'Owner accepts', $html );
		$this->assertStringContainsString( 'Owner accepts', ShieldScope_Export::to_csv( $report ) );
	}

	public function test_handler_checks_access() {
		ss_tests_override(
			'current_user_can',
			function () {
				return false;
			}
		);
		$this->expectException( SS_Test_Exit::class );
		$this->expectExceptionMessage( 'Insufficient permissions.' );
		ShieldScope_Ignore::handle();
	}
}
