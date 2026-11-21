<?php
/**
 * Tests for S-05: verdict, fix-first list, headed severity sections, method.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S05_Report_Structure
 */
class Test_S05_Report_Structure extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	private function row( $severity, $title, $check = 'core' ) {
		return array(
			'severity'       => $severity,
			'title'          => $title,
			'check_id'       => $check,
			'description'    => 'D <b>bold</b>',
			'recommendation' => 'R',
			'target'         => 'x.php',
			'context'        => '',
			'created_at'     => '2026-11-01 09:30:00',
		);
	}

	private function render( array $findings ) {
		$last_scan = 'scan_s05';
		$summary   = array();
		ob_start();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/report.php';
		return ob_get_clean();
	}

	public function test_verdict_tiles_link_to_sections_and_fix_first() {
		$html = $this->render(
			array(
				$this->row( 'critical', 'Crit A' ),
				$this->row( 'high', 'High A' ),
				$this->row( 'low', 'Low A' ),
			)
		);
		$this->assertStringContainsString( '1 critical and 1 high findings need attention first.', $html );
		$this->assertStringContainsString( 'href="#shieldscope-sev-critical"', $html );
		$this->assertStringNotContainsString( 'href="#shieldscope-sev-medium"', $html, 'Empty severities are not links.' );
		$this->assertMatchesRegularExpression( '/<ol class="shieldscope-top-actions">.*Crit A.*High A.*<\/ol>/s', $html );
		$this->assertStringContainsString( 'id="shieldscope-sev-low"', $html );
		$this->assertStringNotContainsString( 'id="shieldscope-sev-medium"', $html, 'No section without findings.' );
		$this->assertStringNotContainsString( 'role="tablist"', $html );
	}

	public function test_method_and_no_findings_list() {
		ShieldScope_Coverage::save(
			'scan_s05',
			array(
				'core' => array( 'status' => 'done', 'notes' => array() ),
				'ssl'  => array( 'status' => 'done', 'notes' => array() ),
			),
			array( 'core' => 'WordPress Core', 'ssl' => 'SSL / TLS' )
		);
		$html = $this->render( array( $this->row( 'low', 'Low A', 'core' ) ) );
		$this->assertStringContainsString( 'Checks with no findings', $html );
		$this->assertMatchesRegularExpression( '/Checks with no findings<\/h2>\s*<p>SSL \/ TLS<\/p>/', $html );
		$this->assertStringContainsString( 'Method and limits', $html );
		$this->assertStringContainsString( 'does not mean the site is secure', $html );
	}

	public function test_verdict_names_only_nonzero_severities() {
		$this->assertSame( '4 high findings need attention first.', ShieldScope_PDF_Report::verdict( array( 'critical' => 0, 'high' => 4 ) ) );
		$this->assertSame( '1 critical finding needs attention first.', ShieldScope_PDF_Report::verdict( array( 'critical' => 1 ) ) );
		$this->assertSame( '2 critical and 3 high findings need attention first.', ShieldScope_PDF_Report::verdict( array( 'critical' => 2, 'high' => 3 ) ) );
	}

	public function test_check_label_not_raw_id() {
		$html = $this->render( array( $this->row( 'low', 'Low A', 'security_config' ) ) );
		$this->assertStringNotContainsString( '>security_config<', $html );
	}

	public function test_filter_controls_render_with_findings() {
		$html = $this->render( array( $this->row( 'low', 'Low A' ) ) );
		$this->assertStringContainsString( 'id="shieldscope-filter-text"', $html );
		$this->assertStringContainsString( 'id="shieldscope-filter-review"', $html );
	}

	public function test_description_html_is_escaped() {
		$html = $this->render( array( $this->row( 'low', 'Low A' ) ) );
		$this->assertStringNotContainsString( '<b>bold</b>', $html );
	}
}
