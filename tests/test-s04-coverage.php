<?php
/**
 * Tests for S-04: per-check status and coverage line.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S04_Coverage
 */
class Test_S04_Coverage extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		update_option( 'shieldscope_settings', array( 'developer_review' => 1 ) );
	}

	public function test_save_marks_missing_checks_as_not_run_and_summarises() {
		ShieldScope_Coverage::save(
			'scan_a',
			array(
				'core'  => array( 'status' => 'done', 'notes' => array() ),
				'files' => array( 'status' => 'partial', 'notes' => array( '3 file(s) and 0 folder(s) not scanned' ) ),
				'ssl'   => array( 'status' => 'error', 'notes' => array( 'step "tls" failed with an error' ) ),
			),
			array( 'core' => 'Core', 'files' => 'Files', 'ssl' => 'SSL', 'vuln' => 'Vulnerabilities' )
		);
		$checks = ShieldScope_Coverage::get( 'scan_a' );
		$this->assertSame( array( 'core', 'files', 'ssl', 'vuln' ), array_keys( $checks ) );
		$this->assertSame( 'not_run', $checks['vuln']['status'] );
		$this->assertSame( 'Files', $checks['files']['label'] );
		$this->assertSame(
			'1 of 4 checks completed in full. 1 partly completed; 1 failed with an error; 1 did not run.',
			ShieldScope_Coverage::summary( $checks )
		);
		$this->assertNull( ShieldScope_Coverage::get( 'other_scan' ), 'Coverage belongs to one scan only.' );
	}

	public function test_all_done_summary() {
		$this->assertSame(
			'2 of 2 checks completed in full.',
			ShieldScope_Coverage::summary( array( 'a' => array( 'status' => 'done' ), 'b' => array( 'status' => 'done' ) ) )
		);
	}

	public function test_mark_check_keeps_the_worst_status_and_all_notes() {
		$method = new ReflectionMethod( 'ShieldScope_Scanner', 'mark_check' );
		$method->setAccessible( true );
		$check = new ShieldScope_Check_Core( 's', new SS_Fake_Logger() );
		$state = array( 'check_status' => array() );
		$state = $method->invoke( null, $state, $check, 'partial', 'n1' );
		$state = $method->invoke( null, $state, $check, 'done' );
		$state = $method->invoke( null, $state, $check, 'error', 'n2' );
		$state = $method->invoke( null, $state, $check, 'partial', 'n1' );
		$this->assertSame( array( 'status' => 'error', 'notes' => array( 'n1', 'n2' ) ), $state['check_status'][ $check->get_id() ] );
	}

	public function test_walker_skips_raise_a_partial_note() {
		update_option( 'shieldscope_settings', array( 'max_scan_file_size' => 50, 'developer_review' => 1 ) );
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR . '/p', 0777, true );
		file_put_contents( SHIELDSCOPE_WP_PLUGINS_DIR . '/p/big.php', "<?php\n// " . str_repeat( 'x', 200 ) );
		$check  = new ShieldScope_Check_Injection( 's', new SS_Fake_Logger() );
		$cursor = array();
		$notes  = array();
		do {
			$r      = $check->run_step( 'scan_plugins', $cursor );
			$cursor = $r['cursor'];
			$notes  = array_merge( $notes, $check->take_coverage_notes() );
		} while ( ! empty( $r['continue'] ) );
		$this->assertSame( array( '1 file(s) and 0 folder(s) not scanned' ), $notes );
		$this->assertSame( array(), $check->take_coverage_notes(), 'Notes are cleared once taken.' );
	}

	public function test_pdf_shows_coverage() {
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
			'findings'     => array( array( 'severity' => 'info', 'title' => 'x' ) ),
			'coverage'     => array(
				'vuln_db' => array( 'label' => 'Vulnerability Database', 'status' => 'partial', 'notes' => array( 'only the limited built-in list was checked (no WPScan API key)' ) ),
				'core'    => array( 'label' => 'Core', 'status' => 'done', 'notes' => array() ),
			),
		);
		$html = ShieldScope_PDF_Report::build_html( $report );
		$this->assertStringContainsString( 'Coverage: 1 of 2 checks completed in full. 1 partly completed.', $html );
		$this->assertStringContainsString( 'only the limited built-in list was checked', $html );
	}
}
