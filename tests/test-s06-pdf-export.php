<?php
/**
 * Tests for S-06: PDF export of the last completed scan.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S06_PDF_Export
 */
class Test_S06_PDF_Export extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	/**
	 * Minimal report array.
	 *
	 * @param array $findings Findings.
	 * @return array
	 */
	private function report( array $findings ) {
		return array(
			'site_name'    => 'Example <b>Shop</b>',
			'site_url'     => 'https://shop.example.com/',
			'scan_id'      => 'scan_123',
			'scan_date'    => '19 November 2026 10:00',
			'generated'    => '19 November 2026 10:05',
			'version'      => SHIELDSCOPE_VERSION,
			'save_failed'  => false,
			'findings'     => $findings,
			'check_labels' => array( 'code_patterns' => 'Code Patterns' ),
			'root'         => '/srv/www/site/',
		);
	}

	private function finding( $severity, $title, $target = '', $extra = array() ) {
		return array_merge(
			array(
				'check_id'       => 'code_patterns',
				'severity'       => $severity,
				'title'          => $title,
				'description'    => 'Description.',
				'recommendation' => 'Recommendation.',
				'target'         => $target,
			),
			$extra
		);
	}

	public function test_untrusted_values_are_escaped() {
		$html = ShieldScope_PDF_Report::build_html(
			$this->report(
				array(
					$this->finding(
						'high',
						'<script>alert(1)</script>',
						'/srv/www/site/wp-content/plugins/x/<img src=file:///etc/passwd>.php',
						array(
							'description'    => '<link rel="stylesheet" href="https://evil.example/x.css">',
							'recommendation' => '<style>@import url(https://evil.example/y.css);</style>',
						)
					),
				)
			)
		);
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringNotContainsString( '<img', $html );
		$this->assertStringNotContainsString( '<link', $html );
		$this->assertStringNotContainsString( '<b>Shop', $html );
		$this->assertSame( 1, substr_count( $html, '<style>' ), 'Only the report stylesheet.' );
		$this->assertStringContainsString( '&lt;script&gt;alert(1)&lt;/script&gt;', $html );
		$this->assertStringContainsString( 'Example &lt;b&gt;Shop&lt;/b&gt;', $html );
	}

	public function test_paths_are_relative_to_the_wordpress_root() {
		$this->assertSame( 'wp-content/plugins/a/b.php', ShieldScope_PDF_Report::relative_target( '/srv/www/site/wp-content/plugins/a/b.php', '/srv/www/site/' ) );
		$this->assertSame( 'wp-config.php', ShieldScope_PDF_Report::relative_target( 'C:\\www\\wp-config.php', 'C:\\www' ) );
		$this->assertSame( 'php.ini', ShieldScope_PDF_Report::relative_target( 'php.ini', '/srv/www/site/' ) );
		$this->assertSame( '/other/file.php', ShieldScope_PDF_Report::relative_target( '/other/file.php', '/srv/www/site/' ) );

		$html = ShieldScope_PDF_Report::build_html( $this->report( array( $this->finding( 'low', 'T', '/srv/www/site/wp-content/x.php' ) ) ) );
		$this->assertStringContainsString( '<li>wp-content/x.php</li>', $html );
		$this->assertStringNotContainsString( '/srv/www/site', $html );
	}

	public function test_same_title_is_grouped_and_long_target_lists_are_capped() {
		$findings = array();
		for ( $i = 0; $i < ShieldScope_PDF_Report::MAX_TARGETS + 5; $i++ ) {
			$findings[] = $this->finding( 'medium', 'Repeated issue', "/srv/www/site/f$i.php" );
		}
		$html = ShieldScope_PDF_Report::build_html( $this->report( $findings ) );
		$this->assertSame( 1, substr_count( $html, '<div class="ftitle">Repeated issue <span' ) );
		$this->assertStringContainsString( 'and 5 more', $html );
		$this->assertStringContainsString( 'Code Patterns', $html, 'Check id is shown as its label.' );
	}

	public function test_summary_verdict_and_fix_first_list() {
		$html = ShieldScope_PDF_Report::build_html(
			$this->report(
				array(
					$this->finding( 'critical', 'Crit one' ),
					$this->finding( 'high', 'High one' ),
					$this->finding( 'low', 'Low one' ),
				)
			)
		);
		$this->assertStringContainsString( '1 critical and 1 high findings need attention first.', $html );
		$this->assertMatchesRegularExpression( '/<ol class="top">.*Crit one.*High one.*<\/ol>/s', $html );
		$this->assertStringNotContainsString( 'Low one</li>', $html );

		$this->assertStringStartsWith( 'No critical or high findings.', ShieldScope_PDF_Report::verdict( array( 'medium' => 2 ) ) );
	}

	public function test_method_and_limits_states_footprint_and_privacy() {
		$html = ShieldScope_PDF_Report::build_html( $this->report( array( $this->finding( 'info', 'Info' ) ) ) );
		$this->assertStringContainsString( 'Method and limits', $html );
		$this->assertStringContainsString( htmlspecialchars( ShieldScope_Admin::footprint_statement(), ENT_QUOTES ), $html );
		$this->assertStringContainsString( htmlspecialchars( ShieldScope_Admin::privacy_statement(), ENT_QUOTES ), $html );
		$this->assertStringContainsString( 'not confirmed vulnerabilities', $html );
	}

	public function test_save_failed_warning() {
		$report                = $this->report( array( $this->finding( 'info', 'Info' ) ) );
		$report['save_failed'] = true;
		$this->assertStringContainsString( 'could not be saved', ShieldScope_PDF_Report::build_html( $report ) );
	}

	public function test_file_name_and_download_url() {
		$this->assertSame( 'shieldscope-report-shop.example.com-' . gmdate( 'Y-m-d' ) . '.pdf', ShieldScope_PDF_Report::file_name( $this->report( array() ) ) );
		$url = ShieldScope_PDF_Report::download_url();
		$this->assertStringContainsString( 'admin-post.php?action=shieldscope_export_pdf', $url );
		$this->assertStringContainsString( '_wpnonce=', $url );
	}

	public function test_library_is_available_in_the_plugin() {
		$this->assertSame( '', ShieldScope_PDF_Report::unavailable_reason() );
	}

	public function test_render_produces_a_pdf_and_never_loads_files_or_urls() {
		$secret = tempnam( sys_get_temp_dir(), 'ss-secret' );
		file_put_contents( $secret, 'TOPSECRETVALUE' );
		$html = '<html><body><h1>Hi ✓ Привет</h1>'
			. '<img src="file://' . $secret . '"><img src="' . $secret . '">'
			. '<img src="https://example.invalid/x.png">'
			. '<link rel="stylesheet" href="file://' . $secret . '">'
			. '<p>' . str_repeat( 'Line. ', 400 ) . '</p></body></html>';
		$pdf = ShieldScope_PDF_Report::render_pdf( $html, $this->report( array() ) );
		unlink( $secret );

		$this->assertStringStartsWith( '%PDF-', $pdf );
		$this->assertStringNotContainsString( 'TOPSECRETVALUE', $pdf );
		$this->assertGreaterThan( 1000, strlen( $pdf ) );
	}

	public function test_full_report_renders() {
		$findings = array(
			$this->finding( 'critical', 'wp-config.php is publicly readable', '/srv/www/site/wp-config.php' ),
			$this->finding( 'high', 'Matches pattern: eval() on encoded data', '/srv/www/site/wp-content/plugins/a/a.php' ),
			$this->finding( 'low', 'Review: user input near echo ($name)', '/srv/www/site/wp-content/themes/t/x.php' ),
		);
		$report = $this->report( $findings );
		$pdf    = ShieldScope_PDF_Report::render_pdf( ShieldScope_PDF_Report::build_html( $report ), $report );
		$this->assertStringStartsWith( '%PDF-', $pdf );
	}

	public function test_handler_requires_capability() {
		ss_tests_override(
			'current_user_can',
			function () {
				return false;
			}
		);
		$this->expectException( SS_Test_Exit::class );
		ShieldScope_PDF_Report::handle();
	}

	public function test_handler_requires_nonce() {
		ss_tests_override(
			'check_admin_referer',
			function () {
				return false;
			}
		);
		$this->expectException( SS_Test_Exit::class );
		$this->expectExceptionMessage( 'bad nonce' );
		ShieldScope_PDF_Report::handle();
	}

	public function test_handler_without_a_scan_stops_with_message() {
		$this->expectException( SS_Test_Exit::class );
		$this->expectExceptionMessage( 'There is no completed scan to export' );
		ShieldScope_PDF_Report::handle();
	}

	public function test_pdf_ends_with_the_developer_help_section() {
		$html = ShieldScope_PDF_Report::build_html( $this->report( array( $this->finding( 'info', 'Info' ) ) ) );
		$this->assertStringContainsString( 'Need a deeper review, or help fixing what ShieldScope found?', $html );
		$this->assertStringContainsString( 'href="https://www.dhirenpatel.me/contact/"', $html );
		$this->assertGreaterThan( strpos( $html, 'Method and limits' ), strpos( $html, 'class="help"' ), 'last section' );
	}

	public function test_pdf_help_section_follows_the_downloads_setting() {
		update_option( 'shieldscope_settings', array( 'report_help_link' => 0 ) );
		$html = ShieldScope_PDF_Report::build_html( $this->report( array( $this->finding( 'info', 'Info' ) ) ) );
		$this->assertStringNotContainsString( 'class="help"', $html );
	}
}
