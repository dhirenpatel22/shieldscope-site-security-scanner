<?php
/**
 * Developer contact link: plugin screens and PDF footer.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Help_Link
 */
class Test_Help_Link extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	private function report() {
		return array( 'version' => '2.0.0', 'site_url' => 'https://example.com/' );
	}

	public function test_footer_has_version_site_and_contact_link() {
		$this->assertSame(
			'ShieldScope 2.0.0 · example.com · Detailed audit or help with fixes: dhirenpatel.me/contact',
			ShieldScope_PDF_Report::footer_text( $this->report(), true )
		);
	}

	public function test_footer_without_link_keeps_version_and_site() {
		$this->assertSame( 'ShieldScope 2.0.0 · example.com', ShieldScope_PDF_Report::footer_text( $this->report(), false ) );
	}

	public function test_pdf_link_is_on_by_default_and_can_be_turned_off() {
		$this->assertTrue( ShieldScope_Admin::pdf_help_link() );
		update_option( 'shieldscope_settings', array( 'pdf_help_link' => 0 ) );
		$this->assertFalse( ShieldScope_Admin::pdf_help_link() );
	}

	public function test_box_is_a_plain_link_to_the_contact_page() {
		ob_start();
		ShieldScope_Admin::render_help_box();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'href="https://www.dhirenpatel.me/contact/"', $html );
		$this->assertStringContainsString( 'rel="noopener noreferrer"', $html );
		// Guidelines 7 and 11: nothing loaded from elsewhere, no form, no referral tracking.
		$this->assertDoesNotMatchRegularExpression( '/<(img|script|iframe|form)\b|utm_|[?&]ref=/i', $html );
	}

	public function test_box_is_only_on_shieldscope_screens() {
		foreach ( array( 'scan', 'report', 'settings' ) as $view ) {
			$this->assertStringContainsString( 'render_help_box()', file_get_contents( SHIELDSCOPE_PLUGIN_DIR . "admin/views/$view.php" ), $view );
		}
		$this->assertDoesNotMatchRegularExpression( '/add_action\(\s*[\'"](admin_notices|all_admin_notices|wp_dashboard_setup)[\'"][^;]*help_box/', file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'includes/class-shieldscope-admin.php' ) );
	}
}
