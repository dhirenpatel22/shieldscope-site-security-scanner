<?php
/**
 * Tests for ticket A-13: one name, one privacy and write statement, no
 * overclaims in user-facing strings.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_A13_Strings
 */
class Test_A13_Strings extends TestCase {

	/**
	 * Source of every admin view, admin class and the main plugin file.
	 *
	 * @return string[] path => contents
	 */
	private function ui_sources() {
		$files = array_merge(
			glob( SHIELDSCOPE_PLUGIN_DIR . 'admin/views/*.php' ),
			glob( SHIELDSCOPE_PLUGIN_DIR . 'admin/js/*.js' ),
			glob( SHIELDSCOPE_PLUGIN_DIR . 'includes/*.php' ),
			array( SHIELDSCOPE_PLUGIN_DIR . 'shieldscope-site-security-scanner.php' )
		);
		$out = array();
		foreach ( $files as $file ) {
			$out[ $file ] = file_get_contents( $file );
		}
		return $out;
	}

	public function test_old_product_and_menu_names_are_gone() {
		foreach ( $this->ui_sources() as $file => $source ) {
			$this->assertDoesNotMatchRegularExpression( '/Security Scan\b|Security Audit|Last Report/', $source, $file );
		}
	}

	public function test_no_overclaims_in_ui_strings() {
		foreach ( $this->ui_sources() as $file => $source ) {
			$this->assertDoesNotMatchRegularExpression( '/malware|known signatures|slow your site|CPU-throttled|processing capacity|never written to the filesystem|~25|18\+/i', $source, $file );
		}
	}

	public function test_header_description_does_not_say_background() {
		$main = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'shieldscope-site-security-scanner.php' );
		$this->assertMatchesRegularExpression( '/^ \* Description:\s+(.+)$/m', $main );
		preg_match( '/^ \* Description:\s+(.+)$/m', $main, $m );
		$this->assertStringNotContainsStringIgnoringCase( 'background', $m[1] );
		$this->assertStringNotContainsStringIgnoringCase( 'comprehensive', $m[1] );
	}

	public function test_privacy_statement_names_every_outbound_destination() {
		$text = ShieldScope_Admin::privacy_statement();
		$this->assertStringContainsString( 'api.wordpress.org', $text );
		$this->assertStringContainsString( 'WordPress version and locale', $text );
		$this->assertStringContainsString( 'wpscan.com', $text );
		$this->assertStringContainsString( 'your own site', $text );
	}

	public function test_footprint_statement_lists_what_is_stored() {
		$text = ShieldScope_Admin::footprint_statement();
		foreach ( array( 'options', 'transients', 'findings table', 'scheduled tasks' ) as $part ) {
			$this->assertStringContainsString( $part, $text );
		}
	}

	public function test_time_estimate_comes_from_one_place() {
		$this->assertSame( 'about 5 to 20 minutes', ShieldScope_Admin::scan_time_estimate() );
		foreach ( $this->ui_sources() as $file => $source ) {
			$this->assertDoesNotMatchRegularExpression( '/\d+\s*[–-]\s*\d+ minutes/', $source, $file );
		}
	}

	public function test_support_url() {
		$this->assertSame( 'https://wordpress.org/support/plugin/shieldscope-site-security-scanner/', ShieldScope_Admin::SUPPORT_URL );
	}
}
