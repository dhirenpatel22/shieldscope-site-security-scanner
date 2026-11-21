<?php
/**
 * Tests for S-17: Network Admin menu on multisite.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S17_Network_Page
 */
class Test_S17_Network_Page extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		if ( ! defined( 'SHIELDSCOPE_PLUGIN_BASENAME' ) ) {
			define( 'SHIELDSCOPE_PLUGIN_BASENAME', 'shieldscope-site-security-scanner/shieldscope-site-security-scanner.php' );
		}
	}

	public function test_network_menu_only_on_multisite() {
		( new ShieldScope_Admin() )->register();
		$this->assertArrayNotHasKey( 'network_admin_menu', $GLOBALS['ss_test_filters'] );

		ss_tests_reset_state();
		ss_tests_override(
			'is_multisite',
			function () {
				return true;
			}
		);
		( new ShieldScope_Admin() )->register();
		$this->assertArrayHasKey( 'network_admin_menu', $GLOBALS['ss_test_filters'] );
		$this->assertSame( 'manage_network_options', ShieldScope_Admin::required_capability() );
	}
}
