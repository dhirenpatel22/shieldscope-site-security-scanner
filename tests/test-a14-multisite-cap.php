<?php
/**
 * A-14: on multisite only super admins (manage_network_options) can open the
 * ShieldScope pages or call its AJAX actions; single site stays manage_options.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_A14_Multisite_Cap
 */
class Test_A14_Multisite_Cap extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		$_REQUEST = array( '_wpnonce' => 'test-nonce' );
	}

	protected function tearDown(): void {
		$_REQUEST = array();
		$_POST    = array();
	}

	private function as_multisite( $multisite ) {
		ss_tests_override( 'is_multisite', function () use ( $multisite ) { return $multisite; } );
	}

	/**
	 * A sub-site administrator: has manage_options, not manage_network_options.
	 */
	private function as_site_admin() {
		ss_tests_override( 'current_user_can', function ( $cap ) { return 'manage_options' === $cap; } );
	}

	private function as_super_admin() {
		ss_tests_override( 'current_user_can', function ( $cap ) { return true; } );
	}

	/**
	 * Run register_menu() and return the capability of every page it adds, keyed by slug.
	 */
	private function menu_capabilities() {
		$caps = array();
		ss_tests_override(
			'add_menu_page',
			function ( $page_title, $menu_title, $capability, $menu_slug ) use ( &$caps ) {
				$caps[ 'menu:' . $menu_slug ] = $capability;
				return 'toplevel_page_' . $menu_slug;
			}
		);
		ss_tests_override(
			'add_submenu_page',
			function ( $parent_slug, $page_title, $menu_title, $capability, $menu_slug ) use ( &$caps ) {
				$caps[ $menu_slug ] = $capability;
				return $parent_slug . '_page_' . $menu_slug;
			}
		);
		( new ShieldScope_Admin() )->register_menu();
		return $caps;
	}

	private function authorize_ajax() {
		$method = new ReflectionMethod( 'ShieldScope_Ajax', 'authorize' );
		$method->setAccessible( true );
		$method->invoke( new ShieldScope_Ajax() );
	}

	public function test_capability_is_manage_options_on_single_site() {
		$this->as_multisite( false );
		$this->assertSame( 'manage_options', ShieldScope_Admin::required_capability() );
	}

	public function test_capability_is_manage_network_options_on_multisite() {
		$this->as_multisite( true );
		$this->assertSame( 'manage_network_options', ShieldScope_Admin::required_capability() );
	}

	public function test_every_menu_page_needs_manage_network_options_on_multisite() {
		$this->as_multisite( true );
		$this->assertSame(
			array(
				'menu:shieldscope'     => 'manage_network_options',
				'shieldscope'          => 'manage_network_options',
				'shieldscope-report'   => 'manage_network_options',
				'shieldscope-settings' => 'manage_network_options',
			),
			$this->menu_capabilities()
		);
	}

	public function test_every_menu_page_needs_manage_options_on_single_site() {
		$this->as_multisite( false );
		$this->assertSame(
			array(
				'menu:shieldscope'     => 'manage_options',
				'shieldscope'          => 'manage_options',
				'shieldscope-report'   => 'manage_options',
				'shieldscope-settings' => 'manage_options',
			),
			$this->menu_capabilities()
		);
	}

	public static function render_methods() {
		return array(
			'scan'     => array( 'render_scan_page' ),
			'report'   => array( 'render_report_page' ),
			'settings' => array( 'render_settings_page' ),
		);
	}

	/**
	 * @dataProvider render_methods
	 */
	public function test_site_admin_cannot_open_pages_on_multisite( $method ) {
		$this->as_multisite( true );
		$this->as_site_admin();

		$this->expectException( SS_Test_Exit::class );
		$this->expectExceptionMessage( 'Insufficient permissions.' );
		( new ShieldScope_Admin() )->$method();
	}

	public function test_site_admin_cannot_save_settings_on_multisite() {
		$this->as_multisite( true );
		$this->as_site_admin();
		$_POST = array(
			'shieldscope_settings_submit' => '1',
			'_wpnonce'                    => 'test-nonce',
			'shieldscope_settings'        => array( 'cpu_limit' => 30 ),
		);

		$method = new ReflectionMethod( 'ShieldScope_Admin', 'maybe_save_settings' );
		$method->setAccessible( true );
		try {
			$method->invoke( new ShieldScope_Admin() );
			$this->fail( 'Settings save was not refused.' );
		} catch ( SS_Test_Exit $e ) {
			$this->assertSame( 'Insufficient permissions.', $e->getMessage() );
		}
		$this->assertFalse( get_option( 'shieldscope_settings' ) );
	}

	public function test_site_admin_ajax_is_refused_on_multisite() {
		$this->as_multisite( true );
		$this->as_site_admin();

		try {
			$this->authorize_ajax();
			$this->fail( 'AJAX request was not refused.' );
		} catch ( SS_Test_Exit $e ) {
			$this->assertSame( 403, $e->getCode() );
			$this->assertStringContainsString( 'You do not have permission to do this.', $e->getMessage() );
		}
	}

	public function test_super_admin_ajax_is_allowed_on_multisite() {
		$this->as_multisite( true );
		$this->as_super_admin();

		$this->authorize_ajax();
		$this->addToAssertionCount( 1 );
	}

	public function test_site_admin_ajax_is_allowed_on_single_site() {
		$this->as_multisite( false );
		$this->as_site_admin();

		$this->authorize_ajax();
		$this->addToAssertionCount( 1 );
	}
}
