<?php
/**
 * Tests for S-01: passive login-error and REST write-route checks.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Fake REST server.
 */
class SS_Fake_Rest_Server {
	/** @var array */
	public $routes = array();
	public function get_routes() {
		return $this->routes;
	}
}

/**
 * Class Test_S01_Passive_Access_Checks
 */
class Test_S01_Passive_Access_Checks extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	protected function setUp(): void {
		ss_tests_reset_state();
		$GLOBALS['ss_test_filters'] = array();
		$this->logger               = new SS_Fake_Logger();
	}

	private function run_step( $step ) {
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$check->run_step( $step );
		return array_column( $this->logger->findings, 'title' );
	}

	public function test_both_steps_are_registered() {
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$this->assertContains( 'login_errors', $check->get_steps() );
		$this->assertContains( 'rest_routes', $check->get_steps() );
	}

	public function test_default_login_errors_reveal_usernames() {
		$this->assertSame( array( 'Login error messages reveal whether a username exists' ), $this->run_step( 'login_errors' ) );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->logger->findings[0]['severity'] );
		$this->assertStringContainsString( 'no login was attempted', $this->logger->findings[0]['description'] );
	}

	public function test_generic_login_error_filter_clears_the_finding() {
		add_filter(
			'login_errors',
			function () {
				return 'Login failed.';
			}
		);
		$this->assertSame( array(), $this->run_step( 'login_errors' ) );
	}

	public function test_public_plugin_write_routes_are_grouped_per_namespace() {
		$server         = new SS_Fake_Rest_Server();
		$server->routes = array(
			'/'                    => array( array( 'methods' => array( 'GET' => true ) ) ),
			'/wp/v2/posts'         => array( array( 'methods' => array( 'POST' => true ), 'permission_callback' => '__return_true' ) ),
			'/forms/v1/submit'     => array( array( 'methods' => array( 'POST' => true ), 'permission_callback' => '__return_true' ) ),
			'/forms/v1/delete/(?P<id>\d+)' => array( array( 'methods' => array( 'DELETE' => true ) ) ),
			'/forms/v1/list'       => array( array( 'methods' => array( 'GET' => true ), 'permission_callback' => '__return_true' ) ),
			'/shop/v2/orders'      => array( array( 'methods' => array( 'POST' => true, 'GET' => true ), 'permission_callback' => array( 'Shop', 'can_edit' ) ) ),
		);
		ss_tests_override(
			'rest_get_server',
			function () use ( $server ) {
				return $server;
			}
		);
		$titles = $this->run_step( 'rest_routes' );
		$this->assertSame( array( 'Review: REST routes in forms/v1 accept writes without a login' ), $titles );
		$desc = $this->logger->findings[0]['description'];
		$this->assertStringContainsString( 'POST /forms/v1/submit (__return_true)', $desc );
		$this->assertStringContainsString( 'DELETE /forms/v1/delete/(?P<id>\d+) (no permission check)', $desc );
		$this->assertStringNotContainsString( '/forms/v1/list', $desc, 'Read-only routes are not reported.' );
		$this->assertStringContainsString( 'no request was sent', $desc );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->logger->findings[0]['severity'] );
	}

	public function test_no_rest_server_gives_no_finding() {
		$this->assertSame( array(), $this->run_step( 'rest_routes' ) );
	}

	public function test_check_sends_no_http_requests() {
		$source = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'includes/checks/class-shieldscope-check-access-control.php' );
		$this->assertDoesNotMatchRegularExpression( '/wp_remote_post|wp_signon|wp_authenticate\s*\(/', $source );
	}
}
