<?php
/**
 * Tests for ShieldScope_Check_Access_Control (ticket A-03).
 *
 * Regressions covered:
 * - The check used to POST a failed login for the first administrator to
 *   wp-login.php and POST a draft to /wp/v2/posts, then force-delete whatever
 *   post ID the response named. A read-only scanner must never do either.
 * - The login-error enumeration finding could not be cleared by its own advice.
 * - The application-password finding fired when the user meta existed but held
 *   no passwords (meta stays as an empty array after all are revoked).
 * - add_menu_page() was flagged on the false claim that its capability only
 *   hides the menu; the file-level AJAX heuristics were rated High/Medium.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// Stubs this check needs that tests/wp-stubs.php does not provide. Each is
// guarded so another test file may define the same function first.
// ---------------------------------------------------------------------------

$GLOBALS['ss_a03_http']    = array();
$GLOBALS['ss_a03_deleted'] = array();

/**
 * Class Test_Access_Control
 */
class Test_Access_Control extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var string */
	private $source_file;

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		mkdir( SHIELDSCOPE_WP_PLUGINS_DIR, 0777, true );
		$this->logger      = new SS_Fake_Logger();
		$this->source_file = SHIELDSCOPE_PLUGIN_DIR . 'includes/checks/class-shieldscope-check-access-control.php';
		$GLOBALS['ss_a03_http']    = array();
		$GLOBALS['ss_a03_deleted'] = array();
		$this->record_all_side_effects();
	}

	/**
	 * Make every HTTP call and every post deletion observable. Responses mimic
	 * an unprotected site: the REST write "succeeds" and the login response
	 * contains the default username-confirming error text.
	 */
	private function record_all_side_effects() {
		$ok = function ( $body = '', $code = 200, $headers = array() ) {
			return array( 'response' => array( 'code' => $code ), 'body' => $body, 'headers' => $headers );
		};
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( $ok ) {
				$GLOBALS['ss_a03_http'][] = array( 'GET', $url );
				return $ok( '<form id="loginform"></form>' );
			}
		);
		ss_tests_override(
			'wp_remote_head',
			function ( $url ) use ( $ok ) {
				$GLOBALS['ss_a03_http'][] = array( 'HEAD', $url );
				return $ok( '', 200 );
			}
		);
		ss_tests_override(
			'wp_remote_post',
			function ( $url ) use ( $ok ) {
				$GLOBALS['ss_a03_http'][] = array( 'POST', $url );
				if ( false !== strpos( $url, 'wp/v2/posts' ) ) {
					return $ok( '{"id":42}', 201 );
				}
				return $ok( 'Error: The password you entered for the username admin is incorrect.' );
			}
		);
		ss_tests_override(
			'wp_delete_post',
			function ( $id ) {
				$GLOBALS['ss_a03_deleted'][] = $id;
				return true;
			}
		);
		ss_tests_override(
			'get_users',
			function ( $args ) {
				if ( isset( $args['role'] ) && 'administrator' === $args['role'] ) {
					return array( 'admin' );
				}
				return array();
			}
		);
	}

	/**
	 * Drive every step of the check to completion, as the scanner does.
	 *
	 * @param ShieldScope_Check_Access_Control $check Check.
	 */
	private function run_all_steps( $check ) {
		foreach ( $check->get_steps() as $step ) {
			$cursor = array();
			$guard  = 0;
			do {
				$result = $check->run_step( $step, $cursor );
				$cursor = $result['cursor'];
				$this->assertLessThan( 500, ++$guard );
			} while ( ! empty( $result['continue'] ) );
		}
	}

	/**
	 * Findings whose title contains the given text (case-insensitive).
	 *
	 * @param string $needle Text.
	 * @return array[]
	 */
	private function findings_titled( $needle ) {
		return array_values(
			array_filter(
				$this->logger->findings,
				static function ( $f ) use ( $needle ) {
					return false !== stripos( $f['title'], $needle );
				}
			)
		);
	}

	private function write_plugin_file( $name, $code ) {
		$dir = SHIELDSCOPE_WP_PLUGINS_DIR . '/fixture-plugin';
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0777, true );
		}
		file_put_contents( "$dir/$name", $code );
	}

	// -----------------------------------------------------------------------
	// Active probes removed
	// -----------------------------------------------------------------------

	public function test_source_calls_no_write_delete_or_authentication_function() {
		$forbidden = array( 'wp_remote_post', 'wp_safe_remote_post', 'wp_remote_request', 'wp_safe_remote_request', 'wp_delete_post', 'wp_insert_post', 'wp_authenticate', 'wp_signon' );
		$called    = array();
		foreach ( token_get_all( file_get_contents( $this->source_file ) ) as $token ) {
			if ( is_array( $token ) && T_STRING === $token[0] && in_array( strtolower( $token[1] ), $forbidden, true ) ) {
				$called[] = $token[1];
			}
		}
		$this->assertSame( array(), $called, 'The access-control check must not write, delete or authenticate.' );
	}

	public function test_source_never_targets_the_posts_rest_route() {
		$this->assertStringNotContainsString( 'wp/v2/posts', file_get_contents( $this->source_file ) );
	}

	public function test_removed_probe_steps_are_gone() {
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		// S-01 restored the login-error and REST checks as passive steps.
		$this->assertSame( array( 'app_passwords', 'author_enum', 'login_page', 'login_errors', 'rest_routes', 'scan_plugins' ), $check->get_steps() );
	}

	public function test_full_run_with_login_limit_plugin_sends_no_post_and_deletes_nothing() {
		ss_tests_override(
			'is_plugin_active',
			function ( $plugin ) {
				return 'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php' === $plugin;
			}
		);
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$this->run_all_steps( $check );

		$methods = array_unique( array_column( $GLOBALS['ss_a03_http'], 0 ) );
		sort( $methods );
		$this->assertSame( array( 'GET', 'HEAD' ), $methods, 'Only read-only requests are allowed.' );
		$this->assertSame( array(), $GLOBALS['ss_a03_deleted'], 'No post may be deleted.' );
		$this->assertSame( array(), $this->findings_titled( 'REST API allows' ) );
		foreach ( $this->findings_titled( 'Login error messages' ) as $f ) {
			$this->assertStringContainsString( 'no login was attempted', $f['description'], 'Only the passive S-01 check may report this.' );
		}
	}

	// -----------------------------------------------------------------------
	// Application passwords
	// -----------------------------------------------------------------------

	private function users_with_app_password_meta() {
		ss_tests_override(
			'get_users',
			function ( $args ) {
				return array(
					(object) array( 'ID' => 1, 'user_login' => 'siteadmin', 'roles' => array( 'administrator' ) ),
					(object) array( 'ID' => 2, 'user_login' => 'editor1', 'roles' => array( 'editor' ) ),
				);
			}
		);
		ss_tests_override(
			'user_can',
			function ( $user_id, $cap ) {
				return 1 === $user_id;
			}
		);
	}

	public function test_app_password_finding_is_silent_when_meta_exists_but_holds_no_passwords() {
		$this->users_with_app_password_meta();
		ss_tests_override(
			'WP_Application_Passwords::get_user_application_passwords',
			function () {
				return array();
			}
		);
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$check->run_step( 'app_passwords' );

		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_app_password_finding_names_only_users_who_have_a_password() {
		$this->users_with_app_password_meta();
		ss_tests_override(
			'WP_Application_Passwords::get_user_application_passwords',
			function ( $user_id ) {
				return 2 === $user_id ? array( array( 'uuid' => 'abc', 'name' => 'CI' ) ) : array();
			}
		);
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$check->run_step( 'app_passwords' );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $this->logger->findings[0]['severity'] );
		$this->assertSame( array( 'users' => array( 'editor1' ), 'confidence' => 'confirmed' ), $this->logger->findings[0]['context'] );
	}

	public function test_app_password_on_admin_is_high() {
		$this->users_with_app_password_meta();
		ss_tests_override(
			'WP_Application_Passwords::get_user_application_passwords',
			function ( $user_id ) {
				return 1 === $user_id ? array( array( 'uuid' => 'abc', 'name' => 'Deploy' ) ) : array();
			}
		);
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$check->run_step( 'app_passwords' );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_HIGH, $this->logger->findings[0]['severity'] );
		$this->assertSame( array( 'admin_users' => array( 'siteadmin' ), 'confidence' => 'confirmed' ), $this->logger->findings[0]['context'] );
	}

	// -----------------------------------------------------------------------
	// Plugin-file heuristics
	// -----------------------------------------------------------------------

	public function test_admin_page_without_current_user_can_is_not_flagged() {
		$this->write_plugin_file( 'menu.php', "<?php\nadd_menu_page( 'X', 'X', 'manage_options', 'x', 'x_render' );\n" );
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$this->run_step_to_completion( $check, 'scan_plugins' );

		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_public_ajax_without_nonce_is_low_and_needs_review() {
		$this->write_plugin_file( 'ajax.php', "<?php\nadd_action( 'wp_ajax_nopriv_x', 'x_cb' );\n" );
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$this->run_step_to_completion( $check, 'scan_plugins' );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->logger->findings[0]['severity'] );
		$this->assertStringContainsStringIgnoringCase( 'needs review', $this->logger->findings[0]['title'] );
	}

	public function test_logged_in_ajax_without_auth_is_low_and_needs_review() {
		$this->write_plugin_file( 'ajax.php', "<?php\nadd_action( 'wp_ajax_x', 'x_cb' );\n" );
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$this->run_step_to_completion( $check, 'scan_plugins' );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->logger->findings[0]['severity'] );
		$this->assertStringContainsStringIgnoringCase( 'needs review', $this->logger->findings[0]['title'] );
	}

	public function test_ajax_with_nonce_check_is_not_flagged() {
		$this->write_plugin_file( 'ajax.php', "<?php\nadd_action( 'wp_ajax_nopriv_x', 'x_cb' );\nfunction x_cb() { check_ajax_referer( 'x' ); }\n" );
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$this->run_step_to_completion( $check, 'scan_plugins' );

		$this->assertSame( array(), $this->logger->findings );
	}

	private function run_step_to_completion( $check, $step ) {
		$cursor = array();
		$guard  = 0;
		do {
			$result = $check->run_step( $step, $cursor );
			$cursor = $result['cursor'];
			$this->assertLessThan( 500, ++$guard );
		} while ( ! empty( $result['continue'] ) );
	}

	// -----------------------------------------------------------------------
	// Brute-force protection (single list, here only)
	// -----------------------------------------------------------------------

	/**
	 * @dataProvider brute_force_plugins
	 */
	public function test_recognised_login_protection_plugin_suppresses_brute_force_finding( $plugin ) {
		ss_tests_override(
			'is_plugin_active',
			function ( $p ) use ( $plugin ) {
				return $p === $plugin;
			}
		);
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$check->run_step( 'login_page' );

		$this->assertSame( array(), $this->findings_titled( 'brute-force' ) );
	}

	public static function brute_force_plugins() {
		return array(
			'Loginizer'                  => array( 'loginizer/loginizer.php' ),
			'WP Cerber'                  => array( 'wp-cerber/wp-cerber.php' ),
			'Limit Login Attempts Rel.'  => array( 'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php' ),
		);
	}

	public function test_no_login_protection_plugin_raises_brute_force_finding() {
		$check = new ShieldScope_Check_Access_Control( 'scan_t', $this->logger );
		$check->run_step( 'login_page' );

		$found = $this->findings_titled( 'brute-force' );
		$this->assertCount( 1, $found );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $found[0]['severity'] );
	}
}
