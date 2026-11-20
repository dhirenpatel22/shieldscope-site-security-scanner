<?php
/**
 * Tests for ticket A-09: severity rubric and advice in the config, core,
 * themes and database checks.
 *
 * Regressions covered:
 * - Missing CSP / HSTS / X-Frame-Options were Medium; the rubric makes them Low.
 * - HSTS was reported on HTTP-only sites, where browsers ignore the header.
 * - X-XSS-Protection advice said "1; mode=block"; OWASP says send 0 or omit it.
 * - The asset-version advice pasted a callback that does not exist (fatal).
 * - Brute-force throttling was checked here and in access-control.
 * - FORCE_SSL_ADMIN was reported twice, then by neither check after A-05;
 *   it is now reported once, by the core check, on HTTPS sites only.
 * - Placeholder salts were Critical, although WordPress then uses random
 *   salts stored in the database.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Severity
 */
class Test_Severity extends TestCase {

	/**
	 * Severities the rubric reserves for confirmed problems.
	 *
	 * @var string[]
	 */
	private static $not_hardening = array(
		ShieldScope_Logger::SEVERITY_CRITICAL,
		ShieldScope_Logger::SEVERITY_HIGH,
		ShieldScope_Logger::SEVERITY_MEDIUM,
	);

	/**
	 * Previous $wpdb global.
	 *
	 * @var mixed
	 */
	private $saved_wpdb;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->saved_wpdb = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb']  = new class() {
			public $prefix  = 'wp_';
			public $options = 'wp_options';
			public $posts   = 'wp_posts';
			public function prepare( $sql ) {
				return $sql;
			}
			public function get_results( $sql = null, $output = null ) {
				return array();
			}
		};
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->saved_wpdb;
	}

	/**
	 * Run the given steps of a check and return the findings.
	 *
	 * @param string   $class Check class.
	 * @param string[] $steps Steps (all steps when empty).
	 * @return array[]
	 */
	private function run_check( $class, array $steps = array() ) {
		$logger = new SS_Fake_Logger();
		$check  = new $class( 'scan-a09', $logger );
		foreach ( $steps ? $steps : $check->get_steps() as $step ) {
			$check->run_step( $step );
		}
		return $logger->findings;
	}

	/**
	 * Serve a fixed response for the home page.
	 *
	 * @param array  $headers Response headers.
	 * @param string $body    Response body.
	 */
	private function serve_home( array $headers, $body = '' ) {
		ss_tests_override(
			'wp_remote_get',
			function () use ( $headers, $body ) {
				return array( 'response' => array( 'code' => 200 ), 'headers' => $headers, 'body' => $body );
			}
		);
	}

	private function find_title( array $findings, $needle ) {
		foreach ( $findings as $f ) {
			if ( false !== stripos( $f['title'], $needle ) ) {
				return $f;
			}
		}
		return null;
	}

	// -----------------------------------------------------------------------
	// Rubric
	// -----------------------------------------------------------------------

	public function test_rubric_document_defines_the_five_levels() {
		$file = dirname( __DIR__ ) . '/docs/severity-rubric.md';
		$this->assertFileExists( $file );
		$text = (string) file_get_contents( $file );
		$this->assertStringContainsStringIgnoringCase( 'confirmed compromise or exposed secret', $text );
		$this->assertStringContainsStringIgnoringCase( 'confirmed exploitable misconfiguration', $text );
		$this->assertStringContainsStringIgnoringCase( 'weakened posture', $text );
		$this->assertStringContainsStringIgnoringCase( 'hardening', $text );
		$this->assertStringContainsStringIgnoringCase( 'context', $text );
	}

	// -----------------------------------------------------------------------
	// Config check: headers
	// -----------------------------------------------------------------------

	public function test_missing_security_headers_are_low_on_https_site() {
		$this->serve_home( array() );
		$findings = $this->run_check( 'ShieldScope_Check_Config', array( 'headers' ) );

		foreach ( array( 'X-Frame-Options', 'Content-Security-Policy', 'HSTS' ) as $header ) {
			$f = $this->find_title( $findings, $header );
			$this->assertNotNull( $f, "$header finding missing" );
			$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $f['severity'], $header );
		}
		foreach ( $findings as $f ) {
			$this->assertNotContains( $f['severity'], self::$not_hardening, $f['title'] );
		}
	}

	public function test_hsts_not_reported_on_http_only_site() {
		ss_tests_override(
			'get_site_url',
			function () {
				return 'http://example.test';
			}
		);
		$this->serve_home( array() );
		$findings = $this->run_check( 'ShieldScope_Check_Config', array( 'headers' ) );

		$this->assertNull( $this->find_title( $findings, 'HSTS' ) );
		$this->assertNotNull( $this->find_title( $findings, 'X-Frame-Options' ) );
	}

	public function test_hsts_advice_does_not_claim_to_protect_first_visit() {
		$this->serve_home( array() );
		$f = $this->find_title( $this->run_check( 'ShieldScope_Check_Config', array( 'headers' ) ), 'HSTS' );
		$this->assertStringNotContainsString( 'first-visit', $f['description'] );
	}

	public function test_absent_x_xss_protection_is_not_a_finding() {
		$this->serve_home( array() );
		$findings = $this->run_check( 'ShieldScope_Check_Config', array( 'headers' ) );
		$this->assertNull( $this->find_title( $findings, 'X-XSS-Protection' ) );
	}

	public function test_x_xss_protection_disabled_is_not_a_finding() {
		$this->serve_home( array( 'X-XSS-Protection' => '0' ) );
		$findings = $this->run_check( 'ShieldScope_Check_Config', array( 'headers' ) );
		$this->assertNull( $this->find_title( $findings, 'X-XSS-Protection' ) );
	}

	public function test_x_xss_protection_enabled_advises_zero_or_omit() {
		$this->serve_home( array( 'X-XSS-Protection' => '1; mode=block' ) );
		$f = $this->find_title( $this->run_check( 'ShieldScope_Check_Config', array( 'headers' ) ), 'X-XSS-Protection' );

		$this->assertNotNull( $f );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $f['severity'] );
		$this->assertStringContainsString( "'X-XSS-Protection: 0'", $f['recommendation'] );
		$this->assertStringContainsString( 'omit', $f['recommendation'] );
		$this->assertStringNotContainsString( "Send 'X-XSS-Protection: 1", $f['recommendation'] );
	}

	// -----------------------------------------------------------------------
	// Config check: version disclosure and duplicate throttle check
	// -----------------------------------------------------------------------

	public function test_version_disclosure_findings_are_low_or_info() {
		$body = '<meta name="generator" content="WordPress 6.8.1" />'
			. '<generator>https://wordpress.org/?v=6.8.1</generator> 6.8.1'
			. '<script src="/wp-content/plugins/a/a.js?ver=1.2"></script>'
			. '<script src="/wp-content/plugins/b/b.js?ver=1.3"></script>'
			. '<link href="/wp-content/themes/c/style.css?ver=2.0" />';
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( $body ) {
				if ( false !== strpos( $url, '/wp-json/' ) ) {
					return array( 'response' => array( 'code' => 200 ), 'body' => '{"description":"6.8.1"}' );
				}
				return array( 'response' => array( 'code' => 200 ), 'body' => $body );
			}
		);

		$findings = $this->run_check( 'ShieldScope_Check_Config', array( 'version_disclosure', 'rest_version', 'rss_version', 'asset_versions' ) );

		$this->assertCount( 4, $findings );
		foreach ( $findings as $f ) {
			$this->assertNotContains( $f['severity'], self::$not_hardening, $f['title'] );
		}
	}

	public function test_duplicate_login_throttle_check_is_removed() {
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Config( 'scan-a09', $logger );
		$this->assertNotContains( 'login_throttle', $check->get_steps() );

		// A scan saved before the update may still name the step: it must do nothing.
		$check->run_step( 'login_throttle' );
		$this->assertSame( array(), $logger->findings );
	}

	// -----------------------------------------------------------------------
	// Core check
	// -----------------------------------------------------------------------

	public function test_default_table_prefix_is_info() {
		$findings = $this->run_check( 'ShieldScope_Check_Core', array( 'prefix' ) );
		$this->assertCount( 1, $findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $findings[0]['severity'] );
	}

	public function test_core_constants_follow_rubric() {
		$findings = $this->run_check( 'ShieldScope_Check_Core', array( 'constants' ) );

		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $this->find_title( $findings, 'file editor' )['severity'] );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $this->find_title( $findings, 'File modifications' )['severity'] );
	}

	/**
	 * FORCE_SSL_ADMIN must be reported exactly once (core check), only on
	 * HTTPS sites, without claiming cookies lack the Secure flag
	 * (wp_set_auth_cookie() already uses is_ssl()).
	 */
	public function test_force_ssl_admin_reported_once_on_https_site() {
		$findings = array_merge(
			$this->run_check( 'ShieldScope_Check_Core', array( 'constants' ) ),
			$this->run_check( 'ShieldScope_Check_Security_Config', array( 'cookie_security' ) )
		);
		$matches  = array_values(
			array_filter(
				$findings,
				function ( $f ) {
					return false !== strpos( $f['title'], 'FORCE_SSL_ADMIN' );
				}
			)
		);

		$this->assertCount( 1, $matches );
		$this->assertSame( 'core', $matches[0]['check_id'] );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $matches[0]['severity'] );
		$this->assertStringNotContainsStringIgnoringCase( 'Secure flag', $matches[0]['description'] );
		$this->assertStringContainsString( "define( 'FORCE_SSL_ADMIN', true );", $matches[0]['recommendation'] );
	}

	public function test_force_ssl_admin_not_reported_on_http_only_site() {
		ss_tests_override(
			'get_site_url',
			function () {
				return 'http://example.test';
			}
		);
		$findings = array_merge(
			$this->run_check( 'ShieldScope_Check_Core', array( 'constants' ) ),
			$this->run_check( 'ShieldScope_Check_Security_Config', array( 'cookie_security' ) )
		);
		$this->assertNull( $this->find_title( $findings, 'FORCE_SSL_ADMIN' ) );
	}

	public function test_core_update_available_is_medium() {
		$GLOBALS['ss_test_site_transients']['update_core'] = (object) array(
			'updates' => array( (object) array( 'response' => 'upgrade', 'current' => '6.9' ) ),
		);
		$findings = $this->run_check( 'ShieldScope_Check_Core', array( 'version' ) );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $findings[0]['severity'] );
	}

	public function test_xmlrpc_and_rest_user_list_are_low() {
		ss_tests_override(
			'wp_remote_get',
			function () {
				return array( 'response' => array( 'code' => 200 ), 'body' => '[{"id":1,"slug":"admin"}]' );
			}
		);
		$findings = $this->run_check( 'ShieldScope_Check_Core', array( 'xmlrpc', 'rest_enum' ) );

		$this->assertCount( 2, $findings );
		foreach ( $findings as $f ) {
			$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $f['severity'], $f['title'] );
		}
		$this->assertStringContainsString( 'Require all denied', $findings[0]['recommendation'] );
	}

	/**
	 * Undefined and placeholder salts make wp_salt() fall back to random
	 * values stored in the database, so this is not an exposed secret.
	 * A short custom value is used as-is, so it weakens cookie signing.
	 */
	public function test_salt_severity() {
		$findings = $this->run_check( 'ShieldScope_Check_Core', array( 'salts' ) );
		$this->assertCount( 1, $findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $findings[0]['severity'] );
		$this->assertStringContainsString( 'database', $findings[0]['description'] );

		if ( ! defined( 'NONCE_SALT' ) ) {
			define( 'NONCE_SALT', 'too-short' );
		}
		$findings = $this->run_check( 'ShieldScope_Check_Core', array( 'salts' ) );
		$this->assertCount( 2, $findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $findings[0]['severity'] );
		$this->assertSame( array( 'NONCE_SALT (short)' ), $findings[0]['context']['failed_keys'] );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $findings[1]['severity'] );
		foreach ( $findings as $f ) {
			$this->assertNotSame( ShieldScope_Logger::SEVERITY_CRITICAL, $f['severity'] );
		}
	}

	// -----------------------------------------------------------------------
	// Themes and database checks
	// -----------------------------------------------------------------------

	public function test_theme_update_available_is_medium() {
		$GLOBALS['ss_test_site_transients']['update_themes'] = (object) array(
			'response' => array( 'old-theme' => array( 'new_version' => '2.0' ) ),
		);
		$findings = $this->run_check( 'ShieldScope_Check_Themes', array( 'updates' ) );
		$this->assertCount( 1, $findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $findings[0]['severity'] );
	}

	public function test_database_option_findings_follow_rubric() {
		update_option( 'users_can_register', 1 );
		update_option( 'default_role', 'administrator' );
		update_option( 'siteurl', 'https://example.test' );
		update_option( 'home', 'https://www.example.test' );

		$findings = $this->run_check( 'ShieldScope_Check_Database', array( 'suspicious_options' ) );

		$registration = $this->find_title( $findings, 'Open registration' );
		$this->assertSame( ShieldScope_Logger::SEVERITY_HIGH, $registration['severity'] );
		$this->assertStringNotContainsString( 'almost certainly', $registration['description'] );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $this->find_title( $findings, 'different domains' )['severity'] );
	}

	// -----------------------------------------------------------------------
	// Advice snippets
	// -----------------------------------------------------------------------

	/**
	 * Every PHP snippet in the advice of these four checks must lint, and
	 * every hook callback it names must exist (defined in the snippet or a
	 * core helper), so pasting it cannot fatal.
	 */
	public function test_every_advice_snippet_lints_and_names_real_callbacks() {
		if ( ! defined( 'AUTOMATIC_UPDATER_DISABLED' ) ) {
			define( 'AUTOMATIC_UPDATER_DISABLED', true );
		}
		$GLOBALS['ss_test_site_transients']['update_core'] = (object) array(
			'updates' => array( (object) array( 'response' => 'upgrade', 'current' => '6.9' ) ),
		);
		$body = '<meta name="generator" content="WordPress 6.8.1" />'
			. '<generator>https://wordpress.org/?v=6.8.1</generator>'
			. '<script src="/wp-content/plugins/a/a.js?ver=1.2"></script>'
			. '<script src="/wp-content/plugins/b/b.js?ver=1.3"></script>'
			. '<link href="/wp-content/themes/c/style.css?ver=2.0" />';
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( $body ) {
				if ( false !== strpos( $url, 'wp/v2/users' ) ) {
					return array( 'response' => array( 'code' => 200 ), 'body' => '[{"id":1}]' );
				}
				if ( false !== strpos( $url, '/wp-json/' ) ) {
					return array( 'response' => array( 'code' => 200 ), 'body' => '{"description":"6.8.1"}' );
				}
				return array(
					'response' => array( 'code' => 200 ),
					'headers'  => array( 'x-xss-protection' => '1; mode=block' ),
					'body'     => $body . ' 6.8.1',
				);
			}
		);

		$findings = array_merge(
			$this->run_check( 'ShieldScope_Check_Config' ),
			$this->run_check( 'ShieldScope_Check_Core' ),
			$this->run_check( 'ShieldScope_Check_Themes' ),
			$this->run_check( 'ShieldScope_Check_Database' )
		);

		$core_callbacks = array( '__return_false', '__return_empty_string', 'wp_generator' );
		$linted         = 0;
		foreach ( $findings as $f ) {
			$snippets = self::extract_php_snippets( $f['recommendation'] );
			if ( ! $snippets ) {
				continue;
			}
			$code = "<?php\n" . implode( "\n", $snippets ) . "\n";
			$this->assertSame( '', self::lint( $code ), "Snippet in '{$f['title']}' does not lint:\n$code" );
			$linted += count( $snippets );

			preg_match_all( '/function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $code, $defined );
			preg_match_all( '/\b(?:add|remove)_(?:filter|action)\s*\(\s*\'[^\']+\'\s*,\s*\'([^\']+)\'/', $code, $used );
			foreach ( $used[1] as $callback ) {
				$this->assertTrue(
					in_array( $callback, $defined[1], true ) || in_array( $callback, $core_callbacks, true ),
					"Snippet in '{$f['title']}' names undefined callback $callback"
				);
			}
		}
		// define x3, remove_action, the_generator, asset function + 2 filters, xmlrpc, rest_endpoints.
		$this->assertGreaterThanOrEqual( 10, $linted );
	}

	/**
	 * Pull PHP statements out of an advice string.
	 *
	 * @param string $text Advice text.
	 * @return string[]
	 */
	private static function extract_php_snippets( $text ) {
		$snippets = array();
		$offset   = 0;
		while ( preg_match( '/\b(?:define|add_filter|add_action|remove_action|function\s+[A-Za-z_][A-Za-z0-9_]*)\s*\(/', $text, $m, PREG_OFFSET_CAPTURE, $offset ) ) {
			$start    = $m[0][1];
			$is_fn    = 0 === strpos( $m[0][0], 'function' );
			$depth    = 0;
			$quote    = '';
			$saw_body = false;
			$len      = strlen( $text );
			$end      = $len;
			for ( $i = $start; $i < $len; $i++ ) {
				$c = $text[ $i ];
				if ( '' !== $quote ) {
					if ( '\\' === $c ) {
						$i++;
					} elseif ( $c === $quote ) {
						$quote = '';
					}
					continue;
				}
				if ( "'" === $c || '"' === $c ) {
					$quote = $c;
				} elseif ( false !== strpos( '([{', $c ) ) {
					if ( '{' === $c && 0 === $depth ) {
						$saw_body = true;
					}
					$depth++;
				} elseif ( false !== strpos( ')]}', $c ) ) {
					$depth--;
					if ( $is_fn && $saw_body && 0 === $depth && '}' === $c ) {
						$end = $i + 1;
						break;
					}
				} elseif ( ';' === $c && 0 === $depth && ! $is_fn ) {
					$end = $i + 1;
					break;
				}
			}
			$snippets[] = substr( $text, $start, $end - $start );
			$offset     = $end;
		}
		return $snippets;
	}

	/**
	 * Lint PHP code with the running interpreter.
	 *
	 * @param string $code PHP source.
	 * @return string Empty on success, else the linter output.
	 */
	private static function lint( $code ) {
		$file = tempnam( sys_get_temp_dir(), 'ssa09' );
		file_put_contents( $file, $code );
		exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $file ) . ' 2>&1', $out, $status );
		unlink( $file );
		return 0 === $status ? '' : implode( "\n", $out );
	}
}
