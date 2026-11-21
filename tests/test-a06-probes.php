<?php
/**
 * Tests for ticket A-06: probe accuracy in the filesystem and
 * security-config checks.
 *
 * Regressions covered:
 *  - Sensitive-file probes followed redirects and accepted any final 200, so a
 *    site that redirects 404s to the homepage, or answers every path with a
 *    themed 200 page, got a Critical ".env file is publicly accessible".
 *  - /wp-config.php returning an empty 200 (PHP ran it) raised a finding.
 *  - wp-config.php at 0640/0644 was called "world-readable" (High) while the
 *    advice recommended 0640.
 *  - The scan requested wp-cron.php, which runs due cron events.
 *  - The plugins directory-listing probe requested ShieldScope's own folder.
 *  - The disable_functions advice pointed to .user.ini, where it has no effect.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_A06_Probes
 */
class Test_A06_Probes extends TestCase {

	const HOMEPAGE = '<!doctype html><html><head><title>Example Shop</title><meta name="generator" content="WordPress 6.8.1"></head><body><h1>Welcome</h1><p>Proudly powered by WordPress</p></body></html>';

	/** @var SS_Fake_Logger */
	private $logger;

	/** @var array[] Every wp_remote_get call: array( url, args ). */
	private $gets = array();

	/** @var string[] URLs sent with wp_remote_post. */
	private $posts = array();

	/**
	 * Real files the fake site serves, keyed by path ('/.env').
	 *
	 * @var string[]
	 */
	private $files = array();

	/**
	 * How the fake site answers a path it has no file for:
	 * 'hard404', 'redirect_home' (301 to the homepage) or 'soft404' (200 homepage).
	 *
	 * @var string
	 */
	private $missing = 'hard404';

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$this->logger  = new SS_Fake_Logger();
		$this->gets    = array();
		$this->posts   = array();
		$this->files   = array();
		$this->missing = 'hard404';

		ss_tests_override(
			'wp_remote_get',
			function ( $url, $args ) {
				$this->gets[] = array( $url, $args );
				return $this->serve( $url, $args );
			}
		);
		ss_tests_override(
			'wp_remote_post',
			function ( $url ) {
				$this->posts[] = $url;
				return new WP_Error( 'blocked', 'No POST in tests' );
			}
		);
	}

	/**
	 * The fake site. A redirect is followed only when the caller allows it,
	 * as WP_Http does.
	 */
	private function serve( $url, $args ) {
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		if ( isset( $this->files[ $path ] ) ) {
			return $this->response( 200, $this->files[ $path ] );
		}
		if ( '/' === $path ) {
			return $this->response( 200, self::HOMEPAGE );
		}
		if ( 'soft404' === $this->missing ) {
			return $this->response( 200, self::HOMEPAGE );
		}
		if ( 'redirect_home' === $this->missing ) {
			$follows = ! isset( $args['redirection'] ) || $args['redirection'] > 0;
			return $follows ? $this->response( 200, self::HOMEPAGE ) : $this->response( 301, '' );
		}
		return $this->response( 404, '<html><title>Not found</title></html>' );
	}

	private function response( $code, $body ) {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
			'headers'  => array(),
		);
	}

	private function run_steps( ShieldScope_Check_Base $check, array $steps ) {
		foreach ( $steps as $step ) {
			$cursor = array();
			do {
				$result = $check->run_step( $step, $cursor );
				$cursor = $result['cursor'];
			} while ( $result['continue'] );
		}
	}

	private function run_probes() {
		$this->run_steps( new ShieldScope_Check_Security_Config( 'scan', $this->logger ), array( 'sensitive_files' ) );
		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), array( 'readme', 'directory_listing', 'directory_listing_all', 'wp_config_http', 'sensitive_urls' ) );
	}

	private function titles() {
		return array_column( $this->logger->findings, 'title' );
	}

	private function finding( $title ) {
		foreach ( $this->logger->findings as $f ) {
			if ( $f['title'] === $title ) {
				return $f;
			}
		}
		$this->fail( "No finding titled '$title'. Got: " . implode( ' | ', $this->titles() ) );
	}

	// ------------------------------------------------------------------
	// Soft-404 and redirects
	// ------------------------------------------------------------------

	public function test_site_that_redirects_404s_to_homepage_gets_no_probe_findings() {
		$this->missing = 'redirect_home';
		file_put_contents( ABSPATH . 'readme.html', '<title>WordPress &#8250; ReadMe</title>' );

		$this->run_probes();

		$this->assertSame( array(), $this->titles() );
	}

	public function test_site_that_answers_every_path_with_200_gets_no_probe_findings() {
		$this->missing = 'soft404';
		file_put_contents( ABSPATH . 'readme.html', '<title>WordPress &#8250; ReadMe</title>' );

		$this->run_probes();

		$this->assertSame( array(), $this->titles() );
	}

	public function test_identical_signature_body_on_every_path_is_not_reported() {
		// A catch-all handler that prints the same KEY=value text for any path.
		$catch_all = "STATUS=ok\n";
		ss_tests_override(
			'wp_remote_get',
			function ( $url, $args ) use ( $catch_all ) {
				$this->gets[] = array( $url, $args );
				return $this->response( 200, $catch_all );
			}
		);

		$this->run_steps( new ShieldScope_Check_Security_Config( 'scan', $this->logger ), array( 'sensitive_files' ) );

		$this->assertNotContains( '.env file is publicly accessible', $this->titles() );
	}

	public function test_every_probe_is_a_get_without_redirects_to_the_site_itself() {
		$this->missing = 'soft404';
		file_put_contents( ABSPATH . 'readme.html', '<title>WordPress &#8250; ReadMe</title>' );

		$this->run_probes();

		$this->assertNotEmpty( $this->gets );
		$this->assertSame( array(), $this->posts );
		foreach ( $this->gets as $call ) {
			list( $url, $args ) = $call;
			$this->assertStringStartsWith( 'https://example.test/', $url );
			$this->assertArrayHasKey( 'redirection', $args, $url );
			$this->assertSame( 0, $args['redirection'], $url );
		}
	}

	// ------------------------------------------------------------------
	// Real exposures are still reported
	// ------------------------------------------------------------------

	public function test_real_env_file_is_reported_critical() {
		$this->files['/.env'] = "APP_ENV=production\nDB_PASSWORD=s3cret\n";

		$this->run_probes();

		$this->assertSame( ShieldScope_Logger::SEVERITY_CRITICAL, $this->finding( '.env file is publicly accessible' )['severity'] );
	}

	public function test_real_git_config_is_reported() {
		$this->files['/.git/config'] = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n";

		$this->run_probes();

		$this->assertSame( ShieldScope_Logger::SEVERITY_HIGH, $this->finding( '.git/config is publicly accessible' )['severity'] );
	}

	public function test_phpinfo_needs_phpinfo_output() {
		$this->files['/phpinfo.php'] = '<html><head><title>PHP 8.3.14 - phpinfo()</title></head><body><h1 class="p">PHP Version 8.3.14</h1></body></html>';
		$this->files['/info.php']    = '<html><body>Company info</body></html>';

		$this->run_probes();

		$this->assertContains( 'phpinfo.php is publicly accessible', $this->titles() );
		$this->assertNotContains( 'info.php is publicly accessible (possible phpinfo)', $this->titles() );
	}

	public function test_debug_log_and_sample_config_need_their_content() {
		$this->files['/wp-content/debug.log']  = "[14-Nov-2026 10:00:00 UTC] PHP Warning:  Undefined variable \$x in /var/www/wp-content/plugins/x/x.php on line 3\n";
		$this->files['/wp-config-sample.php'] = "<?php\ndefine( 'DB_NAME', 'database_name_here' );\n";

		$this->run_probes();

		$this->assertContains( 'WordPress debug.log is publicly accessible', $this->titles() );
		$this->assertContains( 'wp-config-sample.php is publicly accessible', $this->titles() );
	}

	public function test_empty_debug_log_and_executed_sample_config_are_not_reported() {
		$this->files['/wp-content/debug.log']  = '';
		$this->files['/wp-config-sample.php'] = '';

		$this->run_probes();

		$this->assertSame( array(), $this->titles() );
	}

	public function test_license_htaccess_and_readme_are_reported_with_their_content() {
		$this->files['/license.txt'] = "WordPress - Web publishing software\n\nCopyright 2011-2026 by the contributors\n";
		$this->files['/.htaccess']   = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\n</IfModule>\n";
		$this->files['/readme.html'] = '<!DOCTYPE html><html><head><title>WordPress &#8250; ReadMe</title></head></html>';
		file_put_contents( ABSPATH . 'readme.html', 'x' );

		$this->run_probes();

		$this->assertContains( 'license.txt is publicly accessible', $this->titles() );
		$this->assertContains( '.htaccess file is publicly accessible', $this->titles() );
		$this->assertContains( 'readme.html is publicly accessible', $this->titles() );
	}

	public function test_directory_listing_is_reported() {
		$this->files['/wp-content/plugins/'] = '<html><head><title>Index of /wp-content/plugins</title></head><body><h1>Index of /wp-content/plugins</h1></body></html>';

		$this->run_probes();

		$this->assertContains( 'Directory listing enabled on wp-content/plugins', $this->titles() );
	}

	// ------------------------------------------------------------------
	// wp-config.php over HTTP
	// ------------------------------------------------------------------

	public function test_wp_config_empty_200_raises_no_finding() {
		$this->files['/wp-config.php'] = '';

		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), array( 'wp_config_http' ) );

		$this->assertSame( array(), $this->titles() );
	}

	public function test_wp_config_source_with_credentials_is_critical() {
		$this->files['/wp-config.php'] = "<?php\ndefine( 'DB_PASSWORD', 'hunter2' );\n";

		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), array( 'wp_config_http' ) );

		$this->assertSame( ShieldScope_Logger::SEVERITY_CRITICAL, $this->finding( 'wp-config.php is publicly readable and contains credentials' )['severity'] );
	}

	// ------------------------------------------------------------------
	// wp-config.php permissions
	// ------------------------------------------------------------------

	private function perms_findings( $mode ) {
		file_put_contents( ABSPATH . 'wp-config.php', '<?php' );
		chmod( ABSPATH . 'wp-config.php', $mode );
		clearstatcache();
		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), array( 'wp_config_perms' ) );
		return $this->logger->findings;
	}

	public function test_wp_config_0640_is_not_flagged() {
		$this->assertSame( array(), $this->perms_findings( 0640 ) );
	}

	public function test_wp_config_0600_is_not_flagged() {
		$this->assertSame( array(), $this->perms_findings( 0600 ) );
	}

	public function test_wp_config_0644_is_low_and_advice_matches() {
		$findings = $this->perms_findings( 0644 );

		$this->assertCount( 1, $findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_LOW, $findings[0]['severity'] );
		$this->assertStringContainsString( '0644', $findings[0]['description'] );
		$this->assertStringContainsString( '0640', $findings[0]['recommendation'] );
	}

	// ------------------------------------------------------------------
	// wp-cron, plugins URL, disable_functions advice
	// ------------------------------------------------------------------

	public function test_wp_cron_is_never_requested() {
		$this->missing = 'soft404';

		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), ( new ShieldScope_Check_Filesystem( 'scan', $this->logger ) )->get_steps() );
		$this->run_steps( new ShieldScope_Check_Security_Config( 'scan', $this->logger ), array( 'sensitive_files', 'wp_cron' ) );

		foreach ( $this->gets as $call ) {
			$this->assertStringNotContainsString( 'wp-cron', $call[0] );
		}
		$this->assertNotContains( 'wp-cron.php is publicly accessible', $this->titles() );
		$this->assertContains( 'WP-Cron fires on page load (default behaviour)', $this->titles() );
	}

	public function test_plugins_listing_probe_uses_plugins_root() {
		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), array( 'directory_listing_all' ) );

		$urls = array_column( $this->gets, 0 );
		$this->assertContains( 'https://example.test/wp-content/plugins/', $urls );
		foreach ( $urls as $url ) {
			$this->assertDoesNotMatchRegularExpression( '#/wp-content/plugins/[^/]+/$#', $url );
		}
	}

	public function test_dangerous_functions_finding_is_info_without_user_ini_advice() {
		if ( ! function_exists( 'exec' ) ) {
			$this->markTestSkipped( 'exec() is disabled in this PHP build.' );
		}

		$this->run_steps( new ShieldScope_Check_Security_Config( 'scan', $this->logger ), array( 'php_functions' ) );

		$f = $this->finding( 'Dangerous PHP functions are not disabled' );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $f['severity'] );
		$this->assertStringNotContainsString( '.user.ini', $f['recommendation'] );
		$this->assertStringContainsString( 'php.ini', $f['recommendation'] );
	}

	// ------------------------------------------------------------------
	// PHP-in-uploads walk (shared walker; characterisation)
	// ------------------------------------------------------------------

	public function test_uploads_walk_reports_php_files_and_skipped_count() {
		$uploads = ABSPATH . 'wp-content/uploads';
		mkdir( $uploads . '/2026/11', 0777, true );
		mkdir( ABSPATH . 'elsewhere', 0777, true );
		file_put_contents( $uploads . '/2026/11/shell.php', '<?php' );
		file_put_contents( $uploads . '/2026/11/photo.jpg', 'x' );
		symlink( ABSPATH . 'elsewhere', $uploads . '/linked' );

		$this->run_steps( new ShieldScope_Check_Filesystem( 'scan', $this->logger ), array( 'uploads_php' ) );

		$this->assertSame( $uploads . '/2026/11/shell.php', $this->finding( 'Review: PHP file inside uploads' )['target'] );
		$this->assertStringContainsString( 'Symlinked folders not followed: 1.', $this->finding( 'Some files were not scanned' )['description'] );
	}
}
