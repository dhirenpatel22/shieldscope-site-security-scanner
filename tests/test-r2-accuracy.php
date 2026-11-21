<?php
/**
 * Review 2 accuracy fixes: IM2-02, IM2-03, IM2-04, IM2-13, IM2-14, SC2-08.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_R2_Accuracy
 */
class Test_R2_Accuracy extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
	}

	public function test_every_review_title_in_the_catalogue_gets_the_review_label() {
		$doc = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'docs/rules.md' );
		preg_match_all( '/^\| SS-[A-Z]+-\d+ \| \w+ \| (.+) \|$/m', $doc, $m );
		$this->assertGreaterThan( 100, count( $m[1] ) );
		foreach ( $m[1] as $title ) {
			if ( false !== stripos( $title, 'review' ) && false === stripos( $title, 'review webhook' ) ) {
				$this->assertTrue( ShieldScope_Check_Base::is_review_title( $title ), $title );
			}
		}
	}

	public function test_plugin_not_known_to_wordpress_org_is_not_looked_up() {
		$GLOBALS['ss_test_plugins'] = array(
			'custom-login/custom-login.php' => array( 'Name' => 'In-house login', 'Version' => '1.0' ),
			'elsewhere/elsewhere.php'       => array( 'Name' => 'Commercial', 'Version' => '1.0', 'UpdateURI' => 'https://vendor.example/updates' ),
		);
		// "elsewhere" is even in the update data, but its Update URI points away from WordPress.org.
		$GLOBALS['ss_test_site_transients']['update_plugins'] = (object) array( 'no_update' => array( 'elsewhere/elsewhere.php' => (object) array() ) );
		$calls = 0;
		ss_tests_override(
			'wp_remote_get',
			function () use ( &$calls ) {
				++$calls;
				return array( 'response' => array( 'code' => 200 ), 'body' => '{"error":"closed","closed":true,"reason":"security-issue"}' );
			}
		);
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Plugins( 's', $logger );
		foreach ( array( 'abandoned', 'checksums' ) as $step ) {
			$cursor = array();
			do {
				$r      = $check->run_step( $step, $cursor );
				$cursor = $r['cursor'];
			} while ( ! empty( $r['continue'] ) );
		}
		$this->assertSame( 0, $calls, 'No folder name is sent to WordPress.org for these plugins.' );
		$this->assertSame( array(), $logger->findings );
		$this->assertStringStartsWith( '2 plugin(s) not verified', implode( '', $check->take_coverage_notes() ) );
	}

	private function uploads_findings( array $files ) {
		$uploads = SS_TESTS_WP_ROOT . '/wp-content/uploads';
		foreach ( $files as $rel => $code ) {
			@mkdir( dirname( "$uploads/$rel" ), 0777, true );
			file_put_contents( "$uploads/$rel", $code );
		}
		ss_tests_override(
			'wp_get_upload_dir',
			function () use ( $uploads ) {
				return array( 'basedir' => $uploads );
			}
		);
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Filesystem( 's', $logger );
		$cursor = array();
		do {
			$r      = $check->run_step( 'uploads_php', $cursor );
			$cursor = $r['cursor'];
		} while ( ! empty( $r['continue'] ) );
		return array_column( $logger->findings, 'target' );
	}

	public function test_placeholder_index_files_in_uploads_are_not_reported() {
		$targets = $this->uploads_findings(
			array(
				'index.php'         => "<?php\n// Silence is golden.\n",
				'2026/index.php'    => '<?php',
				'cache/index.php'   => "<?php echo 'not empty';",
				'2026/11/shell.php' => '<?php system($_GET["c"]);',
			)
		);
		sort( $targets );
		$this->assertCount( 2, $targets );
		$this->assertStringEndsWith( 'shell.php', $targets[0] );
		$this->assertStringEndsWith( 'cache/index.php', $targets[1] );
	}

	public function test_backup_file_is_critical_only_when_served() {
		file_put_contents( ABSPATH . 'backup.sql', "-- MySQL dump\nCREATE TABLE x (id int);" );
		$served = true;
		ss_tests_override(
			'wp_remote_get',
			function ( $url ) use ( &$served ) {
				if ( $served && false !== strpos( $url, 'backup.sql' ) ) {
					return array( 'response' => array( 'code' => 200 ), 'body' => "-- MySQL dump\nCREATE TABLE x (id int);" );
				}
				return array( 'response' => array( 'code' => 404 ), 'body' => 'not found' );
			}
		);
		$logger = new SS_Fake_Logger();
		( new ShieldScope_Check_Filesystem( 's', $logger ) )->run_step( 'backup_files' );
		$this->assertSame( array( 'critical' ), array_column( $logger->findings, 'severity' ) );
		$this->assertSame( 'Backup file can be downloaded from the web', $logger->findings[0]['title'] );

		$served = false;
		$logger = new SS_Fake_Logger();
		( new ShieldScope_Check_Filesystem( 's', $logger ) )->run_step( 'backup_files' );
		$this->assertSame( array( 'medium' ), array_column( $logger->findings, 'severity' ) );
	}

	public function test_no_critical_for_allow_url_include_or_plugin_updates() {
		$src = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'docs/rules.md' );
		$this->assertMatchesRegularExpression( '/\| Medium \| PHP allow_url_include is enabled \|/', $src );
		$this->assertMatchesRegularExpression( '/\| Medium \| Plugin update available \|/', $src );
	}

	public function test_core_integrity_notes_missing_checksums() {
		$check = new ShieldScope_Check_Core_Integrity( 's', new SS_Fake_Logger() );
		$check->run_step( 'verify' );
		$check->run_step( 'extras' );
		$notes = $check->take_coverage_notes();
		$this->assertCount( 2, $notes );
		$this->assertStringContainsString( 'checksums unavailable', $notes[0] );
	}
}
