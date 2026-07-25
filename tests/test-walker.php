<?php
/**
 * Tests for the shared resumable directory walker in ShieldScope_Check_Base.
 *
 * Regression: the previous per-check walkers dropped the remainder of a
 * directory whenever the per-call file budget was hit mid-directory, so
 * some plugin/theme/upload files were silently never scanned.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Minimal concrete check exposing the protected walker.
 */
class SS_Testable_Walker extends ShieldScope_Check_Base {
	public function get_id() { return 'walker_test'; }
	public function get_label() { return 'Walker Test'; }
	public function get_steps() { return array(); }
	public function run_step( $step, array $cursor = array() ) {
		return array( 'continue' => false, 'cursor' => array() );
	}
	public function walk( $root, array $cursor, callable $cb, $budget = 25, array $skip = array( 'node_modules', 'vendor', '.git' ), $pattern = '/\.php$/i', $skip_self = true ) {
		return $this->walk_php_files_step( $root, $cursor, $cb, $budget, $skip, $pattern, $skip_self );
	}
}

/**
 * Class Test_Walker
 */
class Test_Walker extends TestCase {

	/** @var SS_Testable_Walker */
	private $walker;

	/** @var string */
	private $root;

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$this->walker = new SS_Testable_Walker( 'scan_test', new SS_Fake_Logger() );
		$this->root   = SS_TESTS_WP_ROOT . '/tree';
	}

	/**
	 * Create $count php files inside $dir (created if needed).
	 *
	 * @param string $dir   Directory.
	 * @param int    $count File count.
	 * @param string $ext   Extension.
	 * @return string[] Created paths.
	 */
	private function fill( $dir, $count, $ext = 'php' ) {
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0777, true );
		}
		$paths = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$p = "$dir/f-$i.$ext";
			file_put_contents( $p, "<?php // $i\n" );
			$paths[] = $p;
		}
		return $paths;
	}

	/**
	 * Drive the walker to completion, collecting handled paths.
	 *
	 * @param int $budget Files per call.
	 * @return array [handled paths, number of invocations]
	 */
	private function drive( $budget ) {
		$handled = array();
		$cursor  = array();
		$calls   = 0;
		do {
			$result = $this->walker->walk(
				$this->root,
				$cursor,
				function ( $path ) use ( &$handled ) {
					$handled[] = $path;
				},
				$budget
			);
			$cursor = $result['cursor'];
			$this->assertLessThan( 500, ++$calls, 'Walker never finished.' );
		} while ( $result['continue'] );
		return array( $handled, $calls );
	}

	public function test_no_files_lost_when_budget_falls_mid_directory() {
		// 30 files in one directory with a budget of 25 — the old walker
		// dropped the last 5 files of the directory.
		$expected = $this->fill( $this->root . '/a', 30 );

		list( $handled, $calls ) = $this->drive( 25 );

		sort( $expected );
		sort( $handled );
		$this->assertSame( $expected, $handled, 'Every file must be scanned exactly once across batches.' );
		$this->assertGreaterThan( 1, $calls, 'Test must actually span a batch boundary.' );
	}

	public function test_nested_tree_fully_covered_and_no_duplicates() {
		$expected = array_merge(
			$this->fill( $this->root, 7 ),
			$this->fill( $this->root . '/a', 26 ),
			$this->fill( $this->root . '/a/b', 13 ),
			$this->fill( $this->root . '/c', 9 )
		);
		$this->fill( $this->root . '/a', 5, 'txt' ); // non-PHP — ignored.

		list( $handled, ) = $this->drive( 10 );

		$this->assertCount( count( $expected ), $handled );
		$this->assertCount( count( $handled ), array_unique( $handled ), 'No file may be scanned twice.' );
		sort( $expected );
		sort( $handled );
		$this->assertSame( $expected, $handled );
	}

	public function test_skip_dirs_are_not_descended() {
		$this->fill( $this->root, 2 );
		$this->fill( $this->root . '/node_modules/dep', 5 );
		$this->fill( $this->root . '/vendor', 5 );
		$this->fill( $this->root . '/.git', 5 );

		list( $handled, ) = $this->drive( 50 );

		$this->assertCount( 2, $handled );
	}

	public function test_own_plugin_directory_is_skipped() {
		// Walk the plugin's real parent directory (SHIELDSCOPE_PLUGIN_DIR
		// already sits literally inside it, since self-skip is a string
		// prefix match against that constant). Add a deterministic sibling
		// with known files so the test doesn't depend on incidental disk
		// contents to produce a meaningful assertion.
		$plugin_dir_real = rtrim( str_replace( '\\', '/', SHIELDSCOPE_PLUGIN_DIR ), '/' );
		$parent          = dirname( $plugin_dir_real );
		$sibling_dir      = $parent . '/ss-walker-test-sibling';
		$sibling          = $this->fill( $sibling_dir, 3 );

		$handled = array();
		$cursor  = array();
		try {
			do {
				$result = $this->walker->walk( $parent, $cursor, function ( $path ) use ( &$handled ) {
					$handled[] = $path;
				}, 1000 );
				$cursor = $result['cursor'];
			} while ( $result['continue'] );
		} finally {
			ss_tests_rmdir( $sibling_dir );
		}

		// The sibling's files must be found...
		sort( $sibling );
		$found_sibling = array_values( array_intersect( $handled, $sibling ) );
		sort( $found_sibling );
		$this->assertSame( $sibling, $found_sibling, 'Non-plugin files elsewhere on disk must still be scanned.' );

		// ...but nothing from inside the plugin's own directory may appear.
		foreach ( $handled as $path ) {
			$this->assertStringNotContainsString(
				$plugin_dir_real,
				str_replace( '\\', '/', $path ),
				'The walker must never scan ShieldScope\'s own source files.'
			);
		}
	}

	public function test_custom_pattern_matches_all_executable_extensions() {
		$dir = $this->root . '/uploads';
		$this->fill( $dir, 1, 'php' );
		$this->fill( $dir, 1, 'phtml' );
		$this->fill( $dir, 1, 'php5' );
		$this->fill( $dir, 1, 'phar' );
		$this->fill( $dir, 1, 'jpg' );

		$handled = array();
		$cursor  = array();
		do {
			$result = $this->walker->walk(
				$this->root,
				$cursor,
				function ( $path ) use ( &$handled ) {
					$handled[] = $path;
				},
				50,
				array(),
				'/\.(php|phtml|php5|php7|phar)$/i',
				false
			);
			$cursor = $result['cursor'];
		} while ( $result['continue'] );

		$this->assertCount( 4, $handled );
	}

	public function test_nonexistent_root_completes_immediately() {
		$result = $this->walker->walk( SS_TESTS_WP_ROOT . '/does-not-exist', array(), function () {} );
		$this->assertFalse( $result['continue'] );
		$this->assertSame( array(), $result['cursor'] );
	}
}
