<?php
/**
 * A-11b: step time budget, per-step save, failed-step skip, walker limits,
 * symlinks and the "files skipped" note.
 *
 * Reuses the fake wpdb, fake check and scanner from the A-11a tests.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/test-a11a-scanner-pause-abort-lock.php';

/**
 * Thrown by a fake step to stand in for a request killed mid-step
 * (max_execution_time, memory_limit); the test then rolls the database back
 * to what it held at that moment.
 */
class SS_A11b_Killed extends Exception {}

/**
 * Check exposing the walker and the time budget.
 */
class SS_A11b_Walker_Check extends ShieldScope_Check_Base {
	public function get_id() { return 'a11b_walker'; }
	public function get_label() { return 'A-11b walker'; }
	public function get_steps() { return array(); }
	public function run_step( $step, array $cursor = array() ) {
		return array( 'continue' => false, 'cursor' => array() );
	}
	public function walk( $root, array $cursor, callable $cb, $budget = 25 ) {
		return $this->walk_php_files_step( $root, $cursor, $cb, $budget );
	}
}

/**
 * Check whose only step works until the time budget says stop.
 */
class SS_A11b_Budget_Check extends ShieldScope_Check_Base {
	public static $calls = 0;
	public function get_id() { return 'a11b_budget'; }
	public function get_label() { return 'A-11b budget'; }
	public function get_steps() { return array( 'work' ); }
	public function run_step( $step, array $cursor = array() ) {
		self::$calls++;
		$guard = microtime( true ) + 5;
		while ( ! $this->out_of_time() ) {
			if ( microtime( true ) > $guard ) {
				throw new RuntimeException( 'No time budget was given to the step.' );
			}
			usleep( 1000 );
		}
		$done = isset( $cursor['n'] ) ? $cursor['n'] + 1 : 1;
		return array( 'continue' => $done < 2, 'cursor' => array( 'n' => $done ) );
	}
}

/**
 * Scanner running only the budget check.
 */
class SS_A11b_Budget_Scanner extends ShieldScope_Scanner {
	public function get_check_classes() {
		return array( 'SS_A11b_Budget_Check' );
	}
}

/**
 * Class Test_A11b_Step_Budget_Walker
 */
class Test_A11b_Step_Budget_Walker extends TestCase {

	/** @var SS_A11a_WPDB */
	private $wpdb;

	/** @var string */
	private $root;

	/** @var string[] Symlinks to remove; the bootstrap's cleanup cannot. */
	private $links = array();

	protected function tearDown(): void {
		foreach ( $this->links as $link ) {
			if ( is_link( $link ) ) {
				unlink( $link );
			}
		}
		$this->links = array();
	}

	private function link( $target, $link ) {
		symlink( $target, $link );
		$this->links[] = $link;
	}

	protected function setUp(): void {
		ss_tests_reset_state();
		ss_tests_reset_wp_root();
		$this->wpdb      = new SS_A11a_WPDB();
		$GLOBALS['wpdb'] = $this->wpdb;
		update_option( 'shieldscope_settings', array( 'cpu_limit' => 100, 'chunk_time_limit' => 0.25 ) );
		SS_A11a_Fake_Check::$during = array();
		SS_A11a_Fake_Check::$ran    = array();
		SS_A11b_Budget_Check::$calls = 0;
		$this->root = SS_TESTS_WP_ROOT . '/tree';
	}

	private function db_state() {
		return $GLOBALS['ss_test_options'][ ShieldScope_Scanner::STATE_OPTION ];
	}

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
	 * Drive the walker to completion.
	 *
	 * @param SS_A11b_Walker_Check $walker   Walker.
	 * @param callable|null        $cb       Handler; default collects paths.
	 * @param bool                 $no_time  Give every call an already-spent time budget.
	 * @return array [handled paths, invocations]
	 */
	private function drive( $walker, $cb = null, $no_time = false ) {
		$handled = array();
		$cursor  = array();
		$calls   = 0;
		$cb      = $cb ? $cb : function ( $path ) use ( &$handled ) {
			$handled[] = $path;
		};
		do {
			if ( $no_time ) {
				$walker->set_deadline( microtime( true ) - 1 );
			}
			$result = $walker->walk( $this->root, $cursor, $cb, 25 );
			$cursor = $result['cursor'];
			$this->assertLessThan( 5000, ++$calls, 'Walker never finished.' );
		} while ( $result['continue'] );
		return array( $handled, $calls );
	}

	/**
	 * Run a tick that "dies" inside $step: the database is rolled back to
	 * its contents when the step began and the dead tick's lock is expired.
	 */
	private function tick_killed_in( $step ) {
		$snapshot = null;
		SS_A11a_Fake_Check::$during[ $step ] = function () use ( &$snapshot ) {
			$snapshot = array( $GLOBALS['ss_test_options'], $this->wpdb->findings );
			throw new SS_A11b_Killed( 'killed' );
		};
		( new SS_A11a_Scanner() )->run_chunk();
		$this->assertNotNull( $snapshot, "Step $step did not run." );
		list( $GLOBALS['ss_test_options'], $this->wpdb->findings ) = $snapshot;
		$GLOBALS['ss_test_options'][ ShieldScope_Scanner::LOCK_OPTION ] = ( time() - ShieldScope_Scanner::lock_timeout() - 1 ) . ':dead';
		$GLOBALS['ss_test_option_cache'] = array();
		unset( SS_A11a_Fake_Check::$during[ $step ] );
	}

	// -- scanner ------------------------------------------------------------

	public function test_state_is_saved_after_every_step() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		$seen = array();
		SS_A11a_Fake_Check::$during['two'] = function () use ( &$seen ) {
			$seen['two'] = $this->db_state()['step_index'];
		};
		SS_A11a_Fake_Check::$during['three'] = function () use ( &$seen ) {
			$seen['three'] = $this->db_state()['step_index'];
		};

		$scanner->run_chunk();

		$this->assertSame( array( 'two' => 1, 'three' => 2 ), $seen, 'A finished step must already be in the database when the next one runs.' );
	}

	public function test_step_killed_on_two_ticks_is_skipped_with_info_and_scan_continues() {
		$scanner = new SS_A11a_Scanner();
		$state   = $scanner->start();

		$this->tick_killed_in( 'two' );
		$this->tick_killed_in( 'two' );
		SS_A11a_Fake_Check::$ran = array();
		$after = ( new SS_A11a_Scanner() )->run_chunk();

		$this->assertSame( array( 'three' ), SS_A11a_Fake_Check::$ran, 'Step two is not tried a third time.' );
		$this->assertSame( 'completed', $after['status'] );
		$titles = array_column( $this->wpdb->findings_for( $state['scan_id'] ), 'title' );
		$this->assertContains( 'Step skipped: timed out: A-11a fake check, two', $titles );
		$info = array_values( array_filter( $this->wpdb->findings_for( $state['scan_id'] ), function ( $f ) {
			return 0 === strpos( $f['title'], 'Step skipped' );
		} ) );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $info[0]['severity'] );
	}

	public function test_step_killed_once_is_retried_not_skipped() {
		$scanner = new SS_A11a_Scanner();
		$state   = $scanner->start();

		$this->tick_killed_in( 'two' );
		SS_A11a_Fake_Check::$ran = array();
		$after = ( new SS_A11a_Scanner() )->run_chunk();

		$this->assertSame( array( 'two', 'three' ), SS_A11a_Fake_Check::$ran );
		$this->assertSame( 'completed', $after['status'] );
		foreach ( $this->wpdb->findings_for( $state['scan_id'] ) as $f ) {
			$this->assertStringNotContainsString( 'Step skipped', $f['title'] );
		}
	}

	public function test_steps_get_a_time_budget_from_the_chunk() {
		$scanner = new SS_A11b_Budget_Scanner();
		$scanner->start();

		$started = microtime( true );
		$state   = $scanner->run_chunk();

		$this->assertLessThan( 2.0, microtime( true ) - $started );
		$this->assertSame( 1, SS_A11b_Budget_Check::$calls, 'The chunk yields once the step has used the budget.' );
		$this->assertSame( 'running', $state['status'] );
		$this->assertSame( array( 'n' => 1 ), $this->db_state()['cursor'] );
	}

	public function test_lock_is_renewed_before_each_step() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		$seen = array();
		foreach ( array( 'one', 'two', 'three' ) as $step ) {
			SS_A11a_Fake_Check::$during[ $step ] = function () use ( &$seen ) {
				$seen[] = $GLOBALS['ss_test_options'][ ShieldScope_Scanner::LOCK_OPTION ];
			};
		}

		$scanner->run_chunk();

		$this->assertCount( 3, array_unique( $seen ), 'Each step starts with a renewed lock.' );
	}

	public function test_tick_stops_without_saving_when_its_lock_was_taken_over() {
		$scanner = new SS_A11a_Scanner();
		$scanner->start();
		SS_A11a_Fake_Check::$during['one'] = function () {
			// The lock looked expired and another tick took it.
			$GLOBALS['ss_test_options'][ ShieldScope_Scanner::LOCK_OPTION ] = time() . ':other';
		};

		$scanner->run_chunk();

		$this->assertSame( array( 'one' ), SS_A11a_Fake_Check::$ran );
		$this->assertSame( 0, $this->db_state()['step_index'], 'Work done without the lock is not saved.' );
		$this->assertSame( time() . ':other', (string) $GLOBALS['ss_test_options'][ ShieldScope_Scanner::LOCK_OPTION ], 'The other holder keeps its lock.' );
	}

	// -- walker -------------------------------------------------------------

	public function test_150_file_plugin_fully_visited_under_a_spent_time_budget() {
		$expected = array();
		for ( $i = 0; $i < 10; $i++ ) {
			$expected = array_merge( $expected, $this->fill( $this->root . "/fixture-plugin/inc/m$i/sub", 10 ), $this->fill( $this->root . "/fixture-plugin/inc/m$i", 5 ) );
		}
		$this->assertCount( 150, $expected );

		list( $handled, $calls ) = $this->drive( new SS_A11b_Walker_Check( 's', new SS_Fake_Logger() ), null, true );

		sort( $expected );
		sort( $handled );
		$this->assertSame( $expected, $handled, 'Every file visited exactly once.' );
		$this->assertGreaterThan( 150, $calls, 'A spent budget allows one unit of work per call.' );
	}

	public function test_directory_expansion_is_capped_per_call() {
		$path = $this->root;
		for ( $i = 0; $i < 120; $i++ ) {
			$path .= "/d$i";
		}
		mkdir( $path, 0777, true );
		file_put_contents( "$path/deep.php", '<?php' );

		$walker = new SS_A11b_Walker_Check( 's', new SS_Fake_Logger() );
		$first  = $walker->walk( $this->root, array(), function () {} );
		$this->assertTrue( $first['continue'], 'A tree of 120 folders is not expanded in one call.' );

		list( $handled, ) = $this->drive( $walker );
		$this->assertSame( array( "$path/deep.php" ), $handled );
	}

	public function test_symlink_loop_terminates_and_files_are_visited_once() {
		$expected = $this->fill( $this->root . '/a', 3 );
		$this->link( $this->root . '/a', $this->root . '/a/loop' );
		$this->link( $this->root, $this->root . '/a/up' );

		list( $handled, ) = $this->drive( new SS_A11b_Walker_Check( 's', new SS_Fake_Logger() ) );

		sort( $handled );
		$this->assertSame( $expected, $handled );
	}

	public function test_skipped_folders_links_and_files_are_reported_once_as_info() {
		$this->fill( $this->root, 2 );
		$this->fill( $this->root . '/vendor', 5 );
		$this->fill( $this->root . '/node_modules/dep', 5 );
		mkdir( $this->root . '/real', 0777, true );
		$this->link( $this->root . '/real', $this->root . '/linked' );
		$logger = new SS_Fake_Logger();
		$walker = new SS_A11b_Walker_Check( 's', $logger );

		$this->drive(
			$walker,
			function ( $path ) {
				return 'f-0.php' !== basename( $path ); // Handler skipped this one (too large).
			}
		);

		$this->assertCount( 1, $logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $logger->findings[0]['severity'] );
		$this->assertSame( $this->root, $logger->findings[0]['target'] );
		$this->assertStringContainsString( 'Folders skipped (such as vendor, node_modules, .git): 2.', $logger->findings[0]['description'] );
		$this->assertStringContainsString( 'Symlinked folders not followed: 1.', $logger->findings[0]['description'] );
		$this->assertStringContainsString( 'Files skipped (too large or unreadable): 1.', $logger->findings[0]['description'] );
	}

	public function test_clean_walk_reports_nothing() {
		$this->fill( $this->root, 3 );
		$logger = new SS_Fake_Logger();

		$this->drive( new SS_A11b_Walker_Check( 's', $logger ) );

		$this->assertCount( 0, $logger->findings );
	}

	// -- core integrity -----------------------------------------------------

	public function test_core_extras_skips_symlinks_honours_budget_and_keeps_cursor_small() {
		mkdir( ABSPATH . 'wp-includes/sub', 0777, true );
		$known = array();
		for ( $i = 0; $i < 300; $i++ ) {
			file_put_contents( ABSPATH . "wp-includes/sub/k$i.php", '<?php' );
			$known[ "wp-includes/sub/k$i.php" ] = 'x';
		}
		file_put_contents( ABSPATH . 'wp-includes/rogue.php', '<?php' );
		$this->link( ABSPATH . 'wp-includes', ABSPATH . 'wp-includes/sub/loop' );
		set_transient( ShieldScope_Check_Core_Integrity::CHECKSUMS_TRANSIENT, array( 'version' => '6.8.1', 'locale' => 'en_US', 'checksums' => $known ) );

		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Core_Integrity( 's', $logger );
		$cursor = array();
		$calls  = 0;
		do {
			$check->set_deadline( microtime( true ) - 1 );
			$result = $check->run_step( 'extras', $cursor );
			$cursor = $result['cursor'];
			$this->assertArrayNotHasKey( 'known', $cursor, 'The checksum map is not copied into the saved cursor.' );
			$this->assertLessThan( 5000, ++$calls );
		} while ( $result['continue'] );

		$highs = $logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $highs, 'The symlinked copy of wp-includes is not walked again.' );
		$this->assertSame( 'wp-includes/rogue.php', $highs[0]['target'] );
		$this->assertGreaterThan( 300, $calls, 'A spent budget allows one unit of work per call.' );
	}
}
