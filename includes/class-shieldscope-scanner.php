<?php
/**
 * Scanner engine.
 *
 * Holds scan state, runs one chunk at a time, respects CPU and time budget,
 * and advances deterministically through all registered check modules.
 *
 * State is kept in an option so a scan can survive page reloads, cron runs,
 * or AJAX pauses.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Scanner
 */
class ShieldScope_Scanner {

	const STATE_OPTION = 'shieldscope_scan_state';

	const STATUS_IDLE      = 'idle';
	const STATUS_RUNNING   = 'running';
	const STATUS_PAUSED    = 'paused';
	const STATUS_COMPLETED = 'completed';
	const STATUS_ABORTED   = 'aborted';

	/**
	 * Option row used as a mutex so only one tick works on a scan at a time.
	 */
	const LOCK_OPTION = 'shieldscope_tick_lock';

	/**
	 * Seconds after which a lock left by a killed request is taken over.
	 */
	const LOCK_TIMEOUT = 60;

	/**
	 * A step cut off this many times in a row (request killed) is skipped.
	 */
	const MAX_STEP_FAILS = 2;

	/**
	 * Logger.
	 *
	 * @var ShieldScope_Logger
	 */
	private $logger;

	/**
	 * Throttle.
	 *
	 * @var ShieldScope_Throttle
	 */
	private $throttle;

	/**
	 * Seconds of work per chunk; steps get the rest of it as their budget.
	 * Clamped like ShieldScope_Throttle does.
	 *
	 * @var float
	 */
	private $chunk_time_limit;

	/**
	 * Value of the lock row while this instance holds it.
	 *
	 * @var string
	 */
	private $lock_token = '';

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->logger = new ShieldScope_Logger();

		$settings = (array) get_option( 'shieldscope_settings', array() );
		$cpu      = isset( $settings['cpu_limit'] ) ? (int) $settings['cpu_limit'] : 20;
		$chunk    = isset( $settings['chunk_time_limit'] ) ? (float) $settings['chunk_time_limit'] : 2.0;

		$this->throttle         = new ShieldScope_Throttle( $cpu, $chunk );
		$this->chunk_time_limit = max( 0.25, min( 10.0, $chunk ) );
	}

	/**
	 * All registered check modules, in order.
	 *
	 * @return array<int,string> Class names.
	 */
	public function get_check_classes() {
		return array(
			'ShieldScope_Check_Core',
			'ShieldScope_Check_Core_Integrity',
			'ShieldScope_Check_Users',
			'ShieldScope_Check_Database',
			'ShieldScope_Check_Filesystem',
			'ShieldScope_Check_Plugins',
			'ShieldScope_Check_Themes',
			'ShieldScope_Check_Config',
			'ShieldScope_Check_SSL',
			'ShieldScope_Check_Code_Patterns',
			'ShieldScope_Check_Injection',
			'ShieldScope_Check_Access_Control',
			'ShieldScope_Check_Security_Config',
			'ShieldScope_Check_Components',
			'ShieldScope_Check_SSRF',
			'ShieldScope_Check_Vuln_DB',
		);
	}

	/**
	 * Retrieve the current state (or a fresh one).
	 *
	 * @return array
	 */
	public function get_state() {
		$default = array(
			'status'       => self::STATUS_IDLE,
			'scan_id'      => '',
			'started_at'   => 0,
			'updated_at'   => 0,
			'check_index'  => 0,
			'step_index'   => 0,
			'cursor'       => array(),
			'total_steps'  => 0,
			'done_steps'   => 0,
			'last_message' => '',
			'owner_id'     => 0,
			'started_step' => null,
			'check_status' => array(),
		);

		$state = get_option( self::STATE_OPTION, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		return array_merge( $default, $state );
	}

	/**
	 * Retrieve the state straight from the database, bypassing the request's
	 * option cache, so changes made by other requests (Pause, Abort, a new
	 * scan) are seen.
	 *
	 * @return array
	 */
	private function get_fresh_state() {
		wp_cache_delete( self::STATE_OPTION, 'options' );
		return $this->get_state();
	}

	/**
	 * Take the tick lock. The INSERT IGNORE is atomic, unlike add_option(),
	 * which upserts; this is the pattern WP_Upgrader::create_lock() uses.
	 *
	 * @return bool True when this instance now holds the lock.
	 */
	private function acquire_lock() {
		global $wpdb;

		$token = time() . ':' . wp_generate_password( 12, false, false );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- atomic lock row; the options API cannot do this.
		$created = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO `{$wpdb->options}` ( `option_name`, `option_value`, `autoload` ) VALUES ( %s, %s, 'no' )", self::LOCK_OPTION, $token ) );
		if ( ! $created ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- must read the current row, not the cache.
			$held = (string) $wpdb->get_var( $wpdb->prepare( "SELECT `option_value` FROM `{$wpdb->options}` WHERE `option_name` = %s", self::LOCK_OPTION ) );
			if ( (int) $held > time() - self::lock_timeout() ) {
				return false;
			}
			// Expired: take it over only if nobody else did first.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- compare-and-set on the lock row.
			$created = $wpdb->query( $wpdb->prepare( "UPDATE `{$wpdb->options}` SET `option_value` = %s WHERE `option_name` = %s AND `option_value` = %s", $token, self::LOCK_OPTION, $held ) );
			if ( ! $created ) {
				return false;
			}
		}

		$this->lock_token = $token;
		return true;
	}

	/**
	 * Renew the tick lock so a chunk of several steps never outlives it.
	 *
	 * @return bool False when the lock expired and another tick took it.
	 */
	private function refresh_lock() {
		global $wpdb;

		$token = time() . ':' . wp_generate_password( 12, false, false );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- compare-and-set on our own lock row.
		$renewed = $wpdb->query( $wpdb->prepare( "UPDATE `{$wpdb->options}` SET `option_value` = %s WHERE `option_name` = %s AND `option_value` = %s", $token, self::LOCK_OPTION, $this->lock_token ) );
		if ( ! $renewed ) {
			$this->lock_token = '';
			return false;
		}
		$this->lock_token = $token;
		return true;
	}

	/**
	 * Release the tick lock if this instance still holds it.
	 *
	 * @return void
	 */
	private function release_lock() {
		global $wpdb;

		if ( '' === $this->lock_token ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- delete only our own lock row.
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$wpdb->options}` WHERE `option_name` = %s AND `option_value` = %s", self::LOCK_OPTION, $this->lock_token ) );
		$this->lock_token = '';
	}

	/**
	 * Persist state.
	 *
	 * @param array $state State.
	 * @return void
	 */
	private function save_state( array $state ) {
		$state['updated_at'] = time();
		update_option( self::STATE_OPTION, $state, false );
	}

	/**
	 * Seconds without progress after which a running scan is "stalled".
	 */
	const STALL_SECONDS = 120;

	/**
	 * Is background scanning (WP-Cron) on? Default on (S-10).
	 *
	 * @return bool
	 */
	public static function background_enabled() {
		$settings = (array) get_option( 'shieldscope_settings', array() );
		return ! array_key_exists( 'background_scan', $settings ) || ! empty( $settings['background_scan'] );
	}

	/**
	 * Keep a running background scan moving: make sure a cron event is
	 * queued and ask WordPress to run due cron events now. Safe to call
	 * often; chunks never overlap (tick lock).
	 *
	 * @param array $state Current state.
	 * @return void
	 */
	public function kick_background( array $state ) {
		if ( self::STATUS_RUNNING !== $state['status'] || ! self::background_enabled() ) {
			return;
		}
		if ( ! wp_next_scheduled( 'shieldscope_run_scan_chunk' ) ) {
			wp_schedule_single_event( time(), 'shieldscope_run_scan_chunk' );
		}
		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
	}

	/**
	 * Has a running scan stopped making progress?
	 *
	 * @param array $state State.
	 * @return bool
	 */
	public static function is_stalled( array $state ) {
		return self::STATUS_RUNNING === $state['status'] && ! empty( $state['updated_at'] ) && ( time() - (int) $state['updated_at'] ) > self::STALL_SECONDS;
	}

	/**
	 * Per-check progress for the scan page (S-12).
	 *
	 * @param array $state State.
	 * @return array[] Each: label, status (waiting|running|done|partial|error), notes.
	 */
	public function check_progress( array $state ) {
		$out    = array();
		$status = isset( $state['check_status'] ) && is_array( $state['check_status'] ) ? $state['check_status'] : array();
		$active = in_array( $state['status'], array( self::STATUS_RUNNING, self::STATUS_PAUSED ), true );
		foreach ( $this->get_check_classes() as $i => $cls ) {
			if ( ! class_exists( $cls ) ) {
				continue;
			}
			$check = new $cls( '', $this->logger );
			$id    = $check->get_id();
			if ( self::STATUS_IDLE === $state['status'] || '' === $state['scan_id'] ) {
				$st = 'waiting';
			} elseif ( $i < (int) $state['check_index'] || self::STATUS_COMPLETED === $state['status'] ) {
				$st = isset( $status[ $id ]['status'] ) ? $status[ $id ]['status'] : ShieldScope_Coverage::DONE;
			} elseif ( $i === (int) $state['check_index'] && $active ) {
				$st = 'running';
			} else {
				$st = 'waiting';
			}
			$out[] = array(
				'label' => $check->get_label(),
				'status' => $st,
				'notes' => isset( $status[ $id ]['notes'] ) ? array_values( (array) $status[ $id ]['notes'] ) : array(),
			);
		}
		return $out;
	}

	/**
	 * Start a new scan, discarding any previous state.
	 *
	 * @return array New state.
	 */
	public function start( $quick = false ) {
		// Generate a new scan id.
		$scan_id = 'scan_' . gmdate( 'Ymd_His' ) . '_' . wp_generate_password( 8, false, false );

		// Count total steps for progress reporting.
		$total = 0;
		foreach ( $this->get_check_classes() as $cls ) {
			if ( ! class_exists( $cls ) ) {
				continue;
			}
			$instance = new $cls( $scan_id, $this->logger );
			$total   += count( $instance->get_steps() );
		}

		// Purge any stale findings for unfinished scans (defensive).
		$previous = $this->get_state();
		if ( ! empty( $previous['scan_id'] ) && $previous['status'] !== self::STATUS_COMPLETED ) {
			$this->logger->clear_scan( $previous['scan_id'] );
		}

		$state = array(
			'status'       => self::STATUS_RUNNING,
			'scan_id'      => $scan_id,
			'started_at'   => time(),
			'updated_at'   => time(),
			'check_index'  => 0,
			'step_index'   => 0,
			'cursor'       => array(),
			'total_steps'  => $total,
			'done_steps'   => 0,
			'last_message' => __( 'Scan started.', 'shieldscope-site-security-scanner' ),
			'owner_id'     => get_current_user_id(),
			'check_status' => array(),
			'quick'        => (bool) $quick,
		);
		$this->save_state( $state );
		$this->kick_background( $state );
		return $state;
	}

	/**
	 * Pause a running scan (from the UI).
	 *
	 * @return array
	 */
	public function pause() {
		return $this->with_lock(
			function () {
				$state = $this->get_fresh_state();
				if ( self::STATUS_RUNNING === $state['status'] ) {
					$state['status']       = self::STATUS_PAUSED;
					$state['last_message'] = __( 'Scan paused.', 'shieldscope-site-security-scanner' );
					$this->save_state( $state );
				}
				return $state;
			}
		);
	}

	/**
	 * Resume a paused scan.
	 *
	 * @return array
	 */
	public function resume() {
		$state = $this->with_lock(
			function () {
				$state = $this->get_fresh_state();
				if ( self::STATUS_PAUSED === $state['status'] ) {
					$state['status']       = self::STATUS_RUNNING;
					$state['last_message'] = __( 'Scan resumed.', 'shieldscope-site-security-scanner' );
					$this->save_state( $state );
				}
				return $state;
			}
		);
		// Also restarts a stalled running scan's background chain (SC2-10).
		$this->kick_background( $state );
		return $state;
	}

	/**
	 * Run a state change while holding the tick lock, so it cannot overwrite
	 * progress a tick saves at the same moment (SC2-09). Waits up to 5 s for
	 * a running tick; if the lock cannot be had, the change runs anyway.
	 *
	 * @param callable $change Returns the new state.
	 * @return array
	 */
	private function with_lock( callable $change ) {
		$locked = false;
		for ( $i = 0; $i < 50 && ! $locked; $i++ ) {
			$locked = $this->acquire_lock();
			if ( ! $locked ) {
				usleep( 100000 );
			}
		}
		try {
			return $change();
		} finally {
			if ( $locked ) {
				$this->release_lock();
			}
		}
	}

	/**
	 * Seconds after which a tick lock counts as abandoned: longer than any
	 * request can run here (SC2-03). Unlimited requests (WP-CLI) get 10 min.
	 *
	 * @return int
	 */
	public static function lock_timeout() {
		$max = (int) ini_get( 'max_execution_time' );
		return $max <= 0 ? 600 : max( self::LOCK_TIMEOUT, $max + 15 );
	}

	/**
	 * Make sure a background chunk is queued no later than $delay seconds
	 * from now (moving an existing later event earlier).
	 *
	 * @param int $delay Seconds.
	 * @return void
	 */
	public static function queue_cron( $delay ) {
		$hook = 'shieldscope_run_scan_chunk';
		$at   = time() + max( 0, (int) $delay );
		$next = wp_next_scheduled( $hook );
		if ( false !== $next && $next <= $at ) {
			return;
		}
		if ( false !== $next ) {
			wp_unschedule_event( $next, $hook );
		}
		wp_schedule_single_event( $at, $hook );
	}

	/**
	 * Abort a scan entirely and discard its partial findings.
	 *
	 * @return array
	 */
	public function abort() {
		$state = $this->get_state();
		if ( in_array( $state['status'], array( self::STATUS_RUNNING, self::STATUS_PAUSED ), true ) ) {
			$state['status']       = self::STATUS_ABORTED;
			$state['last_message'] = __( 'Scan aborted by user.', 'shieldscope-site-security-scanner' );
			$this->save_state( $state );
			$this->logger->clear_scan( $state['scan_id'] );
		}
		return $state;
	}

	/**
	 * Run a single chunk of work and return updated state.
	 *
	 * Only one chunk runs at a time; an overlapping call returns the current
	 * state with 'busy' => true and does no work.
	 *
	 * @param bool $from_cron True when invoked from wp-cron.
	 * @return array
	 */
	public function run_chunk( $from_cron = false ) {
		$state = $this->get_fresh_state();
		if ( self::STATUS_RUNNING !== $state['status'] ) {
			return $state;
		}

		// Background chain (SC2-02): queue a watchdog first, so a busy or
		// killed chunk can never end the chain; on success it is moved earlier.
		if ( $from_cron || self::background_enabled() ) {
			self::queue_cron( self::lock_timeout() + 5 );
		}

		if ( ! $this->acquire_lock() ) {
			$state         = $this->get_fresh_state();
			$state['busy'] = true;
			return $state;
		}

		// Store findings in the site language whoever runs the chunk, so
		// titles and fingerprints do not depend on a user's locale (IM2-10).
		$switched = function_exists( 'switch_to_locale' ) && function_exists( 'determine_locale' ) && determine_locale() !== get_locale() && switch_to_locale( get_locale() );

		try {
			$state = $this->run_locked_chunk();
		} finally {
			$this->release_lock();
			if ( $switched ) {
				restore_previous_locale();
			}
		}

		if ( $from_cron && self::STATUS_RUNNING === $state['status'] ) {
			$rest = isset( $state['rest_ms'] ) ? (int) ceil( $state['rest_ms'] / 1000 ) : 0;
			self::queue_cron( max( 10, $rest ) );
		}

		return $state;
	}

	/**
	 * Body of run_chunk(), called while holding the tick lock.
	 *
	 * @return array
	 */
	private function run_locked_chunk() {
		$state = $this->get_fresh_state();

		if ( self::STATUS_RUNNING !== $state['status'] ) {
			return $state;
		}

		$classes = $this->get_check_classes();
		$total   = count( $classes );
		$this->throttle->start_chunk();
		$deadline = microtime( true ) + $this->chunk_time_limit;

		while ( $state['check_index'] < $total && ! $this->throttle->should_yield() ) {
			$cls = $classes[ $state['check_index'] ];
			if ( ! class_exists( $cls ) ) {
				$state['check_index']++;
				$state['step_index'] = 0;
				$state['cursor']     = array();
				continue;
			}

			$check = new $cls( $state['scan_id'], $this->logger );
			$steps = $check->get_steps();

			if ( $state['step_index'] >= count( $steps ) ) {
				$state = self::mark_check( $state, $check, ShieldScope_Coverage::DONE );
				$state['check_index']++;
				$state['step_index'] = 0;
				$state['cursor']     = array();
				continue;
			}

			$step = $steps[ $state['step_index'] ];

			// Quick scan (S-11): skip steps that read many files or make many requests.
			if ( ! empty( $state['quick'] ) && in_array( $step, $check->get_slow_steps(), true ) ) {
				$state = self::mark_check(
					$state,
					$check,
					ShieldScope_Coverage::PARTIAL,
					/* translators: %s: step id */
					sprintf( __( 'step "%s" skipped in a quick scan', 'shieldscope-site-security-scanner' ), $step )
				);
				$state['step_index']++;
				$state['cursor']     = array();
				$state['done_steps'] = min( $state['total_steps'], $state['done_steps'] + 1 );
				continue;
			}

			// A step still marked as started when a tick begins was cut off
			// by a killed request (time or memory limit).
			$key   = $state['check_index'] . ':' . $state['step_index'];
			$fails = ( is_array( $state['started_step'] ) && isset( $state['started_step']['key'] ) && $key === $state['started_step']['key'] )
				? (int) $state['started_step']['fails'] + 1
				: 0;
			if ( $fails >= self::MAX_STEP_FAILS ) {
				$this->logger->record(
					$state['scan_id'],
					$check->get_id(),
					ShieldScope_Logger::SEVERITY_INFO,
					sprintf(
						/* translators: 1: check label, 2: step id */
						__( 'Step skipped: timed out: %1$s, %2$s', 'shieldscope-site-security-scanner' ),
						$check->get_label(),
						$step
					),
					__( 'This step did not finish in two attempts, so the scan skipped it and continued. Its results are missing from this report.', 'shieldscope-site-security-scanner' )
				);
				$state                 = self::mark_check(
					$state,
					$check,
					ShieldScope_Coverage::PARTIAL,
					/* translators: %s: step id */
					sprintf( __( 'step "%s" timed out and was skipped', 'shieldscope-site-security-scanner' ), $step )
				);
				$state['started_step'] = null;
				$state['step_index']++;
				$state['cursor']     = array();
				$state['done_steps'] = min( $state['total_steps'], $state['done_steps'] + 1 );
				continue;
			}

			$state['last_message'] = sprintf(
				/* translators: 1: check label, 2: step id */
				__( 'Running %1$s → %2$s', 'shieldscope-site-security-scanner' ),
				$check->get_label(),
				$step
			);

			// Save the progress so far, marked with the step about to run.
			$state['started_step'] = array(
				'key'   => $key,
				'fails' => $fails,
			);
			list( $state, $stop ) = $this->save_progress( $state, $total );
			if ( $stop ) {
				return $state;
			}

			$check->set_deadline( $deadline );
			// A retry after a killed request does not tokenize files (SC2-01).
			$check->set_careful( $fails > 0 );
			$started = microtime( true );
			try {
				$result = $check->run_step( $step, (array) $state['cursor'] );
			} catch ( \Throwable $e ) {
				// Don't kill the scan on a single failed check.
				$this->logger->record(
					$state['scan_id'],
					$check->get_id(),
					ShieldScope_Logger::SEVERITY_INFO,
					__( 'Check module error', 'shieldscope-site-security-scanner' ),
					$e->getMessage()
				);
				$state  = self::mark_check(
					$state,
					$check,
					ShieldScope_Coverage::ERROR,
					/* translators: %s: step id */
					sprintf( __( 'step "%s" failed with an error', 'shieldscope-site-security-scanner' ), $step )
				);
				$result = array( 'continue' => false, 'cursor' => array() );
			}
			foreach ( $check->take_coverage_notes() as $note ) {
				$state = self::mark_check( $state, $check, ShieldScope_Coverage::PARTIAL, $note );
			}
			$elapsed = microtime( true ) - $started;

			$state['started_step'] = null;

			$continue = isset( $result['continue'] ) ? (bool) $result['continue'] : false;
			$cursor   = isset( $result['cursor'] ) && is_array( $result['cursor'] ) ? $result['cursor'] : array();

			if ( $continue ) {
				// Same step again with updated cursor; don't advance step counter.
				$state['cursor'] = $cursor;
			} else {
				$state['step_index']++;
				$state['cursor']   = array();
				$state['done_steps'] = min( $state['total_steps'], $state['done_steps'] + 1 );
			}

			// Throttle proportional to work just done.
			$this->throttle->throttle( $elapsed );
		}

		// Rest before the next chunk is taken by the caller, not slept here (S-14).
		$state['rest_ms'] = (int) round( $this->throttle->rest_seconds() * 1000 );

		list( $state, ) = $this->save_progress( $state, $total );

		return $state;
	}

	/**
	 * Save progress while holding the tick lock, without overwriting a status
	 * another request set (Pause, Abort, a new scan) since this tick began.
	 *
	 * @param array $state        State as advanced by this tick.
	 * @param int   $total_checks Number of check classes.
	 * @return array { 0: array state to continue with or return, 1: bool stop the chunk }
	 */
	private function save_progress( array $state, $total_checks ) {
		// The lock is renewed on every save; if it expired and another tick
		// took it, that tick owns the scan now and this one must not save.
		if ( ! $this->refresh_lock() ) {
			return array( $this->get_fresh_state(), true );
		}

		$fresh = $this->get_fresh_state();
		if ( $fresh['scan_id'] !== $state['scan_id'] || self::STATUS_ABORTED === $fresh['status'] ) {
			// Scan aborted or replaced: drop this chunk and the findings it
			// recorded after the abort or restart cleared the others.
			$this->logger->clear_scan( $state['scan_id'] );
			return array( $fresh, true );
		}
		if ( self::STATUS_PAUSED === $fresh['status'] ) {
			// Keep the progress, but stay paused; the step about to run will not.
			$state['status']       = self::STATUS_PAUSED;
			$state['last_message'] = $fresh['last_message'];
			$state['started_step'] = null;
		} elseif ( self::STATUS_RUNNING !== $fresh['status'] ) {
			return array( $fresh, true );
		}

		// Done?
		if ( self::STATUS_RUNNING === $state['status'] && $state['check_index'] >= $total_checks ) {
			$state['status']       = self::STATUS_COMPLETED;
			$state['last_message'] = ShieldScope_Logger::save_failed( $state['scan_id'] )
				? __( 'Scan finished, but some results could not be saved. This report is incomplete.', 'shieldscope-site-security-scanner' )
				: __( 'Scan complete.', 'shieldscope-site-security-scanner' );
			$state['done_steps']   = $state['total_steps'];

			update_option( 'shieldscope_last_scan', $state['scan_id'], false );
			ShieldScope_Coverage::save( $state['scan_id'], $state['check_status'], $this->check_labels() );
			ShieldScope_History::record( $state['scan_id'], ShieldScope_Ignore::active_summary( $state['scan_id'] ) );
		}

		$this->save_state( $state );

		return array( $state, self::STATUS_RUNNING !== $state['status'] );
	}

	/**
	 * Record a check's status in the scan state. A worse status wins
	 * (error over partial over done); notes accumulate.
	 *
	 * @param array                  $state  State.
	 * @param ShieldScope_Check_Base $check  Check.
	 * @param string                 $status ShieldScope_Coverage status.
	 * @param string                 $note   Optional note.
	 * @return array State.
	 */
	private static function mark_check( array $state, $check, $status, $note = '' ) {
		$id   = $check->get_id();
		$all  = isset( $state['check_status'] ) && is_array( $state['check_status'] ) ? $state['check_status'] : array();
		$item = isset( $all[ $id ] ) ? $all[ $id ] : array(
			'status' => ShieldScope_Coverage::DONE,
			'notes'  => array(),
		);
		if ( ShieldScope_Coverage::rank( $status ) > ShieldScope_Coverage::rank( $item['status'] ) ) {
			$item['status'] = $status;
		}
		if ( '' !== $note && ! in_array( $note, $item['notes'], true ) ) {
			$item['notes'][] = $note;
		}
		$all[ $id ]            = $item;
		$state['check_status'] = $all;
		return $state;
	}

	/**
	 * Check id => label.
	 *
	 * @return array
	 */
	private function check_labels() {
		$labels = array();
		foreach ( $this->get_check_classes() as $cls ) {
			if ( class_exists( $cls ) ) {
				$check                      = new $cls( '', $this->logger );
				$labels[ $check->get_id() ] = $check->get_label();
			}
		}
		return $labels;
	}

	/**
	 * Compute progress percentage.
	 *
	 * @param array $state State.
	 * @return int 0-100
	 */
	public function get_progress( array $state ) {
		if ( empty( $state['total_steps'] ) ) {
			return 0;
		}
		return (int) min( 100, floor( ( $state['done_steps'] * 100 ) / $state['total_steps'] ) );
	}
}
