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
			if ( (int) $held > time() - self::LOCK_TIMEOUT ) {
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
	 * Start a new scan, discarding any previous state.
	 *
	 * @return array New state.
	 */
	public function start() {
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
		);
		$this->save_state( $state );
		return $state;
	}

	/**
	 * Pause a running scan (from the UI).
	 *
	 * @return array
	 */
	public function pause() {
		$state = $this->get_state();
		if ( self::STATUS_RUNNING === $state['status'] ) {
			$state['status']       = self::STATUS_PAUSED;
			$state['last_message'] = __( 'Scan paused.', 'shieldscope-site-security-scanner' );
			$this->save_state( $state );
		}
		return $state;
	}

	/**
	 * Resume a paused scan.
	 *
	 * @return array
	 */
	public function resume() {
		$state = $this->get_state();
		if ( self::STATUS_PAUSED === $state['status'] ) {
			$state['status']       = self::STATUS_RUNNING;
			$state['last_message'] = __( 'Scan resumed.', 'shieldscope-site-security-scanner' );
			$this->save_state( $state );
		}
		return $state;
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

		if ( ! $this->acquire_lock() ) {
			$state         = $this->get_fresh_state();
			$state['busy'] = true;
			return $state;
		}

		try {
			$state = $this->run_locked_chunk();
		} finally {
			$this->release_lock();
		}

		// If we were called from cron and the scan is still running, re-schedule.
		if ( $from_cron && self::STATUS_RUNNING === $state['status'] && ! wp_next_scheduled( 'shieldscope_run_scan_chunk' ) ) {
			wp_schedule_single_event( time() + 10, 'shieldscope_run_scan_chunk' );
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
				$state['check_index']++;
				$state['step_index'] = 0;
				$state['cursor']     = array();
				continue;
			}

			$step = $steps[ $state['step_index'] ];

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
				$result = array( 'continue' => false, 'cursor' => array() );
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
			$state['last_message'] = __( 'Scan complete.', 'shieldscope-site-security-scanner' );
			$state['done_steps']   = $state['total_steps'];

			update_option( 'shieldscope_last_scan', $state['scan_id'], false );
		}

		$this->save_state( $state );

		return array( $state, self::STATUS_RUNNING !== $state['status'] );
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
