<?php
/**
 * Scan pacing.
 *
 * The scanner works in chunks of at most chunk_time_limit seconds. After a
 * chunk it rests for a time proportional to the work done, so that work is
 * about cpu_limit percent of the elapsed time (the "scan pace" setting).
 * The rest is not slept inside the request: the request returns and the
 * caller (the browser tab or WP-Cron) waits rest_seconds() before the next
 * chunk, so no PHP worker is held while idle (S-14).
 *
 * Example: pace 20% and 1.5 s of work → rest 6 s before the next chunk.
 * This paces the scan; it does not measure or cap CPU use.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Throttle
 */
class ShieldScope_Throttle {

	/**
	 * Max percentage of CPU the scanner is allowed to use (1-100).
	 *
	 * @var int
	 */
	private $cpu_limit;

	/**
	 * Max wall-clock time for a single scan chunk, in seconds.
	 *
	 * @var float
	 */
	private $chunk_time_limit;

	/**
	 * Chunk start timestamp (microtime float).
	 *
	 * @var float
	 */
	private $chunk_started_at = 0.0;

	/**
	 * Work done in this chunk, in seconds.
	 *
	 * @var float
	 */
	private $worked = 0.0;

	/**
	 * Longest rest between chunks, in seconds.
	 */
	const MAX_REST = 30.0;

	/**
	 * Constructor.
	 *
	 * @param int   $cpu_limit         Percentage (1-100).
	 * @param float $chunk_time_limit  Seconds.
	 */
	public function __construct( $cpu_limit = 20, $chunk_time_limit = 2.0 ) {
		$cpu_limit       = (int) $cpu_limit;
		$this->cpu_limit = max( 1, min( 100, $cpu_limit ) );

		$chunk_time_limit       = (float) $chunk_time_limit;
		$this->chunk_time_limit = max( 0.25, min( 10.0, $chunk_time_limit ) );
	}

	/**
	 * Mark the start of a scan chunk.
	 *
	 * @return void
	 */
	public function start_chunk() {
		$this->chunk_started_at = microtime( true );
		$this->worked           = 0.0;
	}

	/**
	 * Has the current chunk exceeded its time budget?
	 *
	 * @return bool
	 */
	public function should_yield() {
		if ( 0.0 === $this->chunk_started_at ) {
			return false;
		}
		return ( microtime( true ) - $this->chunk_started_at ) >= $this->chunk_time_limit;
	}

	/**
	 * Record a unit of work. Does not sleep.
	 *
	 * @param float $work_seconds Time the last unit of work took.
	 * @return void
	 */
	public function throttle( $work_seconds ) {
		$this->worked += max( 0.0, (float) $work_seconds );
	}

	/**
	 * How long to rest before the next chunk:
	 * work × (100 − pace) / pace, capped at MAX_REST.
	 *
	 * @return float Seconds.
	 */
	public function rest_seconds() {
		return min( self::MAX_REST, $this->worked * ( 100 - $this->cpu_limit ) / $this->cpu_limit );
	}

	/**
	 * Convenience — run a callable with automatic throttling.
	 *
	 * @param callable $work Function to execute.
	 * @return mixed Return value of $work.
	 */
	public function run_throttled( callable $work ) {
		$started = microtime( true );
		$result  = call_user_func( $work );
		$elapsed = microtime( true ) - $started;
		$this->throttle( $elapsed );
		return $result;
	}
}
