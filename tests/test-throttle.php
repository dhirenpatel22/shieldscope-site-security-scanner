<?php
/**
 * Tests for ShieldScope_Throttle.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Throttle
 */
class Test_Throttle extends TestCase {

	public function test_cpu_limit_is_clamped_to_valid_range() {
		// Reflection to read the private property after construction.
		$read = function ( $throttle, $prop ) {
			$r = new ReflectionProperty( ShieldScope_Throttle::class, $prop );
			$r->setAccessible( true );
			return $r->getValue( $throttle );
		};

		$this->assertSame( 1, $read( new ShieldScope_Throttle( 0 ), 'cpu_limit' ) );
		$this->assertSame( 1, $read( new ShieldScope_Throttle( -50 ), 'cpu_limit' ) );
		$this->assertSame( 100, $read( new ShieldScope_Throttle( 500 ), 'cpu_limit' ) );
		$this->assertSame( 20, $read( new ShieldScope_Throttle( 20 ), 'cpu_limit' ) );
	}

	public function test_chunk_time_limit_is_clamped() {
		$read = function ( $throttle ) {
			$r = new ReflectionProperty( ShieldScope_Throttle::class, 'chunk_time_limit' );
			$r->setAccessible( true );
			return $r->getValue( $throttle );
		};

		$this->assertSame( 0.25, $read( new ShieldScope_Throttle( 20, 0 ) ) );
		$this->assertSame( 10.0, $read( new ShieldScope_Throttle( 20, 99 ) ) );
		$this->assertSame( 2.0, $read( new ShieldScope_Throttle( 20, 2.0 ) ) );
	}

	public function test_should_yield_only_after_time_budget_elapses() {
		$throttle = new ShieldScope_Throttle( 20, 0.25 );

		// Before start_chunk() there is no budget to exceed.
		$this->assertFalse( $throttle->should_yield() );

		$throttle->start_chunk();
		$this->assertFalse( $throttle->should_yield() );

		usleep( 300000 ); // 0.3s > 0.25s budget.
		$this->assertTrue( $throttle->should_yield() );
	}

	public function test_throttle_sleeps_proportionally_to_cpu_limit() {
		// 20% CPU → sleep = work × (100−20)/20 = 4× work. 50ms work → ~200ms sleep.
		$throttle = new ShieldScope_Throttle( 20, 2.0 );
		$start    = microtime( true );
		$throttle->throttle( 0.05 );
		$elapsed = microtime( true ) - $start;

		$this->assertGreaterThan( 0.15, $elapsed, 'Expected roughly 4× the work time asleep.' );
		$this->assertLessThan( 0.6, $elapsed );
	}

	public function test_throttle_sleep_is_capped_at_two_seconds() {
		$throttle = new ShieldScope_Throttle( 1, 2.0 ); // 1% CPU → 99× multiplier.
		$start    = microtime( true );
		$throttle->throttle( 0.5 ); // Uncapped would be 49.5s.
		$elapsed = microtime( true ) - $start;

		$this->assertLessThan( 2.5, $elapsed, 'Sleep must be hard-capped at 2 seconds.' );
	}

	public function test_zero_or_negative_work_does_not_sleep() {
		$throttle = new ShieldScope_Throttle( 10, 2.0 );
		$start    = microtime( true );
		$throttle->throttle( 0 );
		$throttle->throttle( -1 );
		$this->assertLessThan( 0.05, microtime( true ) - $start );
	}

	public function test_run_throttled_returns_callable_result() {
		$throttle = new ShieldScope_Throttle( 100, 2.0 ); // 100% → no sleep.
		$this->assertSame( 42, $throttle->run_throttled( function () { return 42; } ) );
	}
}
