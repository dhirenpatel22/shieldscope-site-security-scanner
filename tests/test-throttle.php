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
			if ( PHP_VERSION_ID < 80100 ) {
				$r->setAccessible( true ); // No effect (and deprecated) from PHP 8.1.
			}
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
			if ( PHP_VERSION_ID < 80100 ) {
				$r->setAccessible( true ); // No effect (and deprecated) from PHP 8.1.
			}
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

	public function test_rest_is_proportional_to_work_and_pace() {
		// Pace 20% → rest = work × (100−20)/20 = 4× work.
		$throttle = new ShieldScope_Throttle( 20, 2.0 );
		$throttle->start_chunk();
		$throttle->throttle( 0.05 );
		$throttle->throttle( 0.05 );
		$this->assertEqualsWithDelta( 0.4, $throttle->rest_seconds(), 0.0001 );
	}

	public function test_rest_is_capped() {
		$throttle = new ShieldScope_Throttle( 1, 2.0 ); // 99× multiplier.
		$throttle->start_chunk();
		$throttle->throttle( 5 );
		$this->assertSame( ShieldScope_Throttle::MAX_REST, $throttle->rest_seconds() );
	}

	public function test_throttle_never_sleeps_and_new_chunk_resets_work() {
		$throttle = new ShieldScope_Throttle( 1, 2.0 );
		$start    = microtime( true );
		$throttle->throttle( 5 );
		$throttle->throttle( -1 );
		$this->assertLessThan( 0.05, microtime( true ) - $start, 'No sleep inside the request (S-14).' );
		$throttle->start_chunk();
		$this->assertSame( 0.0, $throttle->rest_seconds() );
	}

	public function test_throttle_source_has_no_sleep() {
		$this->assertDoesNotMatchRegularExpression( '/\busleep\s*\(|\bsleep\s*\(/', file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'includes/class-shieldscope-throttle.php' ) );
	}

	public function test_run_throttled_returns_callable_result() {
		$throttle = new ShieldScope_Throttle( 100, 2.0 ); // 100% → no sleep.
		$this->assertSame( 42, $throttle->run_throttled( function () { return 42; } ) );
	}
}
