<?php
/**
 * The scan page renders the current progress and check list without waiting
 * for the first poll.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Scan_Page_Initial_State
 */
class Test_Scan_Page_Initial_State extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	private function render( array $state ) {
		ob_start();
		include SHIELDSCOPE_PLUGIN_DIR . 'admin/views/scan.php';
		return ob_get_clean();
	}

	public function test_completed_scan_shows_full_bar_and_checks() {
		$state = array_merge(
			( new ShieldScope_Scanner() )->get_state(),
			array( 'status' => 'completed', 'scan_id' => 's1', 'total_steps' => 67, 'done_steps' => 67, 'check_index' => 16 )
		);
		$html = $this->render( $state );
		$this->assertStringContainsString( 'style="width: 100%;"', $html );
		$this->assertStringContainsString( 'aria-valuenow="100"', $html );
		$this->assertStringContainsString( '<span id="shieldscope-progress-pct">100%</span>', $html );
		$this->assertSame( 16, substr_count( $html, 'class="shieldscope-check-name"' ) );
		$this->assertStringNotContainsString( 'shieldscope-checks-card shieldscope-hidden', $html );
	}

	public function test_idle_page_hides_check_list() {
		$html = $this->render( ( new ShieldScope_Scanner() )->get_state() );
		$this->assertStringContainsString( 'shieldscope-checks-card shieldscope-hidden', $html );
		$this->assertStringContainsString( 'style="width: 0%;"', $html );
	}
}
