<?php
/**
 * AJAX endpoints for the scan UI.
 *
 * All endpoints:
 *   - Require manage_options
 *   - Verify a nonce
 *   - Sanitize every input
 *   - Return JSON via wp_send_json_*
 *
 * @package Site_Security_Audit
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class SSA_Ajax
 */
class SSA_Ajax {

	/**
	 * Register handlers.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'wp_ajax_ssa_start', array( $this, 'handle_start' ) );
		add_action( 'wp_ajax_ssa_pause', array( $this, 'handle_pause' ) );
		add_action( 'wp_ajax_ssa_resume', array( $this, 'handle_resume' ) );
		add_action( 'wp_ajax_ssa_abort', array( $this, 'handle_abort' ) );
		add_action( 'wp_ajax_ssa_tick', array( $this, 'handle_tick' ) );
		add_action( 'wp_ajax_ssa_status', array( $this, 'handle_status' ) );
	}

	/**
	 * Common gate: capability + nonce.
	 *
	 * @return void Exits on failure.
	 */
	private function authorize() {
		if ( ! current_user_can( SSA_MIN_CAP ) ) {
			wp_send_json_error(
				array( 'message' => __( 'You do not have permission to do this.', 'site-security-audit' ) ),
				403
			);
		}
		$nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'ssa_scan' ) ) {
			wp_send_json_error(
				array( 'message' => __( 'Security check failed. Please reload the page.', 'site-security-audit' ) ),
				403
			);
		}
	}

	/**
	 * Start.
	 *
	 * @return void
	 */
	public function handle_start() {
		$this->authorize();
		$scanner = new SSA_Scanner();
		$state   = $scanner->start();
		wp_send_json_success( $this->envelope( $state, $scanner ) );
	}

	/**
	 * Pause.
	 *
	 * @return void
	 */
	public function handle_pause() {
		$this->authorize();
		$scanner = new SSA_Scanner();
		$state   = $scanner->pause();
		wp_send_json_success( $this->envelope( $state, $scanner ) );
	}

	/**
	 * Resume.
	 *
	 * @return void
	 */
	public function handle_resume() {
		$this->authorize();
		$scanner = new SSA_Scanner();
		$state   = $scanner->resume();
		wp_send_json_success( $this->envelope( $state, $scanner ) );
	}

	/**
	 * Abort.
	 *
	 * @return void
	 */
	public function handle_abort() {
		$this->authorize();
		$scanner = new SSA_Scanner();
		$state   = $scanner->abort();
		wp_send_json_success( $this->envelope( $state, $scanner ) );
	}

	/**
	 * Run one chunk of work. This is the heartbeat called by the JS UI.
	 *
	 * @return void
	 */
	public function handle_tick() {
		$this->authorize();
		$scanner = new SSA_Scanner();
		$state   = $scanner->run_chunk( false );
		wp_send_json_success( $this->envelope( $state, $scanner ) );
	}

	/**
	 * Status-only (no work). Used for polling while paused.
	 *
	 * @return void
	 */
	public function handle_status() {
		$this->authorize();
		$scanner = new SSA_Scanner();
		$state   = $scanner->get_state();
		wp_send_json_success( $this->envelope( $state, $scanner ) );
	}

	/**
	 * Build the response body.
	 *
	 * @param array         $state   Scan state.
	 * @param SSA_Scanner $scanner Scanner.
	 * @return array
	 */
	private function envelope( array $state, SSA_Scanner $scanner ) {
		$logger  = new SSA_Logger();
		$summary = ! empty( $state['scan_id'] ) ? $logger->get_summary( $state['scan_id'] ) : array();

		return array(
			'status'       => $state['status'],
			'progress'     => $scanner->get_progress( $state ),
			'done_steps'   => (int) $state['done_steps'],
			'total_steps'  => (int) $state['total_steps'],
			'message'      => (string) $state['last_message'],
			'scan_id'      => (string) $state['scan_id'],
			'summary'      => $summary,
		);
	}
}
