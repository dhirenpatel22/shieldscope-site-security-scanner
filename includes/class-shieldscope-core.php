<?php
/**
 * Core plugin class — singleton controller.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Core
 */
final class ShieldScope_Core {

	/**
	 * Singleton instance.
	 *
	 * @var ShieldScope_Core|null
	 */
	private static $instance = null;

	/**
	 * Admin handler.
	 *
	 * @var ShieldScope_Admin|null
	 */
	public $admin = null;

	/**
	 * AJAX handler.
	 *
	 * @var ShieldScope_Ajax|null
	 */
	public $ajax = null;

	/**
	 * Get singleton.
	 *
	 * @return ShieldScope_Core
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — singleton pattern.
	 */
	private function __construct() {}

	/**
	 * Prevent cloning.
	 *
	 * @return void
	 */
	private function __clone() {}

	/**
	 * Prevent unserialization.
	 *
	 * @return void
	 */
	public function __wakeup() {
		throw new \Exception( 'Cannot unserialize singleton' );
	}

	/**
	 * Wire up hooks.
	 *
	 * @return void
	 */
	public function init() {
		// Admin surfaces only load for users who can manage options.
		if ( is_admin() ) {
			$this->admin = new ShieldScope_Admin();
			$this->admin->register();

			$this->ajax = new ShieldScope_Ajax();
			$this->ajax->register();
		}

		// Cron handler — runs regardless of admin context.
		add_action( 'shieldscope_run_scan_chunk', array( $this, 'run_scheduled_chunk' ) );
		add_action( 'shieldscope_daily_maintenance', array( $this, 'run_daily_maintenance' ) );
	}

	/**
	 * Handle a scheduled scan chunk (used as a cron fallback when AJAX pauses).
	 *
	 * @return void
	 */
	public function run_scheduled_chunk() {
		$scanner = new ShieldScope_Scanner();
		$scanner->run_chunk( true );
	}

	/**
	 * Daily maintenance — prune old findings and transients.
	 *
	 * @return void
	 */
	public function run_daily_maintenance() {
		$logger = new ShieldScope_Logger();
		$logger->prune_old( 30 * DAY_IN_SECONDS );
	}

	/**
	 * Activation hook — schedule events, create table, seed settings.
	 *
	 * @return void
	 */
	public static function on_activate() {
		// Require capability even on activation, belt-and-braces.
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		if ( ! wp_next_scheduled( 'shieldscope_daily_maintenance' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'shieldscope_daily_maintenance' );
		}

		// Create findings table.
		ShieldScope_Logger::create_table();

		// Seed defaults.
		if ( false === get_option( 'shieldscope_settings' ) ) {
			add_option(
				'shieldscope_settings',
				array(
					'cpu_limit'          => 20, // percent.
					'chunk_time_limit'   => 2,  // seconds per chunk.
					'max_scan_file_size' => 2 * MB_IN_BYTES,
					'pause_on_blur'      => 1,
				)
			);
		}

		update_option( 'shieldscope_version', SHIELDSCOPE_VERSION );
	}

	/**
	 * Deactivation hook — unschedule cron.
	 *
	 * @return void
	 */
	public static function on_deactivate() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		$crons = array( 'shieldscope_run_scan_chunk', 'shieldscope_daily_maintenance' );
		foreach ( $crons as $cron ) {
			$timestamp = wp_next_scheduled( $cron );
			while ( false !== $timestamp ) {
				wp_unschedule_event( $timestamp, $cron );
				$timestamp = wp_next_scheduled( $cron );
			}
		}
	}
}
