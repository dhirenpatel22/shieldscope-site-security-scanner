<?php
/**
 * Base class for all security check modules.
 *
 * A "check module" inspects one concern area (core, users, code, etc.)
 * and can be broken into discrete "steps" so the scanner can yield
 * between them and keep CPU usage low.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Base
 */
abstract class ShieldScope_Check_Base {

	/**
	 * Scan identifier.
	 *
	 * @var string
	 */
	protected $scan_id;

	/**
	 * Logger.
	 *
	 * @var ShieldScope_Logger
	 */
	protected $logger;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Current scan ID.
	 * @param ShieldScope_Logger $logger  Logger instance.
	 */
	public function __construct( $scan_id, ShieldScope_Logger $logger ) {
		$this->scan_id = $scan_id;
		$this->logger  = $logger;
	}

	/**
	 * Unique identifier for this check module (used in findings & UI).
	 *
	 * @return string
	 */
	abstract public function get_id();

	/**
	 * Human-readable label.
	 *
	 * @return string
	 */
	abstract public function get_label();

	/**
	 * List of step identifiers this check can run.
	 *
	 * Each step should be small enough to fit inside one CPU-throttled unit
	 * of work (roughly a few hundred ms).
	 *
	 * @return array<int,string>
	 */
	abstract public function get_steps();

	/**
	 * Execute a single step.
	 *
	 * May return an array with 'continue' => true if there is more work
	 * for this step, in which case the scanner will call it again without
	 * advancing the step pointer.
	 *
	 * @param string $step    Step identifier.
	 * @param array  $cursor  Opaque cursor stored between invocations.
	 * @return array { 'continue' => bool, 'cursor' => array }
	 */
	abstract public function run_step( $step, array $cursor = array() );

	/**
	 * Helper — record a finding with this check's id.
	 *
	 * @param string $severity       Severity.
	 * @param string $title          Title.
	 * @param string $description    Description.
	 * @param string $recommendation Recommendation.
	 * @param string $target         Target.
	 * @param array  $context        Context.
	 * @return void
	 */
	protected function finding( $severity, $title, $description = '', $recommendation = '', $target = '', $context = array() ) {
		$this->logger->record(
			$this->scan_id,
			$this->get_id(),
			$severity,
			$title,
			$description,
			$recommendation,
			$target,
			$context
		);
	}

	/**
	 * Shared resumable directory walker (two-queue design).
	 *
	 * Directories are always expanded fully into the file queue before the
	 * per-call file budget is applied, so a batch boundary can never fall in
	 * the middle of a directory and silently drop files — the file queue in
	 * the cursor carries any leftovers to the next invocation.
	 *
	 * Cursor keys:
	 *   dirs    — directories still to expand
	 *   files   — file paths waiting to be handled
	 *   checked — cumulative count of files handled
	 *
	 * @param string   $root           Root directory to walk.
	 * @param array    $cursor         Cursor from the previous invocation (empty on first call).
	 * @param callable $handle_file    Called once per matching file with the full path.
	 * @param int      $files_per_call Max files to handle in this invocation.
	 * @param array    $skip_dirs      Directory basenames to skip entirely.
	 * @param string   $pattern        Regex a file basename must match to be handled.
	 * @param bool     $skip_self      Skip files inside this plugin's own directory.
	 * @return array { 'continue' => bool, 'cursor' => array }
	 */
	protected function walk_php_files_step( $root, array $cursor, callable $handle_file, $files_per_call = 25, array $skip_dirs = array( 'node_modules', 'vendor', '.git' ), $pattern = '/\.php$/i', $skip_self = true ) {
		if ( ! is_dir( $root ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}
		if ( ! isset( $cursor['dirs'] ) && ! isset( $cursor['files'] ) ) {
			$cursor = array(
				'dirs'    => array( $root ),
				'files'   => array(),
				'checked' => isset( $cursor['checked'] ) ? (int) $cursor['checked'] : 0,
			);
		}
		$cursor['dirs']  = isset( $cursor['dirs'] ) ? (array) $cursor['dirs'] : array();
		$cursor['files'] = isset( $cursor['files'] ) ? (array) $cursor['files'] : array();

		$self_dir  = defined( 'SHIELDSCOPE_PLUGIN_DIR' )
			? rtrim( str_replace( '\\', '/', SHIELDSCOPE_PLUGIN_DIR ), '/' ) . '/'
			: '';
		$processed = 0;

		while ( $processed < $files_per_call ) {
			// Drain the file queue before expanding another directory.
			if ( ! empty( $cursor['files'] ) ) {
				$full = array_shift( $cursor['files'] );
				call_user_func( $handle_file, $full );
				$processed++;
				$cursor['checked']++;
				continue;
			}

			if ( empty( $cursor['dirs'] ) ) {
				break;
			}

			$current = array_shift( $cursor['dirs'] );
			$entries = @scandir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $entries ) {
				continue;
			}

			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$full = $current . DIRECTORY_SEPARATOR . $entry;

				// Skip this plugin's own files (our detection regexes would
				// otherwise flag our own source strings).
				if ( $skip_self && '' !== $self_dir && 0 === strpos( str_replace( '\\', '/', $full ) . '/', $self_dir ) ) {
					continue;
				}

				if ( is_dir( $full ) ) {
					if ( in_array( $entry, $skip_dirs, true ) ) {
						continue;
					}
					$cursor['dirs'][] = $full;
				} elseif ( preg_match( $pattern, $entry ) ) {
					$cursor['files'][] = $full;
				}
			}
			// Directory expansion does not count against the file budget.
		}

		return array(
			'continue' => ! empty( $cursor['dirs'] ) || ! empty( $cursor['files'] ),
			'cursor'   => $cursor,
		);
	}
}
