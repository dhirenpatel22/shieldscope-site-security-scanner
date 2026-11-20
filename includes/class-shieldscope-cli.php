<?php
/**
 * WP-CLI commands (S-13).
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Run a ShieldScope audit and read its report from the command line.
 */
class ShieldScope_CLI {

	/**
	 * Severity order, worst first.
	 *
	 * @var string[]
	 */
	private static $order = array( 'critical', 'high', 'medium', 'low', 'info' );

	/**
	 * Run a full scan now and print the findings.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv or summary.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - summary
	 * ---
	 *
	 * [--fail-on=<severity>]
	 * : Exit with status 1 if a finding at or above this severity exists
	 * (ignored findings do not count).
	 * ---
	 * default: critical
	 * options:
	 *   - critical
	 *   - high
	 *   - medium
	 *   - low
	 *   - none
	 * ---
	 *
	 * [--timeout=<seconds>]
	 * : Give up after this many seconds.
	 * ---
	 * default: 1800
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp shieldscope scan
	 *     wp shieldscope scan --format=json --fail-on=high > report.json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 * @return void
	 */
	public function scan( $args, $assoc_args ) {
		$timeout = isset( $assoc_args['timeout'] ) ? max( 10, (int) $assoc_args['timeout'] ) : 1800;
		$scanner = new ShieldScope_Scanner();
		$state   = $scanner->get_state();
		if ( in_array( $state['status'], array( ShieldScope_Scanner::STATUS_RUNNING, ShieldScope_Scanner::STATUS_PAUSED ), true ) ) {
			WP_CLI::error( 'A scan is already running or paused. Abort it in the admin first.' );
		}

		$state   = $scanner->start();
		$started = microtime( true );
		WP_CLI::log( 'Scanning (' . $state['total_steps'] . ' steps)…' );
		while ( ShieldScope_Scanner::STATUS_RUNNING === $state['status'] && ( microtime( true ) - $started ) < $timeout ) {
			$state = $scanner->run_chunk( false );
		}
		if ( ShieldScope_Scanner::STATUS_COMPLETED !== $state['status'] ) {
			WP_CLI::error( 'The scan did not finish (status: ' . $state['status'] . ').' );
		}
		WP_CLI::log( sprintf( 'Scan finished in %.1f s.', microtime( true ) - $started ) );
		$this->output( $state['scan_id'], $assoc_args );
	}

	/**
	 * Print the last completed report.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv or summary.
	 * ---
	 * default: table
	 * ---
	 *
	 * [--fail-on=<severity>]
	 * : Exit with status 1 if a finding at or above this severity exists.
	 * ---
	 * default: none
	 * ---
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 * @return void
	 */
	public function report( $args, $assoc_args ) {
		$scan_id = (string) get_option( 'shieldscope_last_scan', '' );
		if ( '' === $scan_id ) {
			WP_CLI::error( 'No completed scan. Run: wp shieldscope scan' );
		}
		$this->output( $scan_id, $assoc_args + array( 'fail-on' => 'none' ) );
	}

	/**
	 * Print findings and set the exit status.
	 *
	 * @param string $scan_id    Scan id.
	 * @param array  $assoc_args Options.
	 * @return void
	 */
	private function output( $scan_id, array $assoc_args ) {
		$format  = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';
		$fail_on = isset( $assoc_args['fail-on'] ) ? $assoc_args['fail-on'] : 'critical';

		$report           = ShieldScope_PDF_Report::collect_report();
		$report['scan_id'] = $scan_id;
		$logger           = new ShieldScope_Logger();
		$report['findings'] = $logger->get_findings( $scan_id );
		$report['coverage'] = ShieldScope_Coverage::get( $scan_id );
		$rows             = ShieldScope_Export::rows( $report );

		if ( 'json' === $format ) {
			WP_CLI::line( ShieldScope_Export::to_json( $report ) );
		} elseif ( 'csv' === $format ) {
			WP_CLI::line( substr( ShieldScope_Export::to_csv( $report ), 3 ) ); // Without the BOM.
		} elseif ( 'table' === $format && $rows ) {
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'severity', 'confidence', 'check', 'title', 'target', 'line' ) );
		}

		$counts = self::active_counts( $rows );
		WP_CLI::log( ShieldScope_PDF_Report::verdict( $counts ) . ' Counts: ' . wp_json_encode( $counts ) );
		if ( null !== $report['coverage'] ) {
			WP_CLI::log( 'Coverage: ' . ShieldScope_Coverage::summary( $report['coverage'] ) );
		}

		if ( self::should_fail( $counts, $fail_on ) ) {
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * Counts per severity, not counting ignored findings.
	 *
	 * @param array[] $rows Export rows.
	 * @return array
	 */
	public static function active_counts( array $rows ) {
		$counts = array_fill_keys( self::$order, 0 );
		foreach ( $rows as $row ) {
			if ( '' === $row['ignored'] && isset( $counts[ $row['severity'] ] ) ) {
				++$counts[ $row['severity'] ];
			}
		}
		return $counts;
	}

	/**
	 * Is there a finding at or above the --fail-on severity?
	 *
	 * @param array  $counts  Counts per severity.
	 * @param string $fail_on Severity or "none".
	 * @return bool
	 */
	public static function should_fail( array $counts, $fail_on ) {
		$pos = array_search( $fail_on, self::$order, true );
		if ( false === $pos ) {
			return false;
		}
		foreach ( array_slice( self::$order, 0, $pos + 1 ) as $sev ) {
			if ( ! empty( $counts[ $sev ] ) ) {
				return true;
			}
		}
		return false;
	}
}
