<?php
/**
 * Which checks a scan completed, partly completed or could not run (S-04).
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Coverage
 */
class ShieldScope_Coverage {

	const OPTION  = 'shieldscope_coverage';
	const DONE    = 'done';
	const PARTIAL = 'partial';
	const ERROR   = 'error';
	const NOT_RUN = 'not_run';

	/**
	 * Severity order of statuses (higher is worse).
	 *
	 * @param string $status Status.
	 * @return int
	 */
	public static function rank( $status ) {
		$ranks = array(
			self::DONE    => 0,
			self::PARTIAL => 1,
			self::ERROR   => 2,
			self::NOT_RUN => 3,
		);
		return isset( $ranks[ $status ] ) ? $ranks[ $status ] : 0;
	}

	/**
	 * Store the coverage of a completed scan. Checks with no entry did not run.
	 *
	 * @param string $scan_id Scan id.
	 * @param array  $status  check id => { status, notes }.
	 * @param array  $labels  check id => label, in run order.
	 * @return void
	 */
	public static function save( $scan_id, array $status, array $labels ) {
		$checks = array();
		foreach ( $labels as $id => $label ) {
			$item          = isset( $status[ $id ] ) ? $status[ $id ] : array(
				'status' => self::NOT_RUN,
				'notes'  => array(),
			);
			$item['label'] = $label;
			$checks[ $id ] = $item;
		}
		update_option(
			self::OPTION,
			array(
				'scan_id' => (string) $scan_id,
				'checks'  => $checks,
			),
			false
		);
	}

	/**
	 * Coverage for a scan, or null when none was stored (older scans).
	 *
	 * @param string $scan_id Scan id.
	 * @return array|null check id => { label, status, notes }.
	 */
	public static function get( $scan_id ) {
		$data = get_option( self::OPTION, array() );
		if ( ! is_array( $data ) || empty( $data['scan_id'] ) || (string) $scan_id !== $data['scan_id'] || empty( $data['checks'] ) ) {
			return null;
		}
		return (array) $data['checks'];
	}

	/**
	 * One-line summary, for example "14 of 16 checks completed; 2 partly completed."
	 *
	 * @param array $checks From get().
	 * @return string
	 */
	public static function summary( array $checks ) {
		$counts = array_fill_keys( array( self::DONE, self::PARTIAL, self::ERROR, self::NOT_RUN ), 0 );
		foreach ( $checks as $c ) {
			$s = isset( $c['status'], $counts[ $c['status'] ] ) ? $c['status'] : self::DONE;
			++$counts[ $s ];
		}
		$line = sprintf(
			/* translators: 1: completed checks, 2: all checks */
			__( '%1$d of %2$d checks completed in full.', 'shieldscope-site-security-scanner' ),
			$counts[ self::DONE ],
			count( $checks )
		);
		$parts = array();
		if ( $counts[ self::PARTIAL ] ) {
			/* translators: %d: number of checks */
			$parts[] = sprintf( _n( '%d partly completed', '%d partly completed', $counts[ self::PARTIAL ], 'shieldscope-site-security-scanner' ), $counts[ self::PARTIAL ] );
		}
		if ( $counts[ self::ERROR ] ) {
			/* translators: %d: number of checks */
			$parts[] = sprintf( _n( '%d failed with an error', '%d failed with an error', $counts[ self::ERROR ], 'shieldscope-site-security-scanner' ), $counts[ self::ERROR ] );
		}
		if ( $counts[ self::NOT_RUN ] ) {
			/* translators: %d: number of checks */
			$parts[] = sprintf( _n( '%d did not run', '%d did not run', $counts[ self::NOT_RUN ], 'shieldscope-site-security-scanner' ), $counts[ self::NOT_RUN ] );
		}
		if ( $parts ) {
			$line .= ' ' . ucfirst( implode( '; ', $parts ) ) . '.';
		}
		return $line;
	}

	/**
	 * Translated status name.
	 *
	 * @param string $status Status.
	 * @return string
	 */
	public static function status_label( $status ) {
		switch ( $status ) {
			case self::PARTIAL:
				return __( 'Partly completed', 'shieldscope-site-security-scanner' );
			case self::ERROR:
				return __( 'Error', 'shieldscope-site-security-scanner' );
			case self::NOT_RUN:
				return __( 'Did not run', 'shieldscope-site-security-scanner' );
			default:
				return __( 'Completed', 'shieldscope-site-security-scanner' );
		}
	}
}
