<?php
/**
 * Scan history and comparison with the previous scan (S-08).
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_History
 */
class ShieldScope_History {

	const OPTION = 'shieldscope_scan_history';
	const KEEP   = 5;

	/**
	 * Completed scans, newest first: { scan_id, date (UTC, Y-m-d H:i:s), counts }.
	 *
	 * @return array[]
	 */
	public static function all() {
		$list = get_option( self::OPTION, array() );
		return is_array( $list ) ? array_values( $list ) : array();
	}

	/**
	 * Record a completed scan and keep the newest KEEP.
	 *
	 * @param string $scan_id Scan id.
	 * @param array  $counts  Counts per severity.
	 * @return void
	 */
	public static function record( $scan_id, array $counts ) {
		$list = array_values(
			array_filter(
				self::all(),
				static function ( $item ) use ( $scan_id ) {
					return isset( $item['scan_id'] ) && $item['scan_id'] !== $scan_id;
				}
			)
		);
		array_unshift(
			$list,
			array(
				'scan_id' => (string) $scan_id,
				'date'    => gmdate( 'Y-m-d H:i:s' ),
				'counts'  => array_map( 'intval', $counts ),
			)
		);
		update_option( self::OPTION, array_slice( $list, 0, self::KEEP ), false );
	}

	/**
	 * Scan ids to keep when pruning old findings.
	 *
	 * @return string[]
	 */
	public static function ids() {
		return array_values( array_filter( array_column( self::all(), 'scan_id' ) ) );
	}

	/**
	 * The scan recorded before this one, or null.
	 *
	 * @param string $scan_id Scan id.
	 * @return array|null
	 */
	public static function previous( $scan_id ) {
		$list = self::all();
		foreach ( $list as $i => $item ) {
			if ( $item['scan_id'] === $scan_id ) {
				return isset( $list[ $i + 1 ] ) ? $list[ $i + 1 ] : null;
			}
		}
		return null;
	}

	/**
	 * Compare two sets of findings by fingerprint.
	 *
	 * @param array $current  Rows of the current scan.
	 * @param array $previous Rows of the previous scan.
	 * @return array { new: rows, fixed: rows, open: int }
	 */
	public static function compare( array $current, array $previous ) {
		$cur  = array();
		$prev = array();
		foreach ( $current as $row ) {
			$cur[ ShieldScope_Ignore::fingerprint( $row ) ] = $row;
		}
		foreach ( $previous as $row ) {
			$prev[ ShieldScope_Ignore::fingerprint( $row ) ] = $row;
		}
		return array(
			'new'   => array_values( array_diff_key( $cur, $prev ) ),
			'fixed' => array_values( array_diff_key( $prev, $cur ) ),
			'open'  => count( array_intersect_key( $cur, $prev ) ),
		);
	}

	/**
	 * Comparison of a scan with the one before it, or null when there is
	 * no earlier scan with findings still stored.
	 *
	 * @param string $scan_id  Scan id.
	 * @param array  $findings Rows of that scan.
	 * @return array|null { previous: history item, new, fixed, open }
	 */
	public static function compare_with_previous( $scan_id, array $findings ) {
		$prev = self::previous( $scan_id );
		if ( null === $prev ) {
			return null;
		}
		$logger = new ShieldScope_Logger();
		$rows   = $logger->get_findings( $prev['scan_id'] );
		if ( ! $rows ) {
			return null;
		}
		return array( 'previous' => $prev ) + self::compare( $findings, $rows );
	}
}
