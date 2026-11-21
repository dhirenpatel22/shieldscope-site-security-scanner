<?php
/**
 * Ignore a finding with a reason (S-07).
 *
 * Ignored items are stored by fingerprint (check, title, target), so a
 * rescan keeps them ignored. They are left out of counts and the verdict
 * but stay listed, with their reason, in the report and every download.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Ignore
 */
class ShieldScope_Ignore {

	const OPTION = 'shieldscope_ignored';
	const ACTION = 'shieldscope_ignore';

	/**
	 * Allowed reasons => label.
	 *
	 * @return array
	 */
	public static function reasons() {
		return array(
			'accepted'       => __( 'Accepted risk', 'shieldscope-site-security-scanner' ),
			'false_positive' => __( 'False positive', 'shieldscope-site-security-scanner' ),
			'handled'        => __( 'Handled by host or CDN', 'shieldscope-site-security-scanner' ),
			'other'          => __( 'Other', 'shieldscope-site-security-scanner' ),
		);
	}

	/**
	 * Fingerprint of a finding row.
	 *
	 * @param array $row Finding row.
	 * @return string
	 */
	public static function fingerprint( array $row ) {
		return md5(
			( isset( $row['check_id'] ) ? (string) $row['check_id'] : '' ) . '|' .
			( isset( $row['title'] ) ? (string) $row['title'] : '' ) . '|' .
			( isset( $row['target'] ) ? (string) $row['target'] : '' )
		);
	}

	/**
	 * All ignored entries: fingerprint => { reason, note, user, date, title, target }.
	 *
	 * @return array
	 */
	public static function all() {
		$all = get_option( self::OPTION, array() );
		return is_array( $all ) ? $all : array();
	}

	/**
	 * Split findings into active and ignored; ignored rows get an 'ignored' key.
	 *
	 * @param array $findings Rows.
	 * @return array { 0: active rows, 1: ignored rows }
	 */
	public static function split( array $findings ) {
		$all     = self::all();
		$active  = array();
		$ignored = array();
		foreach ( $findings as $row ) {
			$fp = self::fingerprint( $row );
			if ( isset( $all[ $fp ] ) ) {
				$row['ignored'] = $all[ $fp ];
				$ignored[]      = $row;
			} else {
				$active[] = $row;
			}
		}
		return array( $active, $ignored );
	}

	/**
	 * Counts per severity for a scan, not counting ignored findings (IM2-11).
	 *
	 * @param string $scan_id Scan id.
	 * @return array
	 */
	public static function active_summary( $scan_id ) {
		$counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
		if ( '' === (string) $scan_id ) {
			return $counts;
		}
		$logger         = new ShieldScope_Logger();
		list( $active ) = self::split( $logger->get_findings( $scan_id ) );
		foreach ( $active as $row ) {
			if ( isset( $row['severity'], $counts[ $row['severity'] ] ) ) {
				++$counts[ $row['severity'] ];
			}
		}
		return $counts;
	}

	/**
	 * Validate and store an ignore. Returns '' or an error message.
	 *
	 * @param array  $row    Finding row being ignored.
	 * @param string $reason Reason key.
	 * @param string $note   Note.
	 * @return string
	 */
	public static function add( array $row, $reason, $note ) {
		$reasons = self::reasons();
		if ( ! isset( $reasons[ $reason ] ) ) {
			return __( 'Choose a reason.', 'shieldscope-site-security-scanner' );
		}
		$note = trim( sanitize_textarea_field( (string) $note ) );
		if ( '' === $note && ( 'critical' === ( isset( $row['severity'] ) ? $row['severity'] : '' ) || 'other' === $reason ) ) {
			return __( 'Add a note: it is required for Critical findings and for "Other".', 'shieldscope-site-security-scanner' );
		}
		$user                                 = wp_get_current_user();
		$all                                  = self::all();
		$all[ self::fingerprint( $row ) ] = array(
			'reason' => $reason,
			'note'   => substr( $note, 0, 500 ),
			'user'   => isset( $user->user_login ) ? (string) $user->user_login : '',
			'date'   => gmdate( 'Y-m-d' ),
			'title'  => isset( $row['title'] ) ? (string) $row['title'] : '',
			'target' => isset( $row['target'] ) ? (string) $row['target'] : '',
		);
		update_option( self::OPTION, $all, false );
		return '';
	}

	/**
	 * Remove an ignore.
	 *
	 * @param string $fingerprint Fingerprint.
	 * @return void
	 */
	public static function restore( $fingerprint ) {
		$all = self::all();
		unset( $all[ (string) $fingerprint ] );
		update_option( self::OPTION, $all, false );
	}

	/**
	 * Text for an ignored row: "False positive (alice, 2026-11-19): note".
	 *
	 * @param array $entry Ignore entry.
	 * @return string
	 */
	public static function describe( array $entry ) {
		$reasons = self::reasons();
		$label   = isset( $reasons[ $entry['reason'] ] ) ? $reasons[ $entry['reason'] ] : $entry['reason'];
		$text    = $label . ' (' . $entry['user'] . ', ' . $entry['date'] . ')';
		return '' !== $entry['note'] ? $text . ': ' . $entry['note'] : $text;
	}

	/**
	 * admin-post handler for ignore and restore.
	 *
	 * @return void
	 */
	public static function handle() {
		if ( ! current_user_can( ShieldScope_Admin::required_capability() ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce checked above.
		$do  = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$fp  = isset( $_POST['fp'] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_key( wp_unslash( $_POST['fp'] ) ) ) : '';
		$msg = '';
		if ( 'restore' === $do ) {
			self::restore( $fp );
			$msg = 'restored';
		} elseif ( 'ignore' === $do ) {
			$row = self::find_row( $fp );
			if ( null === $row ) {
				$msg = 'notfound';
			} else {
				$error = self::add(
					$row,
					isset( $_POST['reason'] ) ? sanitize_key( wp_unslash( $_POST['reason'] ) ) : '',
					isset( $_POST['note'] ) ? wp_unslash( $_POST['note'] ) : '' // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitised in add().
				);
				$msg   = '' === $error ? 'ignored' : 'invalid';
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		wp_safe_redirect( add_query_arg( 'shieldscope_ignore', $msg, admin_url( 'admin.php?page=' . SHIELDSCOPE_SLUG . '-report' ) ) );
		exit;
	}

	/**
	 * The last scan's finding with this fingerprint, or null.
	 *
	 * @param string $fingerprint Fingerprint.
	 * @return array|null
	 */
	private static function find_row( $fingerprint ) {
		$scan_id = (string) get_option( 'shieldscope_last_scan', '' );
		if ( '' === $scan_id ) {
			return null;
		}
		$logger = new ShieldScope_Logger();
		foreach ( $logger->get_findings( $scan_id ) as $row ) {
			if ( self::fingerprint( $row ) === $fingerprint ) {
				return $row;
			}
		}
		return null;
	}
}
