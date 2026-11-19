<?php
/**
 * CSV and JSON export of the last completed scan (S-06).
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Export
 */
class ShieldScope_Export {

	/**
	 * admin-post action and nonce action.
	 */
	const ACTION = 'shieldscope_export';

	/**
	 * Download URL for a format.
	 *
	 * @param string $format csv|json.
	 * @return string
	 */
	public static function download_url( $format ) {
		return wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION . '&format=' . rawurlencode( $format ) ), self::ACTION );
	}

	/**
	 * admin-post handler.
	 *
	 * @return void
	 */
	public static function handle() {
		if ( ! current_user_can( ShieldScope_Admin::required_capability() ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		$format = isset( $_GET['format'] ) ? sanitize_key( wp_unslash( $_GET['format'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce checked above.
		if ( ! in_array( $format, array( 'csv', 'json' ), true ) ) {
			wp_die( esc_html__( 'Unknown export format.', 'shieldscope-site-security-scanner' ), '', array( 'response' => 400 ) );
		}

		$report = ShieldScope_PDF_Report::collect_report();
		if ( empty( $report['findings'] ) ) {
			wp_die( esc_html__( 'There is no completed scan to export. Run a scan first.', 'shieldscope-site-security-scanner' ), '', array( 'response' => 404 ) );
		}

		$body = 'csv' === $format ? self::to_csv( $report ) : self::to_json( $report );
		$name = preg_replace( '/\.pdf$/', '.' . $format, ShieldScope_PDF_Report::file_name( $report ) );

		nocache_headers();
		header( 'Content-Type: ' . ( 'csv' === $format ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8' ) );
		header( 'Content-Disposition: attachment; filename="' . $name . '"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- file body, not HTML.
		exit;
	}

	/**
	 * One flat row per finding.
	 *
	 * @param array $report From ShieldScope_PDF_Report::collect_report().
	 * @return array[]
	 */
	public static function rows( array $report ) {
		$rows = array();
		foreach ( (array) $report['findings'] as $f ) {
			$ctx    = isset( $f['context'] ) && is_string( $f['context'] ) ? json_decode( $f['context'], true ) : array();
			$ctx    = is_array( $ctx ) ? $ctx : array();
			$title  = isset( $f['title'] ) ? (string) $f['title'] : '';
			$check  = isset( $f['check_id'] ) ? (string) $f['check_id'] : '';
			$rows[] = array(
				'severity'       => isset( $f['severity'] ) ? (string) $f['severity'] : '',
				'confidence'     => isset( $ctx['confidence'] ) ? (string) $ctx['confidence'] : ( ShieldScope_Check_Base::is_review_title( $title ) ? 'review' : 'confirmed' ),
				'check'          => isset( $report['check_labels'][ $check ] ) ? $report['check_labels'][ $check ] : $check,
				'title'          => $title,
				'target'         => ShieldScope_PDF_Report::relative_target( isset( $f['target'] ) ? $f['target'] : '', $report['root'] ),
				'line'           => isset( $ctx['evidence']['line'] ) ? (int) $ctx['evidence']['line'] : '',
				'snippet'        => isset( $ctx['evidence']['snippet'] ) ? (string) $ctx['evidence']['snippet'] : '',
				'description'    => wp_strip_all_tags( isset( $f['description'] ) ? (string) $f['description'] : '' ),
				'recommendation' => wp_strip_all_tags( isset( $f['recommendation'] ) ? (string) $f['recommendation'] : '' ),
			);
		}
		return $rows;
	}

	/**
	 * A spreadsheet cell that cannot start a formula.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function csv_cell( $value ) {
		$value = (string) $value;
		if ( '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ) {
			$value = "'" . $value;
		}
		return $value;
	}

	/**
	 * CSV with a header row, UTF-8 with BOM (so spreadsheets read accents).
	 *
	 * @param array $report Report data.
	 * @return string
	 */
	public static function to_csv( array $report ) {
		$rows = self::rows( $report );
		$out  = fopen( 'php://temp', 'r+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- in-memory buffer.
		fputcsv( $out, array( 'severity', 'confidence', 'check', 'title', 'target', 'line', 'snippet', 'description', 'recommendation' ), ',', '"', '\\' );
		foreach ( $rows as $row ) {
			fputcsv( $out, array_map( array( __CLASS__, 'csv_cell' ), array_values( $row ) ), ',', '"', '\\' );
		}
		rewind( $out );
		$csv = stream_get_contents( $out );
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return "\xEF\xBB\xBF" . $csv;
	}

	/**
	 * JSON with scan metadata, coverage and findings.
	 *
	 * @param array $report Report data.
	 * @return string
	 */
	public static function to_json( array $report ) {
		return (string) wp_json_encode(
			array(
				'tool'      => 'ShieldScope',
				'version'   => $report['version'],
				'site'      => $report['site_url'],
				'scan_id'   => $report['scan_id'],
				'scan_date' => $report['scan_date'],
				'generated' => $report['generated'],
				'complete'  => empty( $report['save_failed'] ),
				'coverage'  => isset( $report['coverage'] ) ? $report['coverage'] : null,
				'findings'  => self::rows( $report ),
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
		);
	}
}
