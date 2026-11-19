<?php
/**
 * PDF export of the last completed scan.
 *
 * The PDF is built with a bundled copy of Dompdf, prefixed under
 * ShieldScope\Vendor\ (see bin/prefix-vendor.php). Report data comes from
 * scanned files and the site (paths, titles, plugin names), so it is treated
 * as untrusted: every value is escaped into the HTML, and Dompdf runs with
 * remote loading, PHP and JavaScript off and file access limited to its own
 * font folder.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_PDF_Report
 */
class ShieldScope_PDF_Report {

	/**
	 * admin-post action and nonce action.
	 */
	const ACTION = 'shieldscope_export_pdf';

	/**
	 * Most affected targets listed per finding group before "and N more".
	 */
	const MAX_TARGETS = 40;

	/**
	 * Severity keys in report order.
	 *
	 * @var string[]
	 */
	private static $severities = array( 'critical', 'high', 'medium', 'low', 'info' );

	/**
	 * URL that downloads the PDF (nonce included).
	 *
	 * @return string
	 */
	public static function download_url() {
		return wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION ), self::ACTION );
	}

	/**
	 * Why a PDF cannot be built on this server, or '' if it can.
	 *
	 * @return string
	 */
	public static function unavailable_reason() {
		$missing = array();
		foreach ( array( 'dom', 'mbstring' ) as $ext ) {
			if ( ! extension_loaded( $ext ) ) {
				$missing[] = $ext;
			}
		}
		if ( $missing ) {
			return sprintf(
				/* translators: %s: comma-separated PHP extension names */
				__( 'PDF download needs these PHP extensions, which this server does not have: %s. Ask your host to enable them.', 'shieldscope-site-security-scanner' ),
				implode( ', ', $missing )
			);
		}
		if ( ! is_readable( self::autoload_file() ) ) {
			return __( 'The PDF library files are missing from the plugin folder. Reinstall ShieldScope.', 'shieldscope-site-security-scanner' );
		}
		return '';
	}

	/**
	 * admin-post handler: check access, build the PDF, send it.
	 *
	 * @return void
	 */
	public static function handle() {
		if ( ! current_user_can( ShieldScope_Admin::required_capability() ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'shieldscope-site-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		$reason = self::unavailable_reason();
		if ( '' !== $reason ) {
			wp_die( esc_html( $reason ), '', array( 'response' => 500 ) );
		}

		$report = self::collect_report();
		if ( empty( $report['findings'] ) ) {
			wp_die( esc_html__( 'There is no completed scan to export. Run a scan first.', 'shieldscope-site-security-scanner' ), '', array( 'response' => 404 ) );
		}

		$pdf = self::render_pdf( self::build_html( $report ), $report );

		nocache_headers();
		header( 'Content-Type: application/pdf' );
		header( 'Content-Disposition: attachment; filename="' . self::file_name( $report ) . '"' );
		header( 'Content-Length: ' . strlen( $pdf ) );
		header( 'X-Content-Type-Options: nosniff' );
		echo $pdf; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- binary PDF body.
		exit;
	}

	/**
	 * Report data for the last completed scan.
	 *
	 * @return array
	 */
	public static function collect_report() {
		$logger    = new ShieldScope_Logger();
		$scan_id   = (string) get_option( 'shieldscope_last_scan', '' );
		$findings  = '' !== $scan_id ? $logger->get_findings( $scan_id ) : array();
		$scan_time = '';
		foreach ( $findings as $f ) {
			if ( ! empty( $f['created_at'] ) && $f['created_at'] > $scan_time ) {
				$scan_time = $f['created_at'];
			}
		}
		$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

		return array(
			'site_name'    => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'site_url'     => home_url( '/' ),
			'scan_id'      => $scan_id,
			'scan_date'    => '' !== $scan_time ? wp_date( $format, strtotime( $scan_time . ' UTC' ) ) : '',
			'generated'    => wp_date( $format ),
			'version'      => SHIELDSCOPE_VERSION,
			'save_failed'  => '' !== $scan_id && ShieldScope_Logger::save_failed( $scan_id ),
			'findings'     => $findings,
			'check_labels' => self::check_labels(),
			'coverage'     => '' !== $scan_id ? ShieldScope_Coverage::get( $scan_id ) : null,
			'root'         => ABSPATH,
		);
	}

	/**
	 * Check id => label for every registered check.
	 *
	 * @return array
	 */
	public static function check_labels() {
		$labels  = array();
		$scanner = new ShieldScope_Scanner();
		$logger  = new ShieldScope_Logger();
		foreach ( $scanner->get_check_classes() as $class ) {
			if ( class_exists( $class ) ) {
				$check                       = new $class( '', $logger );
				$labels[ $check->get_id() ] = $check->get_label();
			}
		}
		return $labels;
	}

	/**
	 * Translated severity names.
	 *
	 * @return array
	 */
	private static function severity_labels() {
		return array(
			'critical' => __( 'Critical', 'shieldscope-site-security-scanner' ),
			'high'     => __( 'High', 'shieldscope-site-security-scanner' ),
			'medium'   => __( 'Medium', 'shieldscope-site-security-scanner' ),
			'low'      => __( 'Low', 'shieldscope-site-security-scanner' ),
			'info'     => __( 'Informational', 'shieldscope-site-security-scanner' ),
		);
	}

	/**
	 * Show a target relative to the WordPress root, so the PDF does not
	 * carry the server's directory layout.
	 *
	 * @param string $target Finding target.
	 * @param string $root   WordPress root (ABSPATH).
	 * @return string
	 */
	public static function relative_target( $target, $root ) {
		$target = (string) $target;
		$norm   = str_replace( '\\', '/', $target );
		$root   = rtrim( str_replace( '\\', '/', (string) $root ), '/' ) . '/';
		if ( '/' !== $root && 0 === strpos( $norm, $root ) ) {
			return substr( $norm, strlen( $root ) );
		}
		return $target;
	}

	/**
	 * One line verdict from the counts (no score).
	 *
	 * @param array $counts severity => count.
	 * @return string
	 */
	public static function verdict( array $counts ) {
		$critical = isset( $counts['critical'] ) ? (int) $counts['critical'] : 0;
		$high     = isset( $counts['high'] ) ? (int) $counts['high'] : 0;
		if ( $critical + $high > 0 ) {
			return sprintf(
				/* translators: 1: number of critical findings, 2: number of high findings */
				__( '%1$d critical and %2$d high findings need attention first.', 'shieldscope-site-security-scanner' ),
				$critical,
				$high
			);
		}
		return __( 'No critical or high findings. Review the medium and low findings below; a report without serious findings does not mean the site is secure.', 'shieldscope-site-security-scanner' );
	}

	/**
	 * HTML for the PDF. Every value from the report is escaped.
	 *
	 * @param array $report From collect_report().
	 * @return string
	 */
	public static function build_html( array $report ) {
		$labels = self::severity_labels();
		$groups = array_fill_keys( self::$severities, array() );
		$counts = array_fill_keys( self::$severities, 0 );

		list( $active, $ignored ) = ShieldScope_Ignore::split( (array) $report['findings'] );
		foreach ( $active as $f ) {
			$sev   = isset( $f['severity'], $groups[ $f['severity'] ] ) ? $f['severity'] : 'info';
			$title = isset( $f['title'] ) && '' !== trim( (string) $f['title'] ) ? trim( (string) $f['title'] ) : __( 'Unknown issue', 'shieldscope-site-security-scanner' );
			++$counts[ $sev ];
			$ctx = isset( $f['context'] ) && is_string( $f['context'] ) ? json_decode( $f['context'], true ) : array();
			$ctx = is_array( $ctx ) ? $ctx : array();
			if ( ! isset( $groups[ $sev ][ $title ] ) ) {
				$groups[ $sev ][ $title ] = array(
					'review'         => isset( $ctx['confidence'] ) ? ShieldScope_Check_Base::CONFIDENCE_REVIEW === $ctx['confidence'] : ShieldScope_Check_Base::is_review_title( $title ),
					'check'          => isset( $f['check_id'] ) ? (string) $f['check_id'] : '',
					'description'    => isset( $f['description'] ) ? (string) $f['description'] : '',
					'recommendation' => isset( $f['recommendation'] ) ? (string) $f['recommendation'] : '',
					'targets'        => array(),
				);
			}
			if ( ! empty( $f['target'] ) ) {
				$line = isset( $ctx['evidence']['line'] ) ? (int) $ctx['evidence']['line'] : 0;
				$key  = self::relative_target( $f['target'], $report['root'] ) . ( $line > 0 ? ':' . $line : '' );

				$groups[ $sev ][ $title ]['targets'][ $key ] = isset( $ctx['evidence']['snippet'] ) ? (string) $ctx['evidence']['snippet'] : '';
			}
		}

		$e    = static function ( $text ) {
			return htmlspecialchars( (string) $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
		};
		$html = '<!DOCTYPE html><html><head><meta charset="utf-8"><style>' . self::css() . '</style></head><body>';

		// Header.
		$html .= '<div class="head"><div class="brand">ShieldScope</div>';
		$html .= '<h1>' . $e( __( 'WordPress security audit', 'shieldscope-site-security-scanner' ) ) . '</h1>';
		$html .= '<div class="site">' . $e( $report['site_name'] ) . ' &middot; ' . $e( $report['site_url'] ) . '</div></div>';

		$html .= '<table class="meta">';
		foreach ( array(
			__( 'Scan date', 'shieldscope-site-security-scanner' )        => $report['scan_date'],
			__( 'Report generated', 'shieldscope-site-security-scanner' ) => $report['generated'],
			__( 'Scan ID', 'shieldscope-site-security-scanner' )          => $report['scan_id'],
			__( 'Tool', 'shieldscope-site-security-scanner' )             => 'ShieldScope ' . $report['version'],
		) as $label => $value ) {
			$html .= '<tr><th>' . $e( $label ) . '</th><td>' . $e( $value ) . '</td></tr>';
		}
		$html .= '</table>';

		if ( ! empty( $report['save_failed'] ) ) {
			$html .= '<p class="warn">' . $e( __( 'Some results of this scan could not be saved, so this report may be missing findings.', 'shieldscope-site-security-scanner' ) ) . '</p>';
		}

		// Summary.
		$html .= '<h2>' . $e( __( 'Summary', 'shieldscope-site-security-scanner' ) ) . '</h2>';
		$html .= '<p class="verdict">' . $e( self::verdict( $counts ) ) . '</p>';
		$coverage = isset( $report['coverage'] ) && is_array( $report['coverage'] ) ? $report['coverage'] : null;
		if ( $coverage ) {
			$html .= '<p class="cov">' . $e( __( 'Coverage:', 'shieldscope-site-security-scanner' ) . ' ' . ShieldScope_Coverage::summary( $coverage ) ) . '</p>';
		}
		$html .= '<table class="counts"><tr>';
		foreach ( self::$severities as $sev ) {
			$html .= '<td class="sev-' . $sev . '"><span class="n">' . (int) $counts[ $sev ] . '</span><br>' . $e( $labels[ $sev ] ) . '</td>';
		}
		$html .= '</tr></table>';

		// Top actions: the first critical/high groups.
		$top = array();
		foreach ( array( 'critical', 'high' ) as $sev ) {
			foreach ( array_keys( $groups[ $sev ] ) as $title ) {
				$top[] = array( $sev, $title );
			}
		}
		if ( $top ) {
			$html .= '<h3>' . $e( __( 'Fix first', 'shieldscope-site-security-scanner' ) ) . '</h3><ol class="top">';
			foreach ( array_slice( $top, 0, 5 ) as $item ) {
				$html .= '<li><span class="chip sev-' . $item[0] . '">' . $e( $labels[ $item[0] ] ) . '</span> ' . $e( $item[1] ) . '</li>';
			}
			$html .= '</ol>';
		}

		// Findings.
		foreach ( self::$severities as $sev ) {
			if ( empty( $groups[ $sev ] ) ) {
				continue;
			}
			$html .= '<h2 class="sevhead sev-' . $sev . '">' . $e(
				sprintf(
					/* translators: 1: severity name, 2: number of findings */
					__( '%1$s (%2$d)', 'shieldscope-site-security-scanner' ),
					$labels[ $sev ],
					$counts[ $sev ]
				)
			) . '</h2>';
			foreach ( $groups[ $sev ] as $title => $g ) {
				$check  = isset( $report['check_labels'][ $g['check'] ] ) ? $report['check_labels'][ $g['check'] ] : $g['check'];
				$html  .= '<div class="finding"><div class="ftitle">' . $e( $title ) . ' <span class="conf' . ( $g['review'] ? ' review' : '' ) . '">' . $e( $g['review'] ? __( 'Needs review', 'shieldscope-site-security-scanner' ) : __( 'Confirmed', 'shieldscope-site-security-scanner' ) ) . '</span></div>';
				if ( '' !== $check ) {
					$html .= '<div class="check">' . $e( $check ) . '</div>';
				}
				if ( '' !== $g['description'] ) {
					$html .= '<p>' . $e( $g['description'] ) . '</p>';
				}
				if ( '' !== $g['recommendation'] ) {
					$html .= '<p class="rec"><strong>' . $e( __( 'What to do:', 'shieldscope-site-security-scanner' ) ) . '</strong> ' . $e( $g['recommendation'] ) . '</p>';
				}
				$targets = $g['targets'];
				if ( $targets ) {
					$html .= '<div class="tlabel">' . $e( __( 'Affected', 'shieldscope-site-security-scanner' ) ) . '</div><ul class="targets">';
					foreach ( array_slice( $targets, 0, self::MAX_TARGETS, true ) as $t => $snippet ) {
						$html .= '<li>' . $e( $t ) . ( '' !== $snippet ? '<div class="snip">' . $e( $snippet ) . '</div>' : '' ) . '</li>';
					}
					if ( count( $targets ) > self::MAX_TARGETS ) {
						$html .= '<li class="more">' . $e(
							sprintf(
								/* translators: %d: number of further affected items */
								__( 'and %d more', 'shieldscope-site-security-scanner' ),
								count( $targets ) - self::MAX_TARGETS
							)
						) . '</li>';
					}
					$html .= '</ul>';
				}
				$html .= '</div>';
			}
		}

		// Ignored findings (S-07): listed with their reason, not counted.
		if ( $ignored ) {
			$html .= '<h2>' . $e( __( 'Ignored findings', 'shieldscope-site-security-scanner' ) ) . '</h2>';
			$html .= '<p class="small">' . $e( __( 'These items were reviewed and marked as ignored on the site; they are not counted above.', 'shieldscope-site-security-scanner' ) ) . '</p><table class="checks">';
			foreach ( $ignored as $f ) {
				$sev   = isset( $f['severity'], $labels[ $f['severity'] ] ) ? $f['severity'] : 'info';
				$html .= '<tr><td>' . $e( $labels[ $sev ] ) . '</td><td>' . $e( $f['title'] ) . ( ! empty( $f['target'] ) ? '<br>' . $e( self::relative_target( $f['target'], $report['root'] ) ) : '' ) . '</td><td>' . $e( ShieldScope_Ignore::describe( $f['ignored'] ) ) . '</td></tr>';
			}
			$html .= '</table>';
		}

		// Method and limits.
		$html .= '<h2>' . $e( __( 'Method and limits', 'shieldscope-site-security-scanner' ) ) . '</h2>';
		$html .= '<p>' . $e( ShieldScope_Admin::method_statement() ) . '</p>';
		$html .= '<p>' . $e( ShieldScope_Admin::footprint_statement() ) . '</p>';
		$html .= '<p>' . $e( ShieldScope_Admin::privacy_statement() ) . '</p>';
		if ( $coverage ) {
			$html .= '<h3>' . $e( __( 'Checks run', 'shieldscope-site-security-scanner' ) ) . '</h3><table class="checks">';
			foreach ( $coverage as $c ) {
				$html .= '<tr><td>' . $e( $c['label'] ) . '</td><td class="st-' . $e( $c['status'] ) . '">' . $e( ShieldScope_Coverage::status_label( $c['status'] ) ) . '</td><td>' . $e( implode( '; ', (array) $c['notes'] ) ) . '</td></tr>';
			}
			$html .= '</table>';
		}
		$html .= '<p class="small">' . $e( __( 'File paths are shown relative to the WordPress root folder.', 'shieldscope-site-security-scanner' ) ) . '</p>';

		$html .= '</body></html>';
		return $html;
	}

	/**
	 * Stylesheet for the PDF (Dompdf supports CSS 2.1 plus a little CSS3).
	 *
	 * @return string
	 */
	private static function css() {
		return '@page{margin:56px 48px 64px 48px}'
			. 'body{font-family:"DejaVu Sans",sans-serif;font-size:10px;color:#1d2327;line-height:1.45}'
			. '.head{border-bottom:2px solid #1a3a5c;padding-bottom:10px;margin-bottom:12px}'
			. '.brand{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2271b1;font-weight:bold}'
			. 'h1{font-size:20px;margin:4px 0 2px;color:#1a3a5c}'
			. '.site{color:#50575e;font-size:10px}'
			. 'h2{font-size:14px;color:#1a3a5c;margin:18px 0 6px;page-break-after:avoid}'
			. 'h3{font-size:11px;margin:10px 0 4px}'
			. 'table.meta{border-collapse:collapse;margin-bottom:6px}'
			. 'table.meta th{text-align:left;color:#50575e;font-weight:normal;padding:1px 14px 1px 0}'
			. 'table.meta td{padding:1px 0}'
			. 'table.counts{width:100%;table-layout:fixed;border-collapse:separate;border-spacing:4px 0}'
			. 'table.counts td{width:20%;text-align:center;padding:6px 2px;border:1px solid #dcdcde;font-size:9px}'
			. 'table.counts .n{font-size:16px;font-weight:bold}'
			. '.verdict{font-size:11px;font-weight:bold}'
			. '.warn{border:1px solid #d63638;background:#fcf0f1;padding:6px;color:#8a1a1a}'
			. '.chip{font-size:8px;font-weight:bold;padding:1px 4px;border:1px solid #dcdcde}'
			. 'ol.top{margin:0 0 0 16px;padding:0}'
			. '.sevhead{border-left:4px solid #8c8f94;padding-left:6px}'
			. '.finding{border:1px solid #dcdcde;padding:6px 8px;margin:0 0 6px;page-break-inside:avoid}'
			. '.ftitle{font-weight:bold;font-size:10.5px}'
			. '.check{color:#50575e;font-size:8.5px;margin-bottom:2px}'
			. '.finding p{margin:3px 0}'
			. '.rec{background:#f6f7f7;padding:3px 5px}'
			. '.tlabel{font-size:8.5px;color:#50575e;margin-top:3px}'
			. 'ul.targets{margin:1px 0 0 14px;padding:0;font-family:"DejaVu Sans Mono",monospace;font-size:8px}'
			. '.more{font-family:"DejaVu Sans",sans-serif;color:#50575e}'
			. '.small{font-size:8.5px;color:#50575e}'
			. '.cov{margin:2px 0 8px}'
			. 'table.checks{width:100%;border-collapse:collapse;font-size:8.5px}'
			. 'table.checks td{border-bottom:1px solid #f0f0f1;padding:2px 4px;vertical-align:top}'
			. '.st-partial{color:#6b4d00}.st-error,.st-not_run{color:#8a1a1a}'
			. '.conf{font-size:7.5px;font-weight:bold;border:1px solid #c3c4c7;padding:0 3px;color:#50575e}'
			. '.conf.review{color:#6b4d00;border-color:#dba617}'
			. '.snip{color:#50575e;border-left:2px solid #dcdcde;padding-left:4px;margin:1px 0 2px}'
			. '.sev-critical{border-color:#b32d2e;color:#8a1a1a}.sevhead.sev-critical{border-left-color:#b32d2e}'
			. '.sev-high{border-color:#d63638;color:#7d3800}.sevhead.sev-high{border-left-color:#d63638}'
			. '.sev-medium{border-color:#dba617;color:#6b4d00}.sevhead.sev-medium{border-left-color:#dba617}'
			. '.sev-low{border-color:#2271b1;color:#164f81}.sevhead.sev-low{border-left-color:#2271b1}'
			. '.sev-info{border-color:#00a32a;color:#1e6823}.sevhead.sev-info{border-left-color:#00a32a}';
	}

	/**
	 * Path of the prefixed library's autoloader.
	 *
	 * @return string
	 */
	private static function autoload_file() {
		return SHIELDSCOPE_PLUGIN_DIR . 'vendor-prefixed/autoload.php';
	}

	/**
	 * Render HTML to PDF bytes with a locked-down Dompdf.
	 *
	 * @param string $html   HTML from build_html().
	 * @param array  $report Report data (for the footer).
	 * @return string
	 */
	public static function render_pdf( $html, array $report ) {
		require_once self::autoload_file();

		$font_dir = SHIELDSCOPE_PLUGIN_DIR . 'vendor-prefixed/dompdf/dompdf/lib/fonts';
		$temp_dir = untrailingslashit( get_temp_dir() );

		$options = new \ShieldScope\Vendor\Dompdf\Options();
		$options->setIsRemoteEnabled( false );
		$options->setIsPhpEnabled( false );
		$options->setIsJavascriptEnabled( false );
		$options->setIsHtml5ParserEnabled( true );
		$options->setFontDir( $font_dir );
		$options->setFontCache( $temp_dir );
		$options->setTempDir( $temp_dir );
		$options->setChroot( array( $font_dir ) );
		$options->setDefaultFont( 'DejaVu Sans' );
		$options->setIsFontSubsettingEnabled( true );

		$dompdf = new \ShieldScope\Vendor\Dompdf\Dompdf( $options );
		$dompdf->loadHtml( $html, 'UTF-8' );
		$dompdf->setPaper( 'A4', 'portrait' );
		$dompdf->addInfo( 'Title', __( 'WordPress security audit', 'shieldscope-site-security-scanner' ) . ' – ' . $report['site_name'] );
		$dompdf->addInfo( 'Creator', 'ShieldScope ' . $report['version'] );
		$dompdf->render();

		$canvas = $dompdf->getCanvas();
		$font   = $dompdf->getFontMetrics()->getFont( 'DejaVu Sans' );
		$footer = sprintf(
			/* translators: 1: ShieldScope version, 2: site address */
			__( 'ShieldScope %1$s · %2$s · ShieldScope did not change this site.', 'shieldscope-site-security-scanner' ),
			$report['version'],
			wp_parse_url( $report['site_url'], PHP_URL_HOST )
		);
		$canvas->page_text( 48, $canvas->get_height() - 36, $footer, $font, 7, array( 0.31, 0.34, 0.37 ) );
		/* translators: {PAGE_NUM} and {PAGE_COUNT} are filled in by the PDF library; keep them as they are. */
		$canvas->page_text( $canvas->get_width() - 110, $canvas->get_height() - 36, __( 'Page {PAGE_NUM} of {PAGE_COUNT}', 'shieldscope-site-security-scanner' ), $font, 7, array( 0.31, 0.34, 0.37 ) );

		return (string) $dompdf->output();
	}

	/**
	 * Download file name, for example shieldscope-report-example.com-2026-11-19.pdf.
	 *
	 * @param array $report Report data.
	 * @return string
	 */
	public static function file_name( array $report ) {
		$host = (string) wp_parse_url( $report['site_url'], PHP_URL_HOST );
		$name = sanitize_file_name( 'shieldscope-report-' . ( '' !== $host ? $host : 'site' ) . '-' . gmdate( 'Y-m-d' ) . '.pdf' );
		return str_replace( '"', '', $name );
	}
}
