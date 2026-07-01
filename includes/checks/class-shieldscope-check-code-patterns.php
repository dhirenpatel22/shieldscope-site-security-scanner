<?php
/**
 * Source code pattern analysis.
 *
 * Walks plugin and theme PHP files looking for:
 *  - Malware / backdoor signatures (eval + base64_decode, shell_exec, …)
 *  - Direct file access without ABSPATH guard
 *  - Dangerous dynamic code execution
 *  - Missing output escaping / prepared SQL (heuristic)
 *
 * This is static lint-style analysis; false positives are possible. Every
 * finding is low confidence by design — the scanner's job is to point a
 * human at suspicious spots, not to judge them.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Code_Patterns
 */
class ShieldScope_Check_Code_Patterns extends ShieldScope_Check_Base {

	/**
	 * Maximum file size to inspect (bytes).
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor — reads max file size from settings.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param ShieldScope_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, ShieldScope_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$settings            = (array) get_option( 'shieldscope_settings', array() );
		$this->max_file_size = isset( $settings['max_scan_file_size'] )
			? (int) $settings['max_scan_file_size']
			: 2 * MB_IN_BYTES;
	}

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'code_patterns';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Code Pattern Analysis', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'scan_plugins', 'scan_themes' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( 'scan_plugins' === $step ) {
			return $this->scan_tree( SHIELDSCOPE_WP_PLUGINS_DIR, 'plugin', $cursor );
		}
		if ( 'scan_themes' === $step ) {
			return $this->scan_tree( get_theme_root(), 'theme', $cursor );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Scan a tree resumably.
	 *
	 * @param string $root   Root directory.
	 * @param string $type   'plugin' or 'theme'.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	private function scan_tree( $root, $type, array $cursor ) {
		if ( ! is_dir( $root ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}
		if ( empty( $cursor ) ) {
			$cursor = array( 'queue' => array( $root ), 'checked' => 0 );
		}

		$files_per_call = 25;
		$processed      = 0;

		while ( ! empty( $cursor['queue'] ) && $processed < $files_per_call ) {
			$current = array_shift( $cursor['queue'] );
			$handle  = @opendir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $handle ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $handle ) ) && $processed < $files_per_call ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$full = $current . DIRECTORY_SEPARATOR . $entry;
				// Skip our own plugin to avoid false-positive recursion on our regex strings.
				if ( false !== strpos( $full, 'shieldscope' ) ) {
					continue;
				}
				if ( is_dir( $full ) ) {
					// Skip common dependency folders.
					if ( in_array( $entry, array( 'node_modules', 'vendor', '.git' ), true ) ) {
						continue;
					}
					$cursor['queue'][] = $full;
				} elseif ( preg_match( '/\.php$/i', $entry ) ) {
					$this->scan_file( $full, $type );
					$processed++;
					$cursor['checked']++;
				}
			}
			closedir( $handle );
		}

		return array(
			'continue' => ! empty( $cursor['queue'] ),
			'cursor'   => $cursor,
		);
	}

	/**
	 * Inspect a single file.
	 *
	 * @param string $path File path.
	 * @param string $type 'plugin' or 'theme'.
	 * @return void
	 */
	private function scan_file( $path, $type ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size || 0 === $size ) {
			return;
		}

		// Read via WP filesystem API would add overhead; direct read is fine here.
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || '' === $contents ) {
			return;
		}

		// --- Malware / backdoor signatures --- .
		// eval() on a base64 or gzinflate payload is very rarely benign.
		if ( preg_match( '/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'Possible obfuscated backdoor', 'shieldscope-site-security-scanner' ),
				__( 'Found eval() wrapping a decode/decompress function. This is a standard shape for PHP backdoors.', 'shieldscope-site-security-scanner' ),
				__( 'Compare against the original plugin/theme source. If not legitimate, remove the file and investigate for further compromise.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		// Direct exec calls are rarely legitimate in plugin/theme code.
		if ( preg_match( '/\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Use of shell execution function', 'shieldscope-site-security-scanner' ),
				__( 'The file calls shell_exec / passthru / proc_open / popen / system. WordPress plugins and themes should never need to run shell commands.', 'shieldscope-site-security-scanner' ),
				__( 'Verify the call. If dynamic user input reaches it, this is a command-injection bug.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		// Dangerous file inclusion on user input.
		if ( preg_match( '/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'File inclusion from user input', 'shieldscope-site-security-scanner' ),
				__( 'include/require with a superglobal — classic local/remote file inclusion vulnerability.', 'shieldscope-site-security-scanner' ),
				__( 'Rewrite to whitelist allowed paths. Never pass user input directly into include/require.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		// Disabled: too many false positives (template partials, CLI entry points,
		// auto-generated files) are legitimately loaded without an ABSPATH guard.
		// Kept here for reference only — do not restore without a tighter heuristic.
		//
		// if (
		//     false !== strpos( $type, 'plugin' ) &&
		//     false === stripos( $contents, 'ABSPATH' ) &&
		//     false === stripos( $contents, 'WPINC' ) &&
		//     preg_match( '/<\?php/', $contents ) &&
		//     preg_match( '/\b(?:function|class)\s+\w/i', $contents )
		// ) {
		//     $this->finding(
		//         ShieldScope_Logger::SEVERITY_LOW,
		//         __( 'PHP file without direct-access guard', 'shieldscope-site-security-scanner' ),
		//         __( "This file does not check for ABSPATH. ...", 'shieldscope-site-security-scanner' ),
		//         __( "Add at the top: if ( ! defined( 'ABSPATH' ) ) { exit; }", 'shieldscope-site-security-scanner' ),
		//         $path
		//     );
		// }

		// Heuristic: raw $wpdb->query with string concatenation of superglobals.
		if ( preg_match( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Likely unprepared SQL with user input', 'shieldscope-site-security-scanner' ),
				__( 'A $wpdb query string appears to concatenate superglobal data directly. This is very likely SQL injection.', 'shieldscope-site-security-scanner' ),
				// phpcs:ignore WordPress.WP.I18n.MissingTranslatorsComment,WordPress.WP.I18n.UnorderedPlaceholdersText -- %s/%d/%f are code examples in the advice text, not sprintf() arguments.
				__( 'Use $wpdb->prepare() with placeholders (%s, %d, %f). Never concatenate user input into SQL.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		// Unescaped echo of superglobals (reflected XSS heuristic).
		if ( preg_match( '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Unescaped output of user input', 'shieldscope-site-security-scanner' ),
				__( 'Directly echoing $_GET / $_POST without escaping is a reflected XSS bug.', 'shieldscope-site-security-scanner' ),
				__( 'Wrap the value in esc_html(), esc_attr() or wp_kses() depending on the context.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		// File writes from user input (upload / arbitrary file write).
		if ( preg_match( '/\bfile_put_contents\s*\([^)]*\$_(?:GET|POST|REQUEST|FILES)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'File write from user input', 'shieldscope-site-security-scanner' ),
				__( 'file_put_contents receiving user-controlled data is a classic arbitrary-file-write / RCE vector.', 'shieldscope-site-security-scanner' ),
				__( 'Use wp_handle_upload() and validate destination paths with realpath against an allowed base.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		// Check for long base64 strings (possible payload).
		if ( preg_match( '/[A-Za-z0-9+\/=]{400,}/', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Long opaque string — possible embedded payload', 'shieldscope-site-security-scanner' ),
				__( 'The file contains a base64-shaped string 400+ characters long. This is sometimes legitimate (SVG, fonts), sometimes a hidden payload.', 'shieldscope-site-security-scanner' ),
				__( 'Open the file and inspect the string context.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}
	}
}
