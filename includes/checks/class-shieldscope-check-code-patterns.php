<?php
/**
 * Source code pattern analysis.
 *
 * Walks plugin and theme PHP files looking for:
 *  - Code patterns that need a manual review (eval on decoded data, shell functions, …)
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
	 * Whether a regex failed on the file being scanned.
	 *
	 * @var bool
	 */
	private $regex_failed = false;

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
	 * vendor/ is walked too, but files in it are checked for the
	 * eval-on-decoded-data shape only.
	 *
	 * @param string $root   Root directory.
	 * @param string $type   'plugin' or 'theme'.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	private function scan_tree( $root, $type, array $cursor ) {
		$root_length = strlen( rtrim( str_replace( '\\', '/', $root ), '/' ) );
		return $this->walk_php_files_step(
			$root,
			$cursor,
			function ( $full ) use ( $type, $root_length ) {
				$relative = substr( str_replace( '\\', '/', $full ), $root_length );
				return $this->scan_file( $full, $type, false !== strpos( $relative, '/vendor/' ) );
			},
			25,
			array( 'node_modules', '.git' )
		);
	}

	/**
	 * Subject and offset of the last successful match().
	 *
	 * @var array
	 */
	private $last_match = array( '', -1 );

	/**
	 * preg_match() that records a regex failure instead of treating it as "no match".
	 *
	 * @param string $pattern Regex.
	 * @param string $subject Subject.
	 * @return bool
	 */
	private function matches( $pattern, $subject ) {
		$this->last_match = array( '', -1 );
		$result = preg_match( $pattern, $subject, $m, PREG_OFFSET_CAPTURE );
		if ( false === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->regex_failed = true;
			return false;
		}
		if ( 1 === $result ) {
			$this->last_match = array( $subject, (int) $m[0][1] );
		}
		return 1 === $result;
	}

	/**
	 * Evidence (line and snippet) for the last successful match().
	 *
	 * @param string $contents Original file contents.
	 * @return array
	 */
	private function last_evidence( $contents ) {
		return self::evidence( $contents, $this->last_match[0], $this->last_match[1] );
	}

	/**
	 * Source with comments blanked out, so commented-out code does not match.
	 *
	 * @param string $contents PHP source.
	 * @return string
	 */
	private function strip_comments( $contents ) {
		return self::code_view( $contents, true );
	}

	/**
	 * Inspect a single file.
	 *
	 * @param string $path      File path.
	 * @param string $type      'plugin' or 'theme'.
	 * @param bool   $eval_only Check only the eval-on-decoded-data shape (vendor/ files).
	 * @return bool False if the file was skipped (too large or unreadable).
	 */
	private function scan_file( $path, $type, $eval_only = false ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size ) {
			return false;
		}
		if ( 0 === $size ) {
			return true;
		}

		// Read via WP filesystem API would add overhead; direct read is fine here.
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents ) {
			return false;
		}
		if ( '' === $contents ) {
			return true;
		}

		$this->regex_failed = false;

		// --- Pattern matches: each one needs a person to confirm it --- .
		if ( $this->matches( '/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Matches pattern: eval() on encoded data', 'shieldscope-site-security-scanner' ),
				__( 'This file applies eval() to the output of a decode or decompress function (base64_decode, gzinflate, str_rot13 or gzuncompress). Malware often uses this shape, but some legitimate libraries and installers do too. This match has not been confirmed as harmful.', 'shieldscope-site-security-scanner' ),
				__( 'Compare the file with the original plugin or theme source. If it does not belong there, remove it and check the site for other changes.', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
			);
		}

		if ( ! $eval_only ) {
			$this->scan_request_patterns( $path, $contents );
		}

		if ( $this->regex_failed ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				/* translators: %s: file path */
				sprintf( __( 'Could not analyse: %s', 'shieldscope-site-security-scanner' ), $path ),
				__( 'A pattern check failed on this file (the regular expression engine hit a limit), so the file was not fully checked. Very large or unusual files can cause this, and so can files written to avoid pattern checks.', 'shieldscope-site-security-scanner' ),
				__( 'Open the file and review it by hand, or compare it with the original plugin or theme source.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		return true;
	}

	/**
	 * Patterns not checked in vendor/ (too noisy in bundled libraries).
	 *
	 * @param string $path     File path.
	 * @param string $contents File contents.
	 * @return void
	 */
	private function scan_request_patterns( $path, $contents ) {
		// Shell functions: whole-word calls only, not methods, definitions or comments.
		$shell = '/(?<![$>:])(?<!function\s)\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(/i';
		if ( $this->matches( $shell, $contents ) && $this->matches( $shell, $this->strip_comments( $contents ) ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Matches pattern: shell command function', 'shieldscope-site-security-scanner' ),
				__( 'This file calls shell_exec, passthru, proc_open, popen or system. Some plugins use these legitimately, for example backup or image tools. This match has not been confirmed as harmful.', 'shieldscope-site-security-scanner' ),
				__( 'Check that the plugin needs the call and that no request data reaches the command without escapeshellarg().', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
			);
		}

		// File inclusion from user input.
		if ( $this->matches( '/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Matches pattern: include/require of request data', 'shieldscope-site-security-scanner' ),
				__( 'An include or require statement appears to use $_GET, $_POST, $_REQUEST or $_COOKIE directly. If the value is not checked first, this can allow file inclusion. This match has not been confirmed.', 'shieldscope-site-security-scanner' ),
				__( 'Open the file and check that the value is limited to a fixed list of allowed paths before it is included.', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
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
		if ( $this->matches( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Matches pattern: request data in a database query string', 'shieldscope-site-security-scanner' ),
				__( 'A $wpdb query string appears to contain $_GET, $_POST, $_REQUEST or $_COOKIE data without $wpdb->prepare(). If the value is not sanitised earlier, this can allow SQL injection. This match has not been confirmed.', 'shieldscope-site-security-scanner' ),
				// phpcs:ignore WordPress.WP.I18n.MissingTranslatorsComment,WordPress.WP.I18n.UnorderedPlaceholdersText -- %s/%d/%f are code examples in the advice text, not sprintf() arguments.
				__( 'Use $wpdb->prepare() with placeholders (%s, %d, %f). Never concatenate user input into SQL.', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
			);
		}

		// Unescaped echo of superglobals (reflected XSS heuristic).
		if ( $this->matches( '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Matches pattern: echo of request data', 'shieldscope-site-security-scanner' ),
				__( 'This file appears to echo $_GET, $_POST, $_REQUEST or $_COOKIE data without escaping. If the value reaches the page as-is, this can allow cross-site scripting (XSS). This match has not been confirmed.', 'shieldscope-site-security-scanner' ),
				__( 'Wrap the value in esc_html(), esc_attr() or wp_kses() depending on the context.', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
			);
		}

		// File writes from user input (upload / arbitrary file write).
		if ( $this->matches( '/\bfile_put_contents\s*\([^)]*\$_(?:GET|POST|REQUEST|FILES)/i', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Matches pattern: file_put_contents() with request data', 'shieldscope-site-security-scanner' ),
				__( 'A file_put_contents() call appears to receive $_GET, $_POST, $_REQUEST or $_FILES data. If the path or content is not checked, this can allow arbitrary file writes. This match has not been confirmed.', 'shieldscope-site-security-scanner' ),
				__( 'Use wp_handle_upload() and validate destination paths with realpath against an allowed base.', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
			);
		}

		// Check for long base64 strings (possible payload).
		if ( $this->matches( '/[A-Za-z0-9+\/=]{400,}/', $contents ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Matches pattern: long encoded string', 'shieldscope-site-security-scanner' ),
				__( 'The file contains a base64-shaped string of 400 or more characters. Such strings are often legitimate (images, fonts, SVG), but can also hide a payload. This match has not been confirmed as harmful.', 'shieldscope-site-security-scanner' ),
				__( 'Open the file and inspect the string context.', 'shieldscope-site-security-scanner' ),
				$path,
				$this->last_evidence( $contents )
			);
		}
	}
}
