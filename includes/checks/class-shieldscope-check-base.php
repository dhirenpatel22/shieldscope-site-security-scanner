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
	 * Most directories the walker expands in one call.
	 */
	const MAX_DIRS_PER_CALL = 50;

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
	 * microtime() after which a step should save its cursor and return
	 * (0 = no limit).
	 *
	 * @var float
	 */
	private $deadline = 0.0;

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
	 * Coverage notes raised during the current step (read by the scanner).
	 *
	 * @var string[]
	 */
	private $coverage_notes = array();

	/**
	 * Note that this check could not cover everything (for example files
	 * skipped). The scanner marks the check "partial" and shows the note.
	 *
	 * @param string $note Short reason.
	 * @return void
	 */
	protected function note_partial( $note ) {
		$this->coverage_notes[] = (string) $note;
	}

	/**
	 * Return and clear the coverage notes.
	 *
	 * @return string[]
	 */
	public function take_coverage_notes() {
		$notes                = $this->coverage_notes;
		$this->coverage_notes = array();
		return $notes;
	}

	/**
	 * Is the optional "Developer review" mode on? It enables the injection
	 * and SSRF code-pattern scans, which only produce findings to review.
	 *
	 * @return bool
	 */
	public static function developer_review_enabled() {
		$settings = (array) get_option( 'shieldscope_settings', array() );
		return ! empty( $settings['developer_review'] );
	}

	/**
	 * Result for a code-scan step skipped because Developer review is off.
	 *
	 * @return array
	 */
	protected function skip_code_scan() {
		$this->note_partial( __( 'plugin and theme code not scanned: Developer review is off in Settings', 'shieldscope-site-security-scanner' ) );
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Set the time budget for the next step.
	 *
	 * @param float $deadline microtime() at which work should stop; 0 for none.
	 * @return void
	 */
	public function set_deadline( $deadline ) {
		$this->deadline = (float) $deadline;
	}

	/**
	 * Has the current step used its time budget?
	 *
	 * @return bool
	 */
	protected function out_of_time() {
		return $this->deadline > 0 && microtime( true ) >= $this->deadline;
	}

	/**
	 * Confidence labels stored in a finding's context.
	 */
	const CONFIDENCE_CONFIRMED = 'confirmed';
	const CONFIDENCE_REVIEW    = 'review';

	/**
	 * Is this a pattern/heuristic title that needs a person to confirm it?
	 *
	 * @param string $title Finding title.
	 * @return bool
	 */
	public static function is_review_title( $title ) {
		return 0 === strpos( (string) $title, 'Review:' ) || 0 === strpos( (string) $title, 'Matches pattern' );
	}

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
		$context = (array) $context;
		if ( ! isset( $context['confidence'] ) ) {
			$context['confidence'] = self::is_review_title( $title ) ? self::CONFIDENCE_REVIEW : self::CONFIDENCE_CONFIRMED;
		}
		// Critical is reserved for confirmed facts (docs/severity-rubric.md).
		if ( self::CONFIDENCE_REVIEW === $context['confidence'] && ShieldScope_Logger::SEVERITY_CRITICAL === $severity ) {
			$severity = ShieldScope_Logger::SEVERITY_HIGH;
		}
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

	// -----------------------------------------------------------------------
	// Source analysis helpers (used by the code-scanning checks)
	// -----------------------------------------------------------------------

	/**
	 * Set when a regular expression run through the rx_* helpers fails
	 * (backtrack or recursion limit, bad UTF-8). Reset per file by the caller.
	 *
	 * @var bool
	 */
	protected $rx_failed = false;

	/**
	 * Functions whose result no longer carries raw user input for the
	 * purposes of the taint heuristics (casts, keys, escaping, guards).
	 *
	 * @var string
	 */
	const NEUTRAL_CALLS = 'absint|intval|floatval|boolval|sanitize_key|sanitize_title|sanitize_email|sanitize_file_name|is_numeric|esc_html|esc_attr|esc_url|esc_url_raw|esc_js|esc_textarea|esc_sql|wp_kses|wp_kses_post|wp_kses_data|wp_validate_redirect|wp_verify_nonce|isset|empty|count|in_array|array_key_exists';

	/**
	 * PHP source with comments, string-literal text and inline HTML removed.
	 *
	 * Variables interpolated into double-quoted strings and heredocs are kept,
	 * so "... $_GET[id]" still shows the variable while '... $_GET ...' does not.
	 * Falls back to the raw source when the tokenizer is unavailable.
	 *
	 * @param string $contents     PHP source.
	 * @param bool   $keep_strings Keep string-literal text (remove comments only).
	 * @return string
	 */
	public static function code_view( $contents, $keep_strings = false ) {
		if ( ! function_exists( 'token_get_all' ) ) {
			return $contents;
		}
		$code = '';
		foreach ( @token_get_all( $contents ) as $token ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- scanned files may be malformed.
			if ( ! is_array( $token ) ) {
				$code .= $token;
				continue;
			}
			if ( $keep_strings && T_COMMENT !== $token[0] && T_DOC_COMMENT !== $token[0] ) {
				$code .= $token[1];
				continue;
			}
			// Blanked tokens keep their line breaks so offsets map to the same line.
			$breaks = str_repeat( "\n", substr_count( $token[1], "\n" ) );
			switch ( $token[0] ) {
				case T_COMMENT:
				case T_DOC_COMMENT:
				case T_ENCAPSED_AND_WHITESPACE:
				case T_INLINE_HTML:
					$code .= ' ' . $breaks;
					break;
				case T_CONSTANT_ENCAPSED_STRING:
					$code .= "''" . $breaks;
					break;
				default:
					$code .= $token[1];
			}
		}
		return $code;
	}

	/**
	 * Replace calls that neutralise user input (casts, escaping, isset guards)
	 * with 0, so what remains shows only raw use of request data.
	 *
	 * @param string $code Output of code_view().
	 * @return string
	 */
	protected function neutralise_safe_calls( $code ) {
		$code = $this->rx_replace(
			'/\b(?:' . self::NEUTRAL_CALLS . ')\s*(\((?:[^()]++|(?1))*\))/i',
			static function ( $m ) {
				return '0' . str_repeat( "\n", substr_count( $m[0], "\n" ) );
			},
			$code
		);
		return $this->rx_replace( '/\(\s*(?:int|integer|float|double|bool|boolean)\s*\)\s*\$_(?:GET|POST|REQUEST|COOKIE)(?:\s*\[[^\]]*\])*/i', '0', $code );
	}

	/**
	 * preg_match() that records a failure instead of reading it as "no match".
	 *
	 * @param string $pattern Regex.
	 * @param string $subject Subject.
	 * @param array  $matches Matches (by reference).
	 * @return bool
	 */
	protected function rx_match( $pattern, $subject, &$matches = null ) {
		$result = preg_match( $pattern, $subject, $matches );
		if ( false === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->rx_failed = true;
			return false;
		}
		return 1 === $result;
	}

	/**
	 * Offset of the first match, or -1 (a regex failure is recorded).
	 *
	 * @param string $pattern Regex.
	 * @param string $subject Subject.
	 * @return int
	 */
	protected function rx_offset( $pattern, $subject ) {
		$result = preg_match( $pattern, $subject, $m, PREG_OFFSET_CAPTURE );
		if ( false === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->rx_failed = true;
			return -1;
		}
		return 1 === $result ? (int) $m[0][1] : -1;
	}

	/**
	 * Line number and a short snippet for a match.
	 *
	 * @param string $original Original file contents.
	 * @param string $view     The text the match was found in (same line breaks as $original).
	 * @param int    $offset   Byte offset of the match in $view.
	 * @return array { evidence: { line: int, snippet: string } } or empty array.
	 */
	public static function evidence( $original, $view, $offset ) {
		if ( $offset < 0 ) {
			return array();
		}
		$line  = substr_count( substr( (string) $view, 0, $offset ), "\n" ) + 1;
		$lines = explode( "\n", (string) $original );
		$text  = isset( $lines[ $line - 1 ] ) ? trim( $lines[ $line - 1 ] ) : '';
		if ( function_exists( 'wp_check_invalid_utf8' ) ) {
			$text = wp_check_invalid_utf8( $text, true );
		}
		if ( function_exists( 'mb_strimwidth' ) ) {
			$text = mb_strimwidth( $text, 0, 160, '…', 'UTF-8' );
		} elseif ( strlen( $text ) > 160 ) {
			$text = substr( $text, 0, 159 ) . '…';
		}
		return array(
			'evidence' => array(
				'line'    => $line,
				'snippet' => $text,
			),
		);
	}

	/**
	 * preg_match_all() that records a failure.
	 *
	 * @param string $pattern Regex.
	 * @param string $subject Subject.
	 * @return array Capture group 1 of every match.
	 */
	protected function rx_all( $pattern, $subject ) {
		$result = preg_match_all( $pattern, $subject, $matches );
		if ( false === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->rx_failed = true;
			return array();
		}
		return isset( $matches[1] ) ? $matches[1] : array();
	}

	/**
	 * preg_replace() / preg_replace_callback() that records a failure and
	 * returns the subject unchanged.
	 *
	 * @param string          $pattern     Regex.
	 * @param string|callable $replacement Replacement string or callback.
	 * @param string          $subject     Subject.
	 * @return string
	 */
	protected function rx_replace( $pattern, $replacement, $subject ) {
		$result = is_callable( $replacement )
			? preg_replace_callback( $pattern, $replacement, $subject )
			: preg_replace( $pattern, $replacement, $subject );
		if ( null === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->rx_failed = true;
			return $subject;
		}
		return $result;
	}

	/**
	 * Record that a file could not be fully analysed.
	 *
	 * @param string $path File path.
	 * @return void
	 */
	protected function could_not_analyse( $path ) {
		$this->finding(
			ShieldScope_Logger::SEVERITY_LOW,
			/* translators: %s: file path */
			sprintf( __( 'Could not analyse: %s', 'shieldscope-site-security-scanner' ), $path ),
			__( 'A pattern check failed on this file (the regular expression engine hit a limit), so the file was not fully checked. Very large or unusual files can cause this, and so can files written to avoid pattern checks.', 'shieldscope-site-security-scanner' ),
			__( 'Open the file and review it by hand, or compare it with the original plugin or theme source.', 'shieldscope-site-security-scanner' ),
			$path
		);
	}

	/**
	 * Read a PHP file for pattern scanning.
	 *
	 * @param string $path          File path.
	 * @param int    $max_file_size Size limit in bytes.
	 * @return string|false Contents; '' for an empty file; false if skipped (too large or unreadable).
	 */
	protected function read_scannable_file( $path, $max_file_size ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $max_file_size ) {
			return false;
		}
		if ( 0 === $size ) {
			return '';
		}
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		return false === $contents ? false : $contents;
	}

	/**
	 * Shared resumable directory walker (two-queue design).
	 *
	 * Directories are always expanded fully into the file queue before the
	 * per-call file budget is applied, so a batch boundary can never fall in
	 * the middle of a directory and silently drop files — the file queue in
	 * the cursor carries any leftovers to the next invocation.
	 *
	 * Each call stops when the time budget is spent (after at least one unit
	 * of work), after $files_per_call files or after MAX_DIRS_PER_CALL
	 * directory expansions. Symlinked directories are not followed. When the
	 * walk ends, one Info finding lists what was skipped, if anything.
	 *
	 * Cursor keys:
	 *   dirs    — directories still to expand
	 *   files   — file paths waiting to be handled
	 *   checked — cumulative count of files handled
	 *   skipped — counts: 'dirs' (skip list), 'links' (symlinks), 'files' (handler returned false)
	 *
	 * @param string   $root           Root directory to walk.
	 * @param array    $cursor         Cursor from the previous invocation (empty on first call).
	 * @param callable $handle_file    Called once per matching file with the full path; returns false if it skipped the file.
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
		$cursor['dirs']    = isset( $cursor['dirs'] ) ? (array) $cursor['dirs'] : array();
		$cursor['files']   = isset( $cursor['files'] ) ? (array) $cursor['files'] : array();
		$cursor['skipped'] = isset( $cursor['skipped'] ) ? (array) $cursor['skipped'] : array();
		$cursor['skipped'] += array( 'dirs' => 0, 'links' => 0, 'files' => 0 );

		$self_dir  = defined( 'SHIELDSCOPE_PLUGIN_DIR' )
			? rtrim( str_replace( '\\', '/', SHIELDSCOPE_PLUGIN_DIR ), '/' ) . '/'
			: '';
		$processed = 0;
		$expanded  = 0;

		while ( $processed < $files_per_call ) {
			if ( ( $processed > 0 || $expanded > 0 ) && $this->out_of_time() ) {
				break;
			}

			// Drain the file queue before expanding another directory.
			if ( ! empty( $cursor['files'] ) ) {
				$full = array_shift( $cursor['files'] );
				if ( false === call_user_func( $handle_file, $full ) ) {
					$cursor['skipped']['files']++;
				}
				$processed++;
				$cursor['checked']++;
				continue;
			}

			if ( empty( $cursor['dirs'] ) || $expanded >= self::MAX_DIRS_PER_CALL ) {
				break;
			}

			$current = array_shift( $cursor['dirs'] );
			$expanded++;
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
					if ( is_link( $full ) ) {
						// Not followed: a link can point back up the tree.
						$cursor['skipped']['links']++;
						continue;
					}
					if ( in_array( $entry, $skip_dirs, true ) ) {
						$cursor['skipped']['dirs']++;
						continue;
					}
					$cursor['dirs'][] = $full;
				} elseif ( preg_match( $pattern, $entry ) ) {
					$cursor['files'][] = $full;
				}
			}
			// Directory expansion does not count against the file budget.
		}

		$continue = ! empty( $cursor['dirs'] ) || ! empty( $cursor['files'] );
		if ( ! $continue && array_sum( $cursor['skipped'] ) > 0 ) {
			$this->note_partial(
				sprintf(
					/* translators: 1: number of files, 2: number of folders */
					__( '%1$d file(s) and %2$d folder(s) not scanned', 'shieldscope-site-security-scanner' ),
					$cursor['skipped']['files'],
					$cursor['skipped']['dirs'] + $cursor['skipped']['links']
				)
			);
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Some files were not scanned', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: number of folders, 2: number of symlinked folders, 3: number of files */
					__( 'Folders skipped (vendor, node_modules, .git): %1$d. Symlinked folders not followed: %2$d. Files skipped (too large or unreadable): %3$d.', 'shieldscope-site-security-scanner' ),
					$cursor['skipped']['dirs'],
					$cursor['skipped']['links'],
					$cursor['skipped']['files']
				),
				'',
				$root
			);
		}

		return array(
			'continue' => $continue,
			'cursor'   => $cursor,
		);
	}
}
