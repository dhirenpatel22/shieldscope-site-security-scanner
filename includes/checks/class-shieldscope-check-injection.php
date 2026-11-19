<?php
/**
 * Injection pattern review.
 *
 * Every rule here is a pattern match on source code, not a proof of a
 * vulnerability. The file is first reduced to a "code view" (comments,
 * string-literal text and inline HTML removed; interpolated variables kept),
 * then three phases run:
 *
 * Phase 1 — Direct patterns: user input and a dangerous call in the same
 *   expression (for example unserialize( $_POST['x'] )). Capped at High.
 *
 * Phase 2 — Intra-file taint: variables assigned from raw request data are
 *   followed to dangerous calls in the same file. Calls that neutralise
 *   input (absint, intval, sanitize_key, esc_*, isset guards, casts) clear
 *   the taint, and values passed as $wpdb->prepare() arguments are not
 *   treated as SQL. Reported as Low "Review" findings.
 *
 * Phase 3 — Co-occurrence: request data or AJAX hooks in the same file as
 *   maybe_unserialize(), and wp_parse_str() on request data. Low "Review".
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Injection
 */
class ShieldScope_Check_Injection extends ShieldScope_Check_Base {

	/**
	 * Max file size to scan (bytes).
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor.
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

	/** @return string */
	public function get_id() {
		return 'injection';
	}

	/** @return string */
	public function get_label() {
		return __( 'Injection Vulnerabilities', 'shieldscope-site-security-scanner' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'scan_plugins', 'scan_themes', 'check_php_settings' );
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
			return $this->scan_tree( SHIELDSCOPE_WP_PLUGINS_DIR, $cursor );
		}
		if ( 'scan_themes' === $step ) {
			return $this->scan_tree( get_theme_root(), $cursor );
		}
		if ( 'check_php_settings' === $step ) {
			$this->check_php_settings();
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Walk a directory tree resumably.
	 *
	 * @param string $root   Root directory.
	 * @param array  $cursor Cursor state.
	 * @return array
	 */
	private function scan_tree( $root, array $cursor ) {
		return $this->walk_php_files_step(
			$root,
			$cursor,
			function ( $full ) {
				return $this->scan_file( $full );
			}
		);
	}

	/**
	 * Scan one PHP file.
	 *
	 * @param string $path Absolute path.
	 * @return bool False if the file was skipped (too large or unreadable).
	 */
	private function scan_file( $path ) {
		$contents = $this->read_scannable_file( $path, $this->max_file_size );
		if ( false === $contents ) {
			return false;
		}
		if ( '' === $contents ) {
			return true;
		}

		$this->rx_failed = false;
		$code            = self::code_view( $contents );
		$raw             = $this->neutralise_safe_calls( $code );

		$this->phase1_direct_patterns( $path, $contents, $raw );
		$this->phase2_taint_tracking( $path, $raw, $contents );
		$this->phase3_cooccurrence( $path, $contents, $code );

		if ( $this->rx_failed ) {
			$this->could_not_analyse( $path );
		}
		return true;
	}

	/**
	 * Sentence appended to every pattern-based description.
	 *
	 * @return string
	 */
	private function review_note() {
		return __( 'This is a pattern match, not a confirmed vulnerability: read the code to confirm whether request data really reaches this call.', 'shieldscope-site-security-scanner' );
	}

	// -----------------------------------------------------------------------
	// Phase 1 — Direct, single-expression patterns
	// -----------------------------------------------------------------------

	/**
	 * Patterns where raw user input and the dangerous call share one expression.
	 *
	 * @param string $path     File path.
	 * @param string $contents Original source (for patterns that need string contents).
	 * @param string $raw      Code view with neutralising calls removed.
	 * @return void
	 */
	private function phase1_direct_patterns( $path, $contents, $raw ) {
		$sg    = '\$_(?:GET|POST|REQUEST|COOKIE)';
		$rules = array(
			array(
				'/\b(?:unserialize|maybe_unserialize)\s*\([^;]*' . $sg . '/i',
				__( 'PHP Object Injection: deserialization of direct user input', 'shieldscope-site-security-scanner' ),
				__( 'unserialize() or maybe_unserialize() appears to be called directly on request data. A crafted serialized payload can instantiate objects and, with a suitable gadget chain, lead to code execution.', 'shieldscope-site-security-scanner' ),
				__( 'Do not deserialize request data. Use json_decode() for data interchange. If deserialization is unavoidable, pass allowed_classes => false.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\$\$_(?:GET|POST|REQUEST|COOKIE)\[/i',
				__( 'Variable variable injection from user input', 'shieldscope-site-security-scanner' ),
				__( 'Using $$_GET or $$_POST creates variable names from request data, which lets a visitor overwrite variables in scope.', 'shieldscope-site-security-scanner' ),
				__( 'Remove variable variables on request data. Read keys explicitly against an allowlist.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\bextract\s*\(\s*' . $sg . '/i',
				__( 'Mass variable extraction from user input', 'shieldscope-site-security-scanner' ),
				__( 'extract() on request data injects visitor-chosen keys into the current variable scope.', 'shieldscope-site-security-scanner' ),
				__( "Remove extract() on request data. Read keys explicitly: \$foo = sanitize_text_field( wp_unslash( \$_POST['foo'] ?? '' ) );", 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\bcall_user_func(?:_array)?\s*\([^;]*' . $sg . '/i',
				__( 'call_user_func() with user-controlled callable', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in a call_user_func() call. If it selects the function name, a visitor can call any PHP function.', 'shieldscope-site-security-scanner' ),
				__( 'Check the callable against a strict allowlist before calling it.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*(?:sprintf|vsprintf)\s*\([^;]*' . $sg . '/i',
				__( 'SQL injection: sprintf() building $wpdb query with user input', 'shieldscope-site-security-scanner' ),
				__( 'sprintf() with request data inside a $wpdb query does not escape SQL values.', 'shieldscope-site-security-scanner' ),
				// phpcs:ignore WordPress.WP.I18n.MissingTranslatorsComment,WordPress.WP.I18n.UnorderedPlaceholdersText -- %s/%d/%f are code examples in the advice text, not sprintf() arguments.
				__( 'Use $wpdb->prepare() with %s / %d / %f placeholders.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*"[^"]*' . $sg . '/i',
				__( 'SQL injection: superglobal interpolated in $wpdb query string', 'shieldscope-site-security-scanner' ),
				__( 'A superglobal appears to be interpolated directly into a $wpdb query string.', 'shieldscope-site-security-scanner' ),
				__( 'Use $wpdb->prepare(); never interpolate request data into SQL.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\b(?:printf|vprintf)\s*\([^;]*' . $sg . '/i',
				__( 'XSS: printf() echoing unescaped user input', 'shieldscope-site-security-scanner' ),
				__( 'printf() or vprintf() appears to output request data without an escaping function.', 'shieldscope-site-security-scanner' ),
				__( 'Escape with esc_html(), esc_attr() or esc_url() before passing values to printf().', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\becho\s+"[^"]*' . $sg . '/i',
				__( 'XSS: superglobal interpolated inside echoed string', 'shieldscope-site-security-scanner' ),
				__( 'A superglobal appears to be interpolated inside an echoed double-quoted string.', 'shieldscope-site-security-scanner' ),
				__( 'Escape with esc_html(), esc_attr() or esc_url(), depending on the output context.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\b(?:ldap_search|ldap_list|ldap_read)\s*\([^;]*\$_(?:GET|POST|REQUEST)/i',
				__( 'LDAP injection: LDAP query function called with user input', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in an LDAP query call, which allows the query to be changed.', 'shieldscope-site-security-scanner' ),
				__( 'Escape with ldap_escape() (LDAP_ESCAPE_FILTER or LDAP_ESCAPE_DN).', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\b(?:simplexml_load_string|DOMDocument\s*->\s*loadXML)\s*\([^;]*\$_(?:GET|POST|REQUEST)/i',
				__( 'XXE risk: SimpleXML parsing user-supplied XML', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears to be parsed as XML. If entity substitution is enabled, a crafted document can read local files or make the server send requests.', 'shieldscope-site-security-scanner' ),
				__( 'Do not pass LIBXML_NOENT or LIBXML_DTDLOAD when parsing untrusted XML (libxml 2.9 and later do not load external entities by default). Reject documents that contain a DOCTYPE.', 'shieldscope-site-security-scanner' ),
			),
		);

		foreach ( $rules as $rule ) {
			$at = $this->rx_offset( $rule[0], $raw );
			if ( $at >= 0 ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_HIGH,
					$rule[1],
					$rule[2] . ' ' . $this->review_note(),
					$rule[3],
					$path,
					array( 'confidence' => self::CONFIDENCE_REVIEW ) + self::evidence( $contents, $raw, $at )
				);
			}
		}

		// Patterns that are risky whatever the input (removed from current PHP).
		$at = $this->rx_offset( '/\bcreate_function\s*\(/i', $raw );
		if ( $at >= 0 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Deprecated create_function() — potential code injection', 'shieldscope-site-security-scanner' ),
				__( 'create_function() works like eval() and was removed in PHP 8. If request data reaches its arguments it allows code execution; on PHP 8 the call is a fatal error.', 'shieldscope-site-security-scanner' ),
				__( 'Replace it with an anonymous function (closure).', 'shieldscope-site-security-scanner' ),
				$path,
				self::evidence( $contents, $raw, $at )
			);
		}
		$no_comments = self::code_view( $contents, true );
		$at = $this->rx_offset( '/preg_replace\s*\(\s*["\'][^"\']*\/e[imsuUxAJD]*["\'][^,]*,/i', $no_comments );
		if ( $at >= 0 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'preg_replace() /e modifier — code injection', 'shieldscope-site-security-scanner' ),
				__( 'The /e modifier runs the replacement as PHP code. It was removed in PHP 7.0, so on current PHP the call fails; on old PHP it is a code-execution risk.', 'shieldscope-site-security-scanner' ),
				__( 'Replace with preg_replace_callback().', 'shieldscope-site-security-scanner' ),
				$path,
				self::evidence( $contents, $no_comments, $at )
			);
		}
	}

	// -----------------------------------------------------------------------
	// Phase 2 — Intra-file taint tracking
	// -----------------------------------------------------------------------

	/**
	 * Follow variables assigned from raw request data to dangerous calls.
	 *
	 * @param string $path     File path.
	 * @param string $raw      Code view with neutralising calls removed.
	 * @param string $contents Original source (for evidence).
	 * @return void
	 */
	private function phase2_taint_tracking( $path, $raw, $contents ) {
		$tainted = $this->extract_tainted_vars( $raw );
		if ( empty( $tainted ) ) {
			return;
		}

		// Values passed as $wpdb->prepare() arguments are bound as placeholders:
		// keep only the query-string argument for the SQL rule.
		$sql_view = $this->rx_replace(
			'/\$wpdb\s*->\s*prepare\s*(\((?:[^()]++|(?1))*\))/i',
			function ( $m ) {
				$first = self::first_argument( substr( $m[1], 1, -1 ) );
				return '$wpdb->prepare(' . $first . ')' . str_repeat( "\n", substr_count( $m[0], "\n" ) - substr_count( $first, "\n" ) );
			},
			$raw
		);

		$sinks = array(
			'unserialize'    => array( '/\b(?:unserialize|maybe_unserialize)\s*\([^;]*\$%s\b/i', __( 'unserialize()', 'shieldscope-site-security-scanner' ), __( 'Deserializing request data can instantiate objects (PHP object injection).', 'shieldscope-site-security-scanner' ), __( 'Use json_decode() instead, or pass allowed_classes => false.', 'shieldscope-site-security-scanner' ) ),
			'sql'            => array( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\([^;]*\$%s\b/i', __( 'a $wpdb query', 'shieldscope-site-security-scanner' ), __( 'The variable appears in the SQL text of a $wpdb query rather than as a $wpdb->prepare() argument.', 'shieldscope-site-security-scanner' ), __( 'Pass the value as a $wpdb->prepare() argument with a typed placeholder, or cast it with absint() first.', 'shieldscope-site-security-scanner' ) ),
			'eval'           => array( '/\beval\s*\([^;]*\$%s\b/i', __( 'eval()', 'shieldscope-site-security-scanner' ), __( 'Request data reaching eval() would be code execution.', 'shieldscope-site-security-scanner' ), __( 'Remove eval(); plugin code almost never needs it.', 'shieldscope-site-security-scanner' ) ),
			'shell'          => array( '/(?<![$>:])\b(?:shell_exec|exec|system|passthru|proc_open|popen)\s*\([^;]*\$%s\b/i', __( 'a shell function', 'shieldscope-site-security-scanner' ), __( 'Request data reaching a shell function would allow OS command execution.', 'shieldscope-site-security-scanner' ), __( 'Do not pass request data to shell functions. If unavoidable, use escapeshellarg() and a strict allowlist.', 'shieldscope-site-security-scanner' ) ),
			'include'        => array( '/\b(?:include|require)(?:_once)?\s*\(?\s*\$%s\b/i', __( 'include/require', 'shieldscope-site-security-scanner' ), __( 'A file path chosen by request data allows local file inclusion.', 'shieldscope-site-security-scanner' ), __( 'Map request values to a fixed list of files; never build an include path from request data.', 'shieldscope-site-security-scanner' ) ),
			'echo'           => array( '/\becho\s+\$%s\b(?!\s*\))/i', __( 'echo', 'shieldscope-site-security-scanner' ), __( 'Echoing request data without escaping is cross-site scripting.', 'shieldscope-site-security-scanner' ), __( 'Escape with esc_html(), esc_attr() or esc_url(), depending on the output context.', 'shieldscope-site-security-scanner' ) ),
			'call_user_func' => array( '/\bcall_user_func(?:_array)?\s*\(\s*\$%s\b/i', __( 'call_user_func()', 'shieldscope-site-security-scanner' ), __( 'A callable chosen by request data can call any PHP function.', 'shieldscope-site-security-scanner' ), __( 'Check the callable against a strict allowlist before calling it.', 'shieldscope-site-security-scanner' ) ),
		);

		foreach ( $tainted as $var ) {
			$quoted = preg_quote( $var, '/' );
			foreach ( $sinks as $key => $sink ) {
				$subject = 'sql' === $key ? $sql_view : $raw;
				$at      = $this->rx_offset( sprintf( $sink[0], $quoted ), $subject );
				if ( $at < 0 ) {
					continue;
				}
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					/* translators: 1: dangerous call, for example "eval()"; 2: PHP variable name */
					sprintf( __( 'Review: user input near %1$s (%2$s)', 'shieldscope-site-security-scanner' ), $sink[1], '$' . $var ),
					sprintf(
						/* translators: 1: PHP variable name, 2: dangerous call, 3: why it matters, 4: review note */
						__( '%1$s is assigned from request data and later appears in %2$s in the same file. %3$s %4$s', 'shieldscope-site-security-scanner' ),
						'$' . $var,
						$sink[1],
						$sink[2],
						$this->review_note()
					),
					$sink[3],
					$path,
					array(
						'tainted_var' => '$' . $var,
						'confidence'  => self::CONFIDENCE_REVIEW,
					) + self::evidence( $contents, $subject, $at )
				);
			}
		}
	}

	/**
	 * First top-level argument of an argument list.
	 *
	 * @param string $args Text between the call's parentheses.
	 * @return string
	 */
	private static function first_argument( $args ) {
		$depth = 0;
		$len   = strlen( $args );
		for ( $i = 0; $i < $len; $i++ ) {
			$c = $args[ $i ];
			if ( '(' === $c || '[' === $c || '{' === $c ) {
				$depth++;
			} elseif ( ')' === $c || ']' === $c || '}' === $c ) {
				$depth--;
			} elseif ( ',' === $c && 0 === $depth ) {
				return substr( $args, 0, $i );
			}
		}
		return $args;
	}

	/**
	 * Names of variables assigned from raw request data.
	 *
	 * Works on the neutralised code view, so values passed through absint(),
	 * intval(), sanitize_key(), esc_*() or guarded by isset() are not tainted.
	 * sanitize_text_field() and wp_unslash() do not clear taint: their output
	 * is still free text.
	 *
	 * @param string $raw Code view with neutralising calls removed.
	 * @return string[] Variable names without the $ prefix.
	 */
	private function extract_tainted_vars( $raw ) {
		$sg      = '\$_(?:GET|POST|REQUEST|COOKIE)\b';
		$tainted = array();

		// $var = <expression containing raw request data>;
		$result = preg_match_all( '/\$(\w+)\s*=(?![=>])([^;]*);/', $raw, $m, PREG_SET_ORDER );
		if ( false === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->rx_failed = true;
		} else {
			foreach ( $m as $match ) {
				if ( $this->rx_match( '/' . $sg . '|\b\w+::get_(?:post_)?param\s*\(|\bfilter_input\s*\(\s*INPUT_(?:POST|GET|REQUEST|COOKIE)/i', $match[2] ) ) {
					$tainted[] = $match[1];
				}
			}
		}

		// wp_parse_str( $_POST['q'], $output ) — $output becomes tainted.
		$tainted = array_merge( $tainted, $this->rx_all( '/wp_parse_str\s*\([^,;]*' . $sg . '[^,;]*,\s*\$(\w+)/i', $raw ) );

		// $arr[] = $_POST['key'] — $arr becomes tainted.
		$tainted = array_merge( $tainted, $this->rx_all( '/\$(\w+)\s*\[[^\]]*\]\s*=\s*' . $sg . '/i', $raw ) );

		$tainted = array_filter(
			$tainted,
			static function ( $v ) {
				// Superglobals themselves and one-letter names are too noisy.
				return strlen( $v ) > 1 && 0 !== strpos( $v, '_' );
			}
		);

		return array_values( array_unique( $tainted ) );
	}

	// -----------------------------------------------------------------------
	// Phase 3 — Co-occurrence heuristics
	// -----------------------------------------------------------------------

	/**
	 * Flag combinations worth a manual look when the data flow is split across
	 * functions or files.
	 *
	 * @param string $path     File path.
	 * @param string $contents Original source (hook names are string literals).
	 * @param string $code     Code view.
	 * @return void
	 */
	private function phase3_cooccurrence( $path, $contents, $code ) {
		$no_comments           = self::code_view( $contents, true );
		$has_user_input        = $this->rx_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i', $code );
		$has_nopriv_ajax       = $this->rx_match( "/add_action\s*\(\s*['\"]wp_ajax_nopriv_/i", $no_comments );
		$has_any_ajax          = $this->rx_match( "/add_action\s*\(\s*['\"]wp_ajax_/i", $no_comments );
		$has_maybe_unserialize = $this->rx_match( '/\bmaybe_unserialize\s*\(/i', $code );
		$has_unserialize       = $this->rx_match( '/\bunserialize\s*\(/i', $code );

		// Calls on stored data (database, options, meta) are the normal use.
		$safe_deserialize_context = $this->rx_match(
			'/\b(?:maybe_unserialize|unserialize)\s*\(\s*(?:\$wpdb\s*->|get_option\s*\(|get_transient\s*\(|get_post_meta\s*\(|get_user_meta\s*\(|get_term_meta\s*\()/i',
			$code
		);

		$unser_at = $this->rx_offset( '/\b(?:maybe_)?unserialize\s*\(/i', $code );
		$unser_ev = self::evidence( $contents, $code, $unser_at );

		$advice = __( 'Trace each maybe_unserialize() call in this file. Confirm its argument comes from stored data (database, options, meta) and never from request data, and that AJAX handlers check a nonce and a capability.', 'shieldscope-site-security-scanner' );

		if ( $has_nopriv_ajax && ( $has_maybe_unserialize || $has_unserialize ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Review: user input near maybe_unserialize() in a file with an unauthenticated AJAX action', 'shieldscope-site-security-scanner' ),
				__( 'This file registers a wp_ajax_nopriv_ action (reachable by logged-out visitors) and also deserializes data. If request data reaches the deserialization call, that would be PHP object injection.', 'shieldscope-site-security-scanner' ) . ' ' . $this->review_note(),
				$advice,
				$path,
				$unser_ev
			);
		} elseif ( $has_user_input && $has_maybe_unserialize && ! $safe_deserialize_context ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Review: user input near maybe_unserialize()', 'shieldscope-site-security-scanner' ),
				__( 'This file reads request data and also calls maybe_unserialize() on a value that is not obviously stored data. If request data reaches that call, it would be PHP object injection.', 'shieldscope-site-security-scanner' ) . ' ' . $this->review_note(),
				$advice,
				$path,
				$unser_ev
			);
		} elseif ( $has_any_ajax && $has_maybe_unserialize && ! $safe_deserialize_context ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Review: user input near maybe_unserialize() in a file with an AJAX action', 'shieldscope-site-security-scanner' ),
				__( 'This file registers an AJAX action and calls maybe_unserialize(). If a logged-in user with few permissions can send data that reaches the call, it would be PHP object injection.', 'shieldscope-site-security-scanner' ) . ' ' . $this->review_note(),
				$advice,
				$path,
				$unser_ev
			);
		}

		$parse_at = $this->rx_offset( '/\bwp_parse_str\s*\([^,;]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $code );
		if ( $parse_at >= 0 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Review: user input near wp_parse_str()', 'shieldscope-site-security-scanner' ),
				__( 'wp_parse_str() turns a query string into an array of visitor-chosen keys. Code that uses those keys without checking them can be steered by the request.', 'shieldscope-site-security-scanner' ) . ' ' . $this->review_note(),
				__( 'Read only the keys you expect from the resulting array and sanitise each one.', 'shieldscope-site-security-scanner' ),
				$path,
				self::evidence( $contents, $code, $parse_at )
			);
		}
	}

	// -----------------------------------------------------------------------
	// PHP runtime settings
	// -----------------------------------------------------------------------

	/**
	 * Check PHP ini settings that amplify injection risk.
	 *
	 * @return void
	 */
	private function check_php_settings() {
		// register_globals was removed in PHP 5.4; kept for very old hosts.
		if ( ini_get( 'register_globals' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'PHP register_globals is enabled', 'shieldscope-site-security-scanner' ),
				__( 'register_globals automatically injects GET/POST/COOKIE values as global variables, enabling variable injection across the entire codebase.', 'shieldscope-site-security-scanner' ),
				__( 'Disable register_globals in php.ini immediately. It was removed from PHP 5.4.', 'shieldscope-site-security-scanner' ),
				'php.ini'
			);
		}

		// allow_url_include — turns file inclusion bugs into remote code execution.
		if ( ini_get( 'allow_url_include' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'PHP allow_url_include is enabled', 'shieldscope-site-security-scanner' ),
				__( 'allow_url_include lets include/require load code from remote URLs. Any local file inclusion bug becomes remote code execution.', 'shieldscope-site-security-scanner' ),
				__( 'Set allow_url_include = Off in php.ini.', 'shieldscope-site-security-scanner' ),
				'php.ini'
			);
		}
	}
}
