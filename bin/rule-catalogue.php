<?php
/**
 * Generate docs/rules.md from the check sources (S-26).
 *
 *   php bin/rule-catalogue.php           # write docs/rules.md
 *   php bin/rule-catalogue.php --check   # exit 1 if docs/rules.md is stale
 *
 * Every finding() call and every row of a rule table becomes a rule with an
 * ID SS-<CHECK>-<NN> (numbered in source order within the check), its
 * severity and its title. Titles with placeholders show them as {…}.
 *
 * @package ShieldScope
 */

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$root = dirname( __DIR__ );

// What each check covers and does not (kept here so the catalogue is one file).
$about = array(
	'core'            => array( 'WordPress version and support status, debug settings, HTTPS for the admin, salts, file editing.', 'Does not test the site from outside.' ),
	'core_integrity'  => array( 'Core files against WordPress.org checksums; unknown files in core folders; PHP in the WordPress root, wp-content root, drop-ins and must-use plugins.', 'Plugin and theme files are not checksum-verified.' ),
	'users'           => array( 'Administrator accounts: the name "admin", count, empty passwords, password hash formats.', 'Does not test password strength.' ),
	'database'        => array( 'Registration with a risky default role, site address mismatches, recently created administrators.', 'Does not read post or option content for injected scripts.' ),
	'filesystem'      => array( 'File permissions, configuration and backup files reachable from the web, PHP in uploads, directory listings.', 'Web-reachability is checked from the server itself.' ),
	'plugins'         => array( 'Pending updates, inactive plugins, missing update source, plugins closed on WordPress.org or without a release for two years.', 'Commercial plugins are not looked up.' ),
	'themes'          => array( 'Pending updates, inactive themes, active theme sanity.', '' ),
	'config'          => array( 'Browser security headers, version disclosure, XML-RPC.', 'Headers set by a CDN after the origin may differ.' ),
	'ssl'             => array( 'Certificate validity and expiry, TLS versions, HTTP to HTTPS redirect, mixed content, HSTS.', 'Checked from the server; a CDN may present a different certificate.' ),
	'code_patterns'   => array( 'Plugin and theme PHP for code shapes that need review (eval on decoded data, shell calls, request data in includes, queries, echo, file writes, long encoded strings).', 'Pattern matches only; not a malicious-code signature database.' ),
	'injection'       => array( 'Optional (Developer review). Request data reaching risky calls in plugin and theme code; PHP settings that widen injection risk.', 'Intra-file only; cannot prove exploitability.' ),
	'access_control'  => array( 'Author-page and login-error username exposure, application passwords, login protection, 2FA, plugin REST routes open to writes, AJAX handlers without capability checks.', 'Reads settings, code and routes; never logs in or writes.' ),
	'security_config' => array( 'PHP version support, sensitive files reachable from the web, server information leaks, cron configuration.', '' ),
	'components'      => array( 'Database and WordPress versions against end-of-support dates; HTTP version exposure.', '' ),
	'ssrf'            => array( 'Pingbacks and the oEmbed proxy; with Developer review, request data choosing a URL the server fetches.', 'Pattern matches only.' ),
	'vuln_db'         => array( 'Installed plugins against a limited built-in vulnerability list, or WPScan with an API key.', 'Without a key, coverage is limited to the built-in list.' ),
);

/**
 * Severity name from a constant token.
 *
 * @param string $text Token text.
 * @return string
 */
function ss_sev( $text ) {
	return preg_match( '/SEVERITY_(\w+)/', $text, $m ) ? ucfirst( strtolower( $m[1] ) ) : 'Varies';
}

/**
 * The PHP string value of a single-quoted or double-quoted literal token.
 *
 * @param string $lit Literal.
 * @return string
 */
function ss_str( $lit ) {
	$v = substr( $lit, 1, -1 );
	return "'" === $lit[0] ? str_replace( array( "\\'", '\\\\' ), array( "'", '\\' ), $v ) : stripcslashes( $v );
}

/**
 * Rules found in one check file.
 *
 * @param string $file Path.
 * @return array[] Each: severity, title.
 */
function ss_rules( $file ) {
	$t     = array_values(
		array_filter(
			token_get_all( file_get_contents( $file ) ),
			static function ( $x ) {
				return ! is_array( $x ) || ! in_array( $x[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true );
			}
		)
	);
	$n     = count( $t );
	$rules = array();
	$tx    = static function ( $i ) use ( $t ) {
		return is_array( $t[ $i ] ) ? $t[ $i ][1] : $t[ $i ];
	};
	// Table rows: '/regex/', __( 'title' ... in a $rules or $sinks array.
	$table_sev = array();
	for ( $i = 0; $i < $n; $i++ ) {
		if ( 'finding' === $tx( $i ) && '(' === $tx( $i + 1 ) && '->' === $tx( $i - 1 ) ) {
			// Severity: first argument.
			$sev = ss_sev( $tx( $i + 2 ) . $tx( $i + 3 ) . $tx( $i + 4 ) );
			// Title: first __( literal before the first top-level comma after severity.
			$depth = 0;
			$title = null;
			$var   = '';
			for ( $j = $i + 1; $j < $n; $j++ ) {
				$c = $tx( $j );
				if ( '(' === $c ) {
					$depth++;
				} elseif ( ')' === $c ) {
					$depth--;
					if ( 0 === $depth ) {
						break;
					}
				} elseif ( ',' === $c && 1 === $depth ) {
					if ( null !== $title || '' !== $var ) {
						break;
					}
					$title = null;
					$var   = '';
					continue;
				}
				if ( null === $title && '__' === $c && '(' === $tx( $j + 1 ) && T_CONSTANT_ENCAPSED_STRING === ( is_array( $t[ $j + 2 ] ) ? $t[ $j + 2 ][0] : 0 ) ) {
					$title = ss_str( $tx( $j + 2 ) );
				}
				if ( null === $title && '' === $var && is_array( $t[ $j ] ) && T_VARIABLE === $t[ $j ][0] && $j > $i + 3 ) {
					$var = $c;
				}
			}
			if ( null !== $title ) {
				$rules[] = array( $sev, $title );
			} elseif ( '' !== $var ) {
				$table_sev[ $var ] = $sev; // Table-driven: severity applies to the table rows.
			}
		}
	}
	// Table rows: array( <regex literal ...>, __( 'title' ... ).
	for ( $i = 0; $i < $n - 3; $i++ ) {
		if ( 'array' !== strtolower( $tx( $i ) ) || '(' !== $tx( $i + 1 ) ) {
			continue;
		}
		$k        = $i + 2;
		$depth    = 0;
		$is_regex = false;
		for ( ; $k < $n; $k++ ) {
			$c = $tx( $k );
			if ( '(' === $c ) {
				$depth++;
			} elseif ( ')' === $c ) {
				if ( 0 === $depth ) {
					break;
				}
				$depth--;
			} elseif ( ',' === $c && 0 === $depth ) {
				break;
			} elseif ( is_array( $t[ $k ] ) && T_CONSTANT_ENCAPSED_STRING === $t[ $k ][0] && 0 === strpos( ss_str( $c ), '/' ) ) {
				$is_regex = true;
			}
		}
		if ( ! $is_regex || ',' !== $tx( $k ) || '__' !== $tx( $k + 1 ) || '(' !== $tx( $k + 2 ) || ! is_array( $t[ $k + 3 ] ) ) {
			continue;
		}
		$title = ss_str( $tx( $k + 3 ) );
		$sev = $table_sev ? reset( $table_sev ) : 'Varies';
		// Sink fragments ("eval()") are shown inside their review title, with
		// the severity of the finding() call that reports them.
		if ( strlen( $title ) < 40 && false === strpos( $title, ':' ) && false === strpos( $title, 'Review' ) ) {
			$title = 'Review: user input near ' . $title . ' ({variable})';
			foreach ( $rules as $r ) {
				if ( 'Review: user input near %1$s (%2$s)' === $r[1] ) {
					$sev = $r[0];
				}
			}
		}
		$rules[] = array( $sev, $title );
	}
	// Table rows: array( ShieldScope_Logger::SEVERITY_X, __( 'title' ... ).
	for ( $i = 0; $i < $n - 8; $i++ ) {
		if ( 'array' === strtolower( $tx( $i ) ) && '(' === $tx( $i + 1 ) && 'ShieldScope_Logger' === $tx( $i + 2 ) && '::' === $tx( $i + 3 )
			&& 0 === strpos( $tx( $i + 4 ), 'SEVERITY_' ) && ',' === $tx( $i + 5 ) && '__' === $tx( $i + 6 ) && '(' === $tx( $i + 7 )
			&& is_array( $t[ $i + 8 ] ) && T_CONSTANT_ENCAPSED_STRING === $t[ $i + 8 ][0] ) {
			$rules[] = array( ss_sev( $tx( $i + 4 ) ), ss_str( $tx( $i + 8 ) ) );
		}
	}
	// The generic sink title is replaced by one row per sink above.
	$rules = array_values(
		array_filter(
			$rules,
			static function ( $r ) {
				return 'Review: user input near %1$s (%2$s)' !== $r[1];
			}
		)
	);
	foreach ( $rules as &$r ) {
		$r[1] = preg_replace( '/%(\d+\$)?[sd]/', '{…}', $r[1] );
	}
	return $rules;
}

$out  = "# ShieldScope rule catalogue\n\n";
$out .= "Generated by `bin/rule-catalogue.php` from the check sources; `tests/test-s26-rule-catalogue.php` fails when it is out of date. ";
$out .= "IDs are numbered in source order within each check. Severity is the one the rule reports; findings labelled \"Needs review\" are pattern matches and are never Critical. See `docs/severity-rubric.md` for how severities are chosen and `docs/accuracy.md` for false-positive testing.\n";

$checks = glob( "$root/includes/checks/class-shieldscope-check-*.php" );
sort( $checks );
$total = 0;
foreach ( $checks as $file ) {
	$src = file_get_contents( $file );
	if ( ! preg_match( "/function get_id\(\)\s*\{\s*return '([a-z_]+)'/", $src, $m ) ) {
		continue;
	}
	$id    = $m[1];
	$label = preg_match( "/function get_label\(\)\s*\{\s*return __\( '([^']+)'/", $src, $l ) ? $l[1] : $id;
	$rules = ss_rules( $file );
	$total += count( $rules );
	$code   = strtoupper( str_replace( '_', '', $id ) );
	$out   .= "\n## $label (`$id`)\n\n";
	if ( isset( $about[ $id ] ) ) {
		$out .= '**Checks:** ' . $about[ $id ][0] . "\n";
		if ( '' !== $about[ $id ][1] ) {
			$out .= "\n**Limits:** " . $about[ $id ][1] . "\n";
		}
	}
	$out .= "\n| ID | Severity | Finding |\n|---|---|---|\n";
	foreach ( $rules as $i => $r ) {
		$out .= sprintf( "| SS-%s-%02d | %s | %s |\n", $code, $i + 1, $r[0], str_replace( '|', '\\|', $r[1] ) );
	}
}
$out .= "\n$total rules in " . count( $about ) . " checks.\n";

$target = "$root/docs/rules.md";
if ( in_array( '--check', $argv, true ) ) {
	if ( ! is_file( $target ) || file_get_contents( $target ) !== $out ) {
		fwrite( STDERR, "docs/rules.md is out of date: run php bin/rule-catalogue.php\n" );
		exit( 1 );
	}
	exit( 0 );
}
file_put_contents( $target, $out );
echo "docs/rules.md: $total rules\n";
