<?php
/**
 * Core integrity check.
 *
 * Verifies that every shipped WordPress core file matches the official
 * checksums published at api.wordpress.org. Also flags any unknown .php
 * files sitting inside wp-admin/ or wp-includes/ — a classic post-exploit
 * persistence pattern.
 *
 * The WordPress.org checksums API returns a map of
 * { path-relative-to-ABSPATH => md5 }.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Core_Integrity
 */
class ShieldScope_Check_Core_Integrity extends ShieldScope_Check_Base {

	/**
	 * Transient name where the fetched checksums are cached for the duration
	 * of the scan (and a bit beyond, so repeat scans don't hammer the API).
	 */
	const CHECKSUMS_TRANSIENT = 'shieldscope_core_checksums';

	/**
	 * Cache TTL — 12 hours. Core version rarely changes within that window.
	 */
	const CHECKSUMS_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * Batch size for file verification per invocation.
	 *
	 * Kept conservative — each file is a disk read + md5_file.
	 */
	const VERIFY_BATCH = 80;

	/**
	 * Batch size for the unknown-files walker.
	 */
	const EXTRAS_BATCH = 200;

	/**
	 * If more than this fraction of verified core files mismatch, treat the
	 * result as an environment/distribution difference rather than per-file
	 * tampering, and emit one summary finding instead of hundreds.
	 */
	const MASS_MISMATCH_RATIO = 0.30;

	/**
	 * Minimum absolute number of differing files before the mass-mismatch
	 * summary can trigger (avoids the ratio firing on tiny installs).
	 */
	const MASS_MISMATCH_MIN = 20;

	/**
	 * Cap on individually detailed per-file findings; anything beyond this
	 * is rolled into a summary so the report (and DB) is not flooded.
	 */
	const MAX_DETAILED_FINDINGS = 50;

	/**
	 * ID used in findings.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'core_integrity';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'WordPress Core Integrity', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * fetch   — pull the checksums JSON from api.wordpress.org
	 * verify  — walk checksums, verify each file's md5 (resumable, batched)
	 * extras  — walk wp-admin / wp-includes for files NOT in checksums
	 *
	 * @return array
	 */
	/**
	 * Steps a quick scan skips.
	 *
	 * @return string[]
	 */
	public function get_slow_steps() {
		return array( 'verify', 'extras' );
	}

	public function get_steps() {
		return array( 'fetch', 'verify', 'extras', 'persistence' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'fetch':
				$this->step_fetch();
				return array( 'continue' => false, 'cursor' => array() );

			case 'verify':
				return $this->step_verify( $cursor );

			case 'extras':
				return $this->step_extras( $cursor );

			case 'persistence':
				$this->step_persistence();
				return array( 'continue' => false, 'cursor' => array() );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Fetch checksums from api.wordpress.org and cache them.
	 *
	 * @return void
	 */
	private function step_fetch() {
		global $wp_version, $wp_local_package;

		// Non-standard WordPress builds (WordPress Playground, wasm runtimes,
		// SQLite-backed installs) ship patched core files that will never
		// match the official checksums. Comparing them would produce a wall
		// of false "modified core file" findings, so skip with one INFO note.
		$env_reason = $this->detect_nonstandard_environment();
		if ( '' !== $env_reason ) {
			delete_transient( self::CHECKSUMS_TRANSIENT );
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped — non-standard WordPress build', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: detected environment reason */
					__( 'This site appears to be running a modified WordPress distribution (%s). Its core files intentionally differ from the official WordPress.org release, so checksum verification would report false positives and has been skipped. Run this check on your production hosting environment instead.', 'shieldscope-site-security-scanner' ),
					$env_reason
				),
				'',
				ABSPATH
			);
			return;
		}

		$version = isset( $wp_version ) ? $wp_version : '';
		if ( '' === $version ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Core version not detected', 'shieldscope-site-security-scanner' ),
				__( 'Could not read $wp_version — skipping core integrity verification.', 'shieldscope-site-security-scanner' ),
				'',
				ABSPATH
			);
			return;
		}

		// Stale cache from a previous major-version? Bust it.
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		if ( is_array( $cached ) && isset( $cached['version'] ) && $cached['version'] === $version ) {
			return; // Already have the right ones cached.
		}

		$locale = is_string( $wp_local_package ) && '' !== $wp_local_package ? $wp_local_package : 'en_US';
		$url    = add_query_arg(
			array(
				'version' => rawurlencode( $version ),
				'locale'  => rawurlencode( $locale ),
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get( $url, self::wporg_request_args( 15 ) );

		if ( is_wp_error( $response ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: error message */
					__( 'Could not reach the WordPress.org checksums API: %s', 'shieldscope-site-security-scanner' ),
					$response->get_error_message()
				),
				__( 'Ensure outbound HTTPS to api.wordpress.org is allowed, then re-run the scan.', 'shieldscope-site-security-scanner' ),
				$url
			);
			return;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( 200 !== $code || '' === $body ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %d: HTTP status */
					__( 'WordPress.org returned HTTP %d with no usable checksum data. This usually means the exact WP version / locale combination is not indexed (e.g. nightly builds).', 'shieldscope-site-security-scanner' ),
					$code
				),
				'',
				$url
			);
			return;
		}

		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) || empty( $decoded['checksums'] ) || ! is_array( $decoded['checksums'] ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped', 'shieldscope-site-security-scanner' ),
				__( 'The WordPress.org checksums response was malformed or empty.', 'shieldscope-site-security-scanner' ),
				'',
				$url
			);
			return;
		}

		set_transient(
			self::CHECKSUMS_TRANSIENT,
			array(
				'version'   => $version,
				'locale'    => $locale,
				'checksums' => $decoded['checksums'],
			),
			self::CHECKSUMS_TTL
		);
	}

	/**
	 * Walk the checksums list and MD5-verify each file.
	 *
	 * Cursor:
	 *   keys    — remaining relative paths to verify (array shifted from)
	 *   total   — total count (for info only)
	 *   bad     — running count of mismatches (for a summary finding)
	 *   missing — running count of missing-from-disk files
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function step_verify( array $cursor ) {
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		if ( ! is_array( $cached ) || empty( $cached['checksums'] ) ) {
			// No checksums available (fetch step failed): say so in the coverage (SC2-08).
			$this->note_partial( __( 'core files not verified: WordPress.org checksums unavailable', 'shieldscope-site-security-scanner' ) );
			return array( 'continue' => false, 'cursor' => array() );
		}
		$checksums = $cached['checksums'];

		if ( ! isset( $cursor['keys'] ) ) {
			// Filter out entries we deliberately don't want to police.
			$skip_prefixes = array(
				'wp-content/', // User content — owned by the user, not core.
			);
			$skip_paths = array(
				'wp-config-sample.php',
				'readme.html',
				'license.txt',
			);

			$keys = array();
			foreach ( $checksums as $path => $hash ) {
				if ( ! is_string( $path ) || ! is_string( $hash ) ) {
					continue;
				}
				$skip = false;
				foreach ( $skip_prefixes as $p ) {
					if ( 0 === strpos( $path, $p ) ) {
						$skip = true;
						break;
					}
				}
				if ( $skip || in_array( $path, $skip_paths, true ) ) {
					continue;
				}
				$keys[] = $path;
			}

			$cursor = array(
				'keys'    => $keys,
				'total'   => count( $keys ),
				'bad'     => 0,
				'missing' => 0,
			);
		}

		if ( ! isset( $cursor['bad_list'] ) ) {
			$cursor['bad_list']     = array();
			$cursor['missing_list'] = array();
		}

		$seen = 0;
		while ( ! empty( $cursor['keys'] ) && $seen < self::VERIFY_BATCH ) {
			$path     = array_shift( $cursor['keys'] );
			$expected = isset( $checksums[ $path ] ) ? $checksums[ $path ] : '';
			$full     = ABSPATH . $path;

			if ( ! file_exists( $full ) ) {
				// Buffer rather than emit — findings are flushed once the
				// whole walk is done, so mass differences can be aggregated.
				$cursor['missing']++;
				if ( count( $cursor['missing_list'] ) < self::MAX_DETAILED_FINDINGS ) {
					$cursor['missing_list'][] = $path;
				}
				$seen++;
				continue;
			}

			if ( ! is_readable( $full ) ) {
				$seen++;
				continue;
			}

			$actual = md5_file( $full );
			if ( false !== $actual && $actual !== $expected ) {
				$cursor['bad']++;
				if ( count( $cursor['bad_list'] ) < self::MAX_DETAILED_FINDINGS ) {
					$cursor['bad_list'][] = array(
						'path'     => $path,
						'expected' => $expected,
						'actual'   => $actual,
					);
				}
			}
			$seen++;
		}

		// More files left? Ask the scanner to call us again with the cursor.
		if ( ! empty( $cursor['keys'] ) ) {
			return array( 'continue' => true, 'cursor' => $cursor );
		}

		$this->flush_verify_findings( $cursor );
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Emit findings for the completed verify walk.
	 *
	 * If the mismatch ratio indicates the whole installation differs from
	 * the official build (Playground, hosting-patched distro, version or
	 * locale mismatch), emit ONE medium summary. Otherwise emit per-file
	 * findings, capped, with an overflow summary.
	 *
	 * @param array $cursor Completed cursor.
	 * @return void
	 */
	private function flush_verify_findings( array $cursor ) {
		$total   = isset( $cursor['total'] ) ? (int) $cursor['total'] : 0;
		$bad     = isset( $cursor['bad'] ) ? (int) $cursor['bad'] : 0;
		$missing = isset( $cursor['missing'] ) ? (int) $cursor['missing'] : 0;
		$diff    = $bad + $missing;

		if ( 0 === $diff ) {
			return;
		}

		// Mass mismatch — one summary, not hundreds of HIGH findings.
		if ( $total > 0 && $diff >= self::MASS_MISMATCH_MIN && ( $diff / $total ) > self::MASS_MISMATCH_RATIO ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Core files differ from the official WordPress build en masse', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: differing count, 2: total count */
					__( '%1$d of %2$d core files do not match the official WordPress.org checksums. Differences at this scale almost always mean the installation is a modified distribution (WordPress Playground, a hosting-customised build) or a version/locale mismatch — not individual file tampering. Individual per-file findings have been suppressed.', 'shieldscope-site-security-scanner' ),
					$diff,
					$total
				),
				__( 'If this is a local, staging, or Playground environment, this is expected — re-run the scan on production. On a production site, verify your exact WordPress version and locale, then go to Dashboard → Updates and click "Re-install now" to restore official core files.', 'shieldscope-site-security-scanner' ),
				ABSPATH,
				array(
					'differing' => $diff,
					'total'     => $total,
				)
			);
			return;
		}

		$missing_list = isset( $cursor['missing_list'] ) ? (array) $cursor['missing_list'] : array();
		foreach ( $missing_list as $path ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Missing WordPress core file', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: relative path */
					__( 'The core file %s is listed in the WordPress.org checksums but is not present on disk. It may have been deleted or the installation is incomplete.', 'shieldscope-site-security-scanner' ),
					$path
				),
				__( 'Go to Dashboard → Updates and click "Re-install now" — this re-downloads all core files without touching your content, plugins, or wp-config.php. Alternatively, download the matching WordPress version from wordpress.org/download/releases and upload just the missing file via FTP.', 'shieldscope-site-security-scanner' ),
				$path
			);
		}

		$bad_list = isset( $cursor['bad_list'] ) ? (array) $cursor['bad_list'] : array();
		foreach ( $bad_list as $item ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Modified WordPress core file', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: path, 2: expected hash, 3: actual hash */
					__( 'The core file %1$s does not match the hash published on WordPress.org. Expected %2$s, got %3$s. This is almost always a sign of either a manual edit (don\'t do that) or a compromise.', 'shieldscope-site-security-scanner' ),
					$item['path'],
					$item['expected'],
					$item['actual']
				),
				__( 'Download a clean copy of the same WordPress version from wordpress.org/download/releases and compare the file. If you see injected or obfuscated code, your site is compromised — change all passwords, regenerate auth salts, and go to Dashboard → Updates to click "Re-install now" to restore all core files safely.', 'shieldscope-site-security-scanner' ),
				$item['path'],
				array(
					'expected' => $item['expected'],
					'actual'   => $item['actual'],
				)
			);
		}

		// Overflow beyond the detailed cap.
		$overflow = $diff - count( $missing_list ) - count( $bad_list );
		if ( $overflow > 0 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Additional core file differences (summarised)', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %d: count */
					__( '%d further core files differ from the official checksums but were not individually listed to keep the report readable.', 'shieldscope-site-security-scanner' ),
					$overflow
				),
				__( 'Go to Dashboard → Updates and click "Re-install now" to restore all official core files, then re-run the scan.', 'shieldscope-site-security-scanner' ),
				ABSPATH
			);
		}
	}

	/**
	 * Detect environments where core files legitimately differ from the
	 * official WordPress.org build.
	 *
	 * Signals (any one is sufficient):
	 *  - WordPress Playground / wasm PHP runtime (SERVER_SOFTWARE).
	 *  - SQLite database integration (Playground default; core files patched).
	 *  - The `shieldscope_skip_core_integrity` filter returning true.
	 *
	 * @return string Human-readable reason, or '' when the environment looks standard.
	 */
	protected function detect_nonstandard_environment() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read-only comparison.
		if ( '' !== $server && ( false !== stripos( $server, 'php.wasm' ) || false !== stripos( $server, 'playground' ) ) ) {
			return __( 'WordPress Playground / WebAssembly runtime detected', 'shieldscope-site-security-scanner' );
		}

		// SQLite database integration — used by Playground and Studio; these
		// distributions patch core files, so checksums will not match.
		if ( ( defined( 'DB_ENGINE' ) && 'sqlite' === strtolower( (string) DB_ENGINE ) )
			|| ( defined( 'DATABASE_TYPE' ) && 'sqlite' === strtolower( (string) DATABASE_TYPE ) )
			|| class_exists( 'WP_SQLite_DB', false )
		) {
			return __( 'SQLite database integration detected', 'shieldscope-site-security-scanner' );
		}

		/**
		 * Allow site owners / hosts with intentionally patched core files to
		 * skip checksum verification.
		 *
		 * @param bool $skip Default false.
		 */
		if ( apply_filters( 'shieldscope_skip_core_integrity', false ) ) {
			return __( 'skipped via shieldscope_skip_core_integrity filter', 'shieldscope-site-security-scanner' );
		}

		return '';
	}

	/**
	 * Walk wp-admin / wp-includes looking for suspicious extra files
	 * (files NOT present in the WordPress.org checksums list).
	 *
	 * Uses a two-queue approach so no files are lost when a batch boundary
	 * falls in the middle of a directory:
	 *   - dirs  — directories still to expand (via scandir)
	 *   - files — individual file paths waiting to be checked this batch
	 *
	 * Directories are expanded eagerly into the files queue, so the batch
	 * limit only applies to file processing.  On resume the files queue
	 * carries any leftover entries from the last expanded directory.
	 *
	 * Each call also stops when the time budget is spent (after at least one
	 * unit of work) or after MAX_DIRS_PER_CALL expansions. Symlinked
	 * directories are not followed.
	 *
	 * Cursor (the checksum map stays in its transient, not in the cursor,
	 * because the cursor is saved after every step):
	 *   dirs  — directories still to expand
	 *   files — file paths pending inspection
	 *   seen  — cumulative files examined across all batches
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function step_extras( array $cursor ) {
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		if ( ! is_array( $cached ) || empty( $cached['checksums'] ) ) {
			$this->note_partial( __( 'core folders not checked for unknown files: WordPress.org checksums unavailable', 'shieldscope-site-security-scanner' ) );
			return array( 'continue' => false, 'cursor' => array() );
		}

		if ( ! isset( $cursor['dirs'] ) ) {
			$cursor = array(
				'dirs'  => array_values( array_filter(
					array( ABSPATH . 'wp-admin', ABSPATH . 'wp-includes' ),
					'is_dir'
				) ),
				'files' => array(),
				'seen'  => 0,
			);
		}
		unset( $cursor['known'] ); // Cursors saved by 1.3.2 carried the map.
		$known = $cached['checksums']; // path => md5 map.

		$abs_path = wp_normalize_path( ABSPATH );
		$seen     = 0;
		$expanded = 0;

		while ( $seen < self::EXTRAS_BATCH ) {
			if ( ( $seen > 0 || $expanded > 0 ) && $this->out_of_time() ) {
				break;
			}

			// Drain the file queue before expanding another directory.
			if ( ! empty( $cursor['files'] ) ) {
				$full  = array_shift( $cursor['files'] );
				$entry = basename( $full );
				$rel   = ltrim( str_replace( $abs_path, '', wp_normalize_path( $full ) ), '/' );

				if ( ! isset( $known[ $rel ] ) ) {
					// Only flag code-executing files — images, translations, etc.
					// can legitimately appear in core dirs via plugins.
					if ( preg_match( '/\.(php|phtml|php5|php7|phar|inc)$/i', $entry ) ) {
						$this->finding(
							ShieldScope_Logger::SEVERITY_HIGH,
							__( 'Unknown file inside WordPress core directory', 'shieldscope-site-security-scanner' ),
							sprintf(
								/* translators: %s: relative path */
								__( 'The file %s is inside a core WordPress directory but is not part of the official WordPress.org checksums for this version. This is frequently how backdoors hide.', 'shieldscope-site-security-scanner' ),
								$rel
							),
							__( 'Open the file in a text editor (read-only) and look for eval(), base64_decode() or obfuscated code, which are common in injected code. If you did not put it there, delete it immediately via FTP or File Manager, then go to Dashboard → Updates and click "Re-install now" to verify all core files.', 'shieldscope-site-security-scanner' ),
							$rel
						);
					}
				}
				$seen++;
				continue;
			}

			// File queue empty — expand the next directory.
			if ( empty( $cursor['dirs'] ) || $expanded >= self::MAX_DIRS_PER_CALL ) {
				break;
			}

			$dir     = array_shift( $cursor['dirs'] );
			$expanded++;
			$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $entries ) {
				continue;
			}

			foreach ( $entries as $entry_name ) {
				if ( '.' === $entry_name || '..' === $entry_name ) {
					continue;
				}
				$full = $dir . DIRECTORY_SEPARATOR . $entry_name;
				if ( is_dir( $full ) ) {
					if ( ! is_link( $full ) ) {
						$cursor['dirs'][] = $full;
					}
				} else {
					$cursor['files'][] = $full;
				}
			}
			// Directory expansion does not count against the batch limit.
		}

		$cursor['seen'] = (int) $cursor['seen'] + $seen;

		if ( ! empty( $cursor['dirs'] ) || ! empty( $cursor['files'] ) ) {
			return array( 'continue' => true, 'cursor' => $cursor );
		}

		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Most files read per location in the persistence step.
	 */
	const PERSISTENCE_MAX_FILES = 200;

	/**
	 * Places where injected code often hides and that no other check reads
	 * (S-21): PHP files in the WordPress root that are not core, PHP files
	 * in the wp-content root (drop-ins and others) and must-use plugins.
	 * Every file found is also checked for eval() on decoded data.
	 *
	 * @return void
	 */
	private function step_persistence() {
		$settings = (array) get_option( 'shieldscope_settings', array() );
		$max_size = isset( $settings['max_scan_file_size'] ) ? (int) $settings['max_scan_file_size'] : 2 * MB_IN_BYTES;

		// 1. WordPress root.
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		$known  = is_array( $cached ) && ! empty( $cached['checksums'] ) ? $cached['checksums'] : null;
		if ( null === $known ) {
			$this->note_partial( __( 'WordPress root not checked for unknown PHP files: core checksums unavailable', 'shieldscope-site-security-scanner' ) );
		}
		foreach ( $this->php_files_in( ABSPATH ) as $file ) {
			$name = basename( $file );
			if ( in_array( $name, array( 'wp-config.php', 'wp-config-sample.php' ), true ) ) {
				continue;
			}
			if ( null !== $known && ! isset( $known[ $name ] ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_MEDIUM,
					/* translators: %s: file name */
					sprintf( __( 'Review: unknown PHP file in the WordPress root: %s', 'shieldscope-site-security-scanner' ), $name ),
					__( 'This PHP file sits next to wp-config.php but is not part of WordPress. Some are legitimate (for example wordfence-waf.php from Wordfence, or a host\'s health-check file); a file nobody recognises is a common sign of a compromise, because it can be requested directly from the web.', 'shieldscope-site-security-scanner' ),
					__( 'Find out what added the file. If nobody recognises it, take a backup, remove it, and check the site for other changes.', 'shieldscope-site-security-scanner' ),
					$name
				);
			}
			$this->scan_for_decoded_eval( $file, $max_size );
		}

		// 2. wp-content root: drop-ins and other PHP files.
		$content = defined( 'SHIELDSCOPE_WP_CONTENT_DIR' ) ? SHIELDSCOPE_WP_CONTENT_DIR : WP_CONTENT_DIR;
		if ( ! function_exists( '_get_dropins' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$dropins = function_exists( '_get_dropins' ) ? _get_dropins() : array();
		foreach ( $this->php_files_in( $content ) as $file ) {
			$name = basename( $file );
			if ( 'index.php' === $name ) {
				continue;
			}
			if ( isset( $dropins[ $name ] ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_INFO,
					__( 'Drop-in in use', 'shieldscope-site-security-scanner' ),
					__( 'Drop-ins are files in wp-content that replace parts of WordPress (caching, database, maintenance and error pages). They are usually added by a caching or hosting plugin and do not appear in the Plugins screen.', 'shieldscope-site-security-scanner' ),
					__( 'Confirm each drop-in belongs to a plugin or host you use. Remove drop-ins left behind by plugins you deleted.', 'shieldscope-site-security-scanner' ),
					'wp-content/' . $name,
					array( 'description' => isset( $dropins[ $name ][0] ) ? (string) $dropins[ $name ][0] : '' )
				);
			} else {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					/* translators: %s: file name */
					sprintf( __( 'Review: unknown PHP file in wp-content: %s', 'shieldscope-site-security-scanner' ), $name ),
					__( 'WordPress only expects index.php and known drop-ins directly inside wp-content. Other PHP files there are sometimes left by plugins, and sometimes planted.', 'shieldscope-site-security-scanner' ),
					__( 'Find out what added the file and remove it if it is not needed.', 'shieldscope-site-security-scanner' ),
					'wp-content/' . $name
				);
			}
			$this->scan_for_decoded_eval( $file, $max_size );
		}

		// 3. Must-use plugins (WordPress loads only the top-level PHP files).
		$mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : $content . '/mu-plugins';
		foreach ( $this->php_files_in( $mu ) as $file ) {
			$name = basename( $file );
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'Must-use plugin present', 'shieldscope-site-security-scanner' ),
				__( 'Must-use plugins load on every request and cannot be turned off from the Plugins screen. Hosts and some plugins add them legitimately; attackers use them because they are easy to miss.', 'shieldscope-site-security-scanner' ),
				__( 'Confirm each must-use plugin comes from your host or a plugin you use.', 'shieldscope-site-security-scanner' ),
				'wp-content/mu-plugins/' . $name
			);
			$this->scan_for_decoded_eval( $file, $max_size );
		}
	}

	/**
	 * Top-level PHP files in a directory (sorted, capped).
	 *
	 * @param string $dir Directory.
	 * @return string[] Full paths.
	 */
	private function php_files_in( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$files   = array();
		foreach ( (array) $entries as $entry ) {
			$full = rtrim( $dir, '/\\' ) . DIRECTORY_SEPARATOR . $entry;
			if ( preg_match( '/\.(php|phtml|php5|php7|phar|inc)$/i', $entry ) && is_file( $full ) ) {
				$files[] = $full;
			}
			if ( count( $files ) >= self::PERSISTENCE_MAX_FILES ) {
				$this->note_partial(
					sprintf(
						/* translators: 1: number of files, 2: folder */
						__( 'only the first %1$d PHP files in %2$s were checked', 'shieldscope-site-security-scanner' ),
						self::PERSISTENCE_MAX_FILES,
						basename( rtrim( $dir, '/\\' ) )
					)
				);
				break;
			}
		}
		return $files;
	}

	/**
	 * Report eval() applied to decoded data in one file, with evidence.
	 *
	 * @param string $file     Full path.
	 * @param int    $max_size Size limit in bytes.
	 * @return void
	 */
	private function scan_for_decoded_eval( $file, $max_size ) {
		$contents = $this->read_scannable_file( $file, $max_size );
		if ( ! is_string( $contents ) || '' === $contents ) {
			return;
		}
		list( , $view ) = $this->views( $contents );
		$at   = $this->rx_offset( '/\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)/i', $view );
		if ( $at < 0 ) {
			return;
		}
		$this->finding(
			ShieldScope_Logger::SEVERITY_HIGH,
			__( 'Matches pattern: eval() on encoded data', 'shieldscope-site-security-scanner' ),
			__( 'This file applies eval() to the output of a decode or decompress function (base64_decode, gzinflate, str_rot13 or gzuncompress). Malware often uses this shape, but some legitimate libraries and installers do too. This match has not been confirmed as harmful.', 'shieldscope-site-security-scanner' ),
			__( 'Compare the file with the original plugin or theme source. If it does not belong there, remove it and check the site for other changes.', 'shieldscope-site-security-scanner' ),
			$file,
			self::evidence( $contents, $view, $at )
		);
	}
}
