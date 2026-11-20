<?php
/**
 * Plugin-level security checks.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Plugins
 */
class ShieldScope_Check_Plugins extends ShieldScope_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'plugins';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Plugins', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	/**
	 * Steps a quick scan skips.
	 *
	 * @return string[]
	 */
	public function get_slow_steps() {
		return array( 'abandoned', 'checksums' );
	}

	public function get_steps() {
		return array( 'updates', 'inactive', 'unknown_source', 'abandoned', 'checksums' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		switch ( $step ) {
			case 'updates':
				$this->check_updates();
				break;
			case 'inactive':
				$this->check_inactive();
				break;
			case 'unknown_source':
				$this->check_unknown_source();
				break;
			case 'abandoned':
				return $this->check_abandoned( $cursor );
			case 'checksums':
				return $this->check_checksums( $cursor );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Pending plugin updates.
	 *
	 * @return void
	 */
	private function check_updates() {
		$updates = get_site_transient( 'update_plugins' );
		if ( ! $updates || empty( $updates->response ) ) {
			return;
		}
		foreach ( $updates->response as $plugin_file => $info ) {
			$data = get_plugin_data( SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $plugin_file, false, false );
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Plugin update available', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: name, 2: current, 3: new */
					__( 'Plugin "%1$s" is at version %2$s; %3$s is available. Outdated plugins are the single most common WordPress compromise vector.', 'shieldscope-site-security-scanner' ),
					$data['Name'],
					$data['Version'],
					isset( $info->new_version ) ? $info->new_version : 'latest'
				),
				__( 'Go to Dashboard → Updates and update this plugin. Check the changelog for the word "security" to understand what\'s fixed. Outdated plugins are the leading cause of WordPress compromises — do not delay security updates.', 'shieldscope-site-security-scanner' ),
				'plugin:' . $plugin_file,
				array( 'plugin_name' => $data['Name'] )
			);
		}
	}

	/**
	 * Inactive plugins still present.
	 *
	 * @return void
	 */
	private function check_inactive() {
		$all    = get_plugins();
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		foreach ( $all as $file => $data ) {
			if ( ! in_array( $file, $active, true ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					__( 'Inactive plugin present on disk', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: %s: name */
						__( 'Plugin "%s" is installed but not active. Its code is still on disk and could be exploited if it has a vulnerability.', 'shieldscope-site-security-scanner' ),
						$data['Name']
					),
					__( 'Go to Plugins → Installed Plugins and click Delete — not just Deactivate. Inactive plugins leave code on disk that can still be exploited if they contain vulnerabilities. Only keep plugins you actively use.', 'shieldscope-site-security-scanner' ),
					'plugin:' . $file,
					array( 'plugin_name' => $data['Name'] )
				);
			}
		}
	}

	/**
	 * Plugins without a WordPress.org URI (heuristic: possibly nulled/unknown).
	 *
	 * @return void
	 */
	private function check_unknown_source() {
		$plugins = get_plugins();
		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug || '' === $slug ) {
				continue; // Single-file plugins.
			}
			if ( empty( $data['PluginURI'] ) && empty( $data['UpdateURI'] ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					__( 'Plugin has no update source declared', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: %s: name */
						__( 'Plugin "%s" declares neither a PluginURI nor an UpdateURI. If this is not a custom plugin, verify it came from a trusted source.', 'shieldscope-site-security-scanner' ),
						$data['Name']
					),
					__( 'Search wordpress.org/plugins to verify this plugin is legitimate. If it\'s a custom-built plugin, this warning can be ignored. If it came from a "free premium plugin" site, treat it as a possibly nulled (pirated) copy, which often carries injected code, and delete it — replace with the official version from the original developer.', 'shieldscope-site-security-scanner' ),
					'plugin:' . $file,
					array( 'plugin_name' => $data['Name'] )
				);
			}
		}
	}

	/**
	 * WordPress.org plugin information endpoint.
	 */
	const WPORG_API = 'https://api.wordpress.org/plugins/info/1.2/';

	/**
	 * How long a WordPress.org lookup is cached.
	 */
	const WPORG_CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * Closed and long-unmaintained plugins, from WordPress.org (B-10, S-20).
	 *
	 * For each installed plugin in a folder, asks the WordPress.org plugin
	 * directory (sending only the folder name) whether it is listed, closed,
	 * and when it was last updated. WordPress itself shows a closed plugin as
	 * up to date, so this is the only place the closure is visible. Plugins
	 * that are not listed (custom or commercial) are skipped. Resumable:
	 * the cursor holds the position and counts.
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function check_abandoned( array $cursor = array() ) {
		$plugins = array();
		foreach ( (array) get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' !== $slug && '' !== $slug ) {
				$plugins[] = array( $file, $slug, $data );
			}
		}
		$cursor += array(
			'i'      => 0,
			'failed' => 0,
		);

		$done = 0;
		while ( $cursor['i'] < count( $plugins ) ) {
			if ( $done > 0 && $this->out_of_time() ) {
				return array( 'continue' => true, 'cursor' => $cursor );
			}
			list( $file, $slug, $data ) = $plugins[ $cursor['i'] ];
			++$cursor['i'];
			++$done;

			$info = $this->wporg_info( $slug );
			if ( null === $info ) {
				++$cursor['failed'];
				continue;
			}
			$this->report_wporg_status( $file, $data, $info );
		}

		if ( $cursor['failed'] > 0 ) {
			$this->note_partial(
				sprintf(
					/* translators: %d: number of plugins */
					__( '%d plugin(s) could not be looked up on WordPress.org', 'shieldscope-site-security-scanner' ),
					$cursor['failed']
				)
			);
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Findings for one plugin from its WordPress.org information.
	 *
	 * @param string $file Plugin file.
	 * @param array  $data Plugin header data.
	 * @param array  $info Decoded API response.
	 * @return void
	 */
	private function report_wporg_status( $file, array $data, array $info ) {
		$name = isset( $data['Name'] ) ? $data['Name'] : $file;
		$ctx  = array( 'plugin_name' => $name );

		if ( ! empty( $info['closed'] ) || ( isset( $info['error'] ) && 'closed' === $info['error'] ) ) {
			$security = isset( $info['reason'] ) && 'security-issue' === $info['reason'];
			$reason   = isset( $info['reason_text'] ) ? (string) $info['reason_text'] : __( 'not given', 'shieldscope-site-security-scanner' );
			$date     = isset( $info['closed_date'] ) ? (string) $info['closed_date'] : __( 'unknown date', 'shieldscope-site-security-scanner' );
			$this->finding(
				$security ? ShieldScope_Logger::SEVERITY_HIGH : ShieldScope_Logger::SEVERITY_MEDIUM,
				/* translators: %s: plugin name */
				sprintf( __( 'Plugin closed on WordPress.org: %s', 'shieldscope-site-security-scanner' ), $name ),
				sprintf(
					/* translators: 1: plugin name, 2: date, 3: reason */
					__( 'WordPress.org closed "%1$s" on %2$s (reason: %3$s). A closed plugin gets no updates, and WordPress still shows it as up to date. A closure for a security issue usually means a known, unfixed vulnerability.', 'shieldscope-site-security-scanner' ),
					$name,
					$date,
					$reason
				),
				__( 'Replace the plugin with a maintained alternative and delete it. If you must keep it for now, check the plugin\'s page and support forum on WordPress.org for the reason and any fix.', 'shieldscope-site-security-scanner' ),
				'plugin:' . $file,
				$ctx + array(
					'closed_date' => $date,
					'reason'      => isset( $info['reason'] ) ? (string) $info['reason'] : '',
				)
			);
			return;
		}

		if ( empty( $info['last_updated'] ) ) {
			return; // Not listed on WordPress.org (custom or commercial plugin).
		}
		$updated = strtotime( (string) $info['last_updated'] );
		if ( $updated && ( time() - $updated ) > 2 * YEAR_IN_SECONDS ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				/* translators: %s: plugin name */
				sprintf( __( 'Plugin not updated on WordPress.org for over 2 years: %s', 'shieldscope-site-security-scanner' ), $name ),
				sprintf(
					/* translators: 1: plugin name, 2: date */
					__( 'The last release of "%1$s" on WordPress.org was on %2$s. Plugins without updates do not get fixes for newly found vulnerabilities and may break with new WordPress or PHP versions.', 'shieldscope-site-security-scanner' ),
					$name,
					gmdate( 'Y-m-d', $updated )
				),
				__( 'Check the plugin\'s support forum for signs of maintenance and look for a maintained alternative. If you keep it, review it whenever WordPress or PHP is updated.', 'shieldscope-site-security-scanner' ),
				'plugin:' . $file,
				$ctx + array( 'last_updated' => gmdate( 'Y-m-d', $updated ) )
			);
		}
	}

	/**
	 * WordPress.org plugin information for a slug, cached. Null when the
	 * lookup failed (the result is not cached then).
	 *
	 * @param string $slug Plugin folder name.
	 * @return array|null
	 */
	private function wporg_info( $slug ) {
		$key    = 'shieldscope_wporg_' . md5( $slug );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$url      = add_query_arg(
			array(
				'action'  => 'plugin_information',
				'request' => array(
					'slug'   => $slug,
					'fields' => array(
						'sections'     => 0,
						'description'  => 0,
						'screenshots'  => 0,
						'banners'      => 0,
						'icons'        => 0,
						'contributors' => 0,
						'ratings'      => 0,
						'versions'     => 0,
						'tags'         => 0,
					),
				),
			),
			self::WPORG_API
		);
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			// 404 is "not listed": the API answers {"error":"Plugin not found."}.
			if ( ! is_wp_error( $response ) && 404 === (int) wp_remote_retrieve_response_code( $response ) ) {
				$info = json_decode( (string) wp_remote_retrieve_body( $response ), true );
				if ( is_array( $info ) && isset( $info['error'] ) ) {
					set_transient( $key, $info, self::WPORG_CACHE_TTL );
					return $info;
				}
			}
			return null;
		}
		$info = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $info ) ) {
			return null;
		}
		$keep = array_intersect_key( $info, array_flip( array( 'slug', 'version', 'last_updated', 'error', 'closed', 'closed_date', 'reason', 'reason_text' ) ) );
		set_transient( $key, $keep, self::WPORG_CACHE_TTL );
		return $keep;
	}

	/**
	 * WordPress.org plugin checksums endpoint (slug, version).
	 */
	const CHECKSUMS_URL = 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json';

	/**
	 * Files hashed per call before the time budget is checked.
	 */
	const CHECKSUM_BATCH = 200;

	/**
	 * Compare plugin files with the WordPress.org checksums for the
	 * installed version (S-22). Only plugins listed on WordPress.org can
	 * be verified; the rest are counted in a coverage note.
	 *
	 * Cursor: i (plugin index), offset (position in its checksum list),
	 * modified (relative paths found so far for this plugin), and counts.
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function check_checksums( array $cursor = array() ) {
		$plugins = array();
		foreach ( (array) get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' !== $slug && '' !== $slug && ! empty( $data['Version'] ) ) {
				$plugins[] = array( $file, $slug, $data );
			}
		}
		$cursor += array(
			'i'          => 0,
			'offset'     => 0,
			'modified'   => array(),
			'unverified' => 0,
			'verified'   => 0,
		);

		while ( $cursor['i'] < count( $plugins ) ) {
			list( $file, $slug, $data ) = $plugins[ $cursor['i'] ];

			$info = $this->wporg_info( $slug );
			$sums = ( is_array( $info ) && ! empty( $info['last_updated'] ) ) ? $this->plugin_checksums( $slug, $data['Version'] ) : null;
			if ( null === $sums ) {
				++$cursor['unverified'];
				$cursor = array_merge( $cursor, array( 'i' => $cursor['i'] + 1, 'offset' => 0, 'modified' => array() ) );
				continue;
			}

			$dir   = SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $slug;
			$paths = array_keys( $sums );
			sort( $paths );
			$done = 0;
			while ( $cursor['offset'] < count( $paths ) ) {
				if ( $done >= self::CHECKSUM_BATCH && $this->out_of_time() ) {
					return array( 'continue' => true, 'cursor' => $cursor );
				}
				$rel  = $paths[ $cursor['offset'] ];
				$full = $dir . '/' . $rel;
				++$cursor['offset'];
				++$done;
				if ( ! is_file( $full ) ) {
					continue; // Missing files are not a security concern.
				}
				$expected = (array) ( isset( $sums[ $rel ]['sha256'] ) ? $sums[ $rel ]['sha256'] : array() );
				$actual   = hash_file( 'sha256', $full );
				if ( $expected && ! in_array( $actual, $expected, true ) ) {
					$cursor['modified'][] = $rel;
				}
			}

			$this->report_plugin_checksums( $file, $slug, $data, $paths, $cursor['modified'], $dir );
			++$cursor['verified'];
			$cursor = array_merge( $cursor, array( 'i' => $cursor['i'] + 1, 'offset' => 0, 'modified' => array() ) );
			if ( $this->out_of_time() && $cursor['i'] < count( $plugins ) ) {
				return array( 'continue' => true, 'cursor' => $cursor );
			}
		}

		if ( $cursor['unverified'] > 0 ) {
			$this->note_partial(
				sprintf(
					/* translators: %d: number of plugins */
					__( '%d plugin(s) not verified against WordPress.org checksums (not listed there, or no checksums for the installed version)', 'shieldscope-site-security-scanner' ),
					$cursor['unverified']
				)
			);
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Findings for one verified plugin.
	 *
	 * @param string   $file     Plugin file.
	 * @param string   $slug     Folder.
	 * @param array    $data     Header data.
	 * @param string[] $paths    Files in the official release.
	 * @param string[] $modified Files that differ.
	 * @param string   $dir      Plugin directory.
	 * @return void
	 */
	private function report_plugin_checksums( $file, $slug, array $data, array $paths, array $modified, $dir ) {
		$name = isset( $data['Name'] ) ? $data['Name'] : $slug;
		$ctx  = array( 'plugin_name' => $name );

		// Many differences: probably not the official release, report once.
		if ( count( $modified ) > max( 10, (int) ( 0.25 * count( $paths ) ) ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				/* translators: %s: plugin name */
				sprintf( __( 'Most files of %s differ from WordPress.org', 'shieldscope-site-security-scanner' ), $name ),
				sprintf(
					/* translators: 1: number of files, 2: plugin version */
					__( '%1$d files differ from the WordPress.org release of version %2$s. The installed copy is probably not the official release (a different build or a modified copy), so individual files were not listed.', 'shieldscope-site-security-scanner' ),
					count( $modified ),
					$data['Version']
				),
				__( 'Reinstall the plugin from WordPress.org (Plugins → deactivate, delete, reinstall), or confirm where this copy came from.', 'shieldscope-site-security-scanner' ),
				'plugin:' . $file,
				$ctx
			);
			$modified = array();
		}

		foreach ( $modified as $rel ) {
			$php = (bool) preg_match( '/\.(php|phtml|phar|inc)$/i', $rel );
			$this->finding(
				$php ? ShieldScope_Logger::SEVERITY_HIGH : ShieldScope_Logger::SEVERITY_LOW,
				/* translators: %s: plugin name */
				sprintf( __( 'Plugin file differs from the WordPress.org release: %s', 'shieldscope-site-security-scanner' ), $name ),
				$php
					? __( 'This PHP file is not identical to the same file in the official release of the installed version. Someone changed it after installation: a local edit, or injected code.', 'shieldscope-site-security-scanner' )
					: __( 'This file is not identical to the same file in the official release of the installed version.', 'shieldscope-site-security-scanner' ),
				__( 'Compare the file with the official release. If nobody on your team edited it, reinstall the plugin from WordPress.org and check the site for other changes.', 'shieldscope-site-security-scanner' ),
				SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $slug . '/' . $rel,
				$ctx
			);
		}

		// PHP files that are not part of the release.
		$known = array_flip( $paths );
		foreach ( self::php_files_under( $dir ) as $rel ) {
			if ( ! isset( $known[ $rel ] ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_MEDIUM,
					/* translators: %s: plugin name */
					sprintf( __( 'Review: PHP file not in the WordPress.org release: %s', 'shieldscope-site-security-scanner' ), $name ),
					__( 'This PHP file is inside the plugin folder but is not part of the official release of the installed version. Some plugins write cache or configuration files; a file nobody recognises can be a planted backdoor.', 'shieldscope-site-security-scanner' ),
					__( 'Find out what created the file. If it is not needed, remove it, or reinstall the plugin from WordPress.org.', 'shieldscope-site-security-scanner' ),
					SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $slug . '/' . $rel,
					$ctx
				);
			}
		}
	}

	/**
	 * PHP files under a directory, relative paths (symlinks not followed, capped).
	 *
	 * @param string $dir Directory.
	 * @return string[]
	 */
	private static function php_files_under( $dir ) {
		$out   = array();
		$stack = array( '' );
		while ( $stack && count( $out ) < 20000 ) {
			$rel     = array_pop( $stack );
			$entries = @scandir( $dir . ( '' === $rel ? '' : '/' . $rel ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			foreach ( (array) $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$child = '' === $rel ? $entry : $rel . '/' . $entry;
				$full  = $dir . '/' . $child;
				if ( is_dir( $full ) ) {
					if ( ! is_link( $full ) ) {
						$stack[] = $child;
					}
				} elseif ( preg_match( '/\.(php|phtml|phar)$/i', $entry ) ) {
					$out[] = $child;
				}
			}
		}
		return $out;
	}

	/**
	 * Checksums for a plugin version, cached for a day. Null when not available.
	 *
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @return array|null relative path => { md5, sha256 }.
	 */
	private function plugin_checksums( $slug, $version ) {
		$key    = 'shieldscope_psum_' . md5( $slug . '|' . $version );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return empty( $cached ) ? null : $cached;
		}
		$response = wp_remote_get( sprintf( self::CHECKSUMS_URL, rawurlencode( $slug ), rawurlencode( $version ) ), array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			set_transient( $key, array(), DAY_IN_SECONDS ); // No checksums for this version.
			return null;
		}
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || ! is_array( $body ) || empty( $body['files'] ) || ! is_array( $body['files'] ) ) {
			return null;
		}
		$files = array();
		foreach ( $body['files'] as $rel => $hashes ) {
			if ( isset( $hashes['sha256'] ) ) {
				$files[ (string) $rel ] = array( 'sha256' => $hashes['sha256'] );
			}
		}
		set_transient( $key, $files, DAY_IN_SECONDS );
		return $files;
	}
}
