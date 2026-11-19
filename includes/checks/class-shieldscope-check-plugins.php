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
	public function get_steps() {
		return array( 'updates', 'inactive', 'unknown_source', 'abandoned' );
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
}
