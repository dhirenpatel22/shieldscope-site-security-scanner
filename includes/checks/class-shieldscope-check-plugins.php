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
				$this->check_abandoned();
				break;
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
					__( 'Search wordpress.org/plugins to verify this plugin is legitimate. If it\'s a custom-built plugin, this warning can be ignored. If it came from a "free premium plugin" site, treat it as potentially nulled (pirated software with malware injected) and delete it — replace with the official version from the original developer.', 'shieldscope-site-security-scanner' ),
					'plugin:' . $file,
					array( 'plugin_name' => $data['Name'] )
				);
			}
		}
	}

	/**
	 * Plugins that have not been updated in a long time (abandoned heuristic).
	 *
	 * @return void
	 */
	private function check_abandoned() {
		$plugins = get_plugins();
		foreach ( $plugins as $file => $data ) {
			$full_path = SHIELDSCOPE_WP_PLUGINS_DIR . '/' . $file;
			if ( ! file_exists( $full_path ) ) {
				continue;
			}
			$mtime = filemtime( $full_path );
			if ( $mtime && ( time() - $mtime ) > ( 2 * YEAR_IN_SECONDS ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_MEDIUM,
					__( 'Plugin appears abandoned', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: 1: name, 2: date */
						__( 'Plugin "%1$s" has not been updated on disk since %2$s. Unmaintained plugins accumulate unfixed vulnerabilities.', 'shieldscope-site-security-scanner' ),
						$data['Name'],
						gmdate( 'Y-m-d', $mtime )
					),
					__( 'Check wordpress.org/plugins for this plugin — if it shows "not tested with the latest 3 major releases" it is likely abandoned. Consider replacing it with a maintained alternative. If you need to keep it, contact the plugin developer via the wordpress.org support forum to ask about continued maintenance.', 'shieldscope-site-security-scanner' ),
					'plugin:' . $file,
					array( 'plugin_name' => $data['Name'] )
				);
			}
		}
	}
}
