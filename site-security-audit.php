<?php
/**
 * Plugin Name:       Site Security Audit
 * Plugin URI:        https://github.com/dhirenpatel22/site-security-audit
 * Description:       Comprehensive background security scanner for WordPress core, themes, plugins, filesystem, database, users and code patterns. CPU-throttled and non-blocking.
 * Version:           1.2.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Dhiren Patel
 * Author URI:        https://www.dhirenpatel.me/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       site-security-audit
 * Domain Path:       /languages
 *
 * @package Site_Security_Audit
 */

// Abort if accessed directly — standard WPCS direct-access guard.
defined( 'ABSPATH' ) || exit;

// Bail silently if a second copy of this plugin is loaded (e.g. site-security-audit-main).
// Checking SSA_VERSION is sufficient because it is the first thing we define below.
if ( defined( 'SSA_VERSION' ) ) {
	return;
}

// Plugin constants.
define( 'SSA_VERSION', '1.2.0' );
define( 'SSA_PLUGIN_FILE', __FILE__ );
define( 'SSA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SSA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SSA_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'SSA_MIN_CAP', 'manage_options' );
define( 'SSA_SLUG', 'site-security-audit' );

/**
 * PSR-4-style lightweight autoloader for SSA_* classes.
 *
 * Maps class names like SSA_Check_Core to includes/checks/class-ssa-check-core.php
 * or SSA_Scanner to includes/class-ssa-scanner.php.
 *
 * @param string $class_name Fully-qualified class name.
 * @return void
 */
if ( ! function_exists( 'ssa_autoload' ) ) {
	function ssa_autoload( $class_name ) {
		if ( strpos( $class_name, 'SSA_' ) !== 0 ) {
			return;
		}

		$file_name = 'class-' . strtolower( str_replace( '_', '-', $class_name ) ) . '.php';

		$candidates = array(
			SSA_PLUGIN_DIR . 'includes/checks/' . $file_name,
			SSA_PLUGIN_DIR . 'includes/' . $file_name,
		);

		foreach ( $candidates as $candidate ) {
			if ( file_exists( $candidate ) ) {
				require_once $candidate;
				return;
			}
		}
	}
	spl_autoload_register( 'ssa_autoload' );
}

// Activation, deactivation, uninstall hooks.
register_activation_hook( __FILE__, array( 'SSA_Core', 'on_activate' ) );
register_deactivation_hook( __FILE__, array( 'SSA_Core', 'on_deactivate' ) );

/**
 * Boot the plugin once WordPress is ready.
 *
 * @return void
 */
function ssa_bootstrap() {
	load_plugin_textdomain(
		'site-security-audit',
		false,
		dirname( SSA_PLUGIN_BASENAME ) . '/languages'
	);

	SSA_Core::instance()->init();
}
add_action( 'plugins_loaded', 'ssa_bootstrap' );
