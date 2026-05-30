<?php
/**
 * Plugin Name:       ShieldScope – Site Security Scanner
 * Plugin URI:        https://github.com/dhirenpatel22/shieldscope-site-security-scanner
 * Description:       Comprehensive background security scanner for WordPress core, themes, plugins, filesystem, database, users and code patterns. CPU-throttled and non-blocking.
 * Version:           1.3.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Dhiren Patel
 * Author URI:        https://profiles.wordpress.org/dhirenpatel22/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       shieldscope-site-security-scanner
 * Domain Path:       /languages
 *
 * @package ShieldScope
 */

// Abort if accessed directly — standard WPCS direct-access guard.
defined( 'ABSPATH' ) || exit;

// Bail silently if a second copy of this plugin is loaded (e.g. shieldscope-main).
// Checking SHIELDSCOPE_VERSION is sufficient because it is the first thing we define below.
if ( defined( 'SHIELDSCOPE_VERSION' ) ) {
	return;
}

// Plugin constants.
define( 'SHIELDSCOPE_VERSION', '1.3.0' );
define( 'SHIELDSCOPE_PLUGIN_FILE', __FILE__ );
define( 'SHIELDSCOPE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SHIELDSCOPE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SHIELDSCOPE_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'SHIELDSCOPE_MIN_CAP', 'manage_options' );
define( 'SHIELDSCOPE_SLUG', 'shieldscope' );

/**
 * PSR-4-style lightweight autoloader for ShieldScope_* classes.
 *
 * Maps class names like ShieldScope_Check_Core to includes/checks/class-shieldscope-check-core.php
 * or ShieldScope_Scanner to includes/class-shieldscope-scanner.php.
 *
 * @param string $class_name Fully-qualified class name.
 * @return void
 */
if ( ! function_exists( 'shieldscope_autoload' ) ) {
	function shieldscope_autoload( $class_name ) {
		if ( strpos( $class_name, 'ShieldScope_' ) !== 0 ) {
			return;
		}

		// Strip the 'ShieldScope_' prefix and rebuild filename.
		// e.g. ShieldScope_Check_Core  → class-shieldscope-check-core.php
		$without_prefix = substr( $class_name, strlen( 'ShieldScope_' ) );
		$file_name      = 'class-shieldscope-' . strtolower( str_replace( '_', '-', $without_prefix ) ) . '.php';

		$candidates = array(
			SHIELDSCOPE_PLUGIN_DIR . 'includes/checks/' . $file_name,
			SHIELDSCOPE_PLUGIN_DIR . 'includes/' . $file_name,
		);

		foreach ( $candidates as $candidate ) {
			if ( file_exists( $candidate ) ) {
				require_once $candidate;
				return;
			}
		}
	}
	spl_autoload_register( 'shieldscope_autoload' );
}

// Activation, deactivation, uninstall hooks.
register_activation_hook( __FILE__, array( 'ShieldScope_Core', 'on_activate' ) );
register_deactivation_hook( __FILE__, array( 'ShieldScope_Core', 'on_deactivate' ) );

/**
 * Boot the plugin once WordPress is ready.
 *
 * @return void
 */
function shieldscope_bootstrap() {
	// Text domain is loaded automatically by WordPress when the plugin is hosted
	// on wordpress.org — no manual load_plugin_textdomain() call needed (WP 4.6+).
	ShieldScope_Core::instance()->init();
}
add_action( 'plugins_loaded', 'shieldscope_bootstrap' );
