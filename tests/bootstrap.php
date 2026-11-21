<?php
/**
 * PHPUnit bootstrap for ShieldScope standalone unit tests.
 *
 * Creates a throwaway fake WordPress root under the system temp dir, defines
 * the constants the plugin expects, loads WP function stubs, and registers an
 * autoloader for the plugin's classes.
 *
 * These are pure unit tests — no database, no network, no real WordPress.
 * For full integration testing use wp-env / the WP core test suite.
 *
 * @package ShieldScope\Tests
 */

error_reporting( E_ALL );

// ---------------------------------------------------------------------------
// Fake WordPress root (ABSPATH) in the temp dir
// ---------------------------------------------------------------------------

// Unique per run, so parallel runs (other worktrees, CI matrix) never share it.
define( 'SS_TESTS_WP_ROOT', sys_get_temp_dir() . '/shieldscope-tests-wproot-' . getmypid() . '-' . bin2hex( random_bytes( 4 ) ) );

/**
 * Recursively delete a directory.
 *
 * @param string $dir Directory path.
 */
function ss_tests_rmdir( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}
	$items = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $items as $item ) {
		( $item->isDir() && ! $item->isLink() ) ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
	}
	rmdir( $dir );
}

/**
 * Wipe and recreate the fake WP root. Call from setUp().
 */
function ss_tests_reset_wp_root() {
	ss_tests_rmdir( SS_TESTS_WP_ROOT );
	mkdir( SS_TESTS_WP_ROOT, 0777, true );
}

ss_tests_reset_wp_root();
register_shutdown_function( 'ss_tests_rmdir', SS_TESTS_WP_ROOT );

// ---------------------------------------------------------------------------
// Constants the plugin expects (normally defined by WP / the plugin bootstrap)
// ---------------------------------------------------------------------------

define( 'ABSPATH', SS_TESTS_WP_ROOT . '/' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'YEAR_IN_SECONDS', 31536000 );
define( 'MB_IN_BYTES', 1048576 );

$ss_plugin_root = dirname( __DIR__ );
define( 'SHIELDSCOPE_VERSION', '2.1.0' );
define( 'SHIELDSCOPE_PLUGIN_DIR', $ss_plugin_root . '/' );
define( 'SHIELDSCOPE_PLUGIN_FILE', $ss_plugin_root . '/shieldscope-site-security-scanner.php' );
define( 'SHIELDSCOPE_WP_CONTENT_DIR', SS_TESTS_WP_ROOT . '/wp-content' );
define( 'SHIELDSCOPE_WP_PLUGINS_DIR', SS_TESTS_WP_ROOT . '/wp-content/plugins' );
define( 'SHIELDSCOPE_MIN_CAP', 'manage_options' );
define( 'SHIELDSCOPE_SLUG', 'shieldscope' );

// ---------------------------------------------------------------------------
// WP stubs + plugin autoloader
// ---------------------------------------------------------------------------

require_once __DIR__ . '/wp-stubs.php';

spl_autoload_register(
	function ( $class_name ) use ( $ss_plugin_root ) {
		if ( 0 !== strpos( $class_name, 'ShieldScope_' ) ) {
			return;
		}
		$without_prefix = substr( $class_name, strlen( 'ShieldScope_' ) );
		$file_name      = 'class-shieldscope-' . strtolower( str_replace( '_', '-', $without_prefix ) ) . '.php';
		foreach ( array( "$ss_plugin_root/includes/checks/$file_name", "$ss_plugin_root/includes/$file_name" ) as $candidate ) {
			if ( file_exists( $candidate ) ) {
				require_once $candidate;
				return;
			}
		}
	}
);

require_once __DIR__ . '/class-ss-fake-logger.php';
