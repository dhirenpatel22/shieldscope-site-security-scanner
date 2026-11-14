<?php
/**
 * Smoke-run driver, executed inside WordPress Playground by blueprint.json.
 *
 * Named .inc (not .php) so the PHPUnit directory scan of tests/ never loads it.
 *
 * Phases (one Playground request each, so the scan phase loads the plugin the
 * normal way through plugins_loaded):
 *   setup  Seed the profile named in /smoke-out/profile, then activate the plugin.
 *   scan   Start a scan and call the tick work (ShieldScope_Scanner::run_chunk,
 *          what the shieldscope_tick AJAX handler runs) until it reports
 *          `completed` or the time cap runs out.
 *
 * Every phase writes /smoke-out/<phase>.json; run.sh asserts on those files.
 *
 * @package ShieldScope\Tests
 */

const SHIELDSCOPE_SMOKE_OUT    = '/smoke-out';
const SHIELDSCOPE_SMOKE_PLUGIN = 'shieldscope-site-security-scanner/shieldscope-site-security-scanner.php';

/**
 * Run one phase and write its result file.
 *
 * @param string $phase setup|scan.
 * @return void
 */
function shieldscope_smoke( $phase ) {
	$result = array(
		'phase'      => $phase,
		'profile'    => trim( (string) file_get_contents( SHIELDSCOPE_SMOKE_OUT . '/profile' ) ),
		'finished'   => false,
		'notices'    => array(),
		'suppressed' => 0,
	);

	// Collect every notice, warning and deprecation raised in this request.
	// WordPress (WP_DEBUG off) leaves E_WARNING in error_reporting(); the @
	// operator removes it, so a missing E_WARNING bit means "suppressed".
	set_error_handler(
		function ( $errno, $errstr, $errfile, $errline ) use ( &$result ) {
			if ( ! ( error_reporting() & E_WARNING ) ) {
				$result['suppressed']++;
				return true;
			}
			// Playground's generated wp-config.php redefines WP_DEBUG; not plugin code.
			if ( '/wordpress/wp-config.php' === $errfile ) {
				return true;
			}
			$result['notices'][] = sprintf( '[%d] %s in %s:%d', $errno, $errstr, $errfile, $errline );
			return true;
		}
	);

	// A fatal error ends the request before the normal write below; record it.
	register_shutdown_function(
		function () use ( &$result, $phase ) {
			$error = error_get_last();
			if ( ! $result['finished'] && $error ) {
				$result['fatal'] = sprintf( '%s in %s:%d', $error['message'], $error['file'], $error['line'] );
			}
			file_put_contents( SHIELDSCOPE_SMOKE_OUT . '/' . $phase . '.json', json_encode( $result, JSON_PRETTY_PRINT ) );
		}
	);

	require_once '/wordpress/wp-load.php';
	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	require_once ABSPATH . 'wp-admin/includes/user.php';

	if ( 'setup' === $phase ) {
		shieldscope_smoke_seed( $result['profile'] );
		$activated = activate_plugin( SHIELDSCOPE_SMOKE_PLUGIN );
		if ( is_wp_error( $activated ) ) {
			$result['error'] = $activated->get_error_message();
			return;
		}
		$result['active'] = is_plugin_active( SHIELDSCOPE_SMOKE_PLUGIN );
	} else {
		shieldscope_smoke_scan( $result );
	}

	$result['finished'] = true;
}

/**
 * Seed the site for a profile.
 *
 * clean:  one administrator not called "admin", no other plugins.
 * seeded: Playground's default "admin" administrator kept, plus four inactive plugins.
 *
 * @param string $profile Profile name.
 * @return void
 */
function shieldscope_smoke_seed( $profile ) {
	$admin = get_user_by( 'login', 'admin' );

	if ( 'clean' === $profile ) {
		$owner_id = wp_insert_user(
			array(
				'user_login' => 'siteowner',
				'user_pass'  => wp_generate_password( 32 ),
				'user_email' => 'siteowner@example.test',
				'role'       => 'administrator',
			)
		);
		if ( is_wp_error( $owner_id ) ) {
			throw new RuntimeException( $owner_id->get_error_message() );
		}
		if ( $admin ) {
			wp_delete_user( $admin->ID, $owner_id );
		}
		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( SHIELDSCOPE_SMOKE_PLUGIN !== $file ) {
				delete_plugins( array( $file ) );
			}
		}
		return;
	}

	if ( 'seeded' === $profile ) {
		if ( ! $admin ) {
			throw new RuntimeException( 'Expected Playground to create an "admin" user.' );
		}
		foreach ( array( 'old-gallery', 'old-forms', 'old-seo', 'old-cache' ) as $slug ) {
			$dir = WP_PLUGIN_DIR . '/smoke-' . $slug;
			wp_mkdir_p( $dir );
			file_put_contents(
				$dir . '/smoke-' . $slug . '.php',
				"<?php\n/**\n * Plugin Name: Smoke " . $slug . "\n * Version: 0.1.0\n */\n"
			);
		}
		return;
	}

	throw new RuntimeException( 'Unknown profile: ' . $profile );
}

/**
 * Start a scan and tick it to completion within the time cap.
 *
 * @param array $result Result being built (by reference).
 * @return void
 */
function shieldscope_smoke_scan( array &$result ) {
	$cap    = (int) trim( (string) file_get_contents( SHIELDSCOPE_SMOKE_OUT . '/time-cap' ) );
	$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
	wp_set_current_user( $admins[0]->ID );

	$scanner = new ShieldScope_Scanner();
	$started = microtime( true );
	$state   = $scanner->start();
	$ticks   = 0;

	while ( ShieldScope_Scanner::STATUS_RUNNING === $state['status'] && ( microtime( true ) - $started ) < $cap ) {
		$state = $scanner->run_chunk( false );
		$ticks++;
	}

	$logger            = new ShieldScope_Logger();
	$result['status']  = $state['status'];
	$result['elapsed'] = round( microtime( true ) - $started, 1 );
	$result['ticks']   = $ticks;
	$result['php']     = PHP_VERSION;
	$result['wp']      = get_bloginfo( 'version' );
	$result['steps']   = $state['done_steps'] . '/' . $state['total_steps'];
	$result['summary'] = $logger->get_summary( $state['scan_id'] );
}
