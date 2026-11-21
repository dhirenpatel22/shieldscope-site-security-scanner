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
	$coverage          = ShieldScope_Coverage::get( $state['scan_id'] );
	$result['coverage'] = null === $coverage ? null : ShieldScope_Coverage::summary( $coverage );
	$result['coverage_checks'] = null === $coverage ? 0 : count( $coverage );

	// PDF export of the finished scan (S-06), on the real WordPress and PHP.
	$result['pdf_unavailable'] = ShieldScope_PDF_Report::unavailable_reason();
	if ( '' === $result['pdf_unavailable'] && ShieldScope_Scanner::STATUS_COMPLETED === $state['status'] ) {
		$pdf_started          = microtime( true );
		$report               = ShieldScope_PDF_Report::collect_report();
		$pdf                  = ShieldScope_PDF_Report::render_pdf( ShieldScope_PDF_Report::build_html( $report ), $report );
		$result['pdf_bytes']  = strlen( $pdf );
		$result['pdf_ok']     = 0 === strpos( $pdf, '%PDF-' );
		$result['pdf_secs']   = round( microtime( true ) - $pdf_started, 1 );
		$result['pdf_groups'] = count( $report['findings'] );
		file_put_contents( SHIELDSCOPE_SMOKE_OUT . '/report.pdf', $pdf );
	}

	// Background scan (S-10): start a second scan and run only the queued
	// WP-Cron events, as WordPress would with the scan page closed.
	$bg_started = microtime( true );
	$bg_state   = $scanner->start();
	$bg_runs    = 0;
	$hook       = 'shieldscope_run_scan_chunk';
	while ( ShieldScope_Scanner::STATUS_RUNNING === $bg_state['status'] && ( microtime( true ) - $bg_started ) < $cap ) {
		$ts = wp_next_scheduled( $hook );
		if ( false === $ts ) {
			$result['bg_error'] = 'no cron event queued while the scan was running';
			break;
		}
		wp_unschedule_event( $ts, $hook );
		do_action( $hook );
		++$bg_runs;
		wp_cache_delete( 'shieldscope_scan_state', 'options' );
		$bg_state = $scanner->get_state();
	}
	$result['bg_status']  = $bg_state['status'];
	$result['bg_runs']    = $bg_runs;
	$result['bg_elapsed'] = round( microtime( true ) - $bg_started, 1 );

	// Quick scan (S-11).
	$q_started         = microtime( true );
	$q_state           = $scanner->start( true );
	while ( ShieldScope_Scanner::STATUS_RUNNING === $q_state['status'] && ( microtime( true ) - $q_started ) < $cap ) {
		$q_state = $scanner->run_chunk( false );
	}
	$q_cov             = ShieldScope_Coverage::get( $q_state['scan_id'] );
	$result['quick']   = array(
		'status'  => $q_state['status'],
		'secs'    => round( microtime( true ) - $q_started, 1 ),
		'skipped' => null === $q_cov ? 0 : substr_count( wp_json_encode( $q_cov ), 'skipped in a quick scan' ),
	);

	// History and comparison (S-08): the background scan follows the first one.
	$result['history'] = count( ShieldScope_History::all() );
	$cmp               = ShieldScope_History::compare_with_previous( $q_state['scan_id'], $logger->get_findings( $q_state['scan_id'] ) );
	$result['compare'] = null === $cmp ? null : array( 'new' => count( $cmp['new'] ), 'fixed' => count( $cmp['fixed'] ), 'open' => $cmp['open'] );

	// SC2-02: start in the tab, then the tab closes while a cron chunk finds
	// the lock busy; WP-Cron alone must finish the scan.
	$tc_state = $scanner->start();
	$tc_state = $scanner->run_chunk( false );
	$tc_state = $scanner->run_chunk( false );
	global $wpdb;
	$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} ( option_name, option_value, autoload ) VALUES ( %s, %s, 'no' ) ON DUPLICATE KEY UPDATE option_value = VALUES( option_value )", ShieldScope_Scanner::LOCK_OPTION, time() . ':tab' ) );
	$ts = wp_next_scheduled( $hook );
	if ( false !== $ts ) {
		wp_unschedule_event( $ts, $hook );
		do_action( $hook ); // Busy: the tab holds the lock.
	}
	$result['tc_queued_after_busy'] = false !== wp_next_scheduled( $hook );
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", ShieldScope_Scanner::LOCK_OPTION ) );
	$tc_started = microtime( true );
	$tc_runs    = 0;
	while ( ShieldScope_Scanner::STATUS_RUNNING === $tc_state['status'] && ( microtime( true ) - $tc_started ) < $cap ) {
		$ts = wp_next_scheduled( $hook );
		if ( false === $ts ) {
			break;
		}
		wp_unschedule_event( $ts, $hook );
		do_action( $hook );
		++$tc_runs;
		wp_cache_delete( 'shieldscope_scan_state', 'options' );
		$tc_state = $scanner->get_state();
	}
	$result['tab_then_close'] = array( 'status' => $tc_state['status'], 'cron_runs' => $tc_runs, 'queued_after_busy' => $result['tc_queued_after_busy'] );
}
