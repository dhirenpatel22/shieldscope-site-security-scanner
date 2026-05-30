<?php
/**
 * Uninstall handler for ShieldScope.
 *
 * Runs only when the plugin is deleted through the WP UI (not deactivated).
 * Removes all persistent data created by the plugin.
 *
 * @package ShieldScope
 */

// Fired only by WordPress when plugin is deleted.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$shieldscope_options = array(
	'shieldscope_version',
	'shieldscope_settings',
	'shieldscope_last_scan',
	'shieldscope_scan_state',
);

/**
 * Clean up one site's options, transients, cron events, and findings table.
 *
 * @param wpdb   $db     Database object (already switched to the right blog).
 * @param string $prefix Table prefix for this blog.
 */
$shieldscope_clean_site = function ( $db, $prefix ) use ( $shieldscope_options ) {
	// Delete options.
	foreach ( $shieldscope_options as $shieldscope_option ) {
		delete_option( $shieldscope_option );
	}

	// Delete transients (wildcard delete — direct query required).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
	$db->query(
		$db->prepare(
			"DELETE FROM {$db->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$db->esc_like( '_transient_shieldscope_' ) . '%',
			$db->esc_like( '_transient_timeout_shieldscope_' ) . '%'
		)
	);

	// Clear scheduled cron events.
	$crons = array( 'shieldscope_run_scan_chunk', 'shieldscope_daily_maintenance' );
	foreach ( $crons as $cron ) {
		$timestamp = wp_next_scheduled( $cron );
		while ( false !== $timestamp ) {
			wp_unschedule_event( $timestamp, $cron );
			$timestamp = wp_next_scheduled( $cron );
		}
	}

	// Drop findings table.
	$table = $prefix . 'shieldscope_findings';
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
	$db->query( "DROP TABLE IF EXISTS {$table}" );
};

if ( is_multisite() ) {
	$shieldscope_sites = get_sites( array( 'number' => 0, 'fields' => 'ids' ) );
	foreach ( $shieldscope_sites as $shieldscope_site_id ) {
		switch_to_blog( $shieldscope_site_id );
		$shieldscope_clean_site( $wpdb, $wpdb->prefix );
		restore_current_blog();
	}

	// Network-level options.
	foreach ( $shieldscope_options as $shieldscope_option ) {
		delete_site_option( $shieldscope_option );
	}
} else {
	$shieldscope_clean_site( $wpdb, $wpdb->prefix );
}
