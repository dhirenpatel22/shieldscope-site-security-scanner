<?php
/**
 * Uninstall handler for SSA.
 *
 * Runs only when the plugin is deleted through the WP UI (not deactivated).
 * Removes all persistent data created by the plugin.
 *
 * @package Site_Security_Audit
 */

// Fired only by WordPress when plugin is deleted.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$options = array(
	'ssa_version',
	'ssa_settings',
	'ssa_last_scan',
	'ssa_scan_state',
);

/**
 * Clean up one site's options, transients, cron events, and findings table.
 *
 * @param wpdb   $db     Database object (already switched to the right blog).
 * @param string $prefix Table prefix for this blog.
 */
$clean_site = function ( $db, $prefix ) use ( $options ) {
	// Delete options.
	foreach ( $options as $option ) {
		delete_option( $option );
	}

	// Delete transients (wildcard delete — direct query required).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
	$db->query(
		$db->prepare(
			"DELETE FROM {$db->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$db->esc_like( '_transient_ssa_' ) . '%',
			$db->esc_like( '_transient_timeout_ssa_' ) . '%'
		)
	);

	// Clear scheduled cron events.
	$crons = array( 'ssa_run_scan_chunk', 'ssa_daily_maintenance' );
	foreach ( $crons as $cron ) {
		$timestamp = wp_next_scheduled( $cron );
		while ( false !== $timestamp ) {
			wp_unschedule_event( $timestamp, $cron );
			$timestamp = wp_next_scheduled( $cron );
		}
	}

	// Drop findings table.
	$table = $prefix . 'ssa_findings';
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
	$db->query( "DROP TABLE IF EXISTS {$table}" );
};

if ( is_multisite() ) {
	$sites = get_sites( array( 'number' => 0, 'fields' => 'ids' ) );
	foreach ( $sites as $site_id ) {
		switch_to_blog( $site_id );
		$clean_site( $wpdb, $wpdb->prefix );
		restore_current_blog();
	}

	// Network-level options.
	foreach ( $options as $option ) {
		delete_site_option( $option );
	}
} else {
	$clean_site( $wpdb, $wpdb->prefix );
}
