<?php
/**
 * Minimal WordPress function stubs for standalone unit tests.
 *
 * These implement just enough of the WP API surface used by ShieldScope's
 * classes so the plugin logic can be exercised without a full WordPress
 * install. State lives in globals and is reset per-test via ss_tests_reset_state().
 *
 * @package ShieldScope\Tests
 */

// ---------------------------------------------------------------------------
// In-memory state stores
// ---------------------------------------------------------------------------

$GLOBALS['ss_test_options']    = array();
$GLOBALS['ss_test_transients'] = array();
$GLOBALS['ss_test_filters']    = array();
$GLOBALS['ss_test_overrides']  = array(); // callable overrides keyed by function name.

/**
 * Reset all stub state between tests.
 */
function ss_tests_reset_state() {
	$GLOBALS['ss_test_options']    = array();
	$GLOBALS['ss_test_transients'] = array();
	$GLOBALS['ss_test_filters']    = array();
	$GLOBALS['ss_test_overrides']  = array();
	unset( $_SERVER['SERVER_SOFTWARE'] );
	$GLOBALS['wp_version'] = '6.8.1';
}

/**
 * Register a per-test override for a stubbed function (e.g. wp_remote_get).
 *
 * @param string   $fn       Function name.
 * @param callable $callback Replacement behaviour.
 */
function ss_tests_override( $fn, $callback ) {
	$GLOBALS['ss_test_overrides'][ $fn ] = $callback;
}

function ss_tests_maybe_override( $fn, $args ) {
	if ( isset( $GLOBALS['ss_test_overrides'][ $fn ] ) ) {
		return array( true, call_user_func_array( $GLOBALS['ss_test_overrides'][ $fn ], $args ) );
	}
	return array( false, null );
}

// ---------------------------------------------------------------------------
// i18n / escaping
// ---------------------------------------------------------------------------

function __( $text, $domain = 'default' ) { return $text; } // phpcs:ignore
function _e( $text, $domain = 'default' ) { echo $text; } // phpcs:ignore
function esc_html__( $text, $domain = 'default' ) { return $text; }
function esc_html( $text ) { return (string) $text; }
function esc_attr( $text ) { return (string) $text; }
function esc_url( $url ) { return (string) $url; }
function esc_sql( $sql ) { return $sql; }
function wp_kses_post( $text ) { return (string) $text; }
function sanitize_text_field( $text ) { return is_string( $text ) ? trim( preg_replace( '/[\r\n\t ]+/', ' ', $text ) ) : ''; }
function sanitize_key( $key ) { return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) ) ); }
function wp_unslash( $value ) { return is_array( $value ) ? array_map( 'wp_unslash', $value ) : stripslashes( (string) $value ); }

// ---------------------------------------------------------------------------
// Options & transients
// ---------------------------------------------------------------------------

function get_option( $name, $default = false ) {
	return array_key_exists( $name, $GLOBALS['ss_test_options'] ) ? $GLOBALS['ss_test_options'][ $name ] : $default;
}
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['ss_test_options'][ $name ] = $value;
	return true;
}
function add_option( $name, $value = '' ) {
	if ( array_key_exists( $name, $GLOBALS['ss_test_options'] ) ) { return false; }
	$GLOBALS['ss_test_options'][ $name ] = $value;
	return true;
}
function delete_option( $name ) {
	unset( $GLOBALS['ss_test_options'][ $name ] );
	return true;
}
function get_transient( $name ) {
	return array_key_exists( $name, $GLOBALS['ss_test_transients'] ) ? $GLOBALS['ss_test_transients'][ $name ] : false;
}
function set_transient( $name, $value, $ttl = 0 ) {
	$GLOBALS['ss_test_transients'][ $name ] = $value;
	return true;
}
function delete_transient( $name ) {
	unset( $GLOBALS['ss_test_transients'][ $name ] );
	return true;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

function add_action( $hook, $cb, $prio = 10, $args = 1 ) { $GLOBALS['ss_test_filters'][ $hook ][] = $cb; return true; }
function add_filter( $hook, $cb, $prio = 10, $args = 1 ) { $GLOBALS['ss_test_filters'][ $hook ][] = $cb; return true; }
function apply_filters( $hook, $value ) {
	$args = func_get_args();
	array_shift( $args );
	if ( ! empty( $GLOBALS['ss_test_filters'][ $hook ] ) ) {
		foreach ( $GLOBALS['ss_test_filters'][ $hook ] as $cb ) {
			$args[0] = call_user_func_array( $cb, $args );
		}
	}
	return $args[0];
}
function do_action( $hook ) {}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

class WP_Error {
	private $message;
	public function __construct( $code = '', $message = '' ) { $this->message = $message; }
	public function get_error_message() { return $this->message; }
}
function is_wp_error( $thing ) { return $thing instanceof WP_Error; }
function wp_remote_get( $url, $args = array() ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_remote_get', array( $url, $args ) );
	if ( $hit ) { return $result; }
	return new WP_Error( 'no_network', 'Network disabled in tests' );
}
function wp_remote_retrieve_response_code( $response ) {
	return isset( $response['response']['code'] ) ? $response['response']['code'] : 0;
}
function wp_remote_retrieve_body( $response ) {
	return isset( $response['body'] ) ? $response['body'] : '';
}
function add_query_arg( $args, $url ) {
	return $url . '?' . http_build_query( $args );
}

// ---------------------------------------------------------------------------
// Misc WP helpers
// ---------------------------------------------------------------------------

function wp_json_encode( $data ) { return json_encode( $data ); } // phpcs:ignore
function current_time( $type, $gmt = 0 ) { return gmdate( 'Y-m-d H:i:s' ); }
function wp_normalize_path( $path ) {
	$path = str_replace( '\\', '/', (string) $path );
	return preg_replace( '|(?<=.)/+|', '/', $path );
}
function trailingslashit( $string ) { return rtrim( (string) $string, '/\\' ) . '/'; }
function wp_parse_args( $args, $defaults = array() ) { return array_merge( $defaults, (array) $args ); }
function wp_generate_password( $length = 12, $special = true, $extra = true ) {
	return substr( str_shuffle( str_repeat( 'abcdefghjkmnpqrstuvwxyz23456789', 3 ) ), 0, $length );
}
function get_current_user_id() { return 1; }
function current_user_can( $cap ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'current_user_can', array( $cap ) );
	return $hit ? $result : true;
}
function wp_verify_nonce( $nonce, $action = -1 ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_verify_nonce', array( $nonce, $action ) );
	return $hit ? $result : 1;
}
function add_settings_error( $setting, $code, $message, $type = 'error' ) {}
function rawurlencode_deep( $value ) { return $value; }
function wp_next_scheduled( $hook ) { return false; }
function wp_schedule_event( $ts, $recurrence, $hook ) { return true; }
function wp_schedule_single_event( $ts, $hook ) { return true; }
function wp_unschedule_event( $ts, $hook ) { return true; }
function wp_upload_dir() { return wp_get_upload_dir(); }
function wp_get_upload_dir() {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_get_upload_dir', array() );
	if ( $hit ) { return $result; }
	return array( 'basedir' => SS_TESTS_WP_ROOT . '/wp-content/uploads', 'baseurl' => 'https://example.test/wp-content/uploads' );
}
function is_admin() { return false; }
function is_multisite() { return false; }
