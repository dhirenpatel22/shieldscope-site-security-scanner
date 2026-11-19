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

$GLOBALS['ss_test_options']      = array(); // The "database" options table.
$GLOBALS['ss_test_option_cache'] = array(); // Per-request object cache in front of it, as in WP.
$GLOBALS['ss_test_transients']   = array();
$GLOBALS['ss_test_filters']      = array();
$GLOBALS['ss_test_overrides']    = array(); // callable overrides keyed by function name.
$GLOBALS['ss_test_site_transients'] = array(); // get_site_transient() store.
$GLOBALS['ss_test_plugins']         = array(); // get_plugins() result.
$GLOBALS['ss_test_theme']           = null;    // wp_get_theme() result for the active theme.

/**
 * Reset all stub state between tests.
 */
function ss_tests_reset_state() {
	$GLOBALS['ss_test_options']      = array();
	$GLOBALS['ss_test_option_cache'] = array();
	$GLOBALS['ss_test_transients']   = array();
	$GLOBALS['ss_test_filters']      = array();
	$GLOBALS['ss_test_overrides']    = array();
	$GLOBALS['ss_test_site_transients'] = array();
	$GLOBALS['ss_test_plugins']         = array();
	$GLOBALS['ss_test_theme']           = null;
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

/**
 * Run a callable as if it were a separate HTTP request: it starts with an
 * empty option cache and its cache is discarded afterwards, so only its
 * "database" writes are visible to the current request.
 *
 * @param callable $callback Work done by the other request.
 * @return mixed Return value of $callback.
 */
function ss_tests_in_other_request( $callback ) {
	$own_cache                       = $GLOBALS['ss_test_option_cache'];
	$GLOBALS['ss_test_option_cache'] = array();
	try {
		return call_user_func( $callback );
	} finally {
		$GLOBALS['ss_test_option_cache'] = $own_cache;
	}
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

// Like WordPress without a persistent object cache, the first read of an
// option in a request fills the cache and later reads in that request are
// served from it, so writes made by other requests are not seen.
function get_option( $name, $default = false ) {
	if ( array_key_exists( $name, $GLOBALS['ss_test_option_cache'] ) ) {
		return $GLOBALS['ss_test_option_cache'][ $name ];
	}
	if ( ! array_key_exists( $name, $GLOBALS['ss_test_options'] ) ) {
		return $default;
	}
	$GLOBALS['ss_test_option_cache'][ $name ] = $GLOBALS['ss_test_options'][ $name ];
	return $GLOBALS['ss_test_options'][ $name ];
}
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['ss_test_options'][ $name ]      = $value;
	$GLOBALS['ss_test_option_cache'][ $name ] = $value;
	return true;
}
function add_option( $name, $value = '' ) {
	if ( array_key_exists( $name, $GLOBALS['ss_test_options'] ) ) { return false; }
	$GLOBALS['ss_test_options'][ $name ]      = $value;
	$GLOBALS['ss_test_option_cache'][ $name ] = $value;
	return true;
}
function delete_option( $name ) {
	unset( $GLOBALS['ss_test_options'][ $name ], $GLOBALS['ss_test_option_cache'][ $name ] );
	return true;
}
function wp_cache_delete( $key, $group = '' ) {
	if ( 'options' === $group ) {
		unset( $GLOBALS['ss_test_option_cache'][ $key ] );
	}
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
function is_multisite() {
	list( $hit, $result ) = ss_tests_maybe_override( 'is_multisite', array() );
	return $hit ? $result : false;
}

// ---------------------------------------------------------------------------
// URLs. One source of truth: override 'get_site_url' (and optionally
// 'get_home_url') to change the scheme or host for a test.
// ---------------------------------------------------------------------------

function get_site_url() {
	list( $hit, $result ) = ss_tests_maybe_override( 'get_site_url', array() );
	return $hit ? $result : 'https://example.test';
}
function get_home_url() {
	list( $hit, $result ) = ss_tests_maybe_override( 'get_home_url', array() );
	return $hit ? $result : get_site_url();
}
function home_url( $path = '' ) {
	$url = rtrim( get_home_url(), '/' );
	if ( is_string( $path ) && '' !== $path ) {
		$url .= '/' . ltrim( $path, '/' );
	}
	return $url;
}
function rest_url( $path = '' ) {
	return rtrim( get_home_url(), '/' ) . '/wp-json/' . ltrim( (string) $path, '/' );
}
function wp_login_url() { return rtrim( get_site_url(), '/' ) . '/wp-login.php'; }
function get_feed_link( $feed = '' ) { return home_url( '/feed/' ); }
function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
}

// ---------------------------------------------------------------------------
// More HTTP API
// ---------------------------------------------------------------------------

function wp_remote_post( $url, $args = array() ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_remote_post', array( $url, $args ) );
	return $hit ? $result : new WP_Error( 'no_network', 'Network disabled in tests' );
}
function wp_remote_head( $url, $args = array() ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_remote_head', array( $url, $args ) );
	return $hit ? $result : new WP_Error( 'no_network', 'Network disabled in tests' );
}
function wp_remote_retrieve_header( $response, $header ) {
	return isset( $response['headers'][ $header ] ) ? $response['headers'][ $header ] : '';
}
function wp_remote_retrieve_headers( $response ) {
	return isset( $response['headers'] ) ? $response['headers'] : array();
}
class WP_Http_Cookie {
	public function __construct( $data = array() ) {}
}

// ---------------------------------------------------------------------------
// i18n / output helpers
// ---------------------------------------------------------------------------

function _n( $single, $plural, $number, $domain = 'default' ) { return 1 === (int) $number ? $single : $plural; } // phpcs:ignore
function esc_html_e( $text, $domain = 'default' ) { echo $text; } // phpcs:ignore
function esc_attr_e( $text, $domain = 'default' ) { echo $text; } // phpcs:ignore
function disabled( $disabled, $current = true, $echo = true ) { // phpcs:ignore
	$out = ( (string) $disabled === (string) $current ) ? " disabled='disabled'" : '';
	if ( $echo ) {
		echo $out; // phpcs:ignore
	}
	return $out;
}
function wp_date( $format, $timestamp = null, $timezone = null ) {
	return gmdate( $format, null === $timestamp ? time() : $timestamp );
}
function remove_action( $hook, $cb, $prio = 10 ) {
	if ( empty( $GLOBALS['ss_test_filters'][ $hook ] ) ) {
		return false;
	}
	foreach ( $GLOBALS['ss_test_filters'][ $hook ] as $i => $registered ) {
		if ( $registered === $cb ) {
			unset( $GLOBALS['ss_test_filters'][ $hook ][ $i ] );
			return true;
		}
	}
	return false;
}
function wp_list_pluck( $list, $field ) {
	$out = array();
	foreach ( (array) $list as $item ) {
		$out[] = is_object( $item ) ? $item->$field : $item[ $field ];
	}
	return $out;
}

// ---------------------------------------------------------------------------
// Site transients, plugins, themes
// ---------------------------------------------------------------------------

function get_site_transient( $name ) {
	return array_key_exists( $name, $GLOBALS['ss_test_site_transients'] ) ? $GLOBALS['ss_test_site_transients'][ $name ] : false;
}
function get_plugins() {
	list( $hit, $result ) = ss_tests_maybe_override( 'get_plugins', array() );
	return $hit ? $result : $GLOBALS['ss_test_plugins'];
}
function is_plugin_active( $plugin ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'is_plugin_active', array( $plugin ) );
	return $hit ? $result : false;
}

/**
 * Minimal WP_Theme double.
 */
class SS_Test_Theme {
	private $stylesheet;
	private $headers;
	public function __construct( $stylesheet, array $headers = array() ) {
		$this->stylesheet = $stylesheet;
		$this->headers    = $headers;
	}
	public function exists() { return true; }
	public function get_stylesheet() { return $this->stylesheet; }
	public function get( $key ) { return isset( $this->headers[ $key ] ) ? $this->headers[ $key ] : false; }
	public function parent() { return false; }
}

/**
 * With a slug, returns a theme named after it; without, the active theme
 * from $GLOBALS['ss_test_theme'] (null when none is set).
 */
function wp_get_theme( $stylesheet = null ) {
	if ( null !== $stylesheet ) {
		return new SS_Test_Theme( (string) $stylesheet, array( 'Name' => (string) $stylesheet ) );
	}
	return $GLOBALS['ss_test_theme'];
}
function wp_get_themes() {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_get_themes', array() );
	return $hit ? $result : array();
}
function get_stylesheet() { return 'active-theme'; }
function get_template() { return 'active-theme'; }

// ---------------------------------------------------------------------------
// Users, posts, application passwords
// ---------------------------------------------------------------------------

function get_users( $args = array() ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'get_users', array( $args ) );
	return $hit ? $result : array();
}
function get_user_by( $field, $value ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'get_user_by', array( $field, $value ) );
	return $hit ? $result : false;
}
function user_can( $user, $cap ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'user_can', array( $user, $cap ) );
	return $hit ? (bool) $result : false;
}
function wp_delete_post( $post_id = 0, $force = false ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_delete_post', array( $post_id, $force ) );
	return $hit ? $result : false;
}
function wp_is_application_passwords_available() {
	list( $hit, $result ) = ss_tests_maybe_override( 'wp_is_application_passwords_available', array() );
	return $hit ? $result : true;
}
class WP_Application_Passwords {
	public static function get_user_application_passwords( $user_id ) {
		list( $hit, $result ) = ss_tests_maybe_override( 'WP_Application_Passwords::get_user_application_passwords', array( $user_id ) );
		return $hit ? $result : array();
	}
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/**
 * Inert wpdb double for tests that touch the findings table only in passing.
 */
class SS_Test_WPDB {
	public $prefix  = 'wp_';
	public $queries = array();
	public function prepare( $sql ) { return $sql; }
	public function query( $sql ) { $this->queries[] = $sql; return 0; }
	public function get_var( $sql = null ) { return null; }
	public function get_results( $sql = null, $output = null ) { return array(); }
}

// ---------------------------------------------------------------------------
// Site, content, plugin and theme URLs (A-06). Built on get_site_url().
// ---------------------------------------------------------------------------

function site_url( $path = '' ) {
	$url = rtrim( get_site_url(), '/' );
	if ( is_string( $path ) && '' !== $path ) {
		$url .= '/' . ltrim( $path, '/' );
	}
	return $url;
}
function content_url( $path = '' ) {
	$url = rtrim( get_site_url(), '/' ) . '/wp-content';
	if ( is_string( $path ) && '' !== $path ) {
		$url .= '/' . ltrim( $path, '/' );
	}
	return $url;
}
function plugins_url( $path = '', $plugin = '' ) {
	$url = content_url( '/plugins' );
	if ( is_string( $plugin ) && '' !== $plugin ) {
		$url .= '/' . basename( dirname( $plugin ) );
	}
	if ( is_string( $path ) && '' !== $path ) {
		$url .= '/' . ltrim( $path, '/' );
	}
	return $url;
}
function get_theme_root_uri() { return content_url( '/themes' ); }

// ---------------------------------------------------------------------------
// Admin menus and request exits (A-14)
// ---------------------------------------------------------------------------

/**
 * Thrown by the wp_die() and wp_send_json_error() stubs, which exit in WordPress.
 */
class SS_Test_Exit extends Exception {}

function add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $callback = '', $icon_url = '', $position = null ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'add_menu_page', array( $page_title, $menu_title, $capability, $menu_slug ) );
	return $hit ? $result : 'toplevel_page_' . $menu_slug;
}
function add_submenu_page( $parent_slug, $page_title, $menu_title, $capability, $menu_slug, $callback = '', $position = null ) {
	list( $hit, $result ) = ss_tests_maybe_override( 'add_submenu_page', array( $parent_slug, $page_title, $menu_title, $capability, $menu_slug ) );
	return $hit ? $result : $parent_slug . '_page_' . $menu_slug;
}
function wp_die( $message = '' ) {
	throw new SS_Test_Exit( (string) $message );
}
function wp_send_json_error( $data = null, $status_code = null ) {
	throw new SS_Test_Exit( (string) wp_json_encode( $data ), (int) $status_code );
}
