<?php
/**
 * Server-Side Request Forgery (SSRF) checks.
 *
 * Scans plugin and theme PHP files for HTTP request patterns where
 * user-controlled data can influence the target URL (wp_remote_*, cURL,
 * file_get_contents, fsockopen), and checks WordPress features that expose
 * SSRF-prone functionality (oEmbed proxy, pingbacks, open redirects).
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_SSRF
 */
class ShieldScope_Check_SSRF extends ShieldScope_Check_Base {

	/**
	 * Max file size to scan.
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param ShieldScope_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, ShieldScope_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$settings            = (array) get_option( 'shieldscope_settings', array() );
		$this->max_file_size = isset( $settings['max_scan_file_size'] )
			? (int) $settings['max_scan_file_size']
			: 2 * MB_IN_BYTES;
	}

	/** @return string */
	public function get_id() {
		return 'ssrf';
	}

	/** @return string */
	public function get_label() {
		return __( 'Server-Side Request Forgery (SSRF)', 'shieldscope-site-security-scanner' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'scan_plugins', 'scan_themes', 'wp_features' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( 'scan_plugins' === $step ) {
			return $this->scan_tree( SHIELDSCOPE_WP_PLUGINS_DIR, $cursor );
		}
		if ( 'scan_themes' === $step ) {
			return $this->scan_tree( get_theme_root(), $cursor );
		}
		if ( 'wp_features' === $step ) {
			$this->check_wp_ssrf_features();
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Walk a directory tree resumably.
	 *
	 * @param string $root   Root directory.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	private function scan_tree( $root, array $cursor ) {
		return $this->walk_php_files_step(
			$root,
			$cursor,
			function ( $full ) {
				return $this->scan_file( $full );
			}
		);
	}

	/**
	 * Inspect one file for request patterns that take a URL or host from
	 * request data. Every match is a Low "Review" finding: the pattern shows
	 * where to look, not that the code is exploitable.
	 *
	 * @param string $path File path.
	 * @return bool False if the file was skipped (too large or unreadable).
	 */
	private function scan_file( $path ) {
		$contents = $this->read_scannable_file( $path, $this->max_file_size );
		if ( false === $contents ) {
			return false;
		}
		if ( '' === $contents ) {
			return true;
		}

		$this->rx_failed = false;
		$raw             = $this->neutralise_safe_calls( self::code_view( $contents ) );
		$sg              = '\$_(?:GET|POST|REQUEST|COOKIE)';
		$note            = __( 'This is a pattern match, not a confirmed vulnerability: read the code to confirm whether request data really chooses the destination.', 'shieldscope-site-security-scanner' );

		$rules = array(
			array(
				'/\bwp_remote_(?:get|post|request|head)\s*\([^;]*' . $sg . '/i',
				__( 'Review: user input near wp_remote_*() (possible SSRF)', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in a WordPress HTTP API call. If it sets the URL, a visitor can make the server send requests to internal hosts such as cloud metadata endpoints or localhost.', 'shieldscope-site-security-scanner' ),
				__( 'Use wp_safe_remote_get() and check the host against an allowlist before sending the request.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\bwp_safe_remote_(?:get|post|request)\s*\([^;]*' . $sg . '/i',
				__( 'Review: user input near wp_safe_remote_*()', 'shieldscope-site-security-scanner' ),
				__( 'wp_safe_remote_*() rejects private and loopback addresses, which covers most server-side request forgery. Redirects and DNS changes can still reach unexpected hosts.', 'shieldscope-site-security-scanner' ),
				__( 'If the destination comes from the request, also check the host against an allowlist.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\bfile_get_contents\s*\([^;]*' . $sg . '/i',
				__( 'Review: user input near file_get_contents() (possible file read or SSRF)', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in a file_get_contents() call. If it sets the path, a visitor could read local files, or make the server fetch URLs when allow_url_fopen is on.', 'shieldscope-site-security-scanner' ),
				__( 'Map request values to a fixed list of files. For HTTP, use wp_safe_remote_get() with a host allowlist.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/curl_setopt\s*\([^,;]+,\s*CURLOPT_URL\s*,[^;]*' . $sg . '/i',
				__( 'Review: user input near cURL CURLOPT_URL (possible SSRF)', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears where a cURL URL is set. If it sets the URL, a visitor can make the server send requests to internal hosts.', 'shieldscope-site-security-scanner' ),
				__( 'Check the host against an allowlist and reject private and loopback addresses, or use wp_safe_remote_get().', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\b(?:fsockopen|stream_socket_client)\s*\([^;]*' . $sg . '/i',
				__( 'Review: user input near a socket connection', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in fsockopen() or stream_socket_client(). If it sets the host, a visitor can make the server open connections to any host.', 'shieldscope-site-security-scanner' ),
				__( 'Check the host against an allowlist and reject private, loopback and link-local addresses.', 'shieldscope-site-security-scanner' ),
			),
			array(
				'/\bwp_redirect\s*\([^;]*' . $sg . '/i',
				__( 'Review: user input near wp_redirect() (possible open redirect)', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in wp_redirect(). If it sets the destination, the site can be used to send visitors to any site (phishing).', 'shieldscope-site-security-scanner' ),
				__( 'Use wp_safe_redirect(), or wp_validate_redirect() with a fallback URL.', 'shieldscope-site-security-scanner' ),
			),
			'location' => array(
				'/\bheader\s*\(\s*["\']Location:[^;]*' . $sg . '/i',
				__( 'Review: user input near a Location header (possible open redirect)', 'shieldscope-site-security-scanner' ),
				__( 'Request data appears in a Location header. If it sets the destination, the site can be used to send visitors to any site.', 'shieldscope-site-security-scanner' ),
				__( 'Use wp_safe_redirect() with a fallback URL.', 'shieldscope-site-security-scanner' ),
			),
		);

		$with_strings = self::code_view( $contents, true );
		foreach ( $rules as $key => $rule ) {
			// The Location rule needs the header text, which the code view blanks.
			$view = 'location' === $key ? $with_strings : $raw;
			$at   = $this->rx_offset( $rule[0], $view );
			if ( $at >= 0 ) {
				$this->finding( ShieldScope_Logger::SEVERITY_LOW, $rule[1], $rule[2] . ' ' . $note, $rule[3], $path, self::evidence( $contents, $view, $at ) );
			}
		}

		if ( $this->rx_failed ) {
			$this->could_not_analyse( $path );
		}
		return true;
	}

	/**
	 * Check WordPress features that enable server-side request functionality.
	 *
	 * @return void
	 */
	private function check_wp_ssrf_features() {
		// oEmbed proxy endpoint — unauthenticated server-side HTTP fetcher.
		$proxy_url = add_query_arg(
			array(
				'url'    => 'https://example.com/',
				'format' => 'json',
			),
			rest_url( 'oembed/1.0/proxy' )
		);

		$response = wp_remote_get(
			$proxy_url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
			)
		);

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'oEmbed proxy answered a logged-out request', 'shieldscope-site-security-scanner' ),
				__( 'The /wp-json/oembed/1.0/proxy endpoint makes the server fetch a URL and return the result. WordPress core only allows it for users with the edit_posts capability, but it answered a request sent without a login, so a plugin or filter has probably opened it up.', 'shieldscope-site-security-scanner' ),
				__( "Find the plugin or code that changes the proxy's permission check. If you do not need the oEmbed REST routes, remove them: remove_action( 'rest_api_init', 'wp_oembed_register_route' );", 'shieldscope-site-security-scanner' ),
				'/wp-json/oembed/1.0/proxy'
			);
		}

		// Pingback — classic SSRF / DDoS reflection vector.
		if ( apply_filters( 'xmlrpc_enabled', true ) && 'open' === get_option( 'default_ping_status' ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reading WP core filter
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Pingbacks are allowed on new posts', 'shieldscope-site-security-scanner' ),
				__( 'New posts accept pingbacks through XML-RPC. To check a pingback, WordPress fetches the source URL the sender supplies, so anyone can make the server send requests to URLs they choose. Pingbacks have been used for DDoS reflection and to probe internal hosts.', 'shieldscope-site-security-scanner' ),
				__( "If you do not use pingbacks, go to Settings → Discussion and clear 'Allow link notifications from other blogs (pingbacks and trackbacks) on new posts'. Existing posts keep their own setting. Turning off XML-RPC removes pingbacks completely.", 'shieldscope-site-security-scanner' ),
				'xmlrpc.php'
			);
		}

		// allow_url_fopen enabled — increases SSRF risk from file_get_contents.
		if ( ini_get( 'allow_url_fopen' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'PHP allow_url_fopen is enabled', 'shieldscope-site-security-scanner' ),
				__( 'allow_url_fopen lets file_get_contents() and similar functions fetch remote URLs. Combined with any path-traversal or injection bug that passes a URL to file_get_contents(), this becomes an SSRF vector.', 'shieldscope-site-security-scanner' ),
				__( 'Set allow_url_fopen = Off in php.ini if your code does not intentionally use file_get_contents() for HTTP requests (use wp_remote_get() instead).', 'shieldscope-site-security-scanner' ),
				'php.ini'
			);
		}

		// WooCommerce webhooks — if active, flag for review.
		if ( class_exists( 'WooCommerce' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'WooCommerce webhooks may be configured — review webhook URLs', 'shieldscope-site-security-scanner' ),
				__( 'WooCommerce supports webhooks that cause the server to make outbound HTTP requests. A compromised admin account could add a webhook pointing at an internal service, enabling SSRF.', 'shieldscope-site-security-scanner' ),
				__( 'Review active webhooks in WooCommerce → Settings → Advanced → Webhooks. Ensure only trusted external URLs are configured.', 'shieldscope-site-security-scanner' ),
				'woocommerce'
			);
		}
	}
}
