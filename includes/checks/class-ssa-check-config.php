<?php
/**
 * HTTP configuration & security header checks.
 *
 * @package Site_Security_Audit
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class SSA_Check_Config
 */
class SSA_Check_Config extends SSA_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'config';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'HTTP Configuration', 'site-security-audit' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'headers', 'version_disclosure', 'login_throttle', 'rest_version', 'rss_version', 'asset_versions' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'headers':
				$this->check_headers();
				break;
			case 'version_disclosure':
				$this->check_version_disclosure();
				break;
			case 'login_throttle':
				$this->check_login_throttle();
				break;
			case 'rest_version':
				$this->check_rest_version_disclosure();
				break;
			case 'rss_version':
				$this->check_rss_version_disclosure();
				break;
			case 'asset_versions':
				$this->check_asset_version_params();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * HTTP response headers.
	 *
	 * @return void
	 */
	private function check_headers() {
		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return;
		}

		$headers_object = wp_remote_retrieve_headers( $response );
		$headers        = array();
		if ( is_object( $headers_object ) && method_exists( $headers_object, 'getAll' ) ) {
			$headers = $headers_object->getAll();
		} elseif ( is_array( $headers_object ) ) {
			$headers = $headers_object;
		}
		// Normalize keys to lowercase.
		$lower = array();
		foreach ( $headers as $k => $v ) {
			$lower[ strtolower( $k ) ] = $v;
		}

		$checks = array(
			'x-frame-options'           => array(
				'severity' => SSA_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'X-Frame-Options header not set', 'site-security-audit' ),
				'desc'     => __( 'Without this header the site can be iframed by third parties — clickjacking risk.', 'site-security-audit' ),
				'rec'      => __( "Send 'X-Frame-Options: SAMEORIGIN' or set a Content-Security-Policy frame-ancestors directive.", 'site-security-audit' ),
			),
			'x-content-type-options'    => array(
				'severity' => SSA_Logger::SEVERITY_LOW,
				'title'    => __( 'X-Content-Type-Options header not set', 'site-security-audit' ),
				'desc'     => __( 'Browsers may MIME-sniff responses, which enables certain XSS vectors.', 'site-security-audit' ),
				'rec'      => __( "Send 'X-Content-Type-Options: nosniff'.", 'site-security-audit' ),
			),
			'referrer-policy'           => array(
				'severity' => SSA_Logger::SEVERITY_LOW,
				'title'    => __( 'Referrer-Policy header not set', 'site-security-audit' ),
				'desc'     => __( 'Full URLs may leak in the Referer header to third-party sites.', 'site-security-audit' ),
				'rec'      => __( "Send 'Referrer-Policy: strict-origin-when-cross-origin'.", 'site-security-audit' ),
			),
			'strict-transport-security' => array(
				'severity' => SSA_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'HSTS (Strict-Transport-Security) not set', 'site-security-audit' ),
				'desc'     => __( 'Without HSTS, first-visit downgrade attacks are possible even when HTTPS is deployed.', 'site-security-audit' ),
				'rec'      => __( "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (after confirming full HTTPS).", 'site-security-audit' ),
			),
			'content-security-policy'   => array(
				'severity' => SSA_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'Content-Security-Policy (CSP) header not set', 'site-security-audit' ),
				'desc'     => __( 'Without a CSP, browsers will execute any inline script or load resources from any origin. A missing CSP significantly increases the impact of XSS vulnerabilities.', 'site-security-audit' ),
				'rec'      => __( "Define a Content-Security-Policy header in your webserver config or via a plugin. Start with a report-only policy to avoid breaking the site: 'Content-Security-Policy-Report-Only: default-src \\'self\\''.", 'site-security-audit' ),
			),
			'permissions-policy'        => array(
				'severity' => SSA_Logger::SEVERITY_LOW,
				'title'    => __( 'Permissions-Policy header not set', 'site-security-audit' ),
				'desc'     => __( 'Without this header, third-party scripts embedded in the page can request access to browser features such as the camera, microphone, and geolocation.', 'site-security-audit' ),
				'rec'      => __( "Send 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to disable unused browser features.", 'site-security-audit' ),
			),
			'x-xss-protection'          => array(
				'severity' => SSA_Logger::SEVERITY_LOW,
				'title'    => __( 'X-XSS-Protection header not set', 'site-security-audit' ),
				'desc'     => __( "The X-XSS-Protection header activates legacy browsers' built-in reflected-XSS filter. Modern browsers have deprecated it in favour of CSP, but it still provides a safety net for older clients.", 'site-security-audit' ),
				'rec'      => __( "Send 'X-XSS-Protection: 1; mode=block'.", 'site-security-audit' ),
			),
		);

		foreach ( $checks as $header_name => $info ) {
			if ( ! isset( $lower[ $header_name ] ) ) {
				$this->finding( $info['severity'], $info['title'], $info['desc'], $info['rec'], $header_name );
			}
		}
	}

	/**
	 * WordPress version leaked in HTML (generator meta).
	 *
	 * @return void
	 */
	private function check_version_disclosure() {
		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( $body && preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+[\d.]+/i', $body ) ) {
			$this->finding(
				SSA_Logger::SEVERITY_LOW,
				__( 'WordPress version disclosed in HTML meta', 'site-security-audit' ),
				__( 'The generator meta tag reveals the exact WP version to visitors and automated vulnerability scanners.', 'site-security-audit' ),
				__( "Add to functions.php or an mu-plugin: remove_action('wp_head', 'wp_generator');", 'site-security-audit' )
			);
		}
	}

	/**
	 * WordPress version leaked via the REST API root endpoint.
	 *
	 * GET /wp-json returns a JSON object that includes the WP version string
	 * inside the 'description' field or 'namespaces' in older versions.
	 *
	 * @return void
	 */
	private function check_rest_version_disclosure() {
		$url      = rest_url( '/' );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return;
		}

		$body    = wp_remote_retrieve_body( $response );
		$decoded = json_decode( $body, true );

		if ( ! is_array( $decoded ) ) {
			return;
		}

		global $wp_version;

		// The 'name' + 'description' fields are user-controlled, but the generator
		// URL in the _links section or explicit 'wp:v2' version headers may expose it.
		// Most reliably: check if the raw body contains the exact WP version string.
		if ( $wp_version && false !== strpos( $body, $wp_version ) ) {
			$this->finding(
				SSA_Logger::SEVERITY_LOW,
				__( 'WordPress version exposed via REST API root endpoint', 'site-security-audit' ),
				sprintf(
					/* translators: %s: WordPress version */
					__( 'The /wp-json response body contains the WordPress version string (%s). Automated vulnerability scanners query this endpoint to fingerprint the site.', 'site-security-audit' ),
					$wp_version
				),
				__( 'Remove the version from the REST API response by filtering the rest_index data, or remove the generator link from wp_head to reduce fingerprinting surface.', 'site-security-audit' ),
				'/wp-json'
			);
		}
	}

	/**
	 * WordPress version leaked in the RSS feed generator tag.
	 *
	 * @return void
	 */
	private function check_rss_version_disclosure() {
		$feed_url = get_feed_link( 'rss2' );
		if ( ! $feed_url ) {
			return;
		}

		$response = wp_remote_get(
			$feed_url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return;
		}

		$body = wp_remote_retrieve_body( $response );

		// WordPress outputs <generator>https://wordpress.org/?v=6.x.x</generator>
		if ( $body && preg_match( '/<generator>[^<]*wordpress\.org[^<]*\?v=[\d.]+[^<]*<\/generator>/i', $body ) ) {
			$this->finding(
				SSA_Logger::SEVERITY_LOW,
				__( 'WordPress version exposed in RSS feed generator tag', 'site-security-audit' ),
				__( 'The RSS feed includes a <generator> tag with the exact WordPress version. Any visitor or bot can read this without authentication.', 'site-security-audit' ),
				__( "Remove the generator tag with: add_filter('the_generator', '__return_empty_string');", 'site-security-audit' ),
				$feed_url
			);
		}
	}

	/**
	 * Plugin/theme version numbers exposed via ?ver= query parameters on
	 * enqueued scripts and styles.
	 *
	 * @return void
	 */
	private function check_asset_version_params() {
		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( ! $body ) {
			return;
		}

		// Count <script src="...?ver=x.x.x"> and <link href="...?ver=x.x.x"> occurrences
		// that point to wp-content (plugin/theme assets) — these leak version info.
		$count = preg_match_all(
			'/(?:src|href)=["\'][^"\']*wp-content[^"\']*\?ver=[\d.]+[^"\']*["\']/i',
			$body
		);

		if ( $count >= 3 ) {
			$this->finding(
				SSA_Logger::SEVERITY_LOW,
				__( 'Plugin/theme version numbers exposed in asset URLs', 'site-security-audit' ),
				sprintf(
					/* translators: %d: number of assets with version query strings */
					__( '%d enqueued scripts/styles include ?ver= query parameters pointing to wp-content assets. These expose exact plugin and theme version numbers, helping attackers match installed software against known CVEs.', 'site-security-audit' ),
					$count
				),
				__( "Remove version strings from asset URLs by filtering: add_filter('style_loader_src', 'ssa_remove_ver_css_js', 9999); and the same for 'script_loader_src'. Note: this may break cache-busting on updates.", 'site-security-audit' )
			);
		}
	}

	/**
	 * Login throttle presence (heuristic — is there a plugin or known constant?).
	 *
	 * @return void
	 */
	private function check_login_throttle() {
		$known_throttlers = array(
			'wordfence/wordfence.php',
			'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
			'all-in-one-wp-security-and-firewall/wp-security.php',
			'wps-limit-login/wps-limit-login.php',
			'ithemes-security-pro/ithemes-security-pro.php',
			'better-wp-security/better-wp-security.php',
		);
		$active = (array) get_option( 'active_plugins', array() );
		foreach ( $known_throttlers as $p ) {
			if ( in_array( $p, $active, true ) ) {
				return;
			}
		}
		$this->finding(
			SSA_Logger::SEVERITY_MEDIUM,
			__( 'No login brute-force throttling plugin detected', 'site-security-audit' ),
			__( 'WordPress by default accepts unlimited login attempts. Automated credential-stuffing attacks are ubiquitous.', 'site-security-audit' ),
			__( 'Install a login-limiting plugin or enforce throttling at the webserver / WAF.', 'site-security-audit' )
		);
	}
}
