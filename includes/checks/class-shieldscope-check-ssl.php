<?php
/**
 * SSL / TLS security checks.
 *
 * Covers three areas that cannot be assessed from WordPress internals alone:
 *
 *  cert_expiry   — Connects to the site's HTTPS port, reads the TLS certificate,
 *                  and flags certificates that are expired or expiring soon.
 *
 *  tls_version   — Uses cURL (when available) to probe whether the server accepts
 *                  TLS 1.0 or TLS 1.1, both of which are deprecated and insecure.
 *
 *  mixed_content — Fetches the homepage HTML and scans for HTTP (non-HTTPS) URLs
 *                  in src/href/action attributes, which browsers block or warn about.
 *
 * All checks are skipped gracefully if the site is not on HTTPS.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_SSL
 */
class ShieldScope_Check_SSL extends ShieldScope_Check_Base {

	/** @return string */
	public function get_id() {
		return 'ssl';
	}

	/** @return string */
	public function get_label() {
		return __( 'SSL / TLS', 'shieldscope-site-security-scanner' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'cert_expiry', 'tls_version', 'mixed_content' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step name.
	 * @param array  $cursor Cursor (unused — all steps are single-shot).
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'cert_expiry':
				$this->check_cert_expiry();
				break;
			case 'tls_version':
				$this->check_tls_version();
				break;
			case 'mixed_content':
				$this->check_mixed_content();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Return the site hostname, or empty string if not on HTTPS.
	 *
	 * @return string
	 */
	private function get_https_host() {
		$site_url = get_site_url();
		if ( 0 !== stripos( $site_url, 'https://' ) ) {
			return ''; // Site is not on HTTPS; SSL checks are not applicable.
		}
		return (string) wp_parse_url( $site_url, PHP_URL_HOST );
	}

	// -----------------------------------------------------------------------
	// Step: Certificate expiry
	// -----------------------------------------------------------------------

	/**
	 * Connect to the site's HTTPS port and inspect the TLS certificate.
	 *
	 * Reports:
	 *  - CRITICAL if the certificate is already expired.
	 *  - HIGH     if it expires within 7 days.
	 *  - MEDIUM   if it expires within 14 days.
	 *  - LOW      if it expires within 30 days.
	 *  - INFO     otherwise (certificate is valid).
	 *
	 * @return void
	 */
	private function check_cert_expiry() {
		$host = $this->get_https_host();
		if ( '' === $host ) {
			return;
		}

		if ( ! function_exists( 'openssl_x509_parse' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'SSL certificate expiry check skipped', 'shieldscope-site-security-scanner' ),
				__( 'The openssl PHP extension is not available. Cannot inspect the TLS certificate.', 'shieldscope-site-security-scanner' ),
				__( 'Enable the openssl extension in php.ini for full SSL certificate scanning.', 'shieldscope-site-security-scanner' )
			);
			return;
		}

		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false,
					'verify_peer_name'  => false,
				),
			)
		);

		$client = @stream_socket_client( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			'ssl://' . $host . ':443',
			$errno,
			$errstr,
			10,
			STREAM_CLIENT_CONNECT,
			$context
		);

		if ( ! is_resource( $client ) ) {
			// Cannot connect — could be a firewall or non-standard port; skip silently.
			return;
		}

		$params = stream_context_get_params( $client );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closing a socket stream, not a file; WP_Filesystem has no socket equivalent.
		fclose( $client );

		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			return;
		}

		$cert_info = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
		if ( ! is_array( $cert_info ) || empty( $cert_info['validTo_time_t'] ) ) {
			return;
		}

		$expiry    = (int) $cert_info['validTo_time_t'];
		$now       = time();
		$days_left = (int) floor( ( $expiry - $now ) / DAY_IN_SECONDS );
		$cn        = isset( $cert_info['subject']['CN'] ) ? $cert_info['subject']['CN'] : $host;
		$expiry_date = gmdate( 'Y-m-d', $expiry );

		if ( $days_left < 0 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'SSL certificate has expired', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: CN, 2: expiry date */
					__( 'The certificate for %1$s expired on %2$s. Browsers display a full-page warning and will not connect without a security bypass.', 'shieldscope-site-security-scanner' ),
					$cn,
					$expiry_date
				),
				__( 'Renew the SSL certificate immediately via your hosting panel or Let\'s Encrypt (certbot renew).', 'shieldscope-site-security-scanner' ),
				$host,
				array( 'days_left' => $days_left, 'expiry' => $expiry_date )
			);
			return;
		}

		if ( $days_left <= 7 ) {
			$severity = ShieldScope_Logger::SEVERITY_HIGH;
		} elseif ( $days_left <= 14 ) {
			$severity = ShieldScope_Logger::SEVERITY_MEDIUM;
		} elseif ( $days_left <= 30 ) {
			$severity = ShieldScope_Logger::SEVERITY_LOW;
		} else {
			// Certificate is healthy — record as INFO.
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				sprintf(
					/* translators: %d: days until expiry */
					__( 'SSL certificate is valid (%d days remaining)', 'shieldscope-site-security-scanner' ),
					$days_left
				),
				sprintf(
					/* translators: 1: CN, 2: expiry date */
					__( 'Certificate CN: %1$s. Expires: %2$s.', 'shieldscope-site-security-scanner' ),
					$cn,
					$expiry_date
				),
				'',
				$host,
				array( 'days_left' => $days_left, 'expiry' => $expiry_date )
			);
			return;
		}

		$this->finding(
			$severity,
			sprintf(
				/* translators: %d: days until expiry */
				__( 'SSL certificate expires in %d days', 'shieldscope-site-security-scanner' ),
				$days_left
			),
			sprintf(
				/* translators: 1: CN, 2: expiry date */
				__( 'The certificate for %1$s expires on %2$s. Visitors will see a browser warning once it lapses.', 'shieldscope-site-security-scanner' ),
				$cn,
				$expiry_date
			),
			__( 'Renew the certificate before it expires. Let\'s Encrypt certificates can be renewed up to 30 days early without affecting the next cycle.', 'shieldscope-site-security-scanner' ),
			$host,
			array( 'days_left' => $days_left, 'expiry' => $expiry_date )
		);
	}

	// -----------------------------------------------------------------------
	// Step: TLS version support
	// -----------------------------------------------------------------------

	/**
	 * Check whether the server accepts deprecated TLS 1.0 or TLS 1.1 connections.
	 *
	 * Uses cURL directly so we can control the exact TLS version negotiated.
	 * Falls back to INFO if cURL or the required constants are unavailable.
	 *
	 * @return void
	 */
	private function check_tls_version() {
		$host = $this->get_https_host();
		if ( '' === $host ) {
			return;
		}

		if ( ! function_exists( 'curl_init' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				__( 'TLS version check skipped — cURL not available', 'shieldscope-site-security-scanner' ),
				__( 'The cURL PHP extension is required to probe TLS version support. It is not loaded on this server.', 'shieldscope-site-security-scanner' ),
				__( 'Enable the cURL extension in php.ini for TLS version scanning.', 'shieldscope-site-security-scanner' )
			);
			return;
		}

		$deprecated = array(
			// TLS 1.0 — deprecated by PCI DSS since 2018, RFC 8996 (2021).
			'TLS 1.0' => defined( 'CURL_SSLVERSION_TLSv1_0' ) ? CURL_SSLVERSION_TLSv1_0 : 4,
			// TLS 1.1 — deprecated by RFC 8996 (2021).
			'TLS 1.1' => defined( 'CURL_SSLVERSION_TLSv1_1' ) ? CURL_SSLVERSION_TLSv1_1 : 5,
		);

		$url = 'https://' . $host . '/';

		// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init,WordPress.WP.AlternativeFunctions.curl_curl_setopt,WordPress.WP.AlternativeFunctions.curl_curl_exec,WordPress.WP.AlternativeFunctions.curl_curl_getinfo,WordPress.WP.AlternativeFunctions.curl_curl_errno,WordPress.WP.AlternativeFunctions.curl_curl_close
		// Rationale: wp_remote_get() does not expose CURLOPT_SSLVERSION, which is the only
		// way to force a specific TLS protocol version for the handshake probe. Raw cURL is
		// required here and cannot be replaced with a WP HTTP API call.
		foreach ( $deprecated as $label => $curl_version ) {
			$ch = curl_init( $url );
			if ( ! is_resource( $ch ) && ! ( is_object( $ch ) ) ) {
				continue;
			}

			curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
			curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt( $ch, CURLOPT_SSLVERSION, $curl_version );
			curl_setopt( $ch, CURLOPT_TIMEOUT, 8 );
			curl_setopt( $ch, CURLOPT_NOBODY, true );
			curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, false );

			@curl_exec( $ch ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$http_code  = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
			$curl_error = curl_errno( $ch );
			curl_close( $ch );
		// phpcs:enable WordPress.WP.AlternativeFunctions.curl_curl_init,WordPress.WP.AlternativeFunctions.curl_curl_setopt,WordPress.WP.AlternativeFunctions.curl_curl_exec,WordPress.WP.AlternativeFunctions.curl_curl_getinfo,WordPress.WP.AlternativeFunctions.curl_curl_errno,WordPress.WP.AlternativeFunctions.curl_curl_close

			// A non-zero HTTP code (any response) means the handshake succeeded
			// and the server accepted this deprecated TLS version.
			if ( 0 === $curl_error && $http_code > 0 ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_MEDIUM,
					sprintf(
						/* translators: %s: TLS version label e.g. "TLS 1.0" */
						__( 'Server accepts deprecated %s connections', 'shieldscope-site-security-scanner' ),
						$label
					),
					sprintf(
						/* translators: %s: TLS version label */
						__( 'The server completed a TLS handshake using %s, which is deprecated by RFC 8996 and prohibited by PCI DSS. Known attacks (BEAST, POODLE variants) target these versions.', 'shieldscope-site-security-scanner' ),
						$label
					),
					__( 'Disable TLS 1.0 and TLS 1.1 in your web server configuration. For Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1. For Nginx: ssl_protocols TLSv1.2 TLSv1.3;', 'shieldscope-site-security-scanner' ),
					$host,
					array( 'tls_version' => $label )
				);
			}
		}
	}

	// -----------------------------------------------------------------------
	// Step: Mixed content
	// -----------------------------------------------------------------------

	/**
	 * Fetch the homepage HTML and detect mixed content (HTTP resources on HTTPS page).
	 *
	 * Scans src, href, action, data-src, and data-href attributes for http:// URLs
	 * pointing to assets (scripts, styles, images, iframes, forms). Skips anchor
	 * links to external HTTP pages, which are a privacy issue but not mixed content.
	 *
	 * @return void
	 */
	private function check_mixed_content() {
		$host = $this->get_https_host();
		if ( '' === $host ) {
			return; // Not on HTTPS — mixed content is not applicable.
		}

		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 8,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound,
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( ! $body ) {
			return;
		}

		// Match resource-loading attributes only — not <a href> plain links.
		// Covered tags: <script src>, <link href>, <img src>, <iframe src>,
		//               <form action>, <source src>, data-src, data-href.
		$pattern = '/\b(?:src|action|data-src|data-href)\s*=\s*["\']http:\/\//i';
		$count   = preg_match_all( $pattern, $body );

		// Also catch <link rel="stylesheet" href="http://...">
		$link_count = preg_match_all( '/<link\b[^>]*\bhref\s*=\s*["\']http:\/\//i', $body );
		$count     += (int) $link_count;

		if ( $count > 0 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Mixed content detected — HTTP resources loaded on HTTPS page', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %d: number of mixed-content references found */
					_n(
						'Found %d HTTP resource reference on the HTTPS homepage. Browsers block or warn on mixed active content (scripts, stylesheets, iframes), reducing page security to HTTP level.',
						'Found %d HTTP resource references on the HTTPS homepage. Browsers block or warn on mixed active content (scripts, stylesheets, iframes), reducing page security to HTTP level.',
						$count,
						'shieldscope-site-security-scanner'
					),
					$count
				),
				__( 'Replace all HTTP asset URLs with HTTPS equivalents. Check plugin/theme settings, hardcoded URLs in the database (use Better Search Replace to update), and ensure WordPress Address and Site Address both use https://.', 'shieldscope-site-security-scanner' ),
				home_url( '/' ),
				array( 'mixed_content_count' => $count )
			);
		}
	}
}
