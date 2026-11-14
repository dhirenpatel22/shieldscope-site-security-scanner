<?php
/**
 * SSL / TLS security checks.
 *
 * Covers three areas that cannot be assessed from WordPress internals alone:
 *
 *  cert_expiry   — Connects to the site's HTTPS port, reads the TLS certificate,
 *                  and flags certificates that are expired or expiring soon. A
 *                  second connection with verification on flags certificates
 *                  that are not trusted or do not match the hostname.
 *
 *  tls_version   — Probes whether the server accepts TLS 1.0 or TLS 1.1 (both
 *                  deprecated/insecure) via the WP HTTP API with the http_api_curl
 *                  hook to pin CURLOPT_SSLVERSION (minimum and maximum) when cURL
 *                  is available, and confirms the negotiated version.
 *
 *  mixed_content — Fetches the homepage HTML and counts resources the browser
 *                  loads over HTTP (scripts, stylesheets, iframes, images, forms).
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

		$connection = $this->connect_tls( $host, false );
		if ( null === $connection['cert'] ) {
			// Cannot connect — could be a firewall or non-standard port; skip silently.
			return;
		}

		$cert_info = openssl_x509_parse( $connection['cert'] );
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

		$trusted = $this->check_cert_trust( $host );

		if ( $days_left <= 7 ) {
			$severity = ShieldScope_Logger::SEVERITY_HIGH;
		} elseif ( $days_left <= 14 ) {
			$severity = ShieldScope_Logger::SEVERITY_MEDIUM;
		} elseif ( $days_left <= 30 ) {
			$severity = ShieldScope_Logger::SEVERITY_LOW;
		} else {
			if ( ! $trusted ) {
				return; // Already reported as untrusted; do not also call it valid.
			}
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

	/**
	 * Connect a second time with certificate and hostname verification on, and
	 * report a certificate that browsers will not trust.
	 *
	 * @param string $host Site hostname.
	 * @return bool False when verification failed because of the certificate.
	 */
	private function check_cert_trust( $host ) {
		$verified = $this->connect_tls( $host, true );
		if ( null !== $verified['cert'] ) {
			return true;
		}

		// Only a certificate error is a trust problem; a timeout or reset is not.
		if ( ! preg_match( '/certificate|did not match/i', $verified['error'] ) ) {
			return true;
		}

		$this->finding(
			ShieldScope_Logger::SEVERITY_HIGH,
			__( 'SSL certificate is not trusted or does not match the hostname', 'shieldscope-site-security-scanner' ),
			sprintf(
				/* translators: 1: hostname, 2: TLS error message */
				__( 'A connection to %1$s with certificate verification turned on failed: %2$s. Browsers show a security warning for this certificate (for example a self-signed certificate, a missing intermediate certificate or a certificate issued for another hostname).', 'shieldscope-site-security-scanner' ),
				$host,
				$verified['error']
			),
			__( 'Install a certificate from a trusted certificate authority that covers this hostname, including the full intermediate chain. Let\'s Encrypt certificates are free and most hosting panels can issue them.', 'shieldscope-site-security-scanner' ),
			$host,
			array( 'error' => $verified['error'] )
		);
		return false;
	}

	/**
	 * Open a TLS connection to the host and capture the peer certificate.
	 *
	 * @param string $host   Site hostname.
	 * @param bool   $verify Verify the certificate chain and hostname.
	 * @return array{cert: mixed, error: string} Certificate (null on failure) and the TLS error message.
	 */
	protected function connect_tls( $host, $verify ) {
		$ssl = array(
			'capture_peer_cert' => true,
			'verify_peer'       => $verify,
			'verify_peer_name'  => $verify,
			'peer_name'         => $host,
		);
		// Use the CA bundle WordPress ships for its own HTTPS requests, so the
		// result does not depend on the server's php.ini CA configuration.
		if ( $verify && defined( 'WPINC' ) && file_exists( ABSPATH . WPINC . '/certificates/ca-bundle.crt' ) ) {
			$ssl['cafile'] = ABSPATH . WPINC . '/certificates/ca-bundle.crt';
		}

		// stream_socket_client() reports TLS failures only as PHP warnings; collect
		// them so the caller can tell a certificate error from a network error.
		$messages = array();
		set_error_handler( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- scoped to this call, restored below.
			static function ( $errno, $errstr ) use ( &$messages ) {
				$messages[] = preg_replace( '/^stream_socket_client\(\):\s*/', '', (string) $errstr );
				return true;
			}
		);
		$client = stream_socket_client(
			'ssl://' . $host . ':443',
			$errno,
			$errstr,
			10,
			STREAM_CLIENT_CONNECT,
			stream_context_create( array( 'ssl' => $ssl ) )
		);
		restore_error_handler();

		if ( ! is_resource( $client ) ) {
			// The first warning names the cause; the ones after it are generic.
			$error = '' !== (string) $errstr ? (string) $errstr : (string) reset( $messages );
			return array( 'cert' => null, 'error' => trim( preg_replace( '/\s+/', ' ', $error ) ) );
		}

		$params = stream_context_get_params( $client );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closing a socket stream, not a file; WP_Filesystem has no socket equivalent.
		fclose( $client );

		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			return array( 'cert' => null, 'error' => '' );
		}
		return array( 'cert' => $params['options']['ssl']['peer_certificate'], 'error' => '' );
	}

	// -----------------------------------------------------------------------
	// Step: TLS version support
	// -----------------------------------------------------------------------

	/**
	 * Check whether the server accepts deprecated TLS 1.0 or TLS 1.1 connections.
	 *
	 * Each probe pins cURL to exactly one version (minimum and maximum), and a
	 * finding is raised only when the handshake succeeded and the negotiated
	 * version read back from cURL is that version. A failure that is not a clear
	 * rejection by the server (for example the local TLS library refusing to
	 * offer TLS 1.0/1.1 at all) is reported as INFO "could not be determined".
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
			'TLS 1.0' => array(
				'version'  => ( defined( 'CURL_SSLVERSION_TLSv1_0' ) ? CURL_SSLVERSION_TLSv1_0 : 4 ) | ( defined( 'CURL_SSLVERSION_MAX_TLSv1_0' ) ? CURL_SSLVERSION_MAX_TLSv1_0 : 262144 ),
				'protocol' => 'TLSv1',
			),
			// TLS 1.1 — deprecated by RFC 8996 (2021).
			'TLS 1.1' => array(
				'version'  => ( defined( 'CURL_SSLVERSION_TLSv1_1' ) ? CURL_SSLVERSION_TLSv1_1 : 5 ) | ( defined( 'CURL_SSLVERSION_MAX_TLSv1_1' ) ? CURL_SSLVERSION_MAX_TLSv1_1 : 327680 ),
				'protocol' => 'TLSv1.1',
			),
		);

		$url = 'https://' . $host . '/';

		foreach ( $deprecated as $label => $probe ) {
			$result = $this->probe_tls( $url, $probe['version'] );

			if ( '' !== $result['error'] ) {
				// The server answered the handshake with a protocol-version refusal.
				if ( preg_match( '/alert protocol version|unsupported protocol/i', $result['error'] ) ) {
					continue;
				}
				$this->tls_unknown_finding( $host, $label, $result['error'] );
				continue;
			}

			if ( '' === $result['negotiated'] ) {
				$this->tls_unknown_finding( $host, $label, '' );
				continue;
			}

			if ( $probe['protocol'] !== $result['negotiated'] ) {
				continue; // cURL negotiated a newer version than requested; not an acceptance.
			}

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

	/**
	 * Record that support for a TLS version could not be determined.
	 *
	 * @param string $host  Site hostname.
	 * @param string $label TLS version label e.g. "TLS 1.0".
	 * @param string $error Error from the probe, or '' when the handshake result was unreadable.
	 * @return void
	 */
	private function tls_unknown_finding( $host, $label, $error ) {
		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			sprintf(
				/* translators: %s: TLS version label e.g. "TLS 1.0" */
				__( '%s support could not be determined', 'shieldscope-site-security-scanner' ),
				$label
			),
			'' !== $error
				? sprintf(
					/* translators: 1: TLS version label, 2: error message */
					__( 'The %1$s test connection failed before the server could accept or refuse it, often because this server\'s own TLS library no longer offers %1$s. Error: %2$s', 'shieldscope-site-security-scanner' ),
					$label,
					$error
				)
				: sprintf(
					/* translators: %s: TLS version label */
					__( 'The %s test connection completed, but the negotiated TLS version could not be read back, so the result is not reliable.', 'shieldscope-site-security-scanner' ),
					$label
				),
			__( 'Check the enabled TLS versions with an external TLS scanner, or in your web server configuration.', 'shieldscope-site-security-scanner' ),
			$host,
			array( 'tls_version' => $label, 'error' => $error )
		);
	}

	/**
	 * Make one HEAD request with cURL pinned to a TLS version range.
	 *
	 * CURLOPT_SSLVERSION is not a first-class WP HTTP API option, so it is set via
	 * the http_api_curl action. cURL's verbose log is captured to read back the
	 * negotiated version, because PHP's curl_getinfo() does not expose it.
	 *
	 * @param string $url         HTTPS URL to request.
	 * @param int    $ssl_version CURLOPT_SSLVERSION value (minimum | maximum).
	 * @return array{error: string, negotiated: string} WP_Error message ('' on success) and the negotiated protocol ('' if unknown).
	 */
	protected function probe_tls( $url, $ssl_version ) {
		$log      = tmpfile();
		$set_opts = function ( $handle ) use ( $ssl_version, $log ) {
			curl_setopt( $handle, CURLOPT_SSLVERSION, $ssl_version ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
			if ( false !== $log ) {
				curl_setopt( $handle, CURLOPT_VERBOSE, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
				curl_setopt( $handle, CURLOPT_STDERR, $log ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt
			}
		};

		add_action( 'http_api_curl', $set_opts );
		$response = wp_remote_head(
			$url,
			array(
				'timeout'     => 8,
				'sslverify'   => false,
				'redirection' => 0,
			)
		);
		remove_action( 'http_api_curl', $set_opts );

		$verbose = '';
		if ( false !== $log ) {
			rewind( $log );
			$verbose = (string) stream_get_contents( $log );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- temporary stream for cURL's verbose log.
			fclose( $log );
		}

		if ( is_wp_error( $response ) ) {
			return array( 'error' => $response->get_error_message(), 'negotiated' => '' );
		}
		return array( 'error' => '', 'negotiated' => self::parse_negotiated_protocol( $verbose ) );
	}

	/**
	 * Read the negotiated protocol from cURL's verbose log.
	 *
	 * @param string $verbose cURL verbose output.
	 * @return string e.g. "TLSv1", "TLSv1.2", or '' when the log has no such line.
	 */
	protected static function parse_negotiated_protocol( $verbose ) {
		if ( preg_match( '/SSL connection using (TLSv1(?:\.[0-3])?|SSLv3)\b/', $verbose, $m ) ) {
			return $m[1];
		}
		return '';
	}

	// -----------------------------------------------------------------------
	// Step: Mixed content
	// -----------------------------------------------------------------------

	/**
	 * Fetch the homepage HTML and detect mixed content (HTTP resources on HTTPS page).
	 *
	 * Counts only references the browser loads or submits over http://:
	 * <script src>, <link rel="stylesheet" href>, <iframe src>, <img src> and
	 * <form action>. Plain links and metadata such as <link rel="profile"> are
	 * not mixed content.
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

		$count = self::count_mixed_content( $body );

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

	/**
	 * Count resources in the HTML that the browser would load or submit over http://.
	 *
	 * @param string $html Page HTML.
	 * @return int
	 */
	private static function count_mixed_content( $html ) {
		// Attribute value starting with http:// (quoted or unquoted). The leading
		// \s keeps data-src and similar attributes from matching.
		$http_attr = '\s%s\s*=\s*["\']?http:\/\/';

		$count = 0;
		foreach ( array( 'script' => 'src', 'iframe' => 'src', 'img' => 'src', 'form' => 'action' ) as $tag => $attr ) {
			$count += (int) preg_match_all( '/<' . $tag . '\b[^>]*' . sprintf( $http_attr, $attr ) . '/i', $html );
		}

		if ( preg_match_all( '/<link\b[^>]*>/i', $html, $links ) ) {
			foreach ( $links[0] as $link ) {
				if ( preg_match( '/\srel\s*=\s*["\']?[^"\'>]*\bstylesheet\b/i', $link )
					&& preg_match( '/' . sprintf( $http_attr, 'href' ) . '/i', $link ) ) {
					++$count;
				}
			}
		}

		return $count;
	}
}
