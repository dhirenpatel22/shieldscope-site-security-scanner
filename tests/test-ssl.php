<?php
/**
 * Tests for ShieldScope_Check_SSL (ticket A-07: SSL check accuracy).
 *
 * Regressions covered:
 *  - TLS 1.0/1.1 probes only set a minimum version, so every TLS 1.2/1.3 site
 *    was reported as "accepts deprecated TLS 1.0/1.1".
 *  - A refusal by the local TLS library was read as "server rejects it".
 *  - The certificate was read with verification off, so self-signed and
 *    wrong-host certificates were reported as valid.
 *  - Mixed content counted <link rel="profile" href="http://gmpg.org/..."> and
 *    other non-loaded references.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

// Stubs missing from tests/wp-stubs.php (owned by another ticket), defined here.
if ( ! function_exists( 'get_site_url' ) ) {
	function get_site_url() {
		list( $hit, $result ) = ss_tests_maybe_override( 'get_site_url', array() );
		return $hit ? $result : 'https://shop.example.test';
	}
}
if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) {
		return rtrim( get_site_url(), '/' ) . $path;
	}
}
if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component ); // phpcs:ignore
	}
}
if ( ! function_exists( 'remove_action' ) ) {
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
}
if ( ! function_exists( 'wp_remote_head' ) ) {
	function wp_remote_head( $url, $args = array() ) {
		list( $hit, $result ) = ss_tests_maybe_override( 'wp_remote_head', array( $url, $args ) );
		if ( $hit ) {
			return $result;
		}
		return new WP_Error( 'no_network', 'Network disabled in tests' );
	}
}
if ( ! function_exists( '_n' ) ) {
	function _n( $single, $plural, $number, $domain = 'default' ) {
		return 1 === (int) $number ? $single : $plural;
	}
}

/**
 * SSL check with the network seams replaced by canned results.
 */
class SS_Test_SSL_Check extends ShieldScope_Check_SSL {

	/** @var array[] Canned probe results keyed by TLS label, e.g. 'TLS 1.0'. */
	public $probe_results = array();

	/** @var int[] CURLOPT_SSLVERSION values passed to each probe. */
	public $probed_versions = array();

	/** @var array Canned connect_tls() results keyed by 'verify' / 'noverify'. */
	public $connect_results = array();

	protected function probe_tls( $url, $ssl_version ) {
		// CURL_SSLVERSION_TLSv1_0 | MAX_TLSv1_0 = 262148; TLSv1_1 | MAX_TLSv1_1 = 327685.
		$label                           = 262148 === $ssl_version ? 'TLS 1.0' : 'TLS 1.1';
		$this->probed_versions[ $label ] = $ssl_version;
		return $this->probe_results[ $label ];
	}

	protected function connect_tls( $host, $verify ) {
		return $this->connect_results[ $verify ? 'verify' : 'noverify' ];
	}

	public static function negotiated_from_log( $log ) {
		return self::parse_negotiated_protocol( $log );
	}
}

/**
 * Class Test_A07_SSL
 */
class Test_A07_SSL extends TestCase {

	/** @var SS_Fake_Logger */
	private $logger;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->logger = new SS_Fake_Logger();
	}

	private function titles() {
		return array_column( $this->logger->findings, 'title' );
	}

	// ------------------------------------------------------------------
	// TLS version probes
	// ------------------------------------------------------------------

	/**
	 * A TLS 1.2+-only server answers the old minimum-only probe with a normal
	 * HTTP response (the handshake silently upgrades). That must not be read
	 * as "accepts TLS 1.0/1.1".
	 */
	public function test_tls12_only_site_answering_probe_is_not_reported_deprecated() {
		if ( ! function_exists( 'curl_init' ) ) {
			$this->markTestSkipped( 'cURL extension not loaded.' );
		}
		ss_tests_override(
			'wp_remote_head',
			function () {
				return array( 'response' => array( 'code' => 200 ), 'body' => '' );
			}
		);

		$check = new ShieldScope_Check_SSL( 1, $this->logger );
		$check->run_step( 'tls_version' );

		$this->assertSame( array(), $this->logger->of_severity( ShieldScope_Logger::SEVERITY_MEDIUM ) );
	}

	public function test_probes_pin_both_minimum_and_maximum_version() {
		$check                = new SS_Test_SSL_Check( 1, $this->logger );
		$check->probe_results = array(
			'TLS 1.0' => array( 'error' => '', 'negotiated' => 'TLSv1.2' ),
			'TLS 1.1' => array( 'error' => '', 'negotiated' => 'TLSv1.2' ),
		);
		$check->run_step( 'tls_version' );

		// CURL_SSLVERSION_TLSv1_0 (4) | CURL_SSLVERSION_MAX_TLSv1_0 (262144).
		$this->assertSame( 262148, $check->probed_versions['TLS 1.0'] );
		// CURL_SSLVERSION_TLSv1_1 (5) | CURL_SSLVERSION_MAX_TLSv1_1 (327680).
		$this->assertSame( 327685, $check->probed_versions['TLS 1.1'] );
	}

	public function test_handshake_that_negotiated_tls12_yields_no_finding() {
		$check                = new SS_Test_SSL_Check( 1, $this->logger );
		$check->probe_results = array(
			'TLS 1.0' => array( 'error' => '', 'negotiated' => 'TLSv1.2' ),
			'TLS 1.1' => array( 'error' => '', 'negotiated' => 'TLSv1.3' ),
		);
		$check->run_step( 'tls_version' );

		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_confirmed_tls10_handshake_is_reported() {
		$check                = new SS_Test_SSL_Check( 1, $this->logger );
		$check->probe_results = array(
			'TLS 1.0' => array( 'error' => '', 'negotiated' => 'TLSv1' ),
			'TLS 1.1' => array( 'error' => 'cURL error 35: error:0A00042E:SSL routines::tlsv1 alert protocol version', 'negotiated' => '' ),
		);
		$check->run_step( 'tls_version' );

		$this->assertSame( array( 'Server accepts deprecated TLS 1.0 connections' ), $this->titles() );
		$this->assertSame( ShieldScope_Logger::SEVERITY_MEDIUM, $this->logger->findings[0]['severity'] );
	}

	public function test_server_rejection_yields_no_finding() {
		$check                = new SS_Test_SSL_Check( 1, $this->logger );
		$check->probe_results = array(
			'TLS 1.0' => array( 'error' => 'cURL error 35: error:0A00042E:SSL routines::tlsv1 alert protocol version', 'negotiated' => '' ),
			'TLS 1.1' => array( 'error' => 'cURL error 35: error:0A000102:SSL routines::unsupported protocol', 'negotiated' => '' ),
		);
		$check->run_step( 'tls_version' );

		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_refusal_by_local_tls_library_is_unknown_not_safe_or_unsafe() {
		$error                = 'cURL error 35: TLS connect error: error:0A0000BF:SSL routines::no protocols available';
		$check                = new SS_Test_SSL_Check( 1, $this->logger );
		$check->probe_results = array(
			'TLS 1.0' => array( 'error' => $error, 'negotiated' => '' ),
			'TLS 1.1' => array( 'error' => $error, 'negotiated' => '' ),
		);
		$check->run_step( 'tls_version' );

		$this->assertSame( array(), $this->logger->of_severity( ShieldScope_Logger::SEVERITY_MEDIUM ) );
		$info = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_INFO );
		$this->assertCount( 2, $info );
		$this->assertSame( 'TLS 1.0 support could not be determined', $info[0]['title'] );
		$this->assertSame( 'TLS 1.1 support could not be determined', $info[1]['title'] );
		$this->assertSame( $error, $info[0]['context']['error'] );
	}

	public function test_handshake_without_readable_negotiated_version_is_unknown() {
		$check                = new SS_Test_SSL_Check( 1, $this->logger );
		$check->probe_results = array(
			'TLS 1.0' => array( 'error' => '', 'negotiated' => '' ),
			'TLS 1.1' => array( 'error' => '', 'negotiated' => 'TLSv1.2' ),
		);
		$check->run_step( 'tls_version' );

		$this->assertSame( array( 'TLS 1.0 support could not be determined' ), $this->titles() );
	}

	/**
	 * @dataProvider verbose_logs
	 */
	public function test_negotiated_protocol_is_read_from_curl_verbose_log( $log, $expected ) {
		$this->assertSame( $expected, SS_Test_SSL_Check::negotiated_from_log( $log ) );
	}

	public static function verbose_logs() {
		return array(
			'TLS 1.0'      => array( "* ALPN: curl offers h2\n* SSL connection using TLSv1 / ECDHE-RSA-AES128-SHA\n", 'TLSv1' ),
			'TLS 1.1'      => array( "* SSL connection using TLSv1.1 / ECDHE-RSA-AES128-SHA\n", 'TLSv1.1' ),
			'TLS 1.3'      => array( "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768\n", 'TLSv1.3' ),
			'nothing'      => array( '', '' ),
			'other format' => array( "* schannel: connection established\n", '' ),
		);
	}

	// ------------------------------------------------------------------
	// Certificate trust
	// ------------------------------------------------------------------

	/**
	 * Self-signed certificate valid for the given number of days.
	 *
	 * @param int $days Validity in days.
	 * @return mixed OpenSSL certificate.
	 */
	private function make_cert( $days ) {
		if ( ! function_exists( 'openssl_pkey_new' ) ) {
			$this->markTestSkipped( 'openssl extension not loaded.' );
		}
		$key  = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
		$csr  = openssl_csr_new( array( 'commonName' => 'shop.example.test' ), $key );
		$cert = openssl_csr_sign( $csr, null, $key, $days );
		$this->assertNotFalse( $cert );
		return $cert;
	}

	public function test_untrusted_certificate_is_reported_with_the_error() {
		$error                  = 'SSL operation failed with code 1. OpenSSL Error messages: error:0A000086:SSL routines::certificate verify failed';
		$check                  = new SS_Test_SSL_Check( 1, $this->logger );
		$check->connect_results = array(
			'noverify' => array( 'cert' => $this->make_cert( 90 ), 'error' => '' ),
			'verify'   => array( 'cert' => null, 'error' => $error ),
		);
		$check->run_step( 'cert_expiry' );

		$high = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $high );
		$this->assertSame( 'SSL certificate is not trusted or does not match the hostname', $high[0]['title'] );
		$this->assertStringContainsString( 'certificate verify failed', $high[0]['description'] );
		$this->assertSame( $error, $high[0]['context']['error'] );
		// Must not also call the certificate "valid".
		$this->assertSame( array(), $this->logger->of_severity( ShieldScope_Logger::SEVERITY_INFO ) );
	}

	public function test_hostname_mismatch_is_reported() {
		$error                  = "Peer certificate CN=`*.example.test' did not match expected CN=`shop.example.test'";
		$check                  = new SS_Test_SSL_Check( 1, $this->logger );
		$check->connect_results = array(
			'noverify' => array( 'cert' => $this->make_cert( 90 ), 'error' => '' ),
			'verify'   => array( 'cert' => null, 'error' => $error ),
		);
		$check->run_step( 'cert_expiry' );

		$this->assertSame( array( 'SSL certificate is not trusted or does not match the hostname' ), $this->titles() );
	}

	public function test_trusted_certificate_is_reported_valid() {
		$cert                   = $this->make_cert( 90 );
		$check                  = new SS_Test_SSL_Check( 1, $this->logger );
		$check->connect_results = array(
			'noverify' => array( 'cert' => $cert, 'error' => '' ),
			'verify'   => array( 'cert' => $cert, 'error' => '' ),
		);
		$check->run_step( 'cert_expiry' );

		$this->assertCount( 1, $this->logger->findings );
		$this->assertSame( ShieldScope_Logger::SEVERITY_INFO, $this->logger->findings[0]['severity'] );
		$this->assertStringStartsWith( 'SSL certificate is valid', $this->logger->findings[0]['title'] );
	}

	public function test_verified_connection_failing_for_a_network_reason_is_not_a_trust_finding() {
		$cert                   = $this->make_cert( 90 );
		$check                  = new SS_Test_SSL_Check( 1, $this->logger );
		$check->connect_results = array(
			'noverify' => array( 'cert' => $cert, 'error' => '' ),
			'verify'   => array( 'cert' => null, 'error' => 'Unable to connect to ssl://shop.example.test:443 (Connection timed out)' ),
		);
		$check->run_step( 'cert_expiry' );

		$this->assertSame( array(), $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH ) );
	}

	// ------------------------------------------------------------------
	// Mixed content
	// ------------------------------------------------------------------

	private function run_mixed_content( $html ) {
		ss_tests_override(
			'wp_remote_get',
			function () use ( $html ) {
				return array( 'response' => array( 'code' => 200 ), 'body' => $html );
			}
		);
		$check = new ShieldScope_Check_SSL( 1, $this->logger );
		$check->run_step( 'mixed_content' );
	}

	public function test_non_loaded_http_references_are_not_mixed_content() {
		$this->run_mixed_content(
			'<html><head>'
			. '<link rel="profile" href="http://gmpg.org/xfn/11">'
			. '<link rel="preconnect" href="http://fonts.example.test">'
			. '<link rel="alternate" type="application/rss+xml" href="http://shop.example.test/feed/">'
			. '</head><body>'
			. '<a href="http://other.example.test/">link</a>'
			. '<img data-src="http://cdn.example.test/lazy.jpg" src="https://cdn.example.test/ph.gif">'
			. '<script src="https://cdn.example.test/app.js"></script>'
			. '</body></html>'
		);

		$this->assertSame( array(), $this->logger->findings );
	}

	public function test_loaded_http_resources_are_counted() {
		$this->run_mixed_content(
			'<html><head>'
			. '<link rel="profile" href="http://gmpg.org/xfn/11">'
			. "<link rel='stylesheet' id='x-css' href='http://cdn.example.test/a.css' media='all'>"
			. '<script type="text/javascript" src="http://cdn.example.test/a.js"></script>'
			. '</head><body>'
			. '<IMG alt="" SRC="http://cdn.example.test/b.png">'
			. '<iframe width="1" src=http://embed.example.test/></iframe>'
			. '<form method="post" action="http://shop.example.test/subscribe"></form>'
			. '<a href="http://other.example.test/">link</a>'
			. '</body></html>'
		);

		$high = $this->logger->of_severity( ShieldScope_Logger::SEVERITY_HIGH );
		$this->assertCount( 1, $high );
		$this->assertSame( 5, $high[0]['context']['mixed_content_count'] );
	}

	public function test_http_only_site_runs_no_ssl_checks() {
		ss_tests_override(
			'get_site_url',
			function () {
				return 'http://shop.example.test';
			}
		);
		$check = new ShieldScope_Check_SSL( 1, $this->logger );
		foreach ( $check->get_steps() as $step ) {
			$check->run_step( $step );
		}

		$this->assertSame( array(), $this->logger->findings );
	}
}
