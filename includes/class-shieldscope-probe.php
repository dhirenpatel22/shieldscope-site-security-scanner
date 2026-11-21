<?php
/**
 * Read-only HTTP probe of the site's own URLs.
 *
 * Answers "does the site serve this file to visitors?" without false alarms:
 *  - GET only, and redirects are never followed, so a site that redirects
 *    unknown paths to the homepage is not read as serving the file;
 *  - the body must match a content signature, so an empty 200 (PHP ran the
 *    file) or a themed page is not read as the file itself;
 *  - the answer is compared with a random path that does not exist in the
 *    same folder, so a site that answers every path with the same 200 page
 *    (a "soft 404") is not reported.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Probe
 */
class ShieldScope_Probe {

	/**
	 * Seconds to wait for each request.
	 */
	const TIMEOUT = 5;

	/**
	 * Most bytes read from a response body (a large debug.log must not
	 * exhaust memory; every signature appears near the start).
	 */
	const MAX_BYTES = 65536;

	/**
	 * Soft-404 baseline responses, keyed by folder URL and file extension.
	 *
	 * @var array
	 */
	private $baselines = array();

	/**
	 * GET a URL without following redirects.
	 *
	 * @param string $url URL on this site.
	 * @return array|null { 'code' => int, 'body' => string }, or null if the request failed.
	 */
	public function get( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'             => self::TIMEOUT,
				'redirection'         => 0,
				'limit_response_size' => self::MAX_BYTES,
				'sslverify'           => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
			)
		);
		if ( is_wp_error( $response ) ) {
			return null;
		}
		return array(
			'code' => (int) wp_remote_retrieve_response_code( $response ),
			'body' => (string) wp_remote_retrieve_body( $response ),
		);
	}

	/**
	 * Does the site serve this URL with content matching the signature?
	 *
	 * @param string $url       URL on this site.
	 * @param string $signature Regex the body must match.
	 * @return bool
	 */
	public function serves( $url, $signature ) {
		$response = $this->get( $url );
		if ( null === $response || 200 !== $response['code'] || ! preg_match( $signature, $response['body'] ) ) {
			return false;
		}

		$baseline = $this->baseline( $url );
		if ( null !== $baseline && 200 === $baseline['code'] && ( $baseline['body'] === $response['body'] || preg_match( $signature, $baseline['body'] ) ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Response for a random, non-existent file in the same folder as $url,
	 * with the same extension (servers often treat extensions differently).
	 *
	 * @param string $url Probed URL.
	 * @return array|null As get().
	 */
	private function baseline( $url ) {
		$slash  = strrpos( $url, '/' );
		$folder = substr( $url, 0, $slash + 1 );
		$name   = substr( $url, $slash + 1 );
		$dot    = strrpos( $name, '.' );
		$ext    = false !== $dot ? substr( $name, $dot ) : '';
		$key    = $folder . '|' . $ext;

		if ( ! array_key_exists( $key, $this->baselines ) ) {
			$random                  = 'shieldscope-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . $ext;
			$this->baselines[ $key ] = $this->get( $folder . $random );
		}
		return $this->baselines[ $key ];
	}
}
