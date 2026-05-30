<?php
/**
 * Database configuration checks.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Database
 */
class ShieldScope_Check_Database extends ShieldScope_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'database';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Database', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'unknown_admins', 'suspicious_options' );
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
			case 'unknown_admins':
				$this->check_unknown_admins();
				break;
			case 'suspicious_options':
				$this->check_suspicious_options();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Very-recently-created admin accounts (possible compromise indicator).
	 *
	 * @return void
	 */
	private function check_unknown_admins() {
		$since   = gmdate( 'Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ) );
		$recent  = get_users(
			array(
				'role'     => 'administrator',
				'number'   => 20,
				'date_query' => array(
					array(
						'after' => $since,
					),
				),
			)
		);

		foreach ( (array) $recent as $u ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Administrator created in the last 7 days', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: login, 2: date */
					__( "Administrator '%1\$s' was created on %2\$s. If you did not create this account, your site may be compromised.", 'shieldscope-site-security-scanner' ),
					$u->user_login,
					$u->user_registered
				),
				__( 'If you did not create this account, treat it as a compromise. Delete it via Users → All Users, change all admin passwords, and regenerate your auth salts in wp-config.php (get fresh keys at https://api.wordpress.org/secret-key/1.1/salt/). Contact your host if you cannot determine how the account was created.', 'shieldscope-site-security-scanner' ),
				'user:' . $u->ID
			);
		}
	}

	/**
	 * Options that are not permitted to be modified suspiciously.
	 *
	 * @return void
	 */
	private function check_suspicious_options() {
		// Admins registerable to anyone is risky.
		if ( get_option( 'users_can_register' ) && 'administrator' === get_option( 'default_role' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'Open registration with administrator default role', 'shieldscope-site-security-scanner' ),
				__( 'Anyone can register and is automatically granted administrator. This is almost certainly a compromise.', 'shieldscope-site-security-scanner' ),
				__( 'Go to Settings → General and either disable "Anyone can register" or change the default role from Administrator to Subscriber. Then go to Users → All Users, filter by Administrator, and delete any accounts you do not recognise.', 'shieldscope-site-security-scanner' )
			);
		}

		// Unexpected siteurl/home mismatch.
		$site_url = get_option( 'siteurl' );
		$home     = get_option( 'home' );
		if ( $site_url && $home ) {
			$site_host = wp_parse_url( $site_url, PHP_URL_HOST );
			$home_host = wp_parse_url( $home, PHP_URL_HOST );
			if ( $site_host && $home_host && $site_host !== $home_host ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_HIGH,
					__( 'siteurl and home point to different domains', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: 1: siteurl, 2: home */
						__( 'siteurl (%1$s) and home (%2$s) resolve to different hosts. Malware often sets one of these to an attacker-controlled domain.', 'shieldscope-site-security-scanner' ),
						$site_url,
						$home
					),
					__( 'Go to Settings → General and verify both WordPress Address and Site Address point to your own domain. If either was changed to an unknown domain, revert it and change all admin passwords immediately. Also check wp-config.php for WP_HOME or WP_SITEURL constants that may be overriding the values.', 'shieldscope-site-security-scanner' )
				);
			}
		}
	}
}
