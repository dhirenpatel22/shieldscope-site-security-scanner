<?php
/**
 * Database configuration checks.
 *
 * @package Site_Security_Audit
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class SSA_Check_Database
 */
class SSA_Check_Database extends SSA_Check_Base {

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
		return __( 'Database', 'site-security-audit' );
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
				SSA_Logger::SEVERITY_MEDIUM,
				__( 'Administrator created in the last 7 days', 'site-security-audit' ),
				sprintf(
					/* translators: 1: login, 2: date */
					__( "Administrator '%1\$s' was created on %2\$s. If you did not create this account, your site may be compromised.", 'site-security-audit' ),
					$u->user_login,
					$u->user_registered
				),
				__( 'Verify with your team. If unfamiliar, revoke access, rotate all admin passwords, and scan for backdoors.', 'site-security-audit' ),
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
				SSA_Logger::SEVERITY_CRITICAL,
				__( 'Open registration with administrator default role', 'site-security-audit' ),
				__( 'Anyone can register and is automatically granted administrator. This is almost certainly a compromise.', 'site-security-audit' ),
				__( 'Disable public registration or set the default role to Subscriber in Settings → General.', 'site-security-audit' )
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
					SSA_Logger::SEVERITY_HIGH,
					__( 'siteurl and home point to different domains', 'site-security-audit' ),
					sprintf(
						/* translators: 1: siteurl, 2: home */
						__( 'siteurl (%1$s) and home (%2$s) resolve to different hosts. Malware often sets one of these to an attacker-controlled domain.', 'site-security-audit' ),
						$site_url,
						$home
					),
					__( 'Confirm both values in Settings → General are correct. If not, revert and investigate.', 'site-security-audit' )
				);
			}
		}
	}
}
