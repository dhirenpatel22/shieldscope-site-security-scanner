<?php
/**
 * User & authentication security checks.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Users
 */
class ShieldScope_Check_Users extends ShieldScope_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'users';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Users & Authentication', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'admin_user', 'admin_count', 'weak_hashes', 'empty_passwords', 'display_name_login' );
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
			case 'admin_user':
				$this->check_default_admin();
				break;
			case 'admin_count':
				$this->check_admin_count();
				break;
			case 'weak_hashes':
				return $this->check_password_hashes( $cursor );
			case 'empty_passwords':
				$this->check_empty_passwords();
				break;
			case 'display_name_login':
				$this->check_display_name_matches_login();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Default 'admin' username.
	 *
	 * @return void
	 */
	private function check_default_admin() {
		$user = get_user_by( 'login', 'admin' );
		if ( $user && user_can( $user->ID, 'manage_options' ) ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( "An administrator named 'admin' exists", 'shieldscope-site-security-scanner' ),
				__( "Attackers often try the username 'admin' first.", 'shieldscope-site-security-scanner' ),
				__( 'Go to Users → Add New and create a new Administrator with a unique username. Log in as the new admin, then delete the old "admin" account — on the deletion screen choose "Attribute all content to" your new account to transfer all posts.', 'shieldscope-site-security-scanner' ),
				'user:' . $user->ID
			);
		}
	}

	/**
	 * Too many admins.
	 *
	 * @return void
	 */
	private function check_admin_count() {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
			)
		);
		$count  = count( $admins );

		if ( $count >= 5 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Unusually high number of administrators', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %d: count */
					__( '%d administrator accounts exist. Each is a potential point of compromise.', 'shieldscope-site-security-scanner' ),
					$count
				),
				__( 'Go to Users → All Users, filter by Administrator, and review each account. Downgrade accounts that do not need full access — change their role to Editor (content management) or Author (own posts only) via their profile.', 'shieldscope-site-security-scanner' )
			);
		}
	}

	/**
	 * Look for users with non-phpass password hashes (legacy or broken).
	 *
	 * Checks 500 users per call, resuming after the last ID in the cursor.
	 *
	 * @param array $cursor Cursor: 'last_id' of the previous batch.
	 * @return array { 'continue' => bool, 'cursor' => array }
	 */
	private function check_password_hashes( array $cursor ) {
		global $wpdb;

		$batch   = 500;
		$last_id = isset( $cursor['last_id'] ) ? (int) $cursor['last_id'] : 0;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, user_login, user_pass FROM {$wpdb->users} WHERE ID > %d ORDER BY ID LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$last_id,
				$batch
			),
			ARRAY_A
		);
		$rows = (array) $rows;

		foreach ( $rows as $row ) {
			$last_id = (int) $row['ID'];
			$hash    = isset( $row['user_pass'] ) ? $row['user_pass'] : '';

			if ( ! self::is_recognized_hash( $hash ) && '' !== $hash ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_HIGH,
					__( 'Non-standard password hash detected', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: %s: login */
						__( "User '%s' has a password hash that does not match WordPress' phpass or bcrypt format. This may be a legacy md5/sha1 hash.", 'shieldscope-site-security-scanner' ),
						$row['user_login']
					),
					__( 'Force a password reset: go to Users → All Users, edit the user, generate a new password, and save — the hash upgrades to a modern format automatically on next login. If the account is unrecognised, delete it immediately and investigate for a compromise.', 'shieldscope-site-security-scanner' ),
					'user:' . $row['ID']
				);
			}
		}

		if ( count( $rows ) < $batch ) {
			return array( 'continue' => false, 'cursor' => array() );
		}
		return array(
			'continue' => true,
			'cursor'   => array( 'last_id' => $last_id ),
		);
	}

	/**
	 * Is this a password hash format WordPress legitimately produces?
	 *
	 * Covers:
	 *  - phpass portable hashes ($P$ / $H$, 34 chars) — WP < 6.8
	 *  - WP 6.8+ prefixed bcrypt ($wp$2y$…) — the current default
	 *  - plain bcrypt ($2y$ / $2a$ / $2b$) — plugins using wp_hash_password overrides
	 *  - argon2 ($argon2i / $argon2id) — password-hashing plugins
	 *
	 * @param string $hash Stored user_pass value.
	 * @return bool
	 */
	public static function is_recognized_hash( $hash ) {
		if ( ! is_string( $hash ) || '' === $hash ) {
			return false;
		}
		// WordPress phpass hashes start with $P$ or $H$ and are 34 chars.
		if ( strlen( $hash ) >= 34 && ( 0 === strpos( $hash, '$P$' ) || 0 === strpos( $hash, '$H$' ) ) ) {
			return true;
		}
		// WordPress 6.8+ wraps bcrypt with a $wp prefix: $wp$2y$10$…
		if ( 0 === strpos( $hash, '$wp$' ) ) {
			return true;
		}
		// Raw bcrypt variants and argon2.
		if ( 0 === strpos( $hash, '$2y$' ) || 0 === strpos( $hash, '$2a$' ) || 0 === strpos( $hash, '$2b$' ) || 0 === strpos( $hash, '$argon2' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Users with empty password hashes.
	 *
	 * @return void
	 */
	private function check_empty_passwords() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			"SELECT ID, user_login FROM {$wpdb->users} WHERE user_pass = '' OR user_pass IS NULL",
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_CRITICAL,
				__( 'User with empty password detected', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %s: login */
					__( "User '%s' has no password set. This is usually only legitimate for SSO accounts — otherwise it is a critical vulnerability.", 'shieldscope-site-security-scanner' ),
					$row['user_login']
				),
				__( 'Go to Users → All Users and set a strong password on this account immediately. If you do not recognise the account, delete it and change all admin passwords — an unrecognised empty-password account is a strong indicator of compromise.', 'shieldscope-site-security-scanner' ),
				'user:' . $row['ID']
			);
		}
	}

	/**
	 * display_name equals user_login (leaks username on the front end).
	 *
	 * @return void
	 */
	private function check_display_name_matches_login() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			"SELECT ID, user_login FROM {$wpdb->users} WHERE user_login = display_name LIMIT 200",
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			if ( user_can( $row['ID'], 'edit_posts' ) ) {
				$this->finding(
					ShieldScope_Logger::SEVERITY_LOW,
					__( 'Display name exposes the login name', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: %s: login */
						__( "User '%s' has the same display name as login name. This reveals the login to anyone reading a byline.", 'shieldscope-site-security-scanner' ),
						$row['user_login']
					),
					__( 'Go to Users → All Users, edit the user, and change "Display name publicly as" to a first name or nickname that differs from their login username. This prevents the username from appearing in public bylines and comments.', 'shieldscope-site-security-scanner' ),
					'user:' . $row['ID']
				);
			}
		}
	}
}
