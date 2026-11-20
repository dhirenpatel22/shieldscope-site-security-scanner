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
		return array( 'unknown_admins', 'suspicious_options', 'content' );
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
			case 'content':
				return $this->check_content( $cursor );
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
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Open registration with administrator default role', 'shieldscope-site-security-scanner' ),
				__( 'Anyone can register and is automatically granted administrator. WordPress does not ship with this setting, so it is a common sign of compromise.', 'shieldscope-site-security-scanner' ),
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
					ShieldScope_Logger::SEVERITY_MEDIUM,
					__( 'siteurl and home point to different domains', 'shieldscope-site-security-scanner' ),
					sprintf(
						/* translators: 1: siteurl, 2: home */
						__( 'siteurl (%1$s) and home (%2$s) resolve to different hosts. Some sites are set up this way on purpose, but a changed value can also be a sign of compromise.', 'shieldscope-site-security-scanner' ),
						$site_url,
						$home
					),
					__( 'Go to Settings → General and verify both WordPress Address and Site Address point to your own domain. If either was changed to an unknown domain, revert it and change all admin passwords immediately. Also check wp-config.php for WP_HOME or WP_SITEURL constants that may be overriding the values.', 'shieldscope-site-security-scanner' )
				);
			}
		}
	}

	/**
	 * Posts read per query in the content step.
	 */
	const CONTENT_BATCH = 200;

	/**
	 * Patterns for injected code in stored content (S-23), worst first:
	 * key => array( regex, severity, title ).
	 *
	 * @return array
	 */
	private static function content_rules() {
		return array(
			'obfuscated' => array(
				'/(?:eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*unescape\s*\(|\\\\x[0-9a-f]{2}(?:\\\\x[0-9a-f]{2}){20,})/i',
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Review: obfuscated JavaScript in stored content', 'shieldscope-site-security-scanner' ),
			),
			'hidden_iframe' => array(
				'/<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|\bwidth\s*=\s*["\']?[01]["\'\s>]|\bheight\s*=\s*["\']?[01]["\'\s>])/i',
				ShieldScope_Logger::SEVERITY_MEDIUM,
				__( 'Review: hidden iframe in stored content', 'shieldscope-site-security-scanner' ),
			),
			'script' => array(
				'/<script\b/i',
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Review: script tag in stored content', 'shieldscope-site-security-scanner' ),
			),
		);
	}

	/**
	 * Look for injected code in post content and in options (S-23).
	 * Read-only; posts are read in batches by ID; only the first matching
	 * rule per item is reported. Content stays on the server.
	 *
	 * @param array $cursor Cursor: last post ID, options done.
	 * @return array
	 */
	private function check_content( array $cursor = array() ) {
		global $wpdb;
		$cursor += array(
			'after'   => 0,
			'options' => false,
		);

		if ( ! $cursor['options'] ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only scan of stored content.
			$rows = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_value LIKE '%<script%' OR option_value LIKE '%<iframe%' OR option_value LIKE '%eval(%' LIMIT 500", ARRAY_A );
			foreach ( (array) $rows as $row ) {
				if ( 0 === strpos( $row['option_name'], '_transient' ) || 0 === strpos( $row['option_name'], '_site_transient' ) ) {
					continue;
				}
				$this->report_content_match( (string) $row['option_value'], 'option:' . $row['option_name'], __( 'This option', 'shieldscope-site-security-scanner' ) );
			}
			$cursor['options'] = true;
		}

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only scan of stored content.
			$posts = $wpdb->get_results( $wpdb->prepare( "SELECT ID, post_type, post_content FROM {$wpdb->posts} WHERE ID > %d AND post_type NOT IN ('revision','attachment','nav_menu_item') ORDER BY ID ASC LIMIT %d", (int) $cursor['after'], self::CONTENT_BATCH ), ARRAY_A );
			foreach ( (array) $posts as $post ) {
				$cursor['after'] = (int) $post['ID'];
				$this->report_content_match(
					(string) $post['post_content'],
					'post:' . $post['ID'],
					/* translators: 1: post type, 2: post ID */
					sprintf( __( 'This %1$s (ID %2$d)', 'shieldscope-site-security-scanner' ), $post['post_type'], $post['ID'] )
				);
			}
			if ( count( (array) $posts ) < self::CONTENT_BATCH ) {
				return array( 'continue' => false, 'cursor' => array() );
			}
		} while ( ! $this->out_of_time() );

		return array( 'continue' => true, 'cursor' => $cursor );
	}

	/**
	 * Report the worst matching content rule for one item.
	 *
	 * @param string $content Stored content.
	 * @param string $target  Target (post:ID or option:name).
	 * @param string $what    Human description of the item.
	 * @return void
	 */
	private function report_content_match( $content, $target, $what ) {
		if ( '' === $content ) {
			return;
		}
		foreach ( self::content_rules() as $key => $rule ) {
			$at = $this->rx_offset( $rule[0], $content );
			if ( $at < 0 ) {
				continue;
			}
			$this->finding(
				$rule[1],
				$rule[2],
				$what . ' ' . ( 'script' === $key
					? __( 'contains a <script> tag. Page builders, analytics and embeds add scripts legitimately; injected spam and redirect code also hides here.', 'shieldscope-site-security-scanner' )
					: __( 'contains code that is typical of injected spam or redirects. Legitimate content rarely needs it.', 'shieldscope-site-security-scanner' ) )
					. ' ' . __( 'This is a pattern match, not a confirmed infection.', 'shieldscope-site-security-scanner' ),
				__( 'Open the item in the editor (or the options table) and check the code. If nobody added it, remove it and change administrator passwords.', 'shieldscope-site-security-scanner' ),
				$target,
				self::evidence( $content, $content, $at )
			);
			return;
		}
	}
}
