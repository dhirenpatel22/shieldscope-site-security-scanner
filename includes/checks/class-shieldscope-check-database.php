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
	 * Most findings reported per content rule; more are summarised (IM2-05).
	 */
	const CONTENT_MAX_PER_RULE = 50;

	/**
	 * Characters read from each option value.
	 */
	const OPTION_READ_BYTES = 65536;

	/**
	 * Post types that hold cached or temporary copies, not site content.
	 */
	const CONTENT_SKIP_TYPES = array( 'revision', 'attachment', 'nav_menu_item', 'oembed_cache', 'customize_changeset' );

	/**
	 * Content rules, worst first: key => array( severity, title ).
	 *
	 * @return array
	 */
	private static function content_rules() {
		return array(
			'obfuscated'    => array( ShieldScope_Logger::SEVERITY_HIGH, __( 'Review: obfuscated JavaScript in stored content', 'shieldscope-site-security-scanner' ) ),
			'hidden_iframe' => array( ShieldScope_Logger::SEVERITY_MEDIUM, __( 'Review: hidden iframe in stored content', 'shieldscope-site-security-scanner' ) ),
			'script'        => array( ShieldScope_Logger::SEVERITY_LOW, __( 'Review: script tag in stored content', 'shieldscope-site-security-scanner' ) ),
		);
	}

	/**
	 * Offset of the first match of a content rule, or -1.
	 *
	 * @param string $key     Rule key.
	 * @param string $content Content.
	 * @return int
	 */
	private function content_match( $key, $content ) {
		if ( 'obfuscated' === $key ) {
			return $this->rx_offset( '/(?:eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*unescape\s*\(|\\\\x[0-9a-f]{2}(?:\\\\x[0-9a-f]{2}){20,})/i', $content );
		}
		if ( 'script' === $key ) {
			return $this->rx_offset( '/<script\b/i', $content );
		}
		// Hidden iframe: take each <iframe ...> tag (bounded, possessive, so
		// the scan is linear: IM2-07) and test its attributes. Google Tag
		// Manager's noscript iframe (ns.html) is standard and exempt.
		$result = preg_match_all( '/<iframe\b[^>]{0,4000}+/i', $content, $tags, PREG_OFFSET_CAPTURE );
		if ( false === $result || PREG_NO_ERROR !== preg_last_error() ) {
			$this->rx_failed = true;
			return -1;
		}
		foreach ( $tags[0] as $tag ) {
			if ( false !== stripos( $tag[0], 'googletagmanager.com/ns.html' ) ) {
				continue;
			}
			if ( preg_match( '/display\s*:\s*none|visibility\s*:\s*hidden|\b(?:width|height)\s*=\s*["\']?[01](?:px)?(?:["\'\s]|$)/i', $tag[0] ) ) {
				return (int) $tag[1];
			}
		}
		return -1;
	}

	/**
	 * Look for injected code in options and post content (S-23).
	 * Read-only; options and posts are read in batches by ID within the
	 * step time budget; only the worst matching rule per item is reported,
	 * and at most CONTENT_MAX_PER_RULE items per rule. Content stays on the
	 * server.
	 *
	 * @param array $cursor Cursor: phase, last option/post id, per-rule counts.
	 * @return array
	 */
	private function check_content( array $cursor = array() ) {
		global $wpdb;
		$cursor += array(
			'phase'  => 'options',
			'after'  => 0,
			'counts' => array(),
		);

		do {
			if ( 'options' === $cursor['phase'] ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only scan of stored content.
				$rows = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT option_id, option_name, LEFT(option_value, %d) AS option_value FROM {$wpdb->options} WHERE option_id > %d AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND (option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s) ORDER BY option_id ASC LIMIT %d",
						self::OPTION_READ_BYTES,
						(int) $cursor['after'],
						$wpdb->esc_like( '_transient_' ) . '%',
						$wpdb->esc_like( '_site_transient_' ) . '%',
						'%' . $wpdb->esc_like( '<script' ) . '%',
						'%' . $wpdb->esc_like( '<iframe' ) . '%',
						'%' . $wpdb->esc_like( 'eval(' ) . '%',
						self::CONTENT_BATCH
					),
					ARRAY_A
				);
				foreach ( (array) $rows as $row ) {
					$cursor['after'] = (int) $row['option_id'];
					$this->report_content_match( (string) $row['option_value'], 'option:' . $row['option_name'], __( 'This option', 'shieldscope-site-security-scanner' ), $cursor );
				}
				if ( count( (array) $rows ) < self::CONTENT_BATCH ) {
					$cursor['phase'] = 'posts';
					$cursor['after'] = 0;
				}
				continue;
			}

			$skip_types = self::CONTENT_SKIP_TYPES;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only scan of stored content.
			$posts = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ID, post_type, post_content FROM {$wpdb->posts} WHERE ID > %d AND post_type NOT IN (%s, %s, %s, %s, %s) ORDER BY ID ASC LIMIT %d",
					(int) $cursor['after'],
					$skip_types[0],
					$skip_types[1],
					$skip_types[2],
					$skip_types[3],
					$skip_types[4],
					self::CONTENT_BATCH
				),
				ARRAY_A
			);
			foreach ( (array) $posts as $post ) {
				$cursor['after'] = (int) $post['ID'];
				$this->report_content_match(
					(string) $post['post_content'],
					'post:' . $post['ID'],
					/* translators: 1: post type, 2: post ID */
					sprintf( __( 'This %1$s (ID %2$d)', 'shieldscope-site-security-scanner' ), $post['post_type'], $post['ID'] ),
					$cursor
				);
			}
			if ( count( (array) $posts ) < self::CONTENT_BATCH ) {
				$this->summarise_content_caps( $cursor['counts'] );
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
	 * @param array  $cursor  Cursor (per-rule counts, by reference).
	 * @return void
	 */
	private function report_content_match( $content, $target, $what, array &$cursor ) {
		if ( '' === $content ) {
			return;
		}
		$this->rx_failed = false;
		foreach ( self::content_rules() as $key => $rule ) {
			$at = $this->content_match( $key, $content );
			if ( $at < 0 ) {
				continue;
			}
			$cursor['counts'][ $key ] = isset( $cursor['counts'][ $key ] ) ? $cursor['counts'][ $key ] + 1 : 1;
			if ( $cursor['counts'][ $key ] > self::CONTENT_MAX_PER_RULE ) {
				return; // Counted; summarised at the end.
			}
			$this->finding(
				$rule[0],
				$rule[1],
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
		if ( $this->rx_failed ) {
			$this->could_not_analyse( $target );
		}
	}

	/**
	 * One summary per rule that matched more items than were listed.
	 *
	 * @param array $counts Rule key => items matched.
	 * @return void
	 */
	private function summarise_content_caps( array $counts ) {
		$rules = self::content_rules();
		foreach ( $counts as $key => $count ) {
			if ( $count <= self::CONTENT_MAX_PER_RULE || ! isset( $rules[ $key ] ) ) {
				continue;
			}
			$this->finding(
				ShieldScope_Logger::SEVERITY_INFO,
				/* translators: %s: rule title */
				sprintf( __( 'More items matched: %s', 'shieldscope-site-security-scanner' ), $rules[ $key ][1] ),
				sprintf(
					/* translators: 1: items matched, 2: items listed */
					__( '%1$d items matched this rule; the first %2$d are listed. Embeds and page builders can produce many matches.', 'shieldscope-site-security-scanner' ),
					$count,
					self::CONTENT_MAX_PER_RULE
				),
				__( 'Review the listed items first; if they are all legitimate, the rest are likely the same kind of content.', 'shieldscope-site-security-scanner' ),
				'',
				array( 'confidence' => self::CONFIDENCE_REVIEW )
			);
		}
	}
}
