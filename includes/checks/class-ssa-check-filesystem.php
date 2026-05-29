<?php
/**
 * Filesystem & permission checks.
 *
 * @package Site_Security_Audit
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class SSA_Check_Filesystem
 */
class SSA_Check_Filesystem extends SSA_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'filesystem';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Filesystem & Permissions', 'site-security-audit' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'wp_config_perms', 'key_perms', 'readme', 'uploads_php', 'backup_files', 'directory_listing', 'directory_listing_all', 'wp_config_http', 'sensitive_urls' );
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
			case 'wp_config_perms':
				$this->check_wp_config_perms();
				break;
			case 'key_perms':
				$this->check_key_perms();
				break;
			case 'readme':
				$this->check_readme();
				break;
			case 'uploads_php':
				return $this->check_uploads_php( $cursor );
			case 'backup_files':
				$this->check_exposed_backups();
				break;
			case 'directory_listing':
				$this->check_directory_listing();
				break;
			case 'directory_listing_all':
				$this->check_directory_listing_all();
				break;
			case 'wp_config_http':
				$this->check_wp_config_http();
				break;
			case 'sensitive_urls':
				$this->check_sensitive_urls();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * wp-config.php file permission check.
	 *
	 * @return void
	 */
	private function check_wp_config_perms() {
		$path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $path ) ) {
			$path = dirname( ABSPATH ) . '/wp-config.php';
			if ( ! file_exists( $path ) ) {
				return;
			}
		}

		$perms = fileperms( $path ) & 0777;
		if ( $perms & 0044 ) {
			$this->finding(
				SSA_Logger::SEVERITY_HIGH,
				__( 'wp-config.php is world-readable', 'site-security-audit' ),
				sprintf(
					/* translators: %s: octal permissions */
					__( 'Permissions on wp-config.php are %s. Other users on the server could read the database credentials.', 'site-security-audit' ),
					'0' . decoct( $perms )
				),
				__( 'Change permissions to 0640 or 0600 (chmod 600 wp-config.php).', 'site-security-audit' ),
				$path
			);
		}
	}

	/**
	 * Permissions on other key files/directories.
	 *
	 * @return void
	 */
	private function check_key_perms() {
		$targets = array(
			ABSPATH                => array( 'max' => 0755, 'label' => 'WordPress root' ),
			ABSPATH . 'wp-admin'   => array( 'max' => 0755, 'label' => 'wp-admin' ),
			WP_CONTENT_DIR         => array( 'max' => 0755, 'label' => 'wp-content' ),
			WP_CONTENT_DIR . '/uploads' => array( 'max' => 0755, 'label' => 'uploads' ),
		);
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			$targets[ WP_PLUGIN_DIR ] = array( 'max' => 0755, 'label' => 'plugins' );
		}

		foreach ( $targets as $path => $info ) {
			if ( ! is_dir( $path ) ) {
				continue;
			}
			$perms = fileperms( $path ) & 0777;
			// World-writable is always bad.
			if ( $perms & 0002 ) {
				$this->finding(
					SSA_Logger::SEVERITY_HIGH,
					/* translators: %s: label */
					sprintf( __( '%s directory is world-writable', 'site-security-audit' ), $info['label'] ),
					sprintf(
						/* translators: 1: path, 2: octal */
						__( 'Directory %1$s has permissions %2$s. Any user on the server can write to it.', 'site-security-audit' ),
						$path,
						'0' . decoct( $perms )
					),
					__( 'Change permissions to 0755 (directories) / 0644 (files) or stricter, owned by the web user.', 'site-security-audit' ),
					$path
				);
			}
		}
	}

	/**
	 * readme.html exposed.
	 *
	 * @return void
	 */
	private function check_readme() {
		$readme = ABSPATH . 'readme.html';
		if ( file_exists( $readme ) ) {
			$url      = home_url( '/readme.html' );
			$response = wp_remote_get(
				$url,
				array(
					'timeout'   => 5,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				)
			);
			if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
				$this->finding(
					SSA_Logger::SEVERITY_LOW,
					__( 'readme.html is publicly accessible', 'site-security-audit' ),
					__( 'The file discloses the WordPress version, helping attackers match known CVEs.', 'site-security-audit' ),
					__( 'Delete readme.html from your WordPress root via FTP or your hosting File Manager. Since it is recreated on each core update, also block it permanently in Apache .htaccess: <Files readme.html> deny from all </Files>. For Nginx: location = /readme.html { deny all; }', 'site-security-audit' ),
					$readme
				);
			}
		}
	}

	/**
	 * PHP files in uploads — walks the directory tree resumably.
	 *
	 * @param array $cursor Cursor — holds 'queue' of directories left.
	 * @return array
	 */
	private function check_uploads_php( array $cursor ) {
		$upload_dir = wp_get_upload_dir();
		$root       = isset( $upload_dir['basedir'] ) ? $upload_dir['basedir'] : '';
		if ( ! $root || ! is_dir( $root ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}

		if ( ! isset( $cursor['queue'] ) ) {
			$cursor = array( 'queue' => array( $root ), 'checked' => 0 );
		}

		$budget = 200; // files per invocation.
		$seen   = 0;

		while ( ! empty( $cursor['queue'] ) && $seen < $budget ) {
			$current = array_shift( $cursor['queue'] );
			$handle  = @opendir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $handle ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$full = $current . DIRECTORY_SEPARATOR . $entry;
				if ( is_dir( $full ) ) {
					$cursor['queue'][] = $full;
				} elseif ( preg_match( '/\.(php|phtml|php5|php7|phar)$/i', $entry ) ) {
					$this->finding(
						SSA_Logger::SEVERITY_CRITICAL,
						__( 'Executable PHP file inside uploads', 'site-security-audit' ),
						__( 'PHP files inside wp-content/uploads are a classic backdoor indicator. Uploads must never execute server-side code.', 'site-security-audit' ),
						__( 'A PHP file in uploads is almost always a web shell. Do NOT open it in a browser — delete it via FTP or your hosting File Manager immediately. Block PHP execution in uploads permanently by adding to wp-content/uploads/.htaccess: <Files *.php> deny from all </Files>. Then change all admin passwords.', 'site-security-audit' ),
						$full
					);
				}
				$seen++;
				if ( $seen >= $budget ) {
					break;
				}
			}
			closedir( $handle );
		}

		return array(
			'continue' => ! empty( $cursor['queue'] ),
			'cursor'   => $cursor,
		);
	}

	/**
	 * Exposed backup / source files.
	 *
	 * @return void
	 */
	private function check_exposed_backups() {
		$patterns = array(
			'wp-config.php.bak',
			'wp-config.php.save',
			'wp-config.php.old',
			'wp-config.php~',
			'wp-config.bak',
			'.wp-config.php.swp',
			'backup.zip',
			'site.zip',
			'database.sql',
			'backup.sql',
			'dump.sql',
		);

		foreach ( $patterns as $file ) {
			$path = ABSPATH . $file;
			if ( file_exists( $path ) ) {
				$this->finding(
					SSA_Logger::SEVERITY_CRITICAL,
					__( 'Sensitive backup file present in webroot', 'site-security-audit' ),
					sprintf(
						/* translators: %s: filename */
						__( 'Found %s in the site root. Files like these frequently leak database credentials or full site data.', 'site-security-audit' ),
						$file
					),
					__( 'Delete or move this file outside your webroot immediately via FTP or your hosting File Manager — it likely contains database credentials. After removing it, rotate your database password in both wp-config.php and your hosting control panel.', 'site-security-audit' ),
					$path
				);
			}
		}
	}

	/**
	 * Check whether wp-config.php is served over HTTP (webserver should block it).
	 *
	 * Even when file permissions are correct, a misconfigured webserver could
	 * serve wp-config.php as plain text if PHP processing fails. This check
	 * performs an actual HTTP request to confirm.
	 *
	 * @return void
	 */
	private function check_wp_config_http() {
		$url      = home_url( '/wp-config.php' );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		// A 200 response that contains DB_ constants is a definite credential leak.
		if ( 200 === $code ) {
			$has_credentials = $body && preg_match( '/DB_(?:NAME|USER|PASSWORD|HOST)/i', $body );

			if ( $has_credentials ) {
				$this->finding(
					SSA_Logger::SEVERITY_CRITICAL,
					__( 'wp-config.php is publicly readable and contains credentials', 'site-security-audit' ),
					__( 'A request to /wp-config.php returned HTTP 200 and the response body contains database constants (DB_NAME, DB_USER, DB_PASSWORD). Your database credentials are exposed to anyone on the internet.', 'site-security-audit' ),
					__( 'Block access to wp-config.php at the webserver level immediately. Apache: add a <Files wp-config.php> deny from all </Files> block. Nginx: add "location ~* wp-config\\.php { deny all; }". Also rotate your database password immediately.', 'site-security-audit' ),
					$url
				);
			} else {
				$this->finding(
					SSA_Logger::SEVERITY_HIGH,
					__( 'wp-config.php returned HTTP 200 (possible exposure)', 'site-security-audit' ),
					__( 'A request to /wp-config.php returned HTTP 200. Even if PHP processes it as code rather than serving it as text, this indicates the webserver is not explicitly blocking access. A PHP-processing failure could expose database credentials.', 'site-security-audit' ),
					__( 'Explicitly deny access to wp-config.php at the webserver level. Apache: <Files wp-config.php> deny from all </Files>. Nginx: location ~* wp-config\\.php { deny all; }', 'site-security-audit' ),
					$url
				);
			}
		}
		// 403 or 404 are both acceptable; no finding needed.
	}

	/**
	 * Check for publicly accessible sensitive WordPress files.
	 *
	 * Covers files beyond what SSA_Check_Security_Config checks — specifically
	 * WordPress-specific files that leak version information or enable abuse:
	 *  - license.txt       — discloses WordPress version in the copyright year line
	 *  - wp-activate.php   — activation endpoint; should return 302/403, not 200+content
	 *  - wp-cron.php       — should not be directly accessible; enables resource abuse
	 *  - .htaccess         — Apache rewrite rules; may reveal path structure
	 *
	 * @return void
	 */
	private function check_sensitive_urls() {
		$base = trailingslashit( home_url() );

		$checks = array(
			'license.txt'     => array(
				'severity' => SSA_Logger::SEVERITY_LOW,
				'title'    => __( 'license.txt is publicly accessible', 'site-security-audit' ),
				'desc'     => __( 'The WordPress license file is accessible and discloses the WordPress version in its copyright year/version line.', 'site-security-audit' ),
				'rec'      => __( 'Delete license.txt from the webroot, or block it at the webserver level.', 'site-security-audit' ),
				'match'    => null, // 200 response is enough.
			),
			'wp-activate.php' => array(
				'severity' => SSA_Logger::SEVERITY_LOW,
				'title'    => __( 'wp-activate.php is publicly accessible', 'site-security-audit' ),
				'desc'     => __( 'The wp-activate.php file is reachable from the internet. On single-site WordPress it serves no purpose and its content includes the WordPress version in the page title.', 'site-security-audit' ),
				'rec'      => __( 'Block access to wp-activate.php at the webserver level unless you are running WordPress Multisite with email-based user activation.', 'site-security-audit' ),
				'match'    => null,
			),
			'wp-cron.php'     => array(
				'severity' => SSA_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'wp-cron.php is publicly accessible', 'site-security-audit' ),
				'desc'     => __( 'wp-cron.php is reachable by any visitor. Repeated requests can trigger all scheduled tasks simultaneously, wasting server resources. Malicious actors use this for denial-of-service and to exhaust hosting CPU quotas.', 'site-security-audit' ),
				'rec'      => __( "Block direct HTTP access to wp-cron.php at the webserver level and use a real server cron job instead: define('DISABLE_WP_CRON', true); in wp-config.php, then: */5 * * * * php /path/to/wordpress/wp-cron.php", 'site-security-audit' ),
				'match'    => null,
			),
			'.htaccess'       => array(
				'severity' => SSA_Logger::SEVERITY_MEDIUM,
				'title'    => __( '.htaccess file is publicly accessible', 'site-security-audit' ),
				'desc'     => __( 'The .htaccess file returned HTTP 200. It may contain rewrite rules, directory configurations, or access controls that expose your site structure and configuration to attackers.', 'site-security-audit' ),
				'rec'      => __( "Ensure your webserver is configured to block direct access to dotfiles. For Apache, add: <FilesMatch '^\\.'> deny from all </FilesMatch>", 'site-security-audit' ),
				'match'    => null,
			),
		);

		foreach ( $checks as $file => $meta ) {
			$response = wp_remote_get(
				$base . ltrim( $file, '/' ),
				array(
					'timeout'   => 5,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				)
			);

			if ( is_wp_error( $response ) ) {
				continue;
			}

			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 200 !== $code ) {
				continue;
			}

			// Optional body-content match.
			if ( null !== $meta['match'] ) {
				$body = wp_remote_retrieve_body( $response );
				if ( ! $body || false === strpos( $body, $meta['match'] ) ) {
					continue;
				}
			}

			$this->finding(
				$meta['severity'],
				$meta['title'],
				$meta['desc'],
				$meta['rec'],
				'/' . $file
			);
		}
	}

	/**
	 * Directory listing on uploads.
	 *
	 * @return void
	 */
	private function check_directory_listing() {
		$upload_dir = wp_get_upload_dir();
		$url        = isset( $upload_dir['baseurl'] ) ? trailingslashit( $upload_dir['baseurl'] ) : '';
		if ( ! $url ) {
			return;
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return;
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( false !== stripos( $body, 'Index of /' ) || false !== stripos( $body, '<title>Index of' ) ) {
			$this->finding(
				SSA_Logger::SEVERITY_MEDIUM,
				__( 'Directory listing enabled on uploads', 'site-security-audit' ),
				__( 'Visitors can enumerate every file under wp-content/uploads.', 'site-security-audit' ),
				__( 'Add "Options -Indexes" to your root .htaccess file to disable directory listings site-wide. For Nginx, add "autoindex off;" inside your server block. You can also place an empty index.php file in the uploads directory as a fallback.', 'site-security-audit' ),
				$url
			);
		}
	}

	/**
	 * Directory listing on wp-content, plugins, and themes directories.
	 *
	 * If any of these respond with an Apache/Nginx directory index, attackers can
	 * enumerate installed plugins and themes — a direct path to targeted CVE exploitation.
	 *
	 * @return void
	 */
	private function check_directory_listing_all() {
		$dirs = array(
			content_url( '/' )           => 'wp-content',
			plugins_url( '/' )           => 'wp-content/plugins',
			get_theme_root_uri() . '/'   => 'wp-content/themes',
		);

		foreach ( $dirs as $url => $label ) {
			$url      = trailingslashit( $url );
			$response = wp_remote_get(
				$url,
				array(
					'timeout'   => 5,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				)
			);

			if ( is_wp_error( $response ) ) {
				continue;
			}

			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 200 !== $code ) {
				continue;
			}

			$body = wp_remote_retrieve_body( $response );
			if ( ! $body ) {
				continue;
			}

			if ( false !== stripos( $body, 'Index of /' ) || false !== stripos( $body, '<title>Index of' ) ) {
				$this->finding(
					SSA_Logger::SEVERITY_HIGH,
					sprintf(
						/* translators: %s: directory label e.g. "wp-content/plugins" */
						__( 'Directory listing enabled on %s', 'site-security-audit' ),
						$label
					),
					sprintf(
						/* translators: %s: directory label */
						__( 'The %s directory returns a browsable file listing. Attackers can enumerate all installed plugins and themes, then match them to known CVEs.', 'site-security-audit' ),
						$label
					),
					__( "Add 'Options -Indexes' to the root .htaccess file (Apache) or 'autoindex off;' in the Nginx server block. Placing an empty index.php in each directory also suppresses listing.", 'site-security-audit' ),
					$url
				);
			}
		}
	}
}
