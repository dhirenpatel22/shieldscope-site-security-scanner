<?php
/**
 * Vulnerability database check.
 *
 * Compares installed plugin, theme and WordPress core versions against:
 *  1. WPVulnerability (https://www.wpvulnerability.com) — on by default
 *     (Settings → Vulnerability lookups). A free, keyless API whose data is
 *     CC0 1.0 and gathered from CVE, Patchstack, Wordfence, WPScan and
 *     others. Only slugs and version numbers are sent; answers are cached.
 *  2. WPScan API (https://wpscan.com) — when an API key is configured, for
 *     plugins and themes WPVulnerability could not answer (or when it is
 *     off), so the 25-requests-a-day free quota is not spent twice.
 *  3. Built-in list — a small, limited list of plugin CVEs, each checked
 *     against NVD and the vendor changelog on the review date below. Used
 *     only for plugins no online source answered.
 *
 * WPScan free tier: 25 requests/day. Live requests are counted per day and
 * stop at that limit; successful responses are cached in transients (24h).
 * Failed lookups are never cached and are reported as incomplete coverage.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Vuln_DB
 */
class ShieldScope_Check_Vuln_DB extends ShieldScope_Check_Base {

	/**
	 * WPScan API base URL.
	 */
	const WPSCAN_API = 'https://wpscan.com/api/v3/';

	/**
	 * WPVulnerability API base URL.
	 */
	const WPV_API = 'https://www.wpvulnerability.net/';

	/**
	 * WPVulnerability project page, linked in the credit line.
	 */
	const WPV_SITE = 'https://www.wpvulnerability.com/';

	/**
	 * Cache for WPVulnerability answers (seconds).
	 */
	const WPV_CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * Most vulnerabilities listed in one finding's description.
	 */
	const WPV_MAX_LISTED = 8;

	/**
	 * Transient TTL for WPScan responses (seconds).
	 */
	const CACHE_TTL = DAY_IN_SECONDS;

	/**
	 * WPScan free-tier requests per day.
	 */
	const WPSCAN_DAILY_QUOTA = 25;

	/**
	 * Date the built-in list was last checked against NVD and vendor changelogs.
	 */
	const BUILT_IN_REVIEWED = '2026-11-14';

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param ShieldScope_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, ShieldScope_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$this->settings = (array) get_option( 'shieldscope_settings', array() );
	}

	/** @return string */
	public function get_id() {
		return 'vuln_db';
	}

	/** @return string */
	public function get_label() {
		return __( 'Vulnerability Database', 'shieldscope-site-security-scanner' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'check_components' );
	}

	/**
	 * Run step: one component (plugin or theme) per call.
	 *
	 * Cursor keys:
	 *   index     — next component to check
	 *   eligible  — components that should have been looked up on WPScan
	 *   checked   — components WPScan answered for
	 *   reasons   — failure reasons (as keys)
	 *   stop      — reason that ends all further lookups this scan (bad key, quota)
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( 'check_components' !== $step ) {
			return array( 'continue' => false, 'cursor' => array() );
		}

		$cursor = wp_parse_args(
			$cursor,
			array(
				'index'        => 0,
				'eligible'     => 0,
				'checked'      => 0,
				'reasons'      => array(),
				'stop'         => '',
				'wpv_eligible' => 0,
				'wpv_checked'  => 0,
				'wpv_failed'   => 0,
				'wpv_reasons'  => array(),
			)
		);

		$components = $this->get_components();
		$index      = (int) $cursor['index'];

		if ( isset( $components[ $index ] ) ) {
			$cursor = $this->check_component( $components[ $index ], $cursor );
			$index++;
			$cursor['index'] = $index;
		}

		if ( $index < count( $components ) ) {
			return array( 'continue' => true, 'cursor' => $cursor );
		}

		$this->report_coverage( $cursor );
		return array( 'continue' => false, 'cursor' => array() );
	}

	// -----------------------------------------------------------------------
	// Components
	// -----------------------------------------------------------------------

	/**
	 * Installed plugins followed by the active and parent theme.
	 *
	 * @return array[] Each: type, slug, version, name, target, on_org.
	 */
	private function get_components() {
		$components = array();

		$plugin_updates = get_site_transient( 'update_plugins' );
		foreach ( (array) get_plugins() as $plugin_file => $plugin_data ) {
			$slug    = $this->plugin_slug( $plugin_file );
			$version = isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '';
			if ( ! $slug || ! $version ) {
				continue;
			}
			$components[] = array(
				'type'    => 'plugins',
				'slug'    => $slug,
				'version' => $version,
				'name'    => $plugin_data['Name'],
				'target'  => $plugin_file,
				'on_org'  => $this->listed_in_update_transient( $plugin_updates, $plugin_file, 'plugins', isset( $plugin_data['UpdateURI'] ) ? $plugin_data['UpdateURI'] : '' ),
			);
		}

		$themes = array();
		$active = wp_get_theme();
		if ( $active && $active->exists() ) {
			$themes[ $active->get_stylesheet() ] = $active;
		}
		$parent = $active ? $active->parent() : null;
		if ( $parent && $parent->exists() ) {
			$themes[ $parent->get_stylesheet() ] = $parent;
		}

		$theme_updates = get_site_transient( 'update_themes' );
		foreach ( $themes as $slug => $theme ) {
			$version = $theme->get( 'Version' );
			if ( ! $version ) {
				continue;
			}
			$components[] = array(
				'type'    => 'themes',
				'slug'    => $slug,
				'version' => $version,
				'name'    => $theme->get( 'Name' ),
				'target'  => $slug,
				'on_org'  => $this->listed_in_update_transient( $theme_updates, $slug, 'themes', (string) $theme->get( 'UpdateURI' ) ),
			);
		}

		// WordPress core, looked up on WPVulnerability only.
		$core = isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
		if ( '' !== $core && self::wpv_enabled() ) {
			$components[] = array(
				'type'    => 'core',
				'slug'    => $core,
				'version' => $core,
				'name'    => 'WordPress',
				'target'  => 'WordPress ' . $core,
				'on_org'  => true,
			);
		}

		return $components;
	}

	/**
	 * Whether this plugin/theme is the WordPress.org one, per the core update transient.
	 *
	 * Being in the transient is not enough: since WordPress 5.8 plugins with
	 * their own Update URI, and premium updaters, add entries there too. Only
	 * entries that WordPress.org itself returned count, and a plugin or theme
	 * whose Update URI points elsewhere never does (as in wp_update_plugins()).
	 *
	 * @param mixed  $transient  Value of the update_plugins / update_themes site transient.
	 * @param string $key        Plugin file or theme stylesheet.
	 * @param string $type       'plugins' or 'themes'.
	 * @param string $update_uri The Update URI header, if any.
	 * @return bool
	 */
	private function listed_in_update_transient( $transient, $key, $type, $update_uri = '' ) {
		if ( '' !== trim( (string) $update_uri ) && ! self::is_wporg_update_uri( $update_uri ) ) {
			return false;
		}
		if ( ! is_object( $transient ) ) {
			return false;
		}
		foreach ( array( 'response', 'no_update' ) as $list ) {
			if ( isset( $transient->$list ) && is_array( $transient->$list ) && isset( $transient->{$list}[ $key ] ) ) {
				return self::is_wporg_entry( $transient->{$list}[ $key ], $type );
			}
		}
		return false;
	}

	/**
	 * Whether an Update URI header points at WordPress.org (hosts w.org or
	 * wordpress.org, the same rule core uses). "false" and other hosts don't.
	 *
	 * @param string $update_uri Update URI header.
	 * @return bool
	 */
	public static function is_wporg_update_uri( $update_uri ) {
		$uri = strtolower( trim( (string) $update_uri ) );
		if ( false === strpos( $uri, '://' ) ) {
			$uri = 'https://' . $uri;
		}
		$host = wp_parse_url( $uri, PHP_URL_HOST );
		return in_array( $host, array( 'w.org', 'wordpress.org' ), true );
	}

	/**
	 * Whether an update-transient entry came from WordPress.org.
	 *
	 * Plugin entries from WordPress.org carry an id "w.org/plugins/<slug>";
	 * theme entries carry their wordpress.org/themes/ page as url.
	 *
	 * @param mixed  $entry Entry (object for plugins, array for themes).
	 * @param string $type  'plugins' or 'themes'.
	 * @return bool
	 */
	public static function is_wporg_entry( $entry, $type ) {
		$entry = (array) $entry;
		if ( 'plugins' === $type ) {
			return isset( $entry['id'] ) && 0 === strpos( (string) $entry['id'], 'w.org/plugins/' );
		}
		$url  = isset( $entry['url'] ) ? (string) $entry['url'] : '';
		$host = wp_parse_url( $url, PHP_URL_HOST );
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return 'wordpress.org' === $host && 0 === strpos( $path, '/themes/' );
	}

	/**
	 * Check one component against the built-in list and, if configured, WPScan.
	 *
	 * @param array $component Component from get_components().
	 * @param array $cursor    Cursor.
	 * @return array Updated cursor.
	 */
	private function check_component( array $component, array $cursor ) {
		// 1. WPVulnerability, only for components WordPress.org itself lists
		// (see listed_in_update_transient(): premium and custom plugins, even
		// one sharing a slug with a WordPress.org plugin, are never sent).
		if ( self::wpv_enabled() && $component['on_org'] ) {
			$cursor['wpv_eligible']++;
			$lookup = $cursor['wpv_failed'] >= 2
				? array( 'error' => __( 'WPVulnerability could not be reached', 'shieldscope-site-security-scanner' ) )
				: $this->fetch_wpv( $component['type'], $component['slug'] );
			if ( isset( $lookup['error'] ) ) {
				$cursor['wpv_reasons'][ $lookup['error'] ] = true;
				if ( ! empty( $lookup['unreachable'] ) ) {
					$cursor['wpv_failed']++;
				}
			} else {
				$cursor['wpv_checked']++;
				$this->report_wpv_vulns( $lookup['data'], $component );
				return $cursor;
			}
		}

		if ( 'core' === $component['type'] ) {
			return $cursor;
		}

		// 2. Not answered online: the built-in list, then WPScan if a key is set.
		if ( 'plugins' === $component['type'] ) {
			$this->check_built_in_list( $component['slug'], $component['version'], $component['name'], $component['target'] );
		}

		if ( ! $this->get_api_key() || ! $component['on_org'] ) {
			return $cursor;
		}

		$cursor['eligible']++;

		if ( '' !== $cursor['stop'] ) {
			return $cursor;
		}

		$lookup = $this->fetch_wpscan( $component['type'], $component['slug'] );

		if ( isset( $lookup['error'] ) ) {
			$cursor['reasons'][ $lookup['error'] ] = true;
			if ( ! empty( $lookup['stop'] ) ) {
				$cursor['stop'] = $lookup['error'];
			}
			return $cursor;
		}

		$cursor['checked']++;
		$this->report_wpscan_vulns( $lookup['data'], $component );
		return $cursor;
	}

	/**
	 * Report coverage at the end of the step: always one Info finding about
	 * the limited built-in list, plus one Low finding if WPScan lookups failed.
	 *
	 * @param array $cursor Final cursor.
	 * @return void
	 */
	private function report_coverage( array $cursor ) {
		if ( self::wpv_enabled() ) {
			$this->report_wpv_coverage( $cursor );
			if ( (int) $cursor['eligible'] > 0 ) {
				$this->report_wpscan_shortfall( $cursor );
			}
			return;
		}

		$description = __( 'Installed plugins were compared with a limited built-in list of known vulnerabilities. This is not a complete vulnerability scan: a plugin or theme that is not on the list, or a vulnerability published after the review date, is not detected.', 'shieldscope-site-security-scanner' );
		if ( $this->get_api_key() ) {
			$description .= ' ' . sprintf(
				/* translators: 1: components checked, 2: components eligible for lookup */
				__( 'WPScan lookups: %1$d of %2$d WordPress.org plugins and themes checked.', 'shieldscope-site-security-scanner' ),
				(int) $cursor['checked'],
				(int) $cursor['eligible']
			);
		}

		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			sprintf(
				/* translators: %s: "limited built-in list (N plugins, last reviewed DATE)" */
				__( 'Vulnerability check coverage: %s', 'shieldscope-site-security-scanner' ),
				self::built_in_list_label()
			),
			$description,
			__( 'Keep every plugin and theme updated. For lookups beyond the built-in list, add a WPScan API key in Settings.', 'shieldscope-site-security-scanner' ),
			'',
			array(
				'source'            => 'built-in',
				'built_in_plugins'  => self::built_in_plugin_count(),
				'built_in_reviewed' => self::BUILT_IN_REVIEWED,
			)
		);

		if ( ! $this->get_api_key() ) {
			$this->note_partial( __( 'only the limited built-in list was checked (WPVulnerability lookups are off in Settings and there is no WPScan API key)', 'shieldscope-site-security-scanner' ) );
		}

		$this->report_wpscan_shortfall( $cursor );
	}

	/**
	 * Coverage when WPVulnerability lookups are on: one Info finding with the
	 * count, plus a coverage note and a Low finding if lookups failed.
	 *
	 * @param array $cursor Final cursor.
	 * @return void
	 */
	private function report_wpv_coverage( array $cursor ) {
		$checked  = (int) $cursor['wpv_checked'];
		$eligible = (int) $cursor['wpv_eligible'];

		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			sprintf(
				/* translators: 1: components looked up, 2: components eligible */
				__( 'Vulnerability check coverage: WPVulnerability, %1$d of %2$d components looked up', 'shieldscope-site-security-scanner' ),
				$checked,
				$eligible
			),
			__( 'WordPress core and the installed plugins and themes listed on WordPress.org were looked up on WPVulnerability, a free database that combines CVE, Patchstack, Wordfence, WPScan and other sources (data under CC0 1.0). Only slugs and version numbers were sent. Plugins and themes not listed on WordPress.org (custom or premium) are not looked up, and a vulnerability that is not yet published is not detected.', 'shieldscope-site-security-scanner' ) . ' ' . self::wpv_credit(),
			__( 'Keep WordPress, plugins and themes updated. Review custom and premium plugins with their developers.', 'shieldscope-site-security-scanner' ),
			'',
			array(
				'source'   => 'wpvulnerability',
				'checked'  => $checked,
				'eligible' => $eligible,
			)
		);

		if ( $checked >= $eligible ) {
			return;
		}

		$reasons = empty( $cursor['wpv_reasons'] )
			? array( __( 'unknown error', 'shieldscope-site-security-scanner' ) )
			: array_keys( $cursor['wpv_reasons'] );

		$this->note_partial(
			sprintf(
				/* translators: 1: components looked up, 2: components eligible */
				__( 'WPVulnerability lookups: %1$d of %2$d checked', 'shieldscope-site-security-scanner' ),
				$checked,
				$eligible
			)
		);

		$this->finding(
			ShieldScope_Logger::SEVERITY_LOW,
			sprintf(
				/* translators: 1: components checked, 2: components eligible, 3: reason(s) */
				__( 'Vulnerability lookup incomplete: %1$d of %2$d components checked on WPVulnerability (%3$s)', 'shieldscope-site-security-scanner' ),
				$checked,
				$eligible,
				implode( '; ', $reasons )
			),
			__( 'Some components could not be looked up during this scan. Plugins among them were compared with the limited built-in list instead (and with WPScan if a key is set). This does not mean they are safe.', 'shieldscope-site-security-scanner' ),
			__( 'Check that the server can make outgoing HTTPS requests to www.wpvulnerability.net and run the scan again.', 'shieldscope-site-security-scanner' ),
			'',
			array(
				'source'   => 'wpvulnerability',
				'checked'  => $checked,
				'eligible' => $eligible,
				'reasons'  => $reasons,
			)
		);
	}

	/**
	 * Note and report WPScan lookups that failed.
	 *
	 * @param array $cursor Final cursor.
	 * @return void
	 */
	private function report_wpscan_shortfall( array $cursor ) {
		if ( (int) $cursor['checked'] >= (int) $cursor['eligible'] ) {
			return;
		}

		$reasons = empty( $cursor['reasons'] )
			? array( __( 'unknown error', 'shieldscope-site-security-scanner' ) )
			: array_keys( $cursor['reasons'] );

		$this->note_partial(
			sprintf(
				/* translators: 1: components checked, 2: components eligible */
				__( 'WPScan lookups: %1$d of %2$d checked', 'shieldscope-site-security-scanner' ),
				(int) $cursor['checked'],
				(int) $cursor['eligible']
			)
		);

		$this->finding(
			ShieldScope_Logger::SEVERITY_LOW,
			sprintf(
				/* translators: 1: components checked, 2: components eligible, 3: reason(s) */
				__( 'Vulnerability lookup incomplete: %1$d of %2$d components checked (%3$s)', 'shieldscope-site-security-scanner' ),
				(int) $cursor['checked'],
				(int) $cursor['eligible'],
				implode( '; ', $reasons )
			),
			__( 'Some plugins or themes could not be looked up on WPScan during this scan, so they were not checked for known vulnerabilities. This does not mean they are safe.', 'shieldscope-site-security-scanner' ),
			__( 'Check the WPScan API key in Settings and run the scan again later. The free WPScan plan allows 25 requests per day.', 'shieldscope-site-security-scanner' ),
			'',
			array(
				'source'   => 'wpscan',
				'checked'  => (int) $cursor['checked'],
				'eligible' => (int) $cursor['eligible'],
				'reasons'  => $reasons,
			)
		);
	}

	// -----------------------------------------------------------------------
	// WPVulnerability API
	// -----------------------------------------------------------------------

	/**
	 * Credit line for WPVulnerability data (wording the project suggests),
	 * added to every finding and statement built from it.
	 *
	 * @return string
	 */
	public static function wpv_credit() {
		/* translators: 1: "WPVulnerability" (project name, do not translate), 2: its web address */
		return sprintf( __( 'Vulnerability data from %1$s (%2$s).', 'shieldscope-site-security-scanner' ), 'WPVulnerability', self::WPV_SITE );
	}

	/**
	 * Are WPVulnerability lookups on? On by default; Settings turns them off.
	 *
	 * @return bool
	 */
	public static function wpv_enabled() {
		$settings = (array) get_option( 'shieldscope_settings', array() );
		return ! isset( $settings['wpvulnerability'] ) || ! empty( $settings['wpvulnerability'] );
	}

	/**
	 * Fetch WPVulnerability data for one component, from cache or a request.
	 * Failures are cached for 15 minutes so a scan does not retry them.
	 *
	 * @param string $type 'plugins', 'themes' or 'core'.
	 * @param string $slug Slug, or the WordPress version for core.
	 * @return array Either [ 'data' => array ] or [ 'error' => reason, 'unreachable' => bool ].
	 */
	private function fetch_wpv( $type, $slug ) {
		$cache_key = 'shieldscope_wpv_' . md5( $type . '|' . $slug );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return isset( $cached['lookup_failed'] )
				? array( 'error' => (string) $cached['lookup_failed'], 'unreachable' => false )
				: array( 'data' => $cached );
		}

		$paths    = array( 'plugins' => 'plugin', 'themes' => 'theme', 'core' => 'core' );
		$response = wp_remote_get( self::WPV_API . $paths[ $type ] . '/' . rawurlencode( $slug ) . '/', self::wporg_request_args( 8 ) );

		$error       = '';
		$unreachable = false;
		if ( is_wp_error( $response ) ) {
			$error       = __( 'could not connect to WPVulnerability', 'shieldscope-site-security-scanner' );
			$unreachable = true;
		} else {
			$code = (int) wp_remote_retrieve_response_code( $response );
			$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			if ( 200 !== $code ) {
				/* translators: %d: HTTP status code */
				$error       = sprintf( __( 'WPVulnerability error, HTTP %d', 'shieldscope-site-security-scanner' ), $code );
				$unreachable = $code >= 500;
			} elseif ( ! is_array( $body ) || ! empty( $body['error'] ) || ! isset( $body['data'] ) || ! is_array( $body['data'] ) ) {
				$error = __( 'WPVulnerability returned an unreadable response', 'shieldscope-site-security-scanner' );
			} else {
				$data = array( 'vulnerability' => isset( $body['data']['vulnerability'] ) && is_array( $body['data']['vulnerability'] ) ? $body['data']['vulnerability'] : array() );
				set_transient( $cache_key, $data, self::WPV_CACHE_TTL );
				return array( 'data' => $data );
			}
		}

		set_transient( $cache_key, array( 'lookup_failed' => $error ), 15 * MINUTE_IN_SECONDS );
		return array( 'error' => $error, 'unreachable' => $unreachable );
	}

	/**
	 * Does a WPVulnerability entry affect the installed version?
	 *
	 * Core entries are per version (the lookup is for this exact version).
	 * Otherwise the entry gives an optional lower bound (ge/gt) and upper
	 * bound (lt/le); with no upper bound, only an entry marked unfixed counts.
	 *
	 * @param string $version  Installed version.
	 * @param array  $operator The entry's "operator" object.
	 * @param bool   $core     Core entry.
	 * @return bool
	 */
	public static function wpv_affects( $version, array $operator, $core = false ) {
		if ( $core ) {
			return true;
		}
		$min     = isset( $operator['min_version'] ) ? (string) $operator['min_version'] : '';
		$min_op  = isset( $operator['min_operator'] ) ? (string) $operator['min_operator'] : '';
		$max     = isset( $operator['max_version'] ) ? (string) $operator['max_version'] : '';
		$max_op  = isset( $operator['max_operator'] ) ? (string) $operator['max_operator'] : '';
		$unfixed = ! empty( $operator['unfixed'] ) && '0' !== (string) $operator['unfixed'];

		if ( '' !== $min ) {
			$min_cmp = 'gt' === $min_op ? '>' : '>=';
			if ( ! version_compare( $version, $min, $min_cmp ) ) {
				return false;
			}
		}
		if ( '' !== $max ) {
			return version_compare( $version, $max, 'le' === $max_op ? '<=' : '<' );
		}
		return $unfixed;
	}

	/**
	 * CVSS base score of a WPVulnerability entry (0 when none is published).
	 *
	 * @param array $vuln Entry.
	 * @return float
	 */
	public static function wpv_score( array $vuln ) {
		$impact = isset( $vuln['impact'] ) && is_array( $vuln['impact'] ) ? $vuln['impact'] : array();
		foreach ( array( 'cvss3', 'cvss' ) as $key ) {
			if ( isset( $impact[ $key ]['score'] ) && (float) $impact[ $key ]['score'] > 0 ) {
				return (float) $impact[ $key ]['score'];
			}
		}
		return 0.0;
	}

	/**
	 * One finding per affected component, listing its known vulnerabilities.
	 *
	 * @param array $data      Cached lookup: [ 'vulnerability' => entries ].
	 * @param array $component Component from get_components().
	 * @return void
	 */
	private function report_wpv_vulns( array $data, array $component ) {
		$core    = 'core' === $component['type'];
		$version = $component['version'];
		$items   = array();
		$fixes   = array();
		$unfixed = false;
		$upto    = false;
		$top     = 0.0;
		$kev     = false;

		// The same issue is often listed once per source. An entry without a
		// CVE number that has the same fix as an entry with one is treated as
		// the same issue; entries without a CVE are merged per fix version.
		$affecting = array();
		$cve_fixes = array();
		foreach ( (array) $data['vulnerability'] as $vuln ) {
			if ( ! is_array( $vuln ) ) {
				continue;
			}
			$op = isset( $vuln['operator'] ) && is_array( $vuln['operator'] ) ? $vuln['operator'] : array();
			if ( ! self::wpv_affects( $version, $op, $core ) ) {
				continue;
			}
			$affecting[] = $vuln;
			foreach ( isset( $vuln['source'] ) ? (array) $vuln['source'] : array() as $src ) {
				if ( 0 === strpos( isset( $src['id'] ) ? (string) $src['id'] : '', 'CVE-' ) ) {
					$cve_fixes[ isset( $op['max_version'] ) ? (string) $op['max_version'] : '' ] = true;
				}
			}
		}

		foreach ( $affecting as $vuln ) {
			$op = isset( $vuln['operator'] ) && is_array( $vuln['operator'] ) ? $vuln['operator'] : array();

			$cves  = array();
			$label = '';
			$link  = '';
			foreach ( isset( $vuln['source'] ) ? (array) $vuln['source'] : array() as $src ) {
				$id = isset( $src['id'] ) ? (string) $src['id'] : '';
				if ( 0 === strpos( $id, 'CVE-' ) ) {
					$cves[ $id ] = true;
				}
				if ( '' === $label && ! empty( $src['name'] ) ) {
					$label = html_entity_decode( wp_strip_all_tags( (string) $src['name'] ), ENT_QUOTES, 'UTF-8' );
				}
				if ( '' === $link && ! empty( $src['link'] ) ) {
					$link = (string) $src['link'];
				}
			}
			$cves     = array_keys( $cves );
			$fix_key  = isset( $op['max_version'] ) ? (string) $op['max_version'] : '';
			if ( ! $cves && ! $core && isset( $cve_fixes[ $fix_key ] ) ) {
				continue; // Same issue as a CVE entry with this fix, from another source.
			}
			$label = $cves ? implode( ', ', $cves ) : ( '' !== $label ? $label : (string) ( isset( $vuln['name'] ) ? $vuln['name'] : '' ) );
			$key   = ( $cves || $core ? strtolower( $label ) : 'no-cve' ) . '|' . $fix_key;
			if ( isset( $items[ $key ] ) ) {
				continue; // Same issue listed by another source.
			}

			$score = self::wpv_score( $vuln );
			$top   = max( $top, $score );
			$kev   = $kev || ! empty( $vuln['impact']['ssvc']['kev'] );
			// "lt X": X is the fix. "le X": affected up to and including X; the
			// fix is a later release. Only an explicit unfixed flag, or no upper
			// bound at all, means there is no fix yet.
			$max_op      = isset( $op['max_operator'] ) ? (string) $op['max_operator'] : '';
			$max         = ! empty( $op['max_version'] ) ? (string) $op['max_version'] : '';
			$no_fix      = ( isset( $op['unfixed'] ) && '' !== (string) $op['unfixed'] && '0' !== (string) $op['unfixed'] ) || '' === $max;
			$fixed       = ( ! $core && ! $no_fix && 'lt' === $max_op ) ? $max : '';
			$affected_to = ( ! $core && ! $no_fix && 'le' === $max_op ) ? $max : '';
			if ( '' !== $fixed ) {
				$fixes[] = $fixed;
			} elseif ( '' !== $affected_to ) {
				$upto = true;
			} elseif ( ! $core ) {
				$unfixed = true;
			}

			$items[ $key ] = array(
				'label'       => $label,
				'fixed_in'    => $fixed,
				'affected_to' => $affected_to,
				'cvss'     => $score > 0 ? $score : 'unrated',
				'link'     => $link,
			);
		}

		if ( ! $items ) {
			return;
		}

		$severity = $this->wpscan_cvss_to_severity( $top );
		if ( $kev && in_array( $severity, array( ShieldScope_Logger::SEVERITY_MEDIUM, ShieldScope_Logger::SEVERITY_LOW ), true ) ) {
			$severity = ShieldScope_Logger::SEVERITY_HIGH; // Known to be exploited (CISA KEV).
		}

		usort(
			$fixes,
			static function ( $a, $b ) {
				return version_compare( $b, $a );
			}
		);
		$latest_fix = $fixes ? $fixes[0] : '';

		$lines = array();
		foreach ( array_slice( array_values( $items ), 0, self::WPV_MAX_LISTED ) as $item ) {
			$parts = array();
			if ( '' !== $item['fixed_in'] ) {
				/* translators: %s: version */
				$parts[] = sprintf( __( 'fixed in %s', 'shieldscope-site-security-scanner' ), $item['fixed_in'] );
			} elseif ( '' !== $item['affected_to'] ) {
				/* translators: %s: version */
				$parts[] = sprintf( __( 'affected up to %s', 'shieldscope-site-security-scanner' ), $item['affected_to'] );
			} elseif ( ! $core ) {
				$parts[] = __( 'no fix yet', 'shieldscope-site-security-scanner' );
			}
			if ( 'unrated' !== $item['cvss'] ) {
				/* translators: %s: CVSS score */
				$parts[] = sprintf( __( 'CVSS %s', 'shieldscope-site-security-scanner' ), number_format( (float) $item['cvss'], 1 ) );
			}
			$lines[] = $item['label'] . ( $parts ? ' (' . implode( ', ', $parts ) . ')' : '' ) . ( '' !== $item['link'] ? ' ' . $item['link'] : '' );
		}
		if ( count( $items ) > self::WPV_MAX_LISTED ) {
			/* translators: %d: number of further vulnerabilities */
			$lines[] = sprintf( __( 'and %d more', 'shieldscope-site-security-scanner' ), count( $items ) - self::WPV_MAX_LISTED );
		}

		$desc = sprintf(
			/* translators: 1: component name, 2: installed version, 3: number of vulnerabilities, 4: list */
			_n( '%1$s %2$s has %3$d known vulnerability: %4$s.', '%1$s %2$s has %3$d known vulnerabilities: %4$s.', count( $items ), 'shieldscope-site-security-scanner' ),
			$component['name'],
			$version,
			count( $items ),
			implode( '; ', $lines )
		);
		if ( $kev ) {
			$desc .= ' ' . __( 'At least one is listed as exploited in the wild (CISA KEV).', 'shieldscope-site-security-scanner' );
		}
		$desc .= ' ' . self::wpv_credit();

		if ( $core ) {
			$rec = __( 'Update WordPress to the latest version (Dashboard → Updates). Every listed issue is fixed in a later release.', 'shieldscope-site-security-scanner' );
		} elseif ( $unfixed ) {
			$rec = __( 'At least one issue has no fix yet. Deactivate and remove it until a fixed version is released, or replace it; update to the latest version for the issues that are fixed.', 'shieldscope-site-security-scanner' );
		} elseif ( $upto ) {
			$rec = '' !== $latest_fix
				/* translators: %s: version */
				? sprintf( __( 'Update to the latest version (%s or later). For issues listed as "affected up to" a version, the fix is in a later release; the advisory names it.', 'shieldscope-site-security-scanner' ), $latest_fix )
				: __( 'Update to the latest version. For issues listed as "affected up to" a version, the fix is in a later release; the advisory names it.', 'shieldscope-site-security-scanner' );
		} else {
			/* translators: %s: version */
			$rec = sprintf( __( 'Update to version %s or later.', 'shieldscope-site-security-scanner' ), $latest_fix );
		}

		$this->finding(
			$severity,
			sprintf(
				/* translators: 1: component name, 2: installed version, 3: number of vulnerabilities */
				_n( '[WPVulnerability] %1$s %2$s: %3$d known vulnerability', '[WPVulnerability] %1$s %2$s: %3$d known vulnerabilities', count( $items ), 'shieldscope-site-security-scanner' ),
				$component['name'],
				$version,
				count( $items )
			),
			$desc,
			$rec,
			$component['target'],
			array(
				'source'    => 'wpvulnerability',
				'installed' => $version,
				'fixed_in'  => $latest_fix,
				'unfixed'   => $unfixed,
				'cvss'      => $top > 0 ? $top : 'unrated',
				'kev'       => $kev,
				'vulns'     => array_values( $items ),
			)
		);
	}

	// -----------------------------------------------------------------------
	// WPScan API
	// -----------------------------------------------------------------------

	/**
	 * Fetch WPScan data for one slug, from cache or a counted live request.
	 *
	 * @param string $type 'plugins' or 'themes'.
	 * @param string $slug Plugin/theme slug.
	 * @return array Either [ 'data' => array ] or [ 'error' => reason, 'stop' => bool ].
	 */
	private function fetch_wpscan( $type, $slug ) {
		$cache_key = 'shieldscope_wpscan_' . md5( $type . $slug );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return array( 'data' => $cached );
		}

		$counter_key = 'shieldscope_wpscan_requests_' . gmdate( 'Ymd' );
		$used        = (int) get_transient( $counter_key );
		if ( $used >= self::WPSCAN_DAILY_QUOTA ) {
			return array(
				'error' => __( 'WPScan daily request limit reached', 'shieldscope-site-security-scanner' ),
				'stop'  => true,
			);
		}
		set_transient( $counter_key, $used + 1, DAY_IN_SECONDS );

		$response = wp_remote_get(
			self::WPSCAN_API . $type . '/' . rawurlencode( $slug ),
			array(
				'timeout' => 8,
				'headers' => array(
					'Authorization' => 'Token token=' . $this->get_api_key(),
					'User-Agent'    => 'shieldscope/' . SHIELDSCOPE_VERSION,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'error' => __( 'could not connect to WPScan', 'shieldscope-site-security-scanner' ),
				'stop'  => false,
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 === $code ) {
			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! is_array( $body ) ) {
				return array(
					'error' => __( 'WPScan returned an unreadable response', 'shieldscope-site-security-scanner' ),
					'stop'  => false,
				);
			}
			set_transient( $cache_key, $body, self::CACHE_TTL );
			return array( 'data' => $body );
		}

		if ( 404 === $code ) {
			// WPScan has no record of this slug: a real answer, safe to cache.
			set_transient( $cache_key, array(), self::CACHE_TTL );
			return array( 'data' => array() );
		}

		if ( 401 === $code || 403 === $code ) {
			return array(
				'error' => sprintf(
					/* translators: %d: HTTP status code */
					__( 'WPScan rejected the API key, HTTP %d', 'shieldscope-site-security-scanner' ),
					$code
				),
				'stop'  => true,
			);
		}

		if ( 429 === $code ) {
			set_transient( $counter_key, self::WPSCAN_DAILY_QUOTA, DAY_IN_SECONDS );
			return array(
				'error' => __( 'WPScan daily request limit reached, HTTP 429', 'shieldscope-site-security-scanner' ),
				'stop'  => true,
			);
		}

		return array(
			'error' => sprintf(
				/* translators: %d: HTTP status code */
				__( 'WPScan error, HTTP %d', 'shieldscope-site-security-scanner' ),
				$code
			),
			'stop'  => false,
		);
	}

	/**
	 * Flag any unresolved WPScan vulnerabilities for the installed version.
	 *
	 * @param array $data      Decoded WPScan response.
	 * @param array $component Component from get_components().
	 * @return void
	 */
	private function report_wpscan_vulns( array $data, array $component ) {
		$slug    = $component['slug'];
		$version = $component['version'];
		$name    = $component['name'];

		// WPScan response structure: { slug: { vulnerabilities: [...] } }.
		$slug_data = isset( $data[ $slug ] ) ? $data[ $slug ] : array();
		$vulns     = isset( $slug_data['vulnerabilities'] ) ? (array) $slug_data['vulnerabilities'] : array();

		foreach ( $vulns as $vuln ) {
			$fixed_in = isset( $vuln['fixed_in'] ) ? $vuln['fixed_in'] : null;

			// If fixed_in is set and installed version >= fixed_in, the vulnerability is patched.
			if ( $fixed_in && version_compare( $version, $fixed_in, '>=' ) ) {
				continue;
			}
			// Older than the first affected version: not affected (IM2-13).
			$introduced_in = isset( $vuln['introduced_in'] ) ? (string) $vuln['introduced_in'] : '';
			if ( '' !== $introduced_in && version_compare( $version, $introduced_in, '<' ) ) {
				continue;
			}

			$vuln_title = isset( $vuln['title'] ) ? $vuln['title'] : __( 'Unknown vulnerability', 'shieldscope-site-security-scanner' );
			$cve_ids    = array();
			if ( ! empty( $vuln['references']['cve'] ) ) {
				foreach ( (array) $vuln['references']['cve'] as $cve ) {
					$cve_ids[] = 'CVE-' . $cve;
				}
			}

			$score    = isset( $vuln['cvss']['score'] ) ? (float) $vuln['cvss']['score'] : 0.0;
			$severity = $this->wpscan_cvss_to_severity( $score );

			$desc = sprintf(
				/* translators: 1: plugin name, 2: installed version, 3: fix version or 'unknown' */
				__( '%1$s version %2$s is affected. %3$s', 'shieldscope-site-security-scanner' ),
				$name,
				$version,
				$fixed_in
					/* translators: %s: version number */
					? sprintf( __( 'Fixed in version %s.', 'shieldscope-site-security-scanner' ), $fixed_in )
					: __( 'No fix version known — check the plugin/theme page for updates.', 'shieldscope-site-security-scanner' )
			);
			if ( $score <= 0.0 ) {
				$desc .= ' ' . __( 'Severity: Unrated (WPScan published no CVSS score for this issue).', 'shieldscope-site-security-scanner' );
			}

			$rec = $fixed_in
				? sprintf(
					/* translators: %s: fix version */
					__( 'Update to version %s or later immediately.', 'shieldscope-site-security-scanner' ),
					$fixed_in
				)
				: __( 'No fix is available yet. Deactivate and remove this plugin/theme until a patch is released. Contact the developer via the wordpress.org support forum to ask for a timeline.', 'shieldscope-site-security-scanner' );

			$this->finding(
				$severity,
				sprintf(
					/* translators: 1: plugin name, 2: CVE ID(s) or vulnerability title */
					__( '[WPScan] %1$s — %2$s', 'shieldscope-site-security-scanner' ),
					$name,
					! empty( $cve_ids ) ? implode( ', ', $cve_ids ) : $vuln_title
				),
				$desc,
				$rec,
				$component['target'],
				array(
					'vuln_title'  => $vuln_title,
					'fixed_in'    => $fixed_in,
					'cves'        => $cve_ids,
					'installed'   => $version,
					'cvss'        => $score > 0.0 ? $score : 'unrated',
					'source'      => 'wpscan',
				)
			);
		}
	}

	/**
	 * Map a CVSS score to a ShieldScope severity level.
	 *
	 * @param float $score CVSS score (0-10).
	 * @return string
	 */
	private function wpscan_cvss_to_severity( $score ) {
		if ( $score >= 9.0 ) {
			return ShieldScope_Logger::SEVERITY_CRITICAL;
		}
		if ( $score >= 7.0 ) {
			return ShieldScope_Logger::SEVERITY_HIGH;
		}
		if ( $score >= 4.0 ) {
			return ShieldScope_Logger::SEVERITY_MEDIUM;
		}
		if ( $score > 0.0 ) {
			return ShieldScope_Logger::SEVERITY_LOW;
		}
		return ShieldScope_Logger::SEVERITY_MEDIUM; // Unrated: no score published.
	}

	// -----------------------------------------------------------------------
	// Built-in CVE list
	// -----------------------------------------------------------------------

	/**
	 * Number of plugins covered by the built-in list.
	 *
	 * Copy that mentions the list size should use this rather than a literal.
	 *
	 * @return int
	 */
	public static function built_in_plugin_count() {
		return count( self::get_built_in_vuln_db() );
	}

	/**
	 * "limited built-in list (N plugins, last reviewed DATE)".
	 *
	 * @return string
	 */
	private static function built_in_list_label() {
		return sprintf(
			/* translators: 1: number of plugins, 2: review date (YYYY-MM-DD) */
			__( 'limited built-in list (%1$d plugins, last reviewed %2$s)', 'shieldscope-site-security-scanner' ),
			self::built_in_plugin_count(),
			self::BUILT_IN_REVIEWED
		);
	}

	/**
	 * Check a plugin against the built-in vulnerability list.
	 *
	 * Each entry specifies the first fixed version (fixed_in) and, where NVD
	 * gives one, the first affected version (affected_from).
	 *
	 * @param string $slug    Plugin slug (directory name).
	 * @param string $version Installed version string.
	 * @param string $name    Plugin display name.
	 * @param string $target  Plugin file path for the finding target.
	 * @return void
	 */
	private function check_built_in_list( $slug, $version, $name, $target ) {
		$db = self::get_built_in_vuln_db();

		if ( ! isset( $db[ $slug ] ) ) {
			return;
		}

		foreach ( $db[ $slug ] as $vuln ) {
			// Skip if installed version >= fixed version.
			if ( version_compare( $version, $vuln['fixed_in'], '>=' ) ) {
				continue;
			}
			if ( ! empty( $vuln['affected_from'] ) && version_compare( $version, $vuln['affected_from'], '<' ) ) {
				continue;
			}

			$cve_str = ! empty( $vuln['cve'] ) ? ' (' . $vuln['cve'] . ')' : '';
			$cve_url = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode( $vuln['cve'] );

			$this->finding(
				$vuln['severity'],
				sprintf(
					/* translators: 1: plugin name, 2: vulnerability type */
					__( '%1$s — %2$s (installed version is vulnerable)', 'shieldscope-site-security-scanner' ),
					$name,
					$vuln['type'] . $cve_str
				),
				sprintf(
					/* translators: 1: plugin name, 2: installed version, 3: fixed version */
					__( '%1$s version %2$s is affected by a known security vulnerability. The fix was released in version %3$s.', 'shieldscope-site-security-scanner' ),
					$name,
					$version,
					$vuln['fixed_in']
				) . ' ' . sprintf(
					/* translators: 1: "limited built-in list (N plugins, last reviewed DATE)", 2: NVD URL */
					__( 'Source: %1$s. Details: %2$s', 'shieldscope-site-security-scanner' ),
					self::built_in_list_label(),
					$cve_url
				),
				sprintf(
					/* translators: %s: plugin name */
					__( 'Update %s immediately via Dashboard → Plugins → Updates. If an update is not yet available, contact the plugin developer via their wordpress.org support forum to report the issue and ask for a timeline.', 'shieldscope-site-security-scanner' ),
					$name
				),
				$target,
				array(
					'vuln_type'  => $vuln['type'],
					'cve'        => $vuln['cve'],
					'cve_url'    => $cve_url,
					'installed'  => $version,
					'fixed_in'   => $vuln['fixed_in'],
					'source'     => 'built-in',
				)
			);
		}
	}

	/**
	 * Built-in list of plugin CVEs.
	 *
	 * Every entry was checked on BUILT_IN_REVIEWED against its NVD record
	 * (product, type, affected range, NVD base score -> severity) and the
	 * vendor changelog for the fixed version. Entries that could not be
	 * verified were removed. Do not add an entry without the same check.
	 *
	 * Format: slug => [ [ type, cve, fixed_in, severity, affected_from? ], ... ]
	 *
	 * @return array
	 */
	public static function get_built_in_vuln_db() {
		return array(

			// NVD: before 5.3.2, unrestricted file upload and RCE (CVSS 10.0).
			'contact-form-7' => array(
				array(
					'type'     => __( 'Unrestricted File Upload leading to RCE', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2020-35489',
					'fixed_in' => '5.3.2',
					'severity' => ShieldScope_Logger::SEVERITY_CRITICAL,
				),
			),

			// NVD: before 1.3.28, directory traversal via the file parameter (CVSS 7.5).
			'duplicator' => array(
				array(
					'type'     => __( 'Unauthenticated Directory Traversal (Arbitrary File Read)', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2020-11738',
					'fixed_in' => '1.3.28',
					'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				),
			),

			// NVD: before 6.9, unauthenticated upload and execution of PHP (CVSS 9.8).
			'wp-file-manager' => array(
				array(
					'type'     => __( 'Unauthenticated Remote Code Execution', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2020-25213',
					'fixed_in' => '6.9',
					'severity' => ShieldScope_Logger::SEVERITY_CRITICAL,
				),
			),

			// NVD: before 1.4.3, remote attackers can execute arbitrary code (CVSS 9.8).
			'wp-gdpr-compliance' => array(
				array(
					'type'     => __( 'Unauthenticated Remote Code Execution', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2018-19207',
					'fixed_in' => '1.4.3',
					'severity' => ShieldScope_Logger::SEVERITY_CRITICAL,
				),
			),

			// NVD: before 1.2.2, unauthenticated SQL injection (CVSS 7.5).
			'wp-fastest-cache' => array(
				array(
					'type'     => __( 'Unauthenticated SQL Injection', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2023-6063',
					'fixed_in' => '1.2.2',
					'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				),
			),

			// NVD: 5.4.0 through 5.7.1, privilege escalation (CVSS 9.8); 5.7.2 changelog: login/register security fix.
			'essential-addons-for-elementor-lite' => array(
				array(
					'type'          => __( 'Unauthenticated Privilege Escalation', 'shieldscope-site-security-scanner' ),
					'cve'           => 'CVE-2023-32243',
					'fixed_in'      => '5.7.2',
					'affected_from' => '5.4.0',
					'severity'      => ShieldScope_Logger::SEVERITY_CRITICAL,
				),
			),

			// NVD: <= 6.1.5, unauthenticated reflected XSS in ACF and ACF Pro (CVSS 6.1).
			'advanced-custom-fields' => array(
				array(
					'type'     => __( 'Unauthenticated Reflected Cross-Site Scripting', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2023-30777',
					'fixed_in' => '6.1.6',
					'severity' => ShieldScope_Logger::SEVERITY_MEDIUM,
				),
			),
			'advanced-custom-fields-pro' => array(
				array(
					'type'     => __( 'Unauthenticated Reflected Cross-Site Scripting', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2023-30777',
					'fixed_in' => '6.1.6',
					'severity' => ShieldScope_Logger::SEVERITY_MEDIUM,
				),
			),

			// NVD: <= 3.5.5, DOM-based reflected XSS (CVSS 6.1); 3.5.6 changelog: lightbox sanitization hardened.
			'elementor'  => array(
				array(
					'type'     => __( 'DOM-based Reflected Cross-Site Scripting', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2022-29455',
					'fixed_in' => '3.5.6',
					'severity' => ShieldScope_Logger::SEVERITY_MEDIUM,
				),
			),

			// NVD: before 12.1.1, author+ arbitrary file manipulation (CVSS 8.8); vendor 12.1.1 security release.
			'jetpack' => array(
				array(
					'type'     => __( 'Arbitrary File Manipulation (author+)', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2023-2996',
					'fixed_in' => '12.1.1',
					'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				),
			),

			// NVD: <= 13.1.5, unauthenticated SQL injection (CVSS 7.5); 13.1.6 changelog: security hardening.
			'wp-statistics' => array(
				array(
					'type'     => __( 'Unauthenticated SQL Injection', 'shieldscope-site-security-scanner' ),
					'cve'      => 'CVE-2022-25148',
					'fixed_in' => '13.1.6',
					'severity' => ShieldScope_Logger::SEVERITY_HIGH,
				),
			),
		);
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Extract the plugin slug (directory name) from a plugin file path.
	 *
	 * @param string $plugin_file e.g. 'formidable/formidable.php'.
	 * @return string Slug (directory part only), or '' for single-file plugins.
	 */
	private function plugin_slug( $plugin_file ) {
		$parts = explode( '/', $plugin_file );
		return count( $parts ) > 1 ? $parts[0] : '';
	}

	/**
	 * Retrieve the configured WPScan API key.
	 *
	 * @return string Empty string if not configured.
	 */
	private function get_api_key() {
		return isset( $this->settings['wpscan_api_key'] )
			? (string) $this->settings['wpscan_api_key']
			: '';
	}
}
