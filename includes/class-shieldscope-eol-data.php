<?php
/**
 * End-of-life dates for PHP, MySQL, MariaDB and WordPress.
 *
 * One dated table per product: branch ("major.minor") => last day of security
 * support (Y-m-d, UTC), or null when the vendor lists the branch as supported
 * without an announced end date. Checks compare these dates with time(), so a
 * version turns end-of-life on the right day without a code change. Update the
 * table and LAST_REVIEWED together; a unit test fails when LAST_REVIEWED is
 * more than six months old.
 *
 * Sources (all fetched 2026-11-14; endoflife.date used only as a cross-check):
 * - PHP: https://www.php.net/supported-versions.php (8.2-8.5, "security
 *   support until") and https://www.php.net/eol.php (8.1 and older).
 * - MySQL: Oracle Lifetime Support Policy, Technology Products, effective
 *   13 Nov 2026, "Oracle MySQL Releases", end of Extended Support
 *   (https://www.oracle.com/us/support/library/lifetime-support-technology-069183.pdf).
 *   Oracle gives a month only; the last day of that month is used.
 *   Innovation releases: "supported until the next Innovation release"
 *   (https://dev.mysql.com/doc/refman/9.7/en/mysql-releases.html); 26.10.0 was
 *   released 2026-10-20 (https://dev.mysql.com/doc/relnotes/mysql/26.10/en/).
 * - MariaDB: https://mariadb.org/about/#maintenance-policy, "Community" end of
 *   life column of the long-term release table. Rolling releases 13.0 and
 *   13.1 are left out: the page gives only a quarter (Q4 2026, Q1 2027).
 * - WordPress: only the latest major release is officially supported
 *   (https://wordpress.org/documentation/article/supported-versions/). Courtesy
 *   backports ended for 3.7-4.0 "as of December 1, 2022"
 *   (https://make.wordpress.org/security/2022/09/07/dropping-security-updates-for-wordpress-versions-3-7-through-4-0/)
 *   and for 4.1-4.6 "in July 2025", last day of that month used
 *   (https://make.wordpress.org/security/2025/06/18/security-updates-will-cease-for-wordpress-versions-4-1-through-4-6/).
 *   4.7 and later have no announced end date, so they are not listed.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_EOL_Data
 */
class ShieldScope_EOL_Data {

	/**
	 * Date the table below was last checked against the sources.
	 */
	const LAST_REVIEWED = '2026-11-14';

	const STATUS_EOL       = 'eol';
	const STATUS_SUPPORTED = 'supported';
	const STATUS_UNKNOWN   = 'unknown';

	/**
	 * Branch => last day of security support (Y-m-d) or null (no end date announced).
	 *
	 * @return array<string, array<string, string|null>>
	 */
	public static function table() {
		return array(
			'php'       => array(
				'5.6' => '2018-12-31',
				'7.0' => '2019-01-10',
				'7.1' => '2019-12-01',
				'7.2' => '2020-11-30',
				'7.3' => '2021-12-06',
				'7.4' => '2022-11-28',
				'8.0' => '2023-11-26',
				'8.1' => '2025-12-31',
				'8.2' => '2026-12-31',
				'8.3' => '2027-12-31',
				'8.4' => '2028-12-31',
				'8.5' => '2029-12-31',
			),
			'mysql'     => array(
				'5.0'   => '2011-12-31',
				'5.1'   => '2013-12-31',
				'5.5'   => '2018-12-31',
				'5.6'   => '2021-02-28',
				'5.7'   => '2023-10-31',
				'8.0'   => '2026-04-30',
				'8.4'   => '2032-04-30',
				'9.7'   => '2034-04-30',
				'26.7'  => '2026-10-20',
				'26.10' => null,
			),
			'mariadb'   => array(
				'5.1'   => '2015-02-01',
				'5.2'   => '2015-11-10',
				'5.3'   => '2017-03-01',
				'5.5'   => '2020-04-11',
				'10.0'  => '2019-03-31',
				'10.1'  => '2020-10-17',
				'10.2'  => '2022-05-23',
				'10.3'  => '2023-05-25',
				'10.4'  => '2024-06-18',
				'10.5'  => '2025-06-24',
				'10.6'  => '2026-07-06',
				'10.11' => '2028-02-16',
				'11.4'  => '2029-05-29',
				'11.8'  => '2028-06-04',
				'12.3'  => '2029-06-12',
			),
			'wordpress' => array(
				'3.7' => '2022-12-01',
				'3.8' => '2022-12-01',
				'3.9' => '2022-12-01',
				'4.0' => '2022-12-01',
				'4.1' => '2025-07-31',
				'4.2' => '2025-07-31',
				'4.3' => '2025-07-31',
				'4.4' => '2025-07-31',
				'4.5' => '2025-07-31',
				'4.6' => '2025-07-31',
			),
		);
	}

	/**
	 * Products whose unlisted branches between two listed ones are short-term
	 * (MySQL Innovation, MariaDB short-term or rolling) releases that a newer
	 * listed release has superseded, and so are end-of-life.
	 *
	 * @var string[]
	 */
	private static $superseded_unlisted_is_eol = array( 'mysql', 'mariadb' );

	/**
	 * "major.minor" branch of a version string, e.g. "10.11.5-MariaDB" => "10.11".
	 *
	 * @param string $version Version string.
	 * @return string Empty string when no branch can be read.
	 */
	public static function branch( $version ) {
		if ( ! preg_match( '/(\d+)\.(\d+)/', (string) $version, $m ) ) {
			return '';
		}
		return (int) $m[1] . '.' . (int) $m[2];
	}

	/**
	 * Support status of a version.
	 *
	 * @param string   $product One of php, mysql, mariadb, wordpress.
	 * @param string   $version Version string.
	 * @param int|null $now     Unix time to compare with; defaults to time().
	 * @return array { status: string, branch: string, eol_date: string|null }
	 */
	public static function lookup( $product, $version, $now = null ) {
		$now    = null === $now ? time() : (int) $now;
		$table  = self::table();
		$branch = self::branch( $version );
		$result = array(
			'status'   => self::STATUS_UNKNOWN,
			'branch'   => $branch,
			'eol_date' => null,
		);

		if ( '' === $branch || ! isset( $table[ $product ] ) ) {
			return $result;
		}

		$releases = $table[ $product ];

		if ( array_key_exists( $branch, $releases ) ) {
			$date               = $releases[ $branch ];
			$result['eol_date'] = $date;
			$result['status']   = ( null !== $date && $now > strtotime( $date . ' 23:59:59 UTC' ) )
				? self::STATUS_EOL
				: self::STATUS_SUPPORTED;
			return $result;
		}

		$listed = array_keys( $releases );
		usort( $listed, 'version_compare' );
		$oldest = reset( $listed );
		$newest = end( $listed );

		if ( version_compare( $branch, $oldest, '<' ) ) {
			$result['status'] = self::STATUS_EOL;
		} elseif ( version_compare( $branch, $newest, '<' ) && in_array( $product, self::$superseded_unlisted_is_eol, true ) ) {
			$result['status'] = self::STATUS_EOL;
		}

		return $result;
	}

	/**
	 * Format a Y-m-d table date for display.
	 *
	 * @param string $date Date (Y-m-d).
	 * @return string
	 */
	public static function format_date( $date ) {
		return wp_date( 'j F Y', strtotime( $date . ' 12:00:00 UTC' ), new DateTimeZone( 'UTC' ) );
	}
}
