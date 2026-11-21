<?php
/**
 * Tests for S-23: injected code in post content and options.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Fake wpdb for the content step.
 */
class SS_S23_Wpdb {
	public $options = 'wp_options';
	public $posts   = 'wp_posts';
	public $opt_rows  = array();
	public $post_rows = array();
	public $queries   = 0;
	public $last_sql = array();
	public function esc_like( $t ) {
		return addcslashes( $t, '_%\\' );
	}
	public function prepare( $sql, ...$args ) {
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%[ds]/', is_int( $a ) ? (string) $a : "'" . $a . "'", $sql, 1 );
		}
		return $sql;
	}
	public function get_results( $sql, $output = null ) {
		++$this->queries;
		$this->last_sql[] = $sql;
		if ( false !== strpos( $sql, 'option_value' ) ) {
			preg_match( '/option_id > (\d+)/', $sql, $m );
			$out = array();
			foreach ( $this->opt_rows as $i => $row ) {
				$row += array( 'option_id' => $i + 1 );
				if ( $row['option_id'] > (int) $m[1] && 0 !== strpos( $row['option_name'], '_transient' ) ) {
					$out[] = $row;
				}
			}
			return array_slice( $out, 0, 200 );
		}
		preg_match( '/ID > (\d+).*LIMIT (\d+)/s', $sql, $m );
		$out = array();
		foreach ( $this->post_rows as $row ) {
			if ( $row['ID'] > (int) $m[1] && count( $out ) < (int) $m[2] ) {
				$out[] = $row;
			}
		}
		return $out;
	}
}

/**
 * Class Test_S23_DB_Content
 */
class Test_S23_DB_Content extends TestCase {

	/** @var mixed */
	private $saved;

	protected function setUp(): void {
		ss_tests_reset_state();
		$this->saved     = isset( $GLOBALS['wpdb'] ) ? $GLOBALS['wpdb'] : null;
		$GLOBALS['wpdb'] = new SS_S23_Wpdb();
	}

	protected function tearDown(): void {
		$GLOBALS['wpdb'] = $this->saved;
	}

	private function post( $id, $content ) {
		return array( 'ID' => $id, 'post_type' => 'post', 'post_content' => $content );
	}

	private function run_step() {
		$logger = new SS_Fake_Logger();
		$check  = new ShieldScope_Check_Database( 's', $logger );
		$cursor = array();
		do {
			$r      = $check->run_step( 'content', $cursor );
			$cursor = $r['cursor'];
		} while ( ! empty( $r['continue'] ) );
		return $logger->findings;
	}

	public function test_rules_and_severities() {
		$GLOBALS['wpdb']->post_rows = array(
			$this->post( 1, 'Hello world' ),
			$this->post( 2, "Intro\n<script>eval(atob('ZG9jdW1lbnQ='))</script>" ),
			$this->post( 3, '<iframe src="https://x.example" width="1" height="1" style="display:none"></iframe>' ),
			$this->post( 4, '<script src="https://www.googletagmanager.com/gtag/js"></script>' ),
			$this->post( 5, '<iframe src="https://www.youtube.com/embed/x" width="560" height="315"></iframe>' ),
		);
		$GLOBALS['wpdb']->opt_rows = array(
			array( 'option_name' => 'widget_custom_html', 'option_value' => '<script>document.write(unescape("%3Cscript"))</script>' ),
			array( 'option_name' => '_transient_feed_x', 'option_value' => '<script>x</script>' ),
		);
		$got = array();
		foreach ( $this->run_step() as $f ) {
			$got[] = $f['severity'] . ' ' . $f['title'] . ' ' . $f['target'];
		}
		$this->assertSame(
			array(
				'high Review: obfuscated JavaScript in stored content option:widget_custom_html',
				'high Review: obfuscated JavaScript in stored content post:2',
				'medium Review: hidden iframe in stored content post:3',
				'low Review: script tag in stored content post:4',
			),
			$got
		);
	}

	public function test_hex_escaped_payload() {
		$GLOBALS['wpdb']->post_rows = array( $this->post( 9, '<p>x</p>' . str_repeat( '\\x41', 25 ) ) );
		$this->assertSame( 'Review: obfuscated JavaScript in stored content', $this->run_step()[0]['title'] );
		$GLOBALS['wpdb']->post_rows = array( $this->post( 9, 'Price \\x41 only' ) );
		$this->assertSame( array(), $this->run_step() );
	}

	public function test_gtm_noscript_iframe_is_not_hidden_iframe_and_embeds_are_skipped() {
		$GLOBALS['wpdb']->opt_rows = array(
			array( 'option_name' => 'hfcm_footer', 'option_value' => '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-X" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>' ),
		);
		$this->assertSame( array(), $this->run_step() );
		$this->assertStringContainsString( "'oembed_cache'", implode( ' ', $GLOBALS['wpdb']->last_sql ) );
		$this->assertStringContainsString( "NOT LIKE '\\_transient\\_%'", implode( ' ', $GLOBALS['wpdb']->last_sql ) );
	}

	public function test_hidden_iframe_regex_is_linear() {
		$GLOBALS['wpdb']->post_rows = array( $this->post( 1, str_repeat( '<iframe ', 40000 ) ) );
		$start = microtime( true );
		$this->run_step();
		$this->assertLessThan( 2.0, microtime( true ) - $start );
	}

	public function test_findings_per_rule_are_capped_with_a_summary() {
		$rows = array();
		for ( $i = 1; $i <= 70; $i++ ) {
			$rows[] = $this->post( $i, '<script src="https://platform.twitter.com/widgets.js"></script>' );
		}
		$GLOBALS['wpdb']->post_rows = $rows;
		$findings = $this->run_step();
		$this->assertCount( 51, $findings );
		$this->assertSame( 'More items matched: Review: script tag in stored content', $findings[50]['title'] );
		$this->assertStringContainsString( '70 items matched', $findings[50]['description'] );
	}

	public function test_evidence_line() {
		$GLOBALS['wpdb']->post_rows = array( $this->post( 7, "a\nb\n<script>eval(atob('x'))</script>" ) );
		$f = $this->run_step()[0];
		$this->assertSame( 3, $f['context']['evidence']['line'] );
		$this->assertSame( 'review', $f['context']['confidence'] );
	}

	public function test_pages_through_all_posts() {
		$rows = array();
		for ( $i = 1; $i <= 450; $i++ ) {
			$rows[] = $this->post( $i, 450 === $i ? '<script>x</script>' : 'ok' );
		}
		$GLOBALS['wpdb']->post_rows = $rows;
		$findings                   = $this->run_step();
		$this->assertSame( array( 'post:450' ), array_column( $findings, 'target' ) );
	}
}
