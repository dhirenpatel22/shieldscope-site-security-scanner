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
	public function prepare( $sql, ...$args ) {
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%d/', (string) (int) $a, $sql, 1 );
		}
		return $sql;
	}
	public function get_results( $sql, $output = null ) {
		++$this->queries;
		if ( false !== strpos( $sql, 'option_value' ) ) {
			return $this->opt_rows;
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
