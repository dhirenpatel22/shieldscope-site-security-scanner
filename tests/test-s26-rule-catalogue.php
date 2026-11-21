<?php
/**
 * S-26: docs/rules.md must match the check sources.
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_S26_Rule_Catalogue
 */
class Test_S26_Rule_Catalogue extends TestCase {

	public function test_catalogue_is_up_to_date() {
		exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( SHIELDSCOPE_PLUGIN_DIR . 'bin/rule-catalogue.php' ) . ' --check 2>&1', $out, $code );
		$this->assertSame( 0, $code, implode( "\n", $out ) );
	}

	public function test_every_check_is_in_the_catalogue() {
		$doc = file_get_contents( SHIELDSCOPE_PLUGIN_DIR . 'docs/rules.md' );
		foreach ( ( new ShieldScope_Scanner() )->get_check_classes() as $class ) {
			$check = new $class( '', new SS_Fake_Logger() );
			$this->assertStringContainsString( '(`' . $check->get_id() . '`)', $doc, $class );
		}
		$this->assertStringContainsString( '16 checks', $doc );
	}
}
