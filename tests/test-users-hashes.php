<?php
/**
 * Tests for ShieldScope_Check_Users::is_recognized_hash().
 *
 * Regression: WordPress 6.8+ stores bcrypt hashes with a $wp$ prefix
 * ($wp$2y$…). The old check only accepted $P$/$H$/$2y$/$argon2, so every
 * user on a modern install was flagged HIGH as "non-standard hash".
 *
 * @package ShieldScope\Tests
 */

use PHPUnit\Framework\TestCase;

/**
 * Class Test_Users_Hashes
 */
class Test_Users_Hashes extends TestCase {

	protected function setUp(): void {
		ss_tests_reset_state();
	}

	/**
	 * @dataProvider legitimate_hashes
	 */
	public function test_legitimate_wordpress_hashes_are_recognized( $hash ) {
		$this->assertTrue( ShieldScope_Check_Users::is_recognized_hash( $hash ) );
	}

	public static function legitimate_hashes() {
		return array(
			'phpass $P$'          => array( '$P$BDMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21' ),
			'phpass $H$'          => array( '$H$9DMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21' ),
			'WP 6.8 wrapped'      => array( '$wp$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345' ),
			'raw bcrypt $2y$'     => array( '$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345' ),
			'raw bcrypt $2a$'     => array( '$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345' ),
			'raw bcrypt $2b$'     => array( '$2b$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345' ),
			'argon2i'             => array( '$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$hash' ),
			'argon2id'            => array( '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$hash' ),
		);
	}

	/**
	 * @dataProvider suspicious_hashes
	 */
	public function test_suspicious_hashes_are_not_recognized( $hash ) {
		$this->assertFalse( ShieldScope_Check_Users::is_recognized_hash( $hash ) );
	}

	public static function suspicious_hashes() {
		return array(
			'raw md5'          => array( '5f4dcc3b5aa765d61d8327deb882cf99' ),
			'raw sha1'         => array( '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' ),
			'truncated phpass' => array( '$P$short' ),
			'empty string'     => array( '' ),
			'not a string'     => array( null ),
			'plaintext-ish'    => array( 'password123' ),
		);
	}
}
