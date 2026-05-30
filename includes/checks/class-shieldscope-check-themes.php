<?php
/**
 * Theme-level security checks.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class ShieldScope_Check_Themes
 */
class ShieldScope_Check_Themes extends ShieldScope_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'themes';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Themes', 'shieldscope-site-security-scanner' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'updates', 'inactive', 'default_present' );
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
			case 'updates':
				$this->check_updates();
				break;
			case 'inactive':
				$this->check_inactive_themes();
				break;
			case 'default_present':
				$this->check_default_theme_present();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Pending theme updates.
	 *
	 * @return void
	 */
	private function check_updates() {
		$updates = get_site_transient( 'update_themes' );
		if ( ! $updates || empty( $updates->response ) ) {
			return;
		}
		foreach ( $updates->response as $slug => $info ) {
			$theme = wp_get_theme( $slug );
			$this->finding(
				ShieldScope_Logger::SEVERITY_HIGH,
				__( 'Theme update available', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: 1: name, 2: version */
					__( 'Theme "%1$s" has an update to version %2$s available.', 'shieldscope-site-security-scanner' ),
					$theme->get( 'Name' ),
					isset( $info['new_version'] ) ? $info['new_version'] : 'latest'
				),
				__( 'Go to Dashboard → Updates and update this theme. If you have customised the parent theme directly, your changes will be overwritten — migrate them to a child theme first. Child theme customisations are not affected by parent theme updates.', 'shieldscope-site-security-scanner' ),
				'theme:' . $slug
			);
		}
	}

	/**
	 * Inactive themes still on disk.
	 *
	 * @return void
	 */
	private function check_inactive_themes() {
		$active  = get_stylesheet();
		$parent  = get_template();
		$all     = wp_get_themes();
		$keep    = array( $active => true, $parent => true );
		$extra   = 0;
		foreach ( $all as $slug => $theme ) {
			if ( ! isset( $keep[ $slug ] ) ) {
				$extra++;
			}
		}
		if ( $extra > 1 ) {
			$this->finding(
				ShieldScope_Logger::SEVERITY_LOW,
				__( 'Multiple inactive themes installed', 'shieldscope-site-security-scanner' ),
				sprintf(
					/* translators: %d: count */
					__( '%d inactive themes are present. Keep only your active theme, its parent (if any), and one up-to-date default theme as a fallback.', 'shieldscope-site-security-scanner' ),
					$extra
				),
				__( 'Go to Appearance → Themes and delete all themes you are not using — keep only your active theme, its parent (if any), and one default WordPress theme as a fallback. Inactive themes on disk can still be exploited even without being active.', 'shieldscope-site-security-scanner' )
			);
		}
	}

	/**
	 * At least one default WordPress theme should be available as a fallback.
	 *
	 * @return void
	 */
	private function check_default_theme_present() {
		$defaults = array( 'twentytwentyfive', 'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo' );
		$all      = wp_get_themes();
		foreach ( $defaults as $slug ) {
			if ( isset( $all[ $slug ] ) ) {
				return;
			}
		}
		$this->finding(
			ShieldScope_Logger::SEVERITY_INFO,
			__( 'No current default theme installed as fallback', 'shieldscope-site-security-scanner' ),
			__( 'If your active theme breaks, WordPress falls back to a default theme. Without one installed, recovery requires FTP.', 'shieldscope-site-security-scanner' ),
			__( 'Install one of the current default (Twenty*) themes and keep it updated.', 'shieldscope-site-security-scanner' )
		);
	}
}
