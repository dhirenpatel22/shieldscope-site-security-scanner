<?php
/**
 * In-memory logger double — captures findings so tests can assert on them.
 *
 * @package ShieldScope\Tests
 */

/**
 * Class SS_Fake_Logger
 */
class SS_Fake_Logger extends ShieldScope_Logger {

	/**
	 * Captured findings.
	 *
	 * @var array[]
	 */
	public $findings = array();

	/**
	 * Capture instead of hitting the database.
	 *
	 * @inheritDoc
	 */
	public function record( $scan_id, $check_id, $severity, $title, $description = '', $recommendation = '', $target = '', $context = array() ) {
		$this->findings[] = array(
			'scan_id'        => $scan_id,
			'check_id'       => $check_id,
			'severity'       => $severity,
			'title'          => $title,
			'description'    => $description,
			'recommendation' => $recommendation,
			'target'         => $target,
			'context'        => $context,
		);
		return count( $this->findings );
	}

	/**
	 * Findings filtered by severity.
	 *
	 * @param string $severity Severity constant.
	 * @return array[]
	 */
	public function of_severity( $severity ) {
		return array_values(
			array_filter(
				$this->findings,
				static function ( $f ) use ( $severity ) {
					return $f['severity'] === $severity;
				}
			)
		);
	}
}
