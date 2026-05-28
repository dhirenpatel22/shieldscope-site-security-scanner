<?php
/**
 * Settings view.
 *
 * @package Site_Security_Audit
 *
 * @var array $settings Passed from render_settings_page().
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap ssa-wrap">
	<h1><?php esc_html_e( 'Scan Settings', 'site-security-audit' ); ?></h1>
	<?php settings_errors( 'ssa_settings' ); ?>

	<form method="post" action="">
		<?php wp_nonce_field( 'ssa_save_settings' ); ?>

		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row">
						<label for="ssa_cpu_limit"><?php esc_html_e( 'Maximum CPU usage', 'site-security-audit' ); ?></label>
					</th>
					<td>
						<input name="ssa_settings[cpu_limit]" id="ssa_cpu_limit" type="number" min="5" max="80" value="<?php echo esc_attr( $settings['cpu_limit'] ); ?>" />
						<span>%</span>
						<p class="description"><?php esc_html_e( 'The scanner sleeps between units of work so it never takes more than this percentage of CPU. Default 20%.', 'site-security-audit' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="ssa_chunk_time"><?php esc_html_e( 'Chunk time budget (seconds)', 'site-security-audit' ); ?></label>
					</th>
					<td>
						<input name="ssa_settings[chunk_time_limit]" id="ssa_chunk_time" type="number" min="1" max="10" value="<?php echo esc_attr( $settings['chunk_time_limit'] ); ?>" />
						<p class="description"><?php esc_html_e( 'Maximum wall-clock time a single AJAX chunk of work is allowed to take before yielding.', 'site-security-audit' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="ssa_max_file"><?php esc_html_e( 'Skip files larger than (MB)', 'site-security-audit' ); ?></label>
					</th>
					<td>
						<?php
						// Bytes are stored internally; the form expresses the value in whole MB.
						$max_file_mb = isset( $settings['max_scan_file_size'] )
							? max( 1, (int) round( (int) $settings['max_scan_file_size'] / MB_IN_BYTES ) )
							: 2;
						?>
						<input name="ssa_settings[max_scan_file_size_mb]" id="ssa_max_file" type="number" step="1" min="1" max="20" value="<?php echo esc_attr( $max_file_mb ); ?>" />
						<span>MB</span>
						<p class="description"><?php esc_html_e( 'Very large PHP files are rarely malware and very expensive to regex. Accepted range: 1–20 MB. Default 2 MB.', 'site-security-audit' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Pause when tab is hidden', 'site-security-audit' ); ?>
					</th>
					<td>
						<label>
							<input name="ssa_settings[pause_on_blur]" type="checkbox" value="1" <?php checked( $settings['pause_on_blur'] ); ?> />
							<?php esc_html_e( 'Automatically pause the scan if you switch tabs or minimize the window.', 'site-security-audit' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="ssa_wpscan_api_key"><?php esc_html_e( 'WPScan API Key', 'site-security-audit' ); ?></label>
					</th>
					<td>
						<input
							name="ssa_settings[wpscan_api_key]"
							id="ssa_wpscan_api_key"
							type="password"
							class="regular-text"
							value="<?php echo esc_attr( $settings['wpscan_api_key'] ?? '' ); ?>"
							autocomplete="new-password"
						/>
						<p class="description">
							<?php
							printf(
								/* translators: %s: link to wpscan.com */
								esc_html__( 'Optional. When set, the Vulnerability Database check queries %s for up-to-date CVE data on every installed plugin and theme. Free tier: 25 requests/day. Get a key at wpscan.com/register.', 'site-security-audit' ),
								'<strong>wpscan.com</strong>'
							);
							?>
							<?php if ( ! empty( $settings['wpscan_api_key'] ) ) : ?>
								<br><span class="ssa-api-key-set">&#10003; <?php esc_html_e( 'API key is configured.', 'site-security-audit' ); ?></span>
							<?php else : ?>
								<br><em><?php esc_html_e( 'Without a key, only the built-in curated CVE list is used.', 'site-security-audit' ); ?></em>
							<?php endif; ?>
						</p>
					</td>
				</tr>
			</tbody>
		</table>

		<?php submit_button( __( 'Save Changes', 'site-security-audit' ), 'primary', 'ssa_settings_submit' ); ?>
	</form>
</div>
