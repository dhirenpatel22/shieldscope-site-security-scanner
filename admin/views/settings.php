<?php
/**
 * Settings view.
 *
 * @package ShieldScope
 *
 * @var array $settings Passed from render_settings_page().
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- included inside a class method, not global scope
?>
<div class="wrap shieldscope-wrap">
	<h1><?php esc_html_e( 'ShieldScope: Settings', 'shieldscope-site-security-scanner' ); ?></h1>
	<?php settings_errors( 'shieldscope_settings' ); ?>
	<?php ShieldScope_Admin::render_help_box(); ?>

	<form method="post" action="">
		<?php wp_nonce_field( 'shieldscope_save_settings' ); ?>

		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row">
						<label for="shieldscope_load_preset"><?php esc_html_e( 'Server load', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<?php $shieldscope_preset = ShieldScope_Admin::current_preset( $settings ); ?>
						<select name="shieldscope_settings[load_preset]" id="shieldscope_load_preset">
							<?php foreach ( ShieldScope_Admin::load_presets() as $shieldscope_key => $shieldscope_p ) : ?>
								<option value="<?php echo esc_attr( $shieldscope_key ); ?>" <?php selected( $shieldscope_preset, $shieldscope_key ); ?>>
									<?php
									/* translators: 1: preset name, 2: scan pace percent, 3: seconds per step */
									echo esc_html( sprintf( __( '%1$s: %2$d%%, %3$d s per step', 'shieldscope-site-security-scanner' ), $shieldscope_p[0], $shieldscope_p[1], $shieldscope_p[2] ) );
									?>
								</option>
							<?php endforeach; ?>
							<option value="custom" <?php selected( $shieldscope_preset, 'custom' ); ?>><?php esc_html_e( 'Custom (use the two fields below)', 'shieldscope-site-security-scanner' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'Sets the scan pace and time per step together. Choose Custom to set them yourself.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="shieldscope_cpu_limit"><?php esc_html_e( 'Scan pace (share of time working)', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<input name="shieldscope_settings[cpu_limit]" id="shieldscope_cpu_limit" type="number" min="5" max="80" value="<?php echo esc_attr( $settings['cpu_limit'] ); ?>" />
						<span>%</span>
						<p class="description"><?php esc_html_e( 'The scanner works in short steps with pauses between them. This is the share of time spent working: lower values mean longer pauses and a slower scan. It is not a CPU limit. Default 20%.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="shieldscope_chunk_time"><?php esc_html_e( 'Time per step (seconds)', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<input name="shieldscope_settings[chunk_time_limit]" id="shieldscope_chunk_time" type="number" min="1" max="10" value="<?php echo esc_attr( $settings['chunk_time_limit'] ); ?>" />
						<p class="description"><?php esc_html_e( 'How long one step of the scan may run before it saves its place and stops. Lower this if scans time out. Default 2 seconds.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="shieldscope_max_file"><?php esc_html_e( 'Skip files larger than (MB)', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<?php
						// Bytes are stored internally; the form expresses the value in whole MB.
						$max_file_mb = isset( $settings['max_scan_file_size'] )
							? max( 1, (int) round( (int) $settings['max_scan_file_size'] / MB_IN_BYTES ) )
							: 2;
						?>
						<input name="shieldscope_settings[max_scan_file_size_mb]" id="shieldscope_max_file" type="number" step="1" min="1" max="20" value="<?php echo esc_attr( $max_file_mb ); ?>" />
						<span>MB</span>
						<p class="description"><?php esc_html_e( 'Very large PHP files are usually bundled libraries or generated code and are slow to pattern-check. Skipped files are counted in the report. Accepted range: 1–20 MB. Default 2 MB.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Background scanning', 'shieldscope-site-security-scanner' ); ?>
					</th>
					<td>
						<label>
							<input name="shieldscope_settings[background_scan]" type="checkbox" value="1" <?php checked( ! empty( $settings['background_scan'] ) ); ?> />
							<?php esc_html_e( 'Keep scanning when the scan page is closed (uses WP-Cron).', 'shieldscope-site-security-scanner' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'WP-Cron runs when the site gets visits (or from a server cron job), so on a quiet site a background scan can take longer. With the scan page open, it runs at full pace either way.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Pause when tab is hidden', 'shieldscope-site-security-scanner' ); ?>
					</th>
					<td>
						<label>
							<input name="shieldscope_settings[pause_on_blur]" type="checkbox" value="1" <?php checked( ! empty( $settings['pause_on_blur'] ) ); ?> />
							<?php esc_html_e( 'Pause the scan while you switch tabs or minimise the window (only when background scanning is off).', 'shieldscope-site-security-scanner' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Developer review', 'shieldscope-site-security-scanner' ); ?>
					</th>
					<td>
						<label>
							<input name="shieldscope_settings[developer_review]" type="checkbox" value="1" <?php checked( ! empty( $settings['developer_review'] ) ); ?> />
							<?php esc_html_e( 'Also scan plugin and theme code for injection and server-side request patterns.', 'shieldscope-site-security-scanner' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'For developers reviewing code. These checks only find patterns to review (Low findings), and well-written plugins can match them, so they are off by default. Scans take longer when this is on.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Downloaded reports', 'shieldscope-site-security-scanner' ); ?></th>
					<td>
						<label>
							<input name="shieldscope_settings[report_help_link]" type="checkbox" value="1" <?php checked( ! empty( $settings['report_help_link'] ) ); ?> />
							<?php esc_html_e( 'Show a link to the developer\'s contact page in the PDF footer and in CSV and JSON downloads.', 'shieldscope-site-security-scanner' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Turn this off if you hand reports to your own clients.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Vulnerability lookups', 'shieldscope-site-security-scanner' ); ?></th>
					<td>
						<label>
							<input name="shieldscope_settings[wpvulnerability]" type="checkbox" value="1" <?php checked( ! empty( $settings['wpvulnerability'] ) ); ?> />
							<?php esc_html_e( 'Look up WordPress, plugins and themes on WPVulnerability during a scan.', 'shieldscope-site-security-scanner' ); ?>
						</label>
						<p class="description">
							<?php
							printf(
								/* translators: %s: www.wpvulnerability.net */
								esc_html__( 'A free database of known WordPress vulnerabilities (from CVE, Patchstack, Wordfence, WPScan and others). ShieldScope sends only the WordPress version and the slugs of plugins and themes listed on WordPress.org to %s, and caches the answers for 12 hours. Turn this off to use only the limited built-in list and WPScan.', 'shieldscope-site-security-scanner' ),
								'<strong>www.wpvulnerability.net</strong>'
							);
							?>
							<br>
							<?php
							printf(
								/* translators: %s: link to wpvulnerability.com */
								esc_html__( 'Vulnerability data from %s.', 'shieldscope-site-security-scanner' ),
								'<a href="' . esc_url( ShieldScope_Check_Vuln_DB::WPV_SITE ) . '" target="_blank" rel="noopener noreferrer">WPVulnerability</a>'
							);
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="shieldscope_wpscan_api_key"><?php esc_html_e( 'WPScan API Key', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<input
							name="shieldscope_settings[wpscan_api_key]"
							id="shieldscope_wpscan_api_key"
							type="password"
							class="regular-text"
							value=""
							placeholder="<?php echo empty( $settings['wpscan_api_key'] ) ? '' : esc_attr__( 'Leave empty to keep the saved key', 'shieldscope-site-security-scanner' ); ?>"
							autocomplete="new-password"
						/>
						<?php if ( ! empty( $settings['wpscan_api_key'] ) ) : ?>
							<label class="shieldscope-remove-key">
								<input name="shieldscope_settings[wpscan_api_key_remove]" type="checkbox" value="1" />
								<?php esc_html_e( 'Remove the saved key', 'shieldscope-site-security-scanner' ); ?>
							</label>
						<?php endif; ?>
						<p class="description">
							<?php
							printf(
								/* translators: %s: wpscan.com */
								esc_html__( 'Optional. When set, plugins and themes listed on WordPress.org that WPVulnerability could not answer (or all of them, if WPVulnerability lookups are off) are looked up on %s (it sends only the slug). The free key allows 25 requests a day and is for non-commercial use; check WPScan\'s terms before using it on client sites.', 'shieldscope-site-security-scanner' ),
								'<strong>wpscan.com</strong>'
							);
							?>
							<?php if ( ! empty( $settings['wpscan_api_key'] ) ) : ?>
								<br><span class="shieldscope-api-key-set">&#10003;
								<?php
								printf(
									/* translators: %s: last four characters of the saved key */
									esc_html__( 'A key ending in %s is saved.', 'shieldscope-site-security-scanner' ),
									'<code>' . esc_html( ShieldScope_Admin::key_tail( $settings['wpscan_api_key'] ) ) . '</code>'
								);
								?>
								</span>
							<?php else : ?>
								<br><em>
								<?php
								printf(
									/* translators: %d: number of plugins in the built-in list */
									esc_html__( 'Without a key, plugins WPVulnerability could not answer are compared with a limited built-in list of %d plugins.', 'shieldscope-site-security-scanner' ),
									(int) ShieldScope_Check_Vuln_DB::built_in_plugin_count()
								);
								?>
								</em>
							<?php endif; ?>
						</p>
					</td>
				</tr>
			</tbody>
		</table>

		<?php submit_button( __( 'Save Changes', 'shieldscope-site-security-scanner' ), 'primary', 'shieldscope_settings_submit' ); ?>
	</form>

	<div class="shieldscope-card shieldscope-faq">
		<div class="shieldscope-faq-header">
			<div class="shieldscope-faq-header-icon">⚙️</div>
			<div>
				<h2><?php esc_html_e( 'Settings Help &amp; FAQ', 'shieldscope-site-security-scanner' ); ?></h2>
				<p class="shieldscope-faq-header-sub"><?php esc_html_e( 'What each setting does and how to tune the scanner for your hosting environment.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</div>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🔑</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'WPScan API', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item" open>
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What is the WPScan API key and do I need one?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'WPScan keeps a database of known vulnerabilities in WordPress plugins and themes. A key is optional.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Without a key: only a limited built-in list of widely used plugins is checked.', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'With a key: each plugin listed on WordPress.org, and the active theme, is looked up on WPScan by its slug.', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'The free key allows 25 requests a day and is licensed for non-commercial use. If a site has more plugins than the daily limit, the report says how many could not be checked.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What\'s the difference between the built-in CVE list and the WPScan API?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p>
				<?php
				printf(
					/* translators: 1: number of plugins, 2: date the list was last reviewed (YYYY-MM-DD) */
					esc_html__( 'The built-in list covers %1$d widely used plugins and was last reviewed on %2$s. It needs no key and no network access, but it is not a vulnerability database: plugins outside the list are not checked.', 'shieldscope-site-security-scanner' ),
					(int) ShieldScope_Check_Vuln_DB::built_in_plugin_count(),
					esc_html( ShieldScope_Check_Vuln_DB::BUILT_IN_REVIEWED )
				);
				?>
				</p>
				<p><?php esc_html_e( 'WPScan covers far more plugins and themes and is updated as new vulnerabilities are published. When a key is set, the built-in list still runs as well.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How many API requests does each scan use?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'One request per plugin listed on WordPress.org, plus one for the active theme (and its parent theme, if any). Results are cached for 24 hours, so a second scan on the same day uses no extra requests.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'Example: a site with 20 plugins and 2 active themes uses 22 requests on the first scan of the day, and zero on any subsequent scan that day.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🖥️</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'Performance Settings', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What does the scan pace setting do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The scanner works in short steps with pauses between them. The setting is the share of time spent working: at 20%, each step is followed by a pause about four times as long. Lower values spread the work out on a busy server but make the scan slower. It does not measure or cap CPU use.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( '10–15%: busy shared hosting', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '20% (default): most sites', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '30–40%: a VPS or managed WordPress hosting, for a faster scan', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What does Time per step do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Each step is one request from this browser tab to your server. This setting caps how long one step can run before it saves its place and stops.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( '1–2 seconds — use on servers with strict PHP max_execution_time (common on basic shared hosting)', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '2 seconds (default) — works on most hosts', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '5–10 seconds — faster scans on permissive or managed hosting environments', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What does "Skip files larger than" do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The code checks read PHP files into memory to look for patterns that need a review (for example eval() on decoded data). Files over this size are skipped.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'Very large PHP files are mostly bundled libraries or generated code. Skipping them saves time and memory, but they are then not checked: the report counts skipped files so you know. The default of 2 MB suits most sites.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'My scan is very slow or keeps timing out — what can I do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Try these in order:', 'shieldscope-site-security-scanner' ); ?></p>
				<ol>
					<li><?php esc_html_e( 'Reduce Time per step to 1 second to avoid PHP timeouts', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Lower the scan pace to spread the work out', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Reduce "Skip files larger than" to 1 MB to scan fewer large files', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Run the scan during off-peak hours (night-time in your server\'s timezone)', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Contact your hosting provider and ask them to increase the PHP max_execution_time setting', 'shieldscope-site-security-scanner' ); ?></li>
				</ol>
			</div>
		</details>

		<div class="shieldscope-faq-category">
			<span class="shieldscope-faq-category-icon">🔒</span>
			<span class="shieldscope-faq-category-label"><?php esc_html_e( 'Privacy &amp; Data', 'shieldscope-site-security-scanner' ); ?></span>
		</div>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Is any of my site data sent to external servers?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php echo esc_html( ShieldScope_Admin::privacy_statement() ); ?></p>
				<p><?php esc_html_e( 'File contents, passwords, user data and scan results are not sent anywhere.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Where are scan results stored?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php echo esc_html( ShieldScope_Admin::footprint_statement() ); ?> <?php esc_html_e( 'Only administrators can open the report (on multisite, only super admins).', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-footer">
			<span>🛡️</span>
			<span><?php esc_html_e( 'ShieldScope has no telemetry and no tracking.', 'shieldscope-site-security-scanner' ); ?></span>
		</div>
	</div>
</div>
