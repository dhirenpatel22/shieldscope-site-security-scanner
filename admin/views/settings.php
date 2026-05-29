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

	<div class="ssa-card ssa-faq">
		<div class="ssa-faq-header">
			<div class="ssa-faq-header-icon">⚙️</div>
			<div>
				<h2><?php esc_html_e( 'Settings Help &amp; FAQ', 'site-security-audit' ); ?></h2>
				<p class="ssa-faq-header-sub"><?php esc_html_e( 'What each setting does and how to tune the scanner for your hosting environment.', 'site-security-audit' ); ?></p>
			</div>
		</div>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🔑</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'WPScan API', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item" open>
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What is the WPScan API key and do I need one?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The WPScan API is a continuously updated database of known plugin and theme vulnerabilities (CVEs). It is maintained by security researchers and updated as new vulnerabilities are disclosed.', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Without a key — only the built-in curated list is used (covers the most commonly exploited plugins)', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'With a free key — every installed plugin and theme is checked against a live, comprehensive database', 'site-security-audit' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'The free tier allows 25 API requests per day — enough to scan all plugins on a typical site each day. Get a free key at wpscan.com/register.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What\'s the difference between the built-in CVE list and the WPScan API?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The built-in list covers ~25 of the most widely-exploited plugins (Elementor, WooCommerce, Contact Form 7, etc.) and is updated with each plugin release. It requires no configuration and no internet access.', 'site-security-audit' ); ?></p>
				<p><?php esc_html_e( 'The WPScan API covers thousands of plugins and themes and is updated daily as new CVEs are published. It is more comprehensive and catches vulnerabilities in less common plugins that the built-in list does not include.', 'site-security-audit' ); ?></p>
				<div class="ssa-faq-tip">
					<span class="ssa-faq-tip-icon">💡</span>
					<span><?php esc_html_e( 'Both sources run together when a key is configured — the built-in list provides an instant check even while the API results are loading.', 'site-security-audit' ); ?></span>
				</div>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'How many API requests does each scan use?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'One request is made per installed plugin and per active theme. Results are cached for 24 hours, so repeated scans on the same day do not re-use your daily quota.', 'site-security-audit' ); ?></p>
				<p><?php esc_html_e( 'Example: a site with 20 plugins and 2 active themes uses 22 requests on the first scan of the day, and zero on any subsequent scan that day.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🖥️</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'Performance Settings', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What does the CPU limit setting do?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The scanner sleeps between work chunks so it never takes more than this percentage of CPU. This prevents it from impacting your live site performance during busy periods.', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( '10–15% — best for busy shared hosting plans with tight resource limits', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( '20% (default) — a good balance for most shared hosting', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( '30–40% — suitable for VPS or managed WordPress hosting (WP Engine, Kinsta, etc.)', 'site-security-audit' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What does the Chunk time budget do?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Each "chunk" is a single AJAX request that processes a batch of scan work. This setting caps how long a single chunk can run before pausing.', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( '1–2 seconds — use on servers with strict PHP max_execution_time (common on basic shared hosting)', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( '3 seconds (default) — works on most hosts', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( '5–10 seconds — faster scans on permissive or managed hosting environments', 'site-security-audit' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'What does "Skip files larger than" do?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'The code pattern scanner reads PHP files into memory to search for suspicious patterns (eval, base64_decode, obfuscated code, etc.). Files over the configured size are skipped.', 'site-security-audit' ); ?></p>
				<p><?php esc_html_e( 'Real malware is almost always small, injected snippets added to existing files. Skipping large files (e.g. minified libraries, cache files) rarely misses a threat but significantly reduces scan time and memory usage. The default of 2 MB is appropriate for most sites.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'My scan is very slow or keeps timing out — what can I do?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Try these in order:', 'site-security-audit' ); ?></p>
				<ol>
					<li><?php esc_html_e( 'Reduce the Chunk time budget to 1–2 seconds to avoid PHP timeouts', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Lower the CPU limit to reduce server load spikes', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Reduce "Skip files larger than" to 1 MB to scan fewer large files', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Run the scan during off-peak hours (night-time in your server\'s timezone)', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Contact your hosting provider and ask them to increase the PHP max_execution_time setting', 'site-security-audit' ); ?></li>
				</ol>
			</div>
		</details>

		<div class="ssa-faq-category">
			<span class="ssa-faq-category-icon">🔒</span>
			<span class="ssa-faq-category-label"><?php esc_html_e( 'Privacy &amp; Data', 'site-security-audit' ); ?></span>
		</div>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Is any of my site data sent to external servers?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Almost nothing. The only external requests this plugin makes are:', 'site-security-audit' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Fetching WordPress.org core checksums (plugin and theme slugs, no content) to verify file integrity', 'site-security-audit' ); ?></li>
					<li><?php esc_html_e( 'Querying wpscan.com with plugin/theme slugs and versions — only if you configure an API key', 'site-security-audit' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'No file contents, passwords, user data, scan results, or personally identifiable information are ever transmitted. All scan logic and storage runs entirely on your own server.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<details class="ssa-faq-item">
			<summary>
				<span class="ssa-faq-q-icon">?</span>
				<span class="ssa-faq-question"><?php esc_html_e( 'Where are scan results stored?', 'site-security-audit' ); ?></span>
				<span class="ssa-faq-chevron">&#9654;</span>
			</summary>
			<div class="ssa-faq-answer">
				<p><?php esc_html_e( 'Scan results are stored in your WordPress database as custom options/transients. They are never written to the filesystem and are only accessible to users with the manage_options capability (Administrators). You can clear all scan data by deactivating and deleting this plugin — WordPress will remove all associated database entries on uninstall.', 'site-security-audit' ); ?></p>
			</div>
		</details>

		<div class="ssa-faq-footer">
			<span>🛡️</span>
			<span><?php esc_html_e( 'Site Security Audit is a privacy-first plugin. No telemetry, no tracking, no external data collection.', 'site-security-audit' ); ?></span>
		</div>
	</div>
</div>
