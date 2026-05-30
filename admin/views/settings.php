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
	<h1><?php esc_html_e( 'Scan Settings', 'shieldscope-site-security-scanner' ); ?></h1>
	<?php settings_errors( 'shieldscope_settings' ); ?>

	<form method="post" action="">
		<?php wp_nonce_field( 'shieldscope_save_settings' ); ?>

		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row">
						<label for="shieldscope_cpu_limit"><?php esc_html_e( 'Maximum CPU usage', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<input name="shieldscope_settings[cpu_limit]" id="shieldscope_cpu_limit" type="number" min="5" max="80" value="<?php echo esc_attr( $settings['cpu_limit'] ); ?>" />
						<span>%</span>
						<p class="description"><?php esc_html_e( 'The scanner sleeps between units of work so it never takes more than this percentage of CPU. Default 20%.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="shieldscope_chunk_time"><?php esc_html_e( 'Chunk time budget (seconds)', 'shieldscope-site-security-scanner' ); ?></label>
					</th>
					<td>
						<input name="shieldscope_settings[chunk_time_limit]" id="shieldscope_chunk_time" type="number" min="1" max="10" value="<?php echo esc_attr( $settings['chunk_time_limit'] ); ?>" />
						<p class="description"><?php esc_html_e( 'Maximum wall-clock time a single AJAX chunk of work is allowed to take before yielding.', 'shieldscope-site-security-scanner' ); ?></p>
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
						<p class="description"><?php esc_html_e( 'Very large PHP files are rarely malware and very expensive to regex. Accepted range: 1–20 MB. Default 2 MB.', 'shieldscope-site-security-scanner' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Pause when tab is hidden', 'shieldscope-site-security-scanner' ); ?>
					</th>
					<td>
						<label>
							<input name="shieldscope_settings[pause_on_blur]" type="checkbox" value="1" <?php checked( $settings['pause_on_blur'] ); ?> />
							<?php esc_html_e( 'Automatically pause the scan if you switch tabs or minimize the window.', 'shieldscope-site-security-scanner' ); ?>
						</label>
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
							value="<?php echo esc_attr( $settings['wpscan_api_key'] ?? '' ); ?>"
							autocomplete="new-password"
						/>
						<p class="description">
							<?php
							printf(
								/* translators: %s: link to wpscan.com */
								esc_html__( 'Optional. When set, the Vulnerability Database check queries %s for up-to-date CVE data on every installed plugin and theme. Free tier: 25 requests/day. Get a key at wpscan.com/register.', 'shieldscope-site-security-scanner' ),
								'<strong>wpscan.com</strong>'
							);
							?>
							<?php if ( ! empty( $settings['wpscan_api_key'] ) ) : ?>
								<br><span class="shieldscope-api-key-set">&#10003; <?php esc_html_e( 'API key is configured.', 'shieldscope-site-security-scanner' ); ?></span>
							<?php else : ?>
								<br><em><?php esc_html_e( 'Without a key, only the built-in curated CVE list is used.', 'shieldscope-site-security-scanner' ); ?></em>
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
				<p><?php esc_html_e( 'The WPScan API is a continuously updated database of known plugin and theme vulnerabilities (CVEs). It is maintained by security researchers and updated as new vulnerabilities are disclosed.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Without a key — only the built-in curated list is used (covers the most commonly exploited plugins)', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'With a free key — every installed plugin and theme is checked against a live, comprehensive database', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'The free tier allows 25 API requests per day — enough to scan all plugins on a typical site each day. Get a free key at wpscan.com/register.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What\'s the difference between the built-in CVE list and the WPScan API?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The built-in list covers ~25 of the most widely-exploited plugins (Elementor, WooCommerce, Contact Form 7, etc.) and is updated with each plugin release. It requires no configuration and no internet access.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'The WPScan API covers thousands of plugins and themes and is updated daily as new CVEs are published. It is more comprehensive and catches vulnerabilities in less common plugins that the built-in list does not include.', 'shieldscope-site-security-scanner' ); ?></p>
				<div class="shieldscope-faq-tip">
					<span class="shieldscope-faq-tip-icon">💡</span>
					<span><?php esc_html_e( 'Both sources run together when a key is configured — the built-in list provides an instant check even while the API results are loading.', 'shieldscope-site-security-scanner' ); ?></span>
				</div>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'How many API requests does each scan use?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'One request is made per installed plugin and per active theme. Results are cached for 24 hours, so repeated scans on the same day do not re-use your daily quota.', 'shieldscope-site-security-scanner' ); ?></p>
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
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What does the CPU limit setting do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'The scanner sleeps between work chunks so it never takes more than this percentage of CPU. This prevents it from impacting your live site performance during busy periods.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( '10–15% — best for busy shared hosting plans with tight resource limits', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '20% (default) — a good balance for most shared hosting', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '30–40% — suitable for VPS or managed WordPress hosting (WP Engine, Kinsta, etc.)', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'What does the Chunk time budget do?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Each "chunk" is a single AJAX request that processes a batch of scan work. This setting caps how long a single chunk can run before pausing.', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( '1–2 seconds — use on servers with strict PHP max_execution_time (common on basic shared hosting)', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( '3 seconds (default) — works on most hosts', 'shieldscope-site-security-scanner' ); ?></li>
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
				<p><?php esc_html_e( 'The code pattern scanner reads PHP files into memory to search for suspicious patterns (eval, base64_decode, obfuscated code, etc.). Files over the configured size are skipped.', 'shieldscope-site-security-scanner' ); ?></p>
				<p><?php esc_html_e( 'Real malware is almost always small, injected snippets added to existing files. Skipping large files (e.g. minified libraries, cache files) rarely misses a threat but significantly reduces scan time and memory usage. The default of 2 MB is appropriate for most sites.', 'shieldscope-site-security-scanner' ); ?></p>
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
					<li><?php esc_html_e( 'Reduce the Chunk time budget to 1–2 seconds to avoid PHP timeouts', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Lower the CPU limit to reduce server load spikes', 'shieldscope-site-security-scanner' ); ?></li>
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
				<p><?php esc_html_e( 'Almost nothing. The only external requests this plugin makes are:', 'shieldscope-site-security-scanner' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Fetching WordPress.org core checksums (plugin and theme slugs, no content) to verify file integrity', 'shieldscope-site-security-scanner' ); ?></li>
					<li><?php esc_html_e( 'Querying wpscan.com with plugin/theme slugs and versions — only if you configure an API key', 'shieldscope-site-security-scanner' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'No file contents, passwords, user data, scan results, or personally identifiable information are ever transmitted. All scan logic and storage runs entirely on your own server.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<details class="shieldscope-faq-item">
			<summary>
				<span class="shieldscope-faq-q-icon">?</span>
				<span class="shieldscope-faq-question"><?php esc_html_e( 'Where are scan results stored?', 'shieldscope-site-security-scanner' ); ?></span>
				<span class="shieldscope-faq-chevron">&#9654;</span>
			</summary>
			<div class="shieldscope-faq-answer">
				<p><?php esc_html_e( 'Scan results are stored in your WordPress database as custom options/transients. They are never written to the filesystem and are only accessible to users with the manage_options capability (Administrators). You can clear all scan data by deactivating and deleting this plugin — WordPress will remove all associated database entries on uninstall.', 'shieldscope-site-security-scanner' ); ?></p>
			</div>
		</details>

		<div class="shieldscope-faq-footer">
			<span>🛡️</span>
			<span><?php esc_html_e( 'Site Security Audit is a privacy-first plugin. No telemetry, no tracking, no external data collection.', 'shieldscope-site-security-scanner' ); ?></span>
		</div>
	</div>
</div>
