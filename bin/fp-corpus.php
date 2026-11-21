<?php
/**
 * False-positive corpus (S-25): run ShieldScope's code rules over pinned,
 * well-known plugins and fail if any rule reports Critical or High.
 *
 *   php bin/fp-corpus.php            # verify hashes, run, exit 1 on Critical/High
 *   php bin/fp-corpus.php --record   # first run: write missing sha256 values
 *
 * Env: SHIELDSCOPE_CORPUS_CACHE (download cache, default: system temp dir).
 * Downloads come from downloads.wordpress.org. Developer review is on, so
 * the injection and SSRF code scans run too.
 *
 * @package ShieldScope
 */

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$root     = dirname( __DIR__ );
$record   = in_array( '--record', $argv, true );
$manifest = json_decode( file_get_contents( "$root/tests/corpus/manifest.json" ), true );
$cache    = getenv( 'SHIELDSCOPE_CORPUS_CACHE' ) ? getenv( 'SHIELDSCOPE_CORPUS_CACHE' ) : sys_get_temp_dir() . '/shieldscope-corpus';
if ( ! is_dir( $cache ) ) {
	mkdir( $cache, 0755, true );
}

require "$root/tests/bootstrap.php";
ss_tests_reset_state();
ss_tests_reset_wp_root();
mkdir( SHIELDSCOPE_WP_PLUGINS_DIR, 0777, true );
update_option( 'shieldscope_settings', array( 'developer_review' => 1 ) );

$changed = false;
foreach ( $manifest['plugins'] as $slug => &$pin ) {
	$zip = "$cache/$slug.{$pin['version']}.zip";
	if ( ! is_file( $zip ) ) {
		$url  = "https://downloads.wordpress.org/plugin/$slug.{$pin['version']}.zip";
		$data = file_get_contents( $url );
		if ( false === $data ) {
			fwrite( STDERR, "Download failed: $url\n" );
			exit( 2 );
		}
		file_put_contents( $zip, $data );
	}
	$hash = hash_file( 'sha256', $zip );
	if ( '' === $pin['sha256'] ) {
		if ( ! $record ) {
			fwrite( STDERR, "No sha256 for $slug; run with --record once.\n" );
			exit( 2 );
		}
		$pin['sha256'] = $hash;
		$changed       = true;
	} elseif ( ! hash_equals( $pin['sha256'], $hash ) ) {
		fwrite( STDERR, "sha256 mismatch for $slug {$pin['version']}\n" );
		exit( 2 );
	}
	$z = new ZipArchive();
	if ( true !== $z->open( $zip ) ) {
		fwrite( STDERR, "Cannot open $zip\n" );
		exit( 2 );
	}
	$z->extractTo( SHIELDSCOPE_WP_PLUGINS_DIR );
	$z->close();
}
unset( $pin );
if ( $changed ) {
	file_put_contents( "$root/tests/corpus/manifest.json", json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
}

$logger = new SS_Fake_Logger();
$files  = 0;
foreach ( array( 'ShieldScope_Check_Code_Patterns', 'ShieldScope_Check_Injection', 'ShieldScope_Check_SSRF', 'ShieldScope_Check_Access_Control' ) as $class ) {
	$check  = new $class( 'corpus', $logger );
	$cursor = array();
	do {
		$r      = $check->run_step( 'scan_plugins', $cursor );
		$cursor = $r['cursor'];
		$guard  = isset( $guard ) ? $guard + 1 : 1;
	} while ( ! empty( $r['continue'] ) && $guard < 1000000 );
	$files = max( $files, isset( $cursor['checked'] ) ? (int) $cursor['checked'] : 0 );
}

$by_sev    = array_fill_keys( array( 'critical', 'high', 'medium', 'low', 'info' ), 0 );
$by_plugin = array();
$serious   = array();
foreach ( $logger->findings as $f ) {
	++$by_sev[ $f['severity'] ];
	$rel    = ltrim( str_replace( SHIELDSCOPE_WP_PLUGINS_DIR, '', (string) $f['target'] ), '/' );
	$plugin = '' === $rel || false === strpos( $rel, '/' ) ? '(scan notes)' : strtok( $rel, '/' );
	if ( ! isset( $by_plugin[ $plugin ] ) ) {
		$by_plugin[ $plugin ] = array_fill_keys( array_keys( $by_sev ), 0 );
	}
	++$by_plugin[ $plugin ][ $f['severity'] ];
	if ( in_array( $f['severity'], array( 'critical', 'high' ), true ) ) {
		$line      = isset( $f['context']['evidence']['line'] ) ? ':' . $f['context']['evidence']['line'] : '';
		$serious[] = strtoupper( $f['severity'] ) . "  {$f['title']}  $rel$line";
	}
	if ( 'medium' === $f['severity'] || getenv( 'SHIELDSCOPE_CORPUS_VERBOSE' ) ) {
		$line   = isset( $f['context']['evidence']['line'] ) ? ':' . $f['context']['evidence']['line'] : '';
		$detail = isset( $f['context']['evidence']['snippet'] ) ? '  | ' . $f['context']['evidence']['snippet'] : '';
		echo "  [{$f['severity']}] {$f['title']}  $rel$line$detail\n";
	}
}

printf( "Corpus: %d plugins, %d PHP files. Findings: %s\n", count( $manifest['plugins'] ), $files, json_encode( $by_sev ) );
ksort( $by_plugin );
foreach ( $by_plugin as $plugin => $counts ) {
	printf( "  %-20s %s\n", $plugin, json_encode( array_filter( $counts ) ) );
}
if ( $serious ) {
	echo "Critical/High on well-built plugins (false positives to fix):\n  " . implode( "\n  ", $serious ) . "\n";
	exit( 1 );
}
echo "PASS: no Critical or High findings.\n";
