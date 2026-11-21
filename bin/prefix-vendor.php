<?php
/**
 * Build vendor-prefixed/ from vendor/ (run after `composer install --no-dev`).
 *
 *   composer install --no-dev && php bin/prefix-vendor.php
 *
 * Copies only the runtime files of the PDF library and its dependencies,
 * moves every namespace under ShieldScope\Vendor\ (so a different Dompdf
 * version loaded by another plugin cannot clash), keeps only the fonts the
 * report uses, and writes vendor-prefixed/autoload.php. The output is
 * committed; vendor/ is not shipped.
 *
 * @package ShieldScope
 */

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$root   = dirname( __DIR__ );
$vendor = $root . '/vendor';
$out    = $root . '/vendor-prefixed';
$prefix = 'ShieldScope\\Vendor\\';
$roots  = array( 'Dompdf', 'FontLib', 'Svg', 'Masterminds', 'Sabberworm' );

// package dir => array( paths to copy (relative), psr-4 namespace => dir ).
$packages = array(
	'dompdf/dompdf'             => array(
		array( 'src', 'lib/Cpdf.php', 'lib/res', 'LICENSE.LGPL', 'AUTHORS.md', 'VERSION' ),
		array( 'Dompdf\\' => array( 'src', 'lib' ) ),
	),
	'dompdf/php-font-lib'       => array(
		array( 'src', 'maps', 'LICENSE' ),
		array( 'FontLib\\' => array( 'src/FontLib' ) ),
	),
	'dompdf/php-svg-lib'        => array(
		array( 'src', 'LICENSE' ),
		array( 'Svg\\' => array( 'src/Svg' ) ),
	),
	'masterminds/html5'         => array(
		array( 'src', 'LICENSE.txt' ),
		array( 'Masterminds\\' => array( 'src' ) ),
	),
	'sabberworm/php-css-parser' => array(
		array( 'src', 'LICENSE' ),
		array( 'Sabberworm\\CSS\\' => array( 'src' ) ),
	),
);

// Fonts used by the report (DejaVu Sans, DejaVu Sans Mono) plus core-font metrics.
$fonts = array(
	'DejaVuSans', 'DejaVuSans-Bold', 'DejaVuSans-Oblique', 'DejaVuSans-BoldOblique',
	'DejaVuSansMono', 'DejaVuSansMono-Bold',
);

/**
 * Recursively delete a directory.
 *
 * @param string $dir Directory.
 */
function ss_rmdir( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}
	$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $it as $f ) {
		$f->isDir() ? rmdir( $f->getPathname() ) : unlink( $f->getPathname() );
	}
	rmdir( $dir );
}

/**
 * Copy a file or directory.
 *
 * @param string $from Source.
 * @param string $to   Destination.
 */
function ss_copy( $from, $to ) {
	if ( is_file( $from ) ) {
		if ( ! is_dir( dirname( $to ) ) ) {
			mkdir( dirname( $to ), 0755, true );
		}
		copy( $from, $to );
		return;
	}
	$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $from, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST );
	foreach ( $it as $f ) {
		$target = $to . substr( $f->getPathname(), strlen( $from ) );
		if ( $f->isDir() ) {
			if ( ! is_dir( $target ) ) {
				mkdir( $target, 0755, true );
			}
		} else {
			ss_copy( $f->getPathname(), $target );
		}
	}
}

/**
 * Move namespaces in PHP source under the prefix.
 *
 * Handles `namespace X;`, `namespace X\Y`, `use X\Y`, `\X\Y` and class
 * names written in strings with single or doubled backslashes.
 *
 * @param string $src    Source.
 * @param array  $roots  Root namespaces.
 * @param string $prefix Prefix with trailing backslash.
 * @return string
 */
function ss_prefix_source( $src, array $roots, $prefix ) {
	$alt = implode( '|', $roots );
	$src = preg_replace_callback(
		'/\bnamespace\s+(' . $alt . ')\s*([;{])/',
		static function ( $m ) use ( $prefix ) {
			return 'namespace ' . $prefix . $m[1] . $m[2];
		},
		$src
	);
	return preg_replace_callback(
		'/(?<![\w\\\\])(\\\\{0,2})(' . $alt . ')(\\\\{1,2})(?=[A-Za-z_$])/',
		static function ( $m ) use ( $prefix ) {
			$sep = $m[3];
			return $m[1] . str_replace( '\\', $sep, $prefix ) . $m[2] . $sep;
		},
		$src
	);
}

ss_rmdir( $out );
mkdir( $out, 0755, true );

$psr4 = array();
foreach ( $packages as $package => $spec ) {
	list( $paths, $map ) = $spec;
	foreach ( $paths as $path ) {
		$from = "$vendor/$package/$path";
		if ( ! file_exists( $from ) ) {
			fwrite( STDERR, "Missing $from\n" );
			exit( 1 );
		}
		ss_copy( $from, "$out/$package/$path" );
	}
	foreach ( $map as $ns => $dirs ) {
		foreach ( $dirs as $dir ) {
			$psr4[] = array( $prefix . $ns, "$package/$dir" );
		}
	}
}

// Fonts.
$font_src = "$vendor/dompdf/dompdf/lib/fonts";
$font_out = "$out/dompdf/dompdf/lib/fonts";
mkdir( $font_out, 0755, true );
foreach ( glob( "$font_src/*.afm" ) as $afm ) {
	copy( $afm, $font_out . '/' . basename( $afm ) );
}
foreach ( $fonts as $font ) {
	foreach ( array( 'ttf', 'ufm' ) as $ext ) {
		copy( "$font_src/$font.$ext", "$font_out/$font.$ext" );
	}
}
$installed = json_decode( file_get_contents( "$font_src/installed-fonts.dist.json" ), true );
unset( $installed['dejavu serif'] );
$installed['dejavu sans mono'] = array(
	'normal'      => 'DejaVuSansMono',
	'bold'        => 'DejaVuSansMono-Bold',
	'italic'      => 'DejaVuSansMono',
	'bold_italic' => 'DejaVuSansMono-Bold',
);
file_put_contents( "$font_out/installed-fonts.dist.json", json_encode( $installed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );

// Prefix every PHP file.
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $out, FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	if ( 'php' !== $f->getExtension() ) {
		continue;
	}
	$path = $f->getPathname();
	file_put_contents( $path, ss_prefix_source( file_get_contents( $path ), $roots, $prefix ) );
}

// Code that reads a fixed position of its own namespace (the prefix adds two parts).
$patches = array(
	'dompdf/php-font-lib/src/FontLib/TrueType/File.php' => array(
		'return $class_parts[1];',
		'return $class_parts[ count( $class_parts ) - 2 ];',
	),
);
foreach ( $patches as $file => $patch ) {
	$path = "$out/$file";
	$code = file_get_contents( $path );
	if ( 1 !== substr_count( $code, $patch[0] ) ) {
		fwrite( STDERR, "Patch target not found once in $file\n" );
		exit( 1 );
	}
	file_put_contents( $path, str_replace( $patch[0], $patch[1], $code ) );
}

// Autoloader. Longest namespace first so Sabberworm\CSS\ wins over shorter ones.
usort(
	$psr4,
	static function ( $a, $b ) {
		return strlen( $b[0] ) - strlen( $a[0] );
	}
);
$map_php = '';
foreach ( $psr4 as $entry ) {
	$map_php .= "\t\tarray( " . var_export( $entry[0], true ) . ', ' . var_export( $entry[1], true ) . " ),\n";
}
$autoload = <<<PHP
<?php
/**
 * Autoloader for the prefixed PDF library. Generated by bin/prefix-vendor.php.
 *
 * @package ShieldScope
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	static function ( \$class ) {
		static \$map = array(
$map_php		);
		foreach ( \$map as \$entry ) {
			if ( 0 !== strpos( \$class, \$entry[0] ) ) {
				continue;
			}
			\$file = __DIR__ . '/' . \$entry[1] . '/' . str_replace( '\\\\', '/', substr( \$class, strlen( \$entry[0] ) ) ) . '.php';
			if ( is_file( \$file ) ) {
				require_once \$file;
				return;
			}
		}
	}
);

require_once __DIR__ . '/sabberworm/php-css-parser/src/Rule/Rule.php';
require_once __DIR__ . '/sabberworm/php-css-parser/src/RuleSet/RuleContainer.php';

PHP;
file_put_contents( "$out/autoload.php", $autoload );

// Leftover unprefixed references (outside comments) mean the build is wrong.
$bad = 0;
$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $out, FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	if ( 'php' !== $f->getExtension() ) {
		continue;
	}
	$code = '';
	foreach ( token_get_all( file_get_contents( $f->getPathname() ) ) as $t ) {
		if ( is_array( $t ) && in_array( $t[0], array( T_COMMENT, T_DOC_COMMENT ), true ) ) {
			continue;
		}
		$code .= is_array( $t ) ? $t[1] : $t;
	}
	if ( preg_match_all( '/(?<![\w\\\\])\\\\{0,2}(?:' . implode( '|', $roots ) . ')\\\\{1,2}[A-Za-z_$]/', $code, $m ) ) {
		fwrite( STDERR, $f->getPathname() . ': ' . implode( ', ', array_unique( $m[0] ) ) . "\n" );
		$bad++;
	}
}
if ( $bad ) {
	fwrite( STDERR, "$bad file(s) still reference unprefixed namespaces\n" );
	exit( 1 );
}
echo "vendor-prefixed/ built\n";
