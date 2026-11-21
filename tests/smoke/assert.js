// Reads the setup.json and scan.json written by driver.inc and checks them.
// Prints one summary line; exits 1 if any check fails.
'use strict';

const fs = require( 'fs' );
const path = require( 'path' );

const out = process.argv[ 2 ];
const problems = [];

function load( phase ) {
	const file = path.join( out, phase + '.json' );
	if ( ! fs.existsSync( file ) ) {
		problems.push( phase + ': no result file (phase never ran; see playground.log)' );
		return null;
	}
	try {
		return JSON.parse( fs.readFileSync( file, 'utf8' ) );
	} catch ( e ) {
		problems.push( phase + ': unreadable result file: ' + e.message );
		return null;
	}
}

for ( const phase of [ 'setup', 'scan' ] ) {
	const r = load( phase );
	if ( ! r ) {
		continue;
	}
	if ( r.fatal ) {
		problems.push( phase + ': fatal: ' + r.fatal );
	}
	if ( r.error ) {
		problems.push( phase + ': ' + r.error );
	}
	if ( ! r.finished ) {
		problems.push( phase + ': did not finish' );
	}
	for ( const n of r.notices ) {
		problems.push( phase + ': PHP notice/warning: ' + n );
	}
	if ( phase === 'setup' && r.active !== true ) {
		problems.push( 'setup: plugin not active after activation' );
	}
}

const scan = fs.existsSync( path.join( out, 'scan.json' ) ) ? load( 'scan' ) : null;
if ( scan && scan.status !== 'completed' ) {
	problems.push( 'scan: status "' + scan.status + '" (not completed within the time cap)' );
}
if ( scan && scan.coverage_checks !== 16 ) {
	problems.push( 'coverage: expected 16 checks, got ' + scan.coverage_checks );
}
if ( scan && scan.bg_status !== 'completed' ) {
	problems.push( 'background: status "' + scan.bg_status + '"' + ( scan.bg_error ? ' (' + scan.bg_error + ')' : '' ) );
}
if ( scan && ( scan.history < 2 || ! scan.compare ) ) {
	problems.push( 'history: expected 2 scans and a comparison, got ' + scan.history + ' / ' + JSON.stringify( scan.compare ) );
}
if ( scan && ( ! scan.quick || scan.quick.status !== 'completed' || scan.quick.skipped < 5 ) ) {
	problems.push( 'quick: ' + JSON.stringify( scan.quick ) );
}
if ( scan && ( ! scan.tab_then_close || scan.tab_then_close.status !== 'completed' || ! scan.tab_then_close.queued_after_busy ) ) {
	problems.push( 'tab then close: ' + JSON.stringify( scan.tab_then_close ) );
}
if ( scan && scan.pdf_ok !== true ) {
	problems.push( 'pdf: not produced' + ( scan.pdf_unavailable ? ' (' + scan.pdf_unavailable + ')' : '' ) );
}

const facts = scan
	? `php=${ scan.php } wp=${ scan.wp } status=${ scan.status } elapsed=${ scan.elapsed }s ticks=${ scan.ticks } steps=${ scan.steps } findings=${ JSON.stringify( scan.summary ) } pdf=${ scan.pdf_bytes || 0 }B/${ scan.pdf_secs || 0 }s coverage="${ scan.coverage }" background=${ scan.bg_status }/${ scan.bg_runs } cron runs/${ scan.bg_elapsed }s compare=${ JSON.stringify( scan.compare ) } quick=${ JSON.stringify( scan.quick ) } tabThenClose=${ JSON.stringify( scan.tab_then_close ) }`
	: 'no scan result';

if ( problems.length ) {
	console.log( 'FAIL ' + facts );
	problems.forEach( ( p ) => console.error( '  - ' + p ) );
	process.exit( 1 );
}
console.log( 'PASS ' + facts );
