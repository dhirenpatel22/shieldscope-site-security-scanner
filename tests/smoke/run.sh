#!/usr/bin/env bash
# Smoke run: throwaway WordPress Playground site on this checkout, plugin
# activated, scan ticked to `completed`, no PHP notices or warnings allowed.
#
# Usage: tests/smoke/run.sh [clean|seeded|all]   (default: all)
# Env:   SMOKE_TIME_CAP  seconds per scan before giving up (default 900)
#        SMOKE_PHP       PHP version for Playground (default 7.4, the plugin minimum)
#        SMOKE_WP        WordPress version (default latest)
#
# Needs Node 20+ with npx and network access (downloads the Playground CLI and
# WordPress). No Docker. Results: tests/smoke/out/<profile>/*.json; elapsed
# times are appended to tests/smoke/out/timing.txt.
set -euo pipefail

PLAYGROUND_CLI="@wp-playground/cli@3.1.61"
SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "$SMOKE_DIR/../.." && pwd)"
TIME_CAP="${SMOKE_TIME_CAP:-900}"
PHP_VERSION="${SMOKE_PHP:-7.4}"
WP_VERSION="${SMOKE_WP:-latest}"

case "${1:-all}" in
	all) profiles=(clean seeded) ;;
	clean | seeded) profiles=("$1") ;;
	*) echo "Usage: $0 [clean|seeded|all]" >&2; exit 2 ;;
esac

if ! command -v npx >/dev/null 2>&1; then
	echo "SMOKE: missing Node.js/npx (Node 20+ required). Cannot run." >&2
	exit 2
fi

failed=0
for profile in "${profiles[@]}"; do
	out="$SMOKE_DIR/out/$profile"
	rm -rf "$out"
	mkdir -p "$out"
	printf '%s' "$profile" >"$out/profile"
	printf '%s' "$TIME_CAP" >"$out/time-cap"

	# run-blueprint ignores --php/--wp (CLI 3.1.61); versions must come from the
	# blueprint's preferredVersions, so write a per-run copy with them set.
	SMOKE_PHP="$PHP_VERSION" SMOKE_WP="$WP_VERSION" node -e '
		const b = JSON.parse( require( "fs" ).readFileSync( process.argv[ 1 ], "utf8" ) );
		b.preferredVersions = { php: process.env.SMOKE_PHP, wp: process.env.SMOKE_WP };
		require( "fs" ).writeFileSync( process.argv[ 2 ], JSON.stringify( b, null, "\t" ) );
	' "$SMOKE_DIR/blueprint.json" "$out/blueprint.json"

	echo "SMOKE [$profile]: booting Playground (PHP $PHP_VERSION, WP $WP_VERSION)..."
	if ! npx -y "$PLAYGROUND_CLI" run-blueprint \
		--blueprint="$out/blueprint.json" \
		--mount="$PLUGIN_DIR:/wordpress/wp-content/plugins/shieldscope-site-security-scanner" \
		--mount="$SMOKE_DIR:/smoke" \
		--mount="$out:/smoke-out" \
		>"$out/playground.log" 2>&1; then
		echo "SMOKE [$profile]: Playground exited with an error; see $out/playground.log" >&2
	fi

	# Assert on the phase result files; prints one summary line, exit 1 on failure.
	if ! line="$(node "$SMOKE_DIR/assert.js" "$out")"; then
		failed=1
	fi
	echo "$line"
	printf '%s\t%s\t%s\tphp=%s\t%s\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		"$(git -C "$PLUGIN_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)" \
		"$profile" "$PHP_VERSION" "$line" >>"$SMOKE_DIR/out/timing.txt"
done

exit "$failed"
