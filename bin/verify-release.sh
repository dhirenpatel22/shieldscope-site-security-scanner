#!/usr/bin/env bash
# Release guardrails, run by the `verify` job in .github/workflows/deploy.yml
# and runnable locally from the repo root: bin/verify-release.sh
#
# Fails on:
#   - merge conflict markers in tracked files
#   - any mismatch between the plugin header Version, SHIELDSCOPE_VERSION,
#     readme.txt Stable tag, tests/bootstrap.php and (on a tag) the tag name
#   - `php -l` errors in tracked PHP files (with whichever php is on PATH)
#   - a PHPUnit failure (phpunit on PATH, or set PHPUNIT=/path/to/phpunit)
#   - on a tag: the tagged commit not being an ancestor of origin/main
#
# Tag detection uses GitHub's GITHUB_REF_TYPE / GITHUB_REF_NAME.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

failures=0
fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

# 1. Conflict markers.
if git grep -nE '^(<<<<<<<|=======|>>>>>>>)' -- . >&2; then
	fail "conflict markers found in tracked files (see above)"
fi

# 2. Version consistency.
main_file="shieldscope-site-security-scanner.php"
header_version="$(sed -n 's/^[[:space:]]*\*[[:space:]]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$main_file" | head -n 1)"
const_version="$(sed -n "s/^define( 'SHIELDSCOPE_VERSION', '\([^']*\)' );.*/\1/p" "$main_file" | head -n 1)"
readme_version="$(sed -n 's/^Stable tag:[[:space:]]*\([^[:space:]]*\).*/\1/p' readme.txt | tr -d '\r' | head -n 1)"
tests_version="$(sed -n "s/^define( 'SHIELDSCOPE_VERSION', '\([^']*\)' );.*/\1/p" tests/bootstrap.php | head -n 1)"

if [ -z "$header_version" ]; then
	fail "no Version: in the $main_file header"
fi
check_version() {
	if [ "$2" != "$header_version" ]; then
		fail "$1 is '$2' but the plugin header Version is '$header_version'"
	fi
}
check_version "SHIELDSCOPE_VERSION in $main_file" "$const_version"
check_version "readme.txt Stable tag" "$readme_version"
check_version "SHIELDSCOPE_VERSION in tests/bootstrap.php" "$tests_version"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
	check_version "tag name" "${GITHUB_REF_NAME:-}"
fi

# 3. PHP syntax.
echo "php -l with $(php -r 'echo PHP_VERSION;')"
while IFS= read -r -d '' php_file; do
	if ! lint_output="$(php -l "$php_file" 2>&1)"; then
		echo "$lint_output" >&2
		fail "php -l: $php_file"
	fi
done < <(git ls-files -z -- '*.php')

# 4. Tags must point at a commit already on main.
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
	if ! git rev-parse --verify --quiet origin/main >/dev/null; then
		fail "origin/main is not available; cannot confirm the tag is on main"
	elif ! git merge-base --is-ancestor HEAD origin/main; then
		fail "tag ${GITHUB_REF_NAME:-} points at a commit that is not on main"
	fi
fi

# 5. Unit tests.
phpunit="${PHPUNIT:-phpunit}"
if ! command -v "$phpunit" >/dev/null 2>&1; then
	fail "phpunit not found (install it or set PHPUNIT)"
elif ! "$phpunit" --do-not-cache-result; then
	fail "PHPUnit"
fi

if [ "$failures" -gt 0 ]; then
	echo "verify-release: $failures check(s) failed" >&2
	exit 1
fi
echo "verify-release: all checks passed"
