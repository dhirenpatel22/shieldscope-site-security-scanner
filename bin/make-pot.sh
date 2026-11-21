#!/usr/bin/env bash
# Regenerate languages/shieldscope-site-security-scanner.pot from the plugin's
# PHP files (not tests, bin/ or vendor-prefixed/), with WordPress's i18n
# functions and translator comments. Needs GNU gettext (xgettext).
#
#   bin/make-pot.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

domain="shieldscope-site-security-scanner"
version="$(sed -n 's/^[[:space:]]*\*[[:space:]]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' shieldscope-site-security-scanner.php | head -n 1)"
out="languages/${domain}.pot"

git ls-files -- '*.php' ':!tests/**' ':!bin/**' ':!vendor-prefixed/**' | sort >/tmp/shieldscope-pot-files.$$

xgettext --language=PHP --from-code=UTF-8 --sort-by-file --add-comments=translators: \
	--keyword=__:1 --keyword=_e:1 --keyword=esc_html__:1 --keyword=esc_html_e:1 \
	--keyword=esc_attr__:1 --keyword=esc_attr_e:1 --keyword=_x:1,2c --keyword=_ex:1,2c \
	--keyword=esc_html_x:1,2c --keyword=esc_attr_x:1,2c --keyword=_n:1,2 --keyword=_nx:1,2,4c \
	--keyword=_n_noop:1,2 --keyword=_nx_noop:1,2,3c \
	--package-name="ShieldScope" --package-version="$version" \
	--msgid-bugs-address="https://wordpress.org/support/plugin/${domain}/" \
	--copyright-holder="ShieldScope" \
	--files-from=/tmp/shieldscope-pot-files.$$ -o "$out"
rm -f /tmp/shieldscope-pot-files.$$

# Header: domain and license lines in the form WordPress tools write.
sed -i.bak -e 's/^"Content-Type: text\/plain; charset=CHARSET\\n"/"Content-Type: text\/plain; charset=UTF-8\\n"/' \
	-e '/^# SOME DESCRIPTIVE TITLE./d' -e '/^# FIRST AUTHOR/d' \
	-e "s/^# Copyright (C) YEAR ShieldScope/# Copyright (C) $(date +%Y) ShieldScope/" \
	-e 's/^# This file is distributed under the same license as the ShieldScope package./# This file is distributed under the GPL-2.0-or-later license./' \
	"$out" && rm -f "$out.bak"
grep -q '^"X-Domain:' "$out" || sed -i.bak "/^\"Content-Transfer-Encoding/a\\
\"X-Domain: ${domain}\\\\n\"
" "$out" && rm -f "$out.bak"

echo "$out: $(grep -c '^msgid "' "$out") strings (including the header)"
