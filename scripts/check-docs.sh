#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

status=0

while IFS=$'\t' read -r file line target; do
    case "$target" in
        http://*|https://*|mailto:*|\#*|'') continue ;;
    esac

    target="${target%%#*}"
    target="${target%%\?*}"
    target="${target//%20/ }"

    if [[ "$target" == /* ]]; then
        resolved=".${target}"
    else
        resolved="$(dirname "$file")/$target"
    fi

    if [[ ! -e "$resolved" ]]; then
        printf '%s:%s: broken local link: %s\n' "$file" "$line" "$target" >&2
        status=1
    fi
done < <(
    perl -ne '
      while (/\[[^]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+"[^"]*")?\)/g) {
        $target = defined($1) ? $1 : $2;
        print "$ARGV\t$.\t$target\n";
      }
      close ARGV if eof;
    ' README.md CONTRIBUTING.md SECURITY.md $(find docs archive -type f -name '*.md' | sort)
)

if grep -R -n -E --include='*.md' \
    'docs/(components|features|decisions)/|docs/api-reference\.md|docs/payment-architecture\.md|docs/runbook-stuck-swap\.md' \
    README.md CONTRIBUTING.md SECURITY.md docs; then
    printf 'maintained documentation references a retired path\n' >&2
    status=1
fi

if find docs/components docs/features -type f 2>/dev/null | grep -q .; then
    printf 'retired docs/components or docs/features files remain\n' >&2
    status=1
fi

# Maintained public/product documentation must describe permanent names and
# automatic, read-only-to-clients recovery. Superseded RFCs retain historical
# reasoning and carry their own status notices, so they are deliberately not
# part of this current-contract scan.
if grep -R -n -i -E \
    'reactivat|manual recovery|\bRBF\b|compensation|alias release' \
    docs/api docs/products docs/architecture docs/adr; then
    printf 'maintained documentation contains a retired product promise\n' >&2
    status=1
fi

if ! grep -Fqx -- '- Status: Superseded' \
    docs/rfcs/001-chain-swap-reliability.md \
    || ! grep -Fqx -- '- Superseded by: the maintained automatic-recovery contract linked below' \
        docs/rfcs/001-chain-swap-reliability.md \
    || ! grep -Fq -- '> **Historical design record.**' \
        docs/rfcs/001-chain-swap-reliability.md; then
    printf 'chain-swap RFC is missing its historical/superseded status notice\n' >&2
    status=1
fi

if ! grep -Fqx -- '- Status: Superseded by RFC-003' \
    docs/rfcs/002-public-name-reservation.md \
    || ! grep -Fq -- 'This is a historical research/design record.' \
        docs/rfcs/002-public-name-reservation.md; then
    printf 'public-name RFC is missing its historical/superseded status notice\n' >&2
    status=1
fi

exit "$status"
