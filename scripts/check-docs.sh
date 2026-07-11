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

if rg -n 'docs/(components|features|decisions)/|docs/api-reference\.md|docs/payment-architecture\.md|docs/runbook-stuck-swap\.md' \
    README.md CONTRIBUTING.md SECURITY.md docs --glob '*.md'; then
    printf 'maintained documentation references a retired path\n' >&2
    status=1
fi

if find docs/components docs/features -type f 2>/dev/null | grep -q .; then
    printf 'retired docs/components or docs/features files remain\n' >&2
    status=1
fi

exit "$status"
