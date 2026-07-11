#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

status=0

required_paths=(
    LICENSE
    README.md
    CONTRIBUTING.md
    SECURITY.md
    config.example.toml
    scripts/release-preflight.sh
    docs/README.md
    docs/architecture/trust-model.md
    docs/api/README.md
    docs/operations/README.md
    archive/README.md
)

for path in "${required_paths[@]}"; do
    if [[ ! -e "$path" ]]; then
        printf 'missing required repository file: %s\n' "$path" >&2
        status=1
    fi
done

if git ls-files --error-unmatch config.toml >/dev/null 2>&1; then
    printf 'config.toml is runtime state and must not be tracked; use config.example.toml\n' >&2
    status=1
fi

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

if rg -n 'docs/(components|features|decisions)/|docs/api-reference\.md|docs/payment-architecture\.md|docs/compatibility-ledger\.md|docs/runbook-stuck-swap\.md|docs/server-improvement-from-tests/' \
    README.md CONTRIBUTING.md SECURITY.md docs src scripts --glob '*.md' --glob '*.rs' --glob '*.sh' --glob '!check-docs.sh'; then
    printf 'maintained documentation references a retired path\n' >&2
    status=1
fi

if rg -n 'POST /donation-page/image|upload_image|image_pipeline' src Cargo.toml; then
    printf 'unsupported image-upload implementation remains in maintained source\n' >&2
    status=1
fi

if rg -n 'Preferred API shape|If implementation starts' docs/architecture docs/products docs/api; then
    printf 'maintained documentation contains proposal language; move it to an RFC\n' >&2
    status=1
fi

while IFS= read -r file; do
    if ! head -n 8 "$file" | rg -qi 'archiv'; then
        printf '%s: archived document lacks a lifecycle banner in its first eight lines\n' "$file" >&2
        status=1
    fi
done < <(find archive -mindepth 2 -type f -name '*.md' | sort)

while IFS= read -r file; do
    case "$file" in
        */README.md|*/template.md) continue ;;
    esac
    if ! rg -Fq "$(basename "$file")" README.md docs/README.md docs/*/README.md; then
        printf '%s: maintained document is not linked from a repository index\n' "$file" >&2
        status=1
    fi
done < <(find docs -type f -name '*.md' | sort)

if find docs/components docs/features -type f 2>/dev/null | grep -q .; then
    printf 'retired docs/components or docs/features files remain\n' >&2
    status=1
fi

exit "$status"
