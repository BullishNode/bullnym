#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

reference=docs/operations/configuration.md
status=0

example_has_key() {
    local section="$1"
    local field="$2"

    awk -v expected_section="$section" -v expected_field="$field" '
      /^\[[^]]+\][[:space:]]*$/ {
        current_section = $0
        sub(/^\[/, "", current_section)
        sub(/\][[:space:]]*$/, "", current_section)
        next
      }
      {
        line = $0
        sub(/^[[:space:]]*#[[:space:]]*/, "", line)
        if (current_section == expected_section &&
            line ~ "^[[:space:]]*" expected_field "[[:space:]]*=") {
            found = 1
        }
      }
      END { exit !found }
    ' config.example.toml
}

while IFS=$'\t' read -r struct field; do
    case "$struct" in
        Config)
            case "$field" in
                domain|listen|pool_size)
                    key="$field"
                    section=""
                    ;;
                *) continue ;;
            esac
            ;;
        FeaturesConfig) section=features ;;
        WorkersConfig) section=workers ;;
        InvoiceAccountingConfig) section=invoice_accounting ;;
        BoltzConfig) section=boltz ;;
        ClaimConfig) section=claim ;;
        ReconcilerConfig) section=reconciler ;;
        PricerConfig) section=pricer ;;
        PwaConfig) section=pwa ;;
        DonationConfig) section=donation ;;
        LimitsConfig) section=limits ;;
        ProofConfig) section=proof ;;
        BitcoinWatcherConfig) section=bitcoin_watcher ;;
        RateLimitConfig) section=rate_limit ;;
        CertificationConfig) section=certification ;;
        ElectrumConfig) section=electrum ;;
        *) continue ;;
    esac

    if [[ "$struct" != Config ]]; then
        key="$section.$field"
    fi
    if ! rg -Fq "\`$key\`" "$reference"; then
        printf '%s: missing configuration field `%s` from %s\n' "$reference" "$key" "$struct" >&2
        status=1
    fi
    if ! example_has_key "$section" "$field"; then
        printf 'config.example.toml: missing field `%s` under [%s]\n' "$field" "$section" >&2
        status=1
    fi
done < <(
    awk '
      /^pub struct (Config|[A-Za-z0-9_]+Config) / {
        current = $3
        next
      }
      /^    pub [a-zA-Z0-9_]+:/ && current != "" {
        field = $2
        sub(/:.*/, "", field)
        print current "\t" field
      }
    ' src/config.rs
)

environment_keys=(
    DATABASE_URL
    SWAP_MNEMONIC
    BOLTZ_WEBHOOK_URL_SECRET
    BOLTZ_WEBHOOK_SECRET
    BOLTZ_WEBHOOK_URL_SECRET_PREVIOUS
    BULLNYM_RUNTIME_MODE
    BULLNYM_ALLOW_PUBLIC_LISTEN
    RUST_LOG
)

for key in "${environment_keys[@]}"; do
    if ! rg -Fq "\`$key\`" "$reference"; then
        printf '%s: missing environment variable `%s`\n' "$reference" "$key" >&2
        status=1
    fi
done

exit "$status"
