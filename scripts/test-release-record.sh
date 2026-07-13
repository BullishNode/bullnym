#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

write_binary() {
    local path="$1"
    local verification="$2"
    cat >"$path" <<EOF
#!/usr/bin/env bash
printf '%s\n' '{"service":"pay-service","crate_version":"0.1.0","build_commit":"1111111111111111111111111111111111111111","build_profile":"release","build_source_state":"clean","boltz_client_repository":"https://github.com/BullishNode/boltz-rust.git","boltz_client_commit":"2222222222222222222222222222222222222222","boltz_client_verification":"$verification","pwa_content_sha256":"3333333333333333333333333333333333333333333333333333333333333333","expected_schema_marker":"047_direct_payment_lifecycle_foundation","rustc_version":"rustc 1.92.0","cargo_version":"cargo 1.92.0","build_target":"x86_64-unknown-linux-gnu"}'
EOF
    chmod +x "$path"
}

valid_binary="$tmp/pay service"
valid_record="$tmp/valid record.json"
write_binary "$valid_binary" wrapper-built
"$repo_root/scripts/write-release-record.sh" "$valid_binary" "$valid_record" >/dev/null
python3 - "$valid_binary" "$valid_record" <<'PY'
import hashlib
import json
import pathlib
import sys

binary = pathlib.Path(sys.argv[1])
record = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert record["artifact_name"] == binary.name
assert record["artifact_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
assert record["build"]["boltz_client_verification"] == "wrapper-built"
assert record["verification"]["status"] == "pending"
PY

invalid_json="$tmp/invalid-json"
cat >"$invalid_json" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '{not-json}'
EOF
chmod +x "$invalid_json"
if "$repo_root/scripts/write-release-record.sh" "$invalid_json" "$tmp/invalid.json" \
    >/dev/null 2>&1; then
    echo "release record test failed: invalid JSON was accepted" >&2
    exit 1
fi

unverified="$tmp/unverified"
write_binary "$unverified" unverified-debug
if "$repo_root/scripts/write-release-record.sh" "$unverified" "$tmp/unverified.json" \
    >/dev/null 2>&1; then
    echo "release record test failed: unverified build was accepted" >&2
    exit 1
fi

echo "release record fault tests passed"
