#!/usr/bin/env bash
set -Eeuo pipefail

if (($# != 0)); then
    echo "usage: $0" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -n "${BULLNYM_RELEASE_PROVENANCE_VERIFIED+x}" ]]; then
    echo "build release failed: unset BULLNYM_RELEASE_PROVENANCE_VERIFIED" >&2
    exit 1
fi

stage="$repo_root/target/verified-release"
messages="$(mktemp)"
success=0
cleanup() {
    rm -f "$messages"
    if ((success == 0)); then
        rm -rf "$stage"
    fi
}
trap cleanup EXIT
rm -rf "$stage"

# This wrapper is the only supported release build entry point. The marker is
# consumed by build.rs so a bare `cargo build --release` cannot accidentally
# mint an artifact that claims verified provenance.
scripts/release-preflight.sh
if ! BULLNYM_RELEASE_PROVENANCE_VERIFIED=verified-by-build-release-v1 \
    cargo build --release --locked --message-format=json-render-diagnostics >"$messages"; then
    python3 - "$messages" <<'PY'
import json
import pathlib
import sys

for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    rendered = message.get("message", {}).get("rendered")
    if rendered:
        print(rendered, file=sys.stderr, end="")
PY
    exit 1
fi
# Re-check the writable Cargo Git checkout after compilation so the accepted
# artifact is bracketed by the same source-integrity proof.
scripts/release-preflight.sh

artifact="$(python3 - "$messages" <<'PY'
import json
import pathlib
import sys

executables = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    target = message.get("target", {})
    if (message.get("reason") == "compiler-artifact"
            and target.get("name") == "pay-service"
            and "bin" in target.get("kind", [])
            and message.get("executable")):
        executables.append(message["executable"])
if len(executables) != 1:
    raise SystemExit(f"expected one pay-service release executable, found {executables!r}")
print(executables[0])
PY
)"
[[ -x "$artifact" ]] || { echo "build release failed: Cargo executable is missing: $artifact" >&2; exit 1; }

mkdir -p "$stage"
install -m 755 "$artifact" "$stage/pay-service"
scripts/write-release-record.sh \
    "$stage/pay-service" "$stage/pay-service.release.json"
scripts/verify-release-record.sh \
    "$stage/pay-service.release.json" "$stage/pay-service" "$repo_root"
scripts/release-preflight.sh

success=1
rm -f "$messages"
trap - EXIT

echo "verified release build completed: target/verified-release/pay-service"
