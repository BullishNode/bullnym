#!/usr/bin/env bash
set -Eeuo pipefail

if (($# != 2)); then
    echo "usage: $0 BINARY OUTPUT_JSON" >&2
    exit 2
fi

binary="$1"
output="$2"
[[ -x "$binary" ]] || { echo "release record failed: binary is not executable: $binary" >&2; exit 1; }
command -v python3 >/dev/null \
    || { echo "release record failed: python3 is required" >&2; exit 1; }

digest="$(python3 -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$binary")"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "release record failed: invalid SHA-256 output" >&2; exit 1; }

mkdir -p "$(dirname "$output")"
temporary="${output}.tmp.$$"
build_info_file="${output}.build-info.tmp.$$"
trap 'rm -f "$temporary" "$build_info_file"' EXIT
"$binary" --build-info >"$build_info_file"
python3 - "$build_info_file" "$temporary" "$(basename "$binary")" "$digest" <<'PY'
import json
import pathlib
import sys

build_info_path, output_path, artifact_name, digest = sys.argv[1:]
try:
    build = json.loads(pathlib.Path(build_info_path).read_text())
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"release record failed: invalid --build-info JSON: {error}")
if not isinstance(build, dict):
    raise SystemExit("release record failed: --build-info must return a JSON object")
required_strings = (
    "service",
    "crate_version",
    "build_commit",
    "build_profile",
    "build_source_state",
    "boltz_client_repository",
    "boltz_client_commit",
    "boltz_client_verification",
    "pwa_content_sha256",
    "expected_schema_marker",
    "rustc_version",
    "cargo_version",
    "build_target",
)
for field in required_strings:
    if not isinstance(build.get(field), str) or not build[field]:
        raise SystemExit(f"release record failed: missing or invalid {field}")
required = {
    "service": "pay-service",
    "build_profile": "release",
    "build_source_state": "clean",
    "boltz_client_repository": "https://github.com/BullishNode/boltz-rust.git",
    "boltz_client_verification": "wrapper-built",
}
for field, expected in required.items():
    if build.get(field) != expected:
        raise SystemExit(
            f"release record failed: {field} is {build.get(field)!r}, expected {expected!r}"
        )
hex_fields = {"build_commit": 40, "boltz_client_commit": 40, "pwa_content_sha256": 64}
for field, length in hex_fields.items():
    value = build[field]
    if len(value) != length or any(character not in "0123456789abcdef" for character in value):
        raise SystemExit(f"release record failed: invalid {field}")
record = {
    "build": build,
    "artifact_name": artifact_name,
    "artifact_sha256": digest,
    "verification": {"status": "pending"},
}
with pathlib.Path(output_path).open("x") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
mv "$temporary" "$output"
rm -f "$build_info_file"
trap - EXIT

echo "release record written: $output (sha256 $digest)"
