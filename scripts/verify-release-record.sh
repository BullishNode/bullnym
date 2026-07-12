#!/usr/bin/env bash
set -Eeuo pipefail

if (($# != 3)); then
    echo "usage: $0 RELEASE_JSON BINARY REPO_ROOT" >&2
    exit 2
fi

record="$1"
binary="$2"
repo_root="$(cd "$3" && pwd)"
[[ -f "$record" ]] || { echo "release record verification failed: missing $record" >&2; exit 1; }
[[ -x "$binary" ]] || { echo "release record verification failed: invalid binary $binary" >&2; exit 1; }

"$repo_root/scripts/release-preflight.sh" --repo-root "$repo_root"
pwa_digest="$("$repo_root/scripts/content-sha256.py" "$repo_root/pwa/dist")"
original_record="$(mktemp)"
cp "$record" "$original_record"
trap 'rm -f "$original_record"' EXIT
python3 - "$record" "$binary" "$repo_root" "$pwa_digest" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib

record_path, binary_path, repo_path, pwa_digest = sys.argv[1:]
repo = pathlib.Path(repo_path)
record = json.loads(pathlib.Path(record_path).read_text())
build = record.get("build")
if not isinstance(build, dict):
    raise SystemExit("release record verification failed: missing build object")

manifest = tomllib.loads((repo / "release-manifest.toml").read_text())
toolchain = tomllib.loads((repo / "rust-toolchain.toml").read_text())
head = subprocess.check_output(
    ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
).strip()
migrations = sorted((repo / "migrations").glob("*.sql"))
if not migrations:
    raise SystemExit("release record verification failed: no migrations")
rustc_verbose = subprocess.check_output(["rustc", "-Vv"], text=True)
rustc_fields = dict(
    line.split(": ", 1) for line in rustc_verbose.splitlines() if ": " in line
)
channel = toolchain["toolchain"]["channel"]

expected = {
    "service": "pay-service",
    "build_commit": head,
    "build_profile": "release",
    "build_source_state": "clean",
    "boltz_client_repository": manifest["boltz_client"]["repository"],
    "boltz_client_commit": manifest["boltz_client"]["commit"],
    "boltz_client_verification": "wrapper-built",
    "pwa_content_sha256": pwa_digest,
    "expected_schema_marker": migrations[-1].stem,
    "build_target": rustc_fields["host"],
}
for field, value in expected.items():
    if build.get(field) != value:
        raise SystemExit(
            f"release record verification failed: {field}={build.get(field)!r}, "
            f"expected {value!r}"
        )
if not build.get("rustc_version", "").startswith(f"rustc {channel} "):
    raise SystemExit("release record verification failed: rustc version differs from toolchain pin")
if not build.get("cargo_version", "").startswith(f"cargo {channel} "):
    raise SystemExit("release record verification failed: Cargo version differs from toolchain pin")

binary = pathlib.Path(binary_path)
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
if record.get("artifact_name") != binary.name:
    raise SystemExit("release record verification failed: artifact name mismatch")
if record.get("artifact_sha256") != digest:
    raise SystemExit("release record verification failed: artifact digest mismatch")

record["verification"] = {
    "status": "verified",
    "method": "bullnym-release-v1",
    "artifact_sha256": digest,
    "bullnym_commit": head,
    "boltz_client_commit": manifest["boltz_client"]["commit"],
}
record_path = pathlib.Path(record_path)
temporary = record_path.with_name(f"{record_path.name}.verify.tmp")
with temporary.open("w") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
temporary.replace(record_path)
PY
if ! "$repo_root/scripts/release-preflight.sh" --repo-root "$repo_root"; then
    cp "$original_record" "$record"
    exit 1
fi
rm -f "$original_record"
trap - EXIT

echo "release record verified: $record"
