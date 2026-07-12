#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fixture="$tmp/repo"
dependency="$tmp/boltz-checkout"
submodule_source="$tmp/boltz-submodule-source"
mkdir -p "$fixture/scripts" "$tmp/bin" "$dependency" "$submodule_source"
cp "$repo_root/scripts/verify-release-provenance.sh" "$fixture/scripts/"
cp "$repo_root/scripts/release-preflight.sh" "$fixture/scripts/"

repository="https://github.com/BullishNode/boltz-rust.git"
git -C "$dependency" init --quiet
git -C "$dependency" config user.email test@example.com
git -C "$dependency" config user.name "Provenance Test"
git -C "$submodule_source" init --quiet
git -C "$submodule_source" config user.email test@example.com
git -C "$submodule_source" config user.name "Provenance Test"
printf 'clean submodule source\n' >"$submodule_source/tracked.txt"
git -C "$submodule_source" add tracked.txt
git -C "$submodule_source" commit --quiet -m fixture
git -C "$dependency" -c protocol.file.allow=always submodule add --quiet \
    "$submodule_source" regtest/boltz
cat >"$dependency/Cargo.toml" <<'EOF'
[package]
name = "boltz-client"
version = "0.3.1"
edition = "2021"
EOF
printf 'clean dependency source\n' >"$dependency/tracked.txt"
git -C "$dependency" add Cargo.toml tracked.txt
git -C "$dependency" commit --quiet -m fixture
commit="$(git -C "$dependency" rev-parse HEAD)"
source="git+${repository}?rev=${commit}#${commit}"
dependency_manifest="$dependency/Cargo.toml"
# Cargo places this untracked sentinel in managed Git checkouts. It must be the
# sole allowed checkout-local file.
touch "$dependency/.cargo-ok"

write_fixture() {
    rm -f "$fixture/release-manifest.toml" "$fixture/Cargo.toml" "$fixture/Cargo.lock"
    rm -rf "$fixture/.cargo"
    cat >"$fixture/release-manifest.toml" <<EOF
format_version = 1
[boltz_client]
repository = "$repository"
commit = "$commit"
[content]
pwa_directory = "pwa/dist"
EOF
    cat >"$fixture/Cargo.toml" <<EOF
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
[dependencies]
boltz-client = { git = "$repository", rev = "$commit" }
EOF
    cat >"$fixture/Cargo.lock" <<EOF
version = 4
[[package]]
name = "boltz-client"
version = "0.3.1"
source = "$source"
EOF
}

cat >"$tmp/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '{"packages":[{"name":"boltz-client","source":"%s","manifest_path":"%s"}]}' \
    "${STUB_BOLTZ_SOURCE:?}" "${STUB_BOLTZ_MANIFEST:?}"
EOF
chmod +x "$tmp/bin/cargo"

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "provenance test failed: $label unexpectedly succeeded" >&2
        exit 1
    fi
}

run_verify() {
    PATH="$tmp/bin:$PATH" \
        STUB_BOLTZ_SOURCE="${STUB_BOLTZ_SOURCE:-$source}" \
        STUB_BOLTZ_MANIFEST="${STUB_BOLTZ_MANIFEST:-$dependency_manifest}" \
        "$fixture/scripts/verify-release-provenance.sh" --repo-root "$fixture"
}

write_fixture
run_verify >/dev/null

sed -i "s/$commit/$(printf 'a%.0s' {1..40})/" "$fixture/release-manifest.toml"
expect_failure "wrong revision" run_verify

write_fixture
rm "$fixture/Cargo.lock"
expect_failure "missing lock" run_verify

write_fixture
STUB_BOLTZ_SOURCE="path+file:///tmp/boltz-rust" \
    expect_failure "local dependency override" run_verify

write_fixture
sed -i 's#BullishNode/boltz-rust#example/boltz-rust#' "$fixture/release-manifest.toml"
expect_failure "wrong repository" run_verify

write_fixture
STUB_BOLTZ_MANIFEST="$tmp/missing-checkout/Cargo.toml" \
    expect_failure "missing dependency checkout" run_verify

printf 'dirty\n' >>"$dependency/tracked.txt"
expect_failure "dirty tracked dependency file" run_verify
git -C "$dependency" restore tracked.txt

touch "$dependency/untracked-source"
expect_failure "dirty untracked dependency file" run_verify
rm "$dependency/untracked-source"

git -C "$dependency" update-index --assume-unchanged tracked.txt
expect_failure "assume-unchanged dependency file" run_verify
git -C "$dependency" update-index --no-assume-unchanged tracked.txt

git -C "$dependency" update-index --skip-worktree tracked.txt
expect_failure "skip-worktree dependency file" run_verify
git -C "$dependency" update-index --no-skip-worktree tracked.txt

git -C "$dependency/regtest/boltz" update-index --assume-unchanged tracked.txt
expect_failure "assume-unchanged dependency submodule file" run_verify
git -C "$dependency/regtest/boltz" update-index --no-assume-unchanged tracked.txt

git -C "$dependency/regtest/boltz" update-index --skip-worktree tracked.txt
expect_failure "skip-worktree dependency submodule file" run_verify
git -C "$dependency/regtest/boltz" update-index --no-skip-worktree tracked.txt

wrong_dependency="$tmp/wrong-boltz-checkout"
git clone --quiet "$dependency" "$wrong_dependency"
git -C "$wrong_dependency" config user.email test@example.com
git -C "$wrong_dependency" config user.name "Provenance Test"
printf 'different commit\n' >>"$wrong_dependency/tracked.txt"
git -C "$wrong_dependency" add tracked.txt
git -C "$wrong_dependency" commit --quiet -m different
STUB_BOLTZ_MANIFEST="$wrong_dependency/Cargo.toml" \
    expect_failure "wrong dependency checkout revision" run_verify

write_fixture
git -C "$fixture" init --quiet
git -C "$fixture" config user.email test@example.com
git -C "$fixture" config user.name "Provenance Test"
git -C "$fixture" add .
git -C "$fixture" commit --quiet -m fixture
PATH="$tmp/bin:$PATH" STUB_BOLTZ_SOURCE="$source" \
    STUB_BOLTZ_MANIFEST="$dependency_manifest" \
    "$fixture/scripts/release-preflight.sh" --repo-root "$fixture" >/dev/null

git -C "$fixture" update-index --assume-unchanged Cargo.toml
expect_failure "assume-unchanged Bullnym file" \
    env PATH="$tmp/bin:$PATH" STUB_BOLTZ_SOURCE="$source" \
    STUB_BOLTZ_MANIFEST="$dependency_manifest" \
    "$fixture/scripts/release-preflight.sh" --repo-root "$fixture"
git -C "$fixture" update-index --no-assume-unchanged Cargo.toml

git -C "$fixture" update-index --skip-worktree Cargo.toml
expect_failure "skip-worktree Bullnym file" \
    env PATH="$tmp/bin:$PATH" STUB_BOLTZ_SOURCE="$source" \
    STUB_BOLTZ_MANIFEST="$dependency_manifest" \
    "$fixture/scripts/release-preflight.sh" --repo-root "$fixture"
git -C "$fixture" update-index --no-skip-worktree Cargo.toml

printf '\n# dirty\n' >>"$fixture/Cargo.toml"
expect_failure "dirty tracked Bullnym file" \
    env PATH="$tmp/bin:$PATH" STUB_BOLTZ_SOURCE="$source" \
    STUB_BOLTZ_MANIFEST="$dependency_manifest" \
    "$fixture/scripts/release-preflight.sh" --repo-root "$fixture"
git -C "$fixture" show HEAD:Cargo.toml >"$fixture/Cargo.toml"

touch "$fixture/untracked-file"
expect_failure "dirty untracked Bullnym file" \
    env PATH="$tmp/bin:$PATH" STUB_BOLTZ_SOURCE="$source" \
    STUB_BOLTZ_MANIFEST="$dependency_manifest" \
    "$fixture/scripts/release-preflight.sh" --repo-root "$fixture"
rm "$fixture/untracked-file"

mkdir -p "$fixture/.cargo"
touch "$fixture/.cargo/config.toml"
expect_failure "repository-local path override" run_verify

echo "release provenance fault tests passed"
