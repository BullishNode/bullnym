//! Build provenance (issue #70).
//!
//! Two jobs:
//!
//! 1. Populate the `BULLNYM_BUILD_*` env vars that `src/version.rs` reads via
//!    `option_env!`, so `/version` reports the real commit instead of
//!    "unknown" without any wrapper script.
//! 2. Identify — and for `--release` builds, enforce — the exact revision of
//!    the sibling `boltz-client` path dependency against
//!    `release-manifest.toml`. That crate constructs and signs swap
//!    transactions; a release artifact built against an unknown or dirty
//!    checkout cannot be audited or reproduced during incident response.
//!
//! Debug builds never fail on the pin (local development iterates on the
//! fork); they still embed whatever revision was used. A release build with
//! a missing, wrong-remote, wrong-commit, or dirty checkout fails, unless
//! `BULLNYM_ALLOW_UNPINNED_BOLTZ=1` is set — and that override is embedded
//! in the binary as `pin=overridden`, so an unpinned artifact is
//! self-identifying rather than silently equal to a verified one.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Dirty = modified/staged tracked files. Untracked files are not counted:
/// they cannot alter compiled sources without first being added, and local
/// editor/tooling droppings would otherwise permanently block release builds.
fn is_dirty(dir: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
}

fn manifest_value(manifest: &str, key: &str) -> Option<String> {
    // Minimal single-table TOML scrape; avoids a build-dependency for two keys.
    manifest.lines().find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix(key)?.trim_start();
        let rest = rest.strip_prefix('=')?.trim();
        Some(rest.trim_matches('"').to_string())
    })
}

fn manifest_remotes(manifest: &str) -> Vec<String> {
    let start = match manifest.find("allowed_remotes") {
        Some(i) => i,
        None => return Vec::new(),
    };
    let tail = &manifest[start..];
    let open = match tail.find('[') {
        Some(i) => i,
        None => return Vec::new(),
    };
    let close = match tail[open..].find(']') {
        Some(i) => open + i,
        None => return Vec::new(),
    };
    tail[open + 1..close]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn main() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let is_release = profile == "release";

    println!("cargo:rerun-if-changed=release-manifest.toml");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-env-changed=BULLNYM_ALLOW_UNPINNED_BOLTZ");

    // --- 1. bullnym's own build identity ---
    let commit = git(repo_root, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let branch =
        git(repo_root, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = if commit == "unknown" {
        "unknown".to_string()
    } else {
        is_dirty(repo_root).to_string()
    };
    let time = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=BULLNYM_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=BULLNYM_BUILD_BRANCH={branch}");
    println!("cargo:rustc-env=BULLNYM_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=BULLNYM_BUILD_TIME={time}");

    // --- 2. boltz-client provenance ---
    let manifest = std::fs::read_to_string(repo_root.join("release-manifest.toml"))
        .expect("release-manifest.toml must exist at the repository root");
    let expected_path =
        manifest_value(&manifest, "path").expect("release-manifest.toml: missing boltz path");
    let expected_commit =
        manifest_value(&manifest, "commit").expect("release-manifest.toml: missing boltz commit");
    let allowed_remotes = manifest_remotes(&manifest);

    let boltz_dir = repo_root.join(&expected_path);
    let boltz_commit = git(&boltz_dir, &["rev-parse", "HEAD"]);
    let boltz_remote = git(&boltz_dir, &["remote", "get-url", "origin"]);
    let boltz_dirty = boltz_commit.is_some() && is_dirty(&boltz_dir);
    if boltz_dir.join(".git").exists() {
        println!("cargo:rerun-if-changed={}", boltz_dir.join(".git/HEAD").display());
    }

    let override_set = std::env::var("BULLNYM_ALLOW_UNPINNED_BOLTZ").as_deref() == Ok("1");
    let mut problems: Vec<String> = Vec::new();
    match &boltz_commit {
        None => problems.push(format!(
            "boltz-client checkout missing or not a git repository at {}",
            boltz_dir.display()
        )),
        Some(actual) => {
            if actual != &expected_commit {
                problems.push(format!(
                    "boltz-client is at {actual}, release-manifest.toml pins {expected_commit}"
                ));
            }
            if boltz_dirty {
                problems.push("boltz-client worktree has modified tracked files".into());
            }
            match &boltz_remote {
                Some(url) if allowed_remotes.iter().any(|r| url.contains(r.as_str())) => {}
                Some(url) => problems.push(format!(
                    "boltz-client origin {url} is not in release-manifest.toml allowed_remotes"
                )),
                None => problems.push("boltz-client has no origin remote".into()),
            }
        }
    }

    let pin_status = if problems.is_empty() {
        "verified"
    } else if is_release && !override_set {
        eprintln!("release provenance check failed (release-manifest.toml, issue #70):");
        for p in &problems {
            eprintln!("  - {p}");
        }
        eprintln!("fix the checkout or, to knowingly build an unpinned artifact, set BULLNYM_ALLOW_UNPINNED_BOLTZ=1 (the binary will report pin=overridden)");
        panic!("refusing to build a release against an unverified boltz-client");
    } else if is_release {
        "overridden"
    } else {
        "unenforced-debug"
    };

    println!(
        "cargo:rustc-env=BOLTZ_CLIENT_COMMIT={}",
        boltz_commit.as_deref().unwrap_or("unknown")
    );
    println!("cargo:rustc-env=BOLTZ_CLIENT_DIRTY={boltz_dirty}");
    println!("cargo:rustc-env=BOLTZ_CLIENT_PIN={pin_status}");
    println!("cargo:rustc-env=BULLNYM_BUILD_PROFILE={profile}");
}
