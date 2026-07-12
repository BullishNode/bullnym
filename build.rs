//! Stable build provenance for release and incident reproduction.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const RELEASE_VERIFICATION_TOKEN: &str = "verified-by-build-release-v1";

#[derive(Debug, Deserialize)]
struct ReleaseManifest {
    format_version: u32,
    boltz_client: BoltzClientPin,
    content: ContentManifest,
}

#[derive(Debug, Deserialize)]
struct BoltzClientPin {
    repository: String,
    commit: String,
}

#[derive(Debug, Deserialize)]
struct ContentManifest {
    pwa_directory: String,
}

fn command_output(dir: &Path, program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn git_output(repo: &Path, args: &[&str]) -> Option<String> {
    command_output(repo, "git", args)
}

fn git_is_clean(repo: &Path) -> Option<bool> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout.is_empty())
}

fn validate_hex_commit(commit: &str) {
    assert!(
        commit.len() == 40
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "release-manifest.toml boltz_client.commit must be a full lowercase 40-character Git SHA"
    );
}

fn tool_version(repo_root: &Path, variable: &str, fallback: &str) -> Option<String> {
    let program = std::env::var(variable).unwrap_or_else(|_| fallback.to_string());
    command_output(repo_root, &program, &["--version"])
}

fn validate_cargo_pin(repo_root: &Path, pin: &BoltzClientPin) {
    let cargo_toml: toml::Value = toml::from_str(
        &fs::read_to_string(repo_root.join("Cargo.toml"))
            .expect("Cargo.toml must be readable for provenance validation"),
    )
    .expect("Cargo.toml must be valid TOML");
    let dependency = &cargo_toml["dependencies"]["boltz-client"];
    assert_eq!(
        dependency.get("git").and_then(toml::Value::as_str),
        Some(pin.repository.as_str()),
        "Cargo.toml boltz-client.git disagrees with release-manifest.toml"
    );
    assert_eq!(
        dependency.get("rev").and_then(toml::Value::as_str),
        Some(pin.commit.as_str()),
        "Cargo.toml boltz-client.rev disagrees with release-manifest.toml"
    );
    assert!(
        dependency.get("path").is_none(),
        "Cargo.toml must not use a path dependency for boltz-client"
    );

    let cargo_lock: toml::Value = toml::from_str(
        &fs::read_to_string(repo_root.join("Cargo.lock"))
            .expect("Cargo.lock must be readable for provenance validation"),
    )
    .expect("Cargo.lock must be valid TOML");
    let expected_source = format!("git+{}?rev={}#{}", pin.repository, pin.commit, pin.commit);
    let locked = cargo_lock["package"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|package| {
            package.get("name").and_then(toml::Value::as_str) == Some("boltz-client")
                && package.get("source").and_then(toml::Value::as_str)
                    == Some(expected_source.as_str())
        });
    assert!(
        locked,
        "Cargo.lock does not resolve boltz-client to the release-manifest.toml repository and SHA"
    );
}

fn latest_schema_marker(migrations_dir: &Path) -> String {
    let mut migrations: Vec<String> = fs::read_dir(migrations_dir)
        .expect("migrations directory must be readable")
        .map(|entry| entry.expect("migration entry must be readable").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sql"))
        .filter_map(|path| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_string)
        })
        .collect();
    migrations.sort();
    migrations
        .pop()
        .expect("at least one SQL migration is required")
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(current).unwrap_or_else(|error| panic!("read {}: {error}", current.display()));
    for entry in entries {
        let path = entry.expect("content entry must be readable").path();
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));
        if metadata.file_type().is_symlink() {
            panic!(
                "release content must not contain symlinks: {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            collect_files(root, &path, files);
        } else if metadata.is_file() {
            files.push(
                path.strip_prefix(root)
                    .expect("content path must remain under its root")
                    .to_path_buf(),
            );
        }
    }
}

/// Hash a framed, path-sorted stream of relative UTF-8 paths and file bytes.
/// This is independent of filesystem enumeration order and mtimes.
fn content_sha256(root: &Path) -> String {
    assert!(
        root.is_dir(),
        "release content directory is missing: {}",
        root.display()
    );
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort();
    let mut hasher = Sha256::new();
    for relative in files {
        let relative = relative
            .to_str()
            .unwrap_or_else(|| panic!("non-UTF-8 release content path: {}", relative.display()));
        let bytes = fs::read(root.join(relative))
            .unwrap_or_else(|error| panic!("read release content {relative}: {error}"));
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn watch_git_identity(repo_root: &Path) {
    if let Some(head_path) = git_output(repo_root, &["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head_path}");
    }
    if let Some(reference) = git_output(repo_root, &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(reference_path) =
            git_output(repo_root, &["rev-parse", "--git-path", reference.as_str()])
        {
            println!("cargo:rerun-if-changed={reference_path}");
        }
    }
}

fn main() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest: ReleaseManifest = toml::from_str(
        &fs::read_to_string(repo_root.join("release-manifest.toml"))
            .expect("release-manifest.toml must be readable"),
    )
    .expect("release-manifest.toml must be valid TOML");
    assert_eq!(
        manifest.format_version, 1,
        "unsupported release manifest format"
    );
    validate_hex_commit(&manifest.boltz_client.commit);
    validate_cargo_pin(repo_root, &manifest.boltz_client);

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let build_commit = git_output(repo_root, &["rev-parse", "HEAD"]);
    let clean = git_is_clean(repo_root);
    let release_verified = std::env::var("BULLNYM_RELEASE_PROVENANCE_VERIFIED").as_deref()
        == Ok(RELEASE_VERIFICATION_TOKEN);
    if profile == "release" {
        assert!(
            release_verified,
            "release builds must run through scripts/build-release.sh"
        );
        assert!(
            !repo_root.join(".cargo/config.toml").exists(),
            "release builds reject the local boltz-client path override at .cargo/config.toml"
        );
        assert!(
            build_commit.is_some(),
            "release builds require a Git commit identity"
        );
        assert_eq!(
            clean,
            Some(true),
            "release builds require a clean Bullnym worktree"
        );
    }
    let source_state = match clean {
        Some(true) => "clean",
        Some(false) => "dirty-debug",
        None => "unknown-debug",
    };
    let schema_marker = latest_schema_marker(&repo_root.join("migrations"));
    let pwa_sha256 = content_sha256(&repo_root.join(&manifest.content.pwa_directory));
    let rustc_version =
        tool_version(repo_root, "RUSTC", "rustc").unwrap_or_else(|| "unknown".to_string());
    let cargo_version =
        tool_version(repo_root, "CARGO", "cargo").unwrap_or_else(|| "unknown".to_string());
    let build_target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    if profile == "release" {
        assert_ne!(
            rustc_version, "unknown",
            "release builds require rustc identity"
        );
        assert_ne!(
            cargo_version, "unknown",
            "release builds require Cargo identity"
        );
        assert_ne!(
            build_target, "unknown",
            "release builds require target identity"
        );
    }
    let boltz_verification = if profile == "release" && release_verified {
        "wrapper-built"
    } else {
        "unverified-debug"
    };

    println!(
        "cargo:rustc-env=BULLNYM_BUILD_COMMIT={}",
        build_commit.as_deref().unwrap_or("unknown")
    );
    println!("cargo:rustc-env=BULLNYM_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=BULLNYM_BUILD_SOURCE_STATE={source_state}");
    println!(
        "cargo:rustc-env=BULLNYM_BOLTZ_CLIENT_REPOSITORY={}",
        manifest.boltz_client.repository
    );
    println!(
        "cargo:rustc-env=BULLNYM_BOLTZ_CLIENT_COMMIT={}",
        manifest.boltz_client.commit
    );
    println!("cargo:rustc-env=BULLNYM_BOLTZ_CLIENT_VERIFICATION={boltz_verification}");
    println!("cargo:rustc-env=BULLNYM_SCHEMA_MARKER={schema_marker}");
    println!("cargo:rustc-env=BULLNYM_PWA_CONTENT_SHA256={pwa_sha256}");
    println!("cargo:rustc-env=BULLNYM_RUSTC_VERSION={rustc_version}");
    println!("cargo:rustc-env=BULLNYM_CARGO_VERSION={cargo_version}");
    println!("cargo:rustc-env=BULLNYM_BUILD_TARGET={build_target}");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=release-manifest.toml");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=rust-toolchain.toml");
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed={}", manifest.content.pwa_directory);
    println!("cargo:rerun-if-env-changed=BULLNYM_RELEASE_PROVENANCE_VERIFIED");
    watch_git_identity(repo_root);
}
