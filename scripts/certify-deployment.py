#!/usr/bin/env python3
"""Fail-closed, read-only Bullnym release and deployment certification.

This runner intentionally owns no deployment, provider, wallet, or payment
operation.  It verifies an already-built release with the repository's release
verifier, then performs four bounded public GETs against the supplied origin.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA_MARKER_RE = re.compile(r"[0-9]{3}_[a-z0-9][a-z0-9_]*\Z")
UNKNOWN_VALUES = frozenset({"", "unknown", "unknown-debug", "unverified", "pending"})
MAX_HTTP_BODY_BYTES = 64 * 1024
CURRENT_PUBLIC_NAME_POLICY = "permanent_names_v1"
CURRENT_RUNTIME_MODE = "production"


class CertificationError(Exception):
    """A missing, ambiguous, or mismatched certification fact."""


def fail(message: str) -> None:
    raise CertificationError(message)


def strict_json(data: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate JSON field {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        fail(f"{label} contains non-finite JSON value {value}")

    try:
        value = json.loads(
            data,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_object(parent: dict[str, Any], field: str, label: str) -> dict[str, Any]:
    value = parent.get(field)
    if not isinstance(value, dict):
        fail(f"{label}.{field} must be an object")
    return value


def require_string(
    parent: dict[str, Any],
    field: str,
    label: str,
    *,
    expected: str | None = None,
    reject_unknown: bool = True,
) -> str:
    value = parent.get(field)
    if not isinstance(value, str):
        fail(f"{label}.{field} must be a string")
    if reject_unknown and value.strip().lower() in UNKNOWN_VALUES:
        fail(f"{label}.{field} is unknown or unverified")
    if expected is not None and value != expected:
        fail(f"{label}.{field}={value!r}, expected {expected!r}")
    return value


def require_true(parent: dict[str, Any], field: str, label: str) -> None:
    if parent.get(field) is not True:
        fail(f"{label}.{field} must be true")


def require_hex(value: str, pattern: re.Pattern[str], label: str) -> str:
    if pattern.fullmatch(value) is None:
        fail(f"{label} must be full-length lowercase hexadecimal")
    return value


def regular_file(path: pathlib.Path, label: str, *, executable: bool = False) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect {label} {path}: {error}")
    if not stat.S_ISREG(mode) or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable: {path}")


def regular_directory(path: pathlib.Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect {label} {path}: {error}")
    if not stat.S_ISDIR(mode) or path.is_symlink():
        fail(f"{label} must be a non-symlink directory: {path}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash {path}: {error}")
    return digest.hexdigest()


def run_checked(
    argv: list[str],
    *,
    cwd: pathlib.Path,
    label: str,
    timeout_seconds: int = 300,
) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"{label} could not complete: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        fail(f"{label} failed with exit {completed.returncode}{suffix}")
    return completed.stdout.strip()


def git_output(repo: pathlib.Path, *args: str) -> str:
    return run_checked(["git", "-C", str(repo), *args], cwd=repo, label="Git inspection")


def check_repo(repo: pathlib.Path, expected_commit: str, expected_schema: str) -> None:
    regular_directory(repo, "repository root")
    top = pathlib.Path(git_output(repo, "rev-parse", "--show-toplevel")).resolve()
    if top != repo:
        fail(f"repository root {repo} resolves to different Git top-level {top}")
    head = git_output(repo, "rev-parse", "HEAD")
    if head != expected_commit:
        fail(f"repository HEAD {head!r} does not match expected commit {expected_commit!r}")
    status = git_output(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        fail("repository worktree is dirty")

    migrations = repo / "migrations"
    if not migrations.is_dir() or migrations.is_symlink():
        fail("repository migrations directory is missing or is a symlink")
    markers = sorted(
        path.stem
        for path in migrations.iterdir()
        if path.is_file() and not path.is_symlink() and path.suffix == ".sql"
    )
    if not markers:
        fail("repository has no SQL migrations")
    if markers[-1] != expected_schema:
        fail(
            f"repository latest schema marker {markers[-1]!r} does not match "
            f"expected {expected_schema!r}"
        )


def hash_content_tree(repo: pathlib.Path, pwa_dir: pathlib.Path) -> str:
    regular_directory(pwa_dir, "PWA content root")
    helper = repo / "scripts" / "content-sha256.py"
    regular_file(helper, "content digest helper", executable=True)
    digest = run_checked(
        [str(helper), str(pwa_dir)],
        cwd=repo,
        label="PWA content digest verification",
    )
    return require_hex(digest, SHA256_RE, "PWA content digest output")


def verify_release_record(
    repo: pathlib.Path,
    release_record: pathlib.Path,
    binary: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    verifier = repo / "scripts" / "verify-release-record.sh"
    regular_file(verifier, "release verifier", executable=True)
    regular_file(release_record, "release record")
    regular_file(binary, "release binary", executable=True)
    original_bytes = release_record.read_bytes()
    strict_json(original_bytes, "operator release record")
    original_digest = hashlib.sha256(original_bytes).hexdigest()

    with tempfile.TemporaryDirectory(prefix="bullnym-certification-") as directory:
        copied_record = pathlib.Path(directory) / "release.json"
        shutil.copyfile(release_record, copied_record)
        run_checked(
            [str(verifier), str(copied_record), str(binary), str(repo)],
            cwd=repo,
            label="repository release-record verifier",
        )
        verified = strict_json(copied_record.read_bytes(), "verified release record")

    if sha256_file(release_record) != original_digest:
        fail("release verifier mutated the operator-supplied release record")
    return verified, original_digest


def check_release_fields(
    record: dict[str, Any],
    *,
    expected_commit: str,
    expected_artifact: str,
    expected_pwa: str,
    expected_schema: str,
) -> str:
    build = require_object(record, "build", "release record")
    require_string(build, "service", "release record.build", expected="pay-service")
    require_string(build, "build_commit", "release record.build", expected=expected_commit)
    require_string(build, "build_profile", "release record.build", expected="release")
    require_string(build, "build_source_state", "release record.build", expected="clean")
    require_string(
        build,
        "boltz_client_repository",
        "release record.build",
        expected="https://github.com/BullishNode/boltz-rust.git",
    )
    boltz_commit = require_string(build, "boltz_client_commit", "release record.build")
    require_hex(boltz_commit, SHA1_RE, "release record.build.boltz_client_commit")
    require_string(
        build,
        "boltz_client_verification",
        "release record.build",
        expected="wrapper-built",
    )
    require_string(
        build, "pwa_content_sha256", "release record.build", expected=expected_pwa
    )
    require_string(
        build, "expected_schema_marker", "release record.build", expected=expected_schema
    )
    crate_version = require_string(build, "crate_version", "release record.build")
    for field in ("rustc_version", "cargo_version", "build_target"):
        require_string(build, field, "release record.build")

    require_string(record, "artifact_sha256", "release record", expected=expected_artifact)
    artifact_name = require_string(record, "artifact_name", "release record")
    if pathlib.PurePath(artifact_name).name != artifact_name:
        fail("release record.artifact_name must be a basename")

    verification = require_object(record, "verification", "release record")
    require_string(verification, "status", "release record.verification", expected="verified")
    require_string(
        verification,
        "method",
        "release record.verification",
        expected="bullnym-release-v1",
    )
    require_string(
        verification,
        "artifact_sha256",
        "release record.verification",
        expected=expected_artifact,
    )
    require_string(
        verification,
        "bullnym_commit",
        "release record.verification",
        expected=expected_commit,
    )
    require_string(
        verification,
        "boltz_client_commit",
        "release record.verification",
        expected=boltz_commit,
    )
    return crate_version


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def normalize_base_url(value: str, allow_loopback_http: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        fail("base URL must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        fail("base URL must be an origin without path, query, or fragment")
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        fail("base URL must be an absolute HTTP(S) origin")
    try:
        parsed.port
    except ValueError as error:
        fail(f"base URL has an invalid port: {error}")
    if parsed.scheme == "http":
        loopback = False
        if parsed.hostname == "localhost":
            loopback = True
        else:
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = False
        if not allow_loopback_http or not loopback:
            fail("plain HTTP is allowed only for loopback fixtures with --allow-loopback-http")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


class PublicProbe:
    def __init__(self, base_url: str, timeout_seconds: float) -> None:
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def get(self, path: str, *, json_response: bool) -> tuple[bytes, str]:
        url = f"{self.base_url}{path}"
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json" if json_response else "text/plain",
                "Cache-Control": "no-cache",
                "User-Agent": "bullnym-certification-preflight-v1",
            },
        )
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                status = response.status
                content_type = response.headers.get_content_type()
                body = response.read(MAX_HTTP_BODY_BYTES + 1)
        except urllib.error.HTTPError as error:
            fail(f"GET {path} returned HTTP {error.code}; redirects and failures are refused")
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            fail(f"GET {path} failed: {error}")
        if status != 200:
            fail(f"GET {path} returned HTTP {status}, expected 200")
        if len(body) > MAX_HTTP_BODY_BYTES:
            fail(f"GET {path} response exceeds {MAX_HTTP_BODY_BYTES} bytes")
        if json_response and content_type != "application/json":
            fail(f"GET {path} content type {content_type!r} is not application/json")
        return body, content_type


def check_version(
    value: dict[str, Any],
    *,
    expected_commit: str,
    expected_crate_version: str,
    expected_schema: str,
    expected_runtime_mode: str,
) -> dict[str, str]:
    label = "remote /version"
    require_string(value, "service", label, expected="pay-service")
    require_string(value, "crate_version", label, expected=expected_crate_version)
    require_string(value, "build_commit", label, expected=expected_commit)
    require_string(value, "build_dirty", label, expected="false")
    require_string(value, "runtime_mode", label, expected=expected_runtime_mode)
    require_string(value, "expected_schema_marker", label, expected=expected_schema)
    require_string(
        value,
        "public_name_policy",
        label,
        expected=CURRENT_PUBLIC_NAME_POLICY,
    )
    # Branch and time are informational rather than identity authorities. They
    # may be "unknown" in current release builds, so the exact commit remains
    # the fail-closed deployment identity.
    return {
        field: value[field]
        for field in (
            "service",
            "crate_version",
            "build_commit",
            "build_dirty",
            "runtime_mode",
            "expected_schema_marker",
            "public_name_policy",
        )
    }


def check_ready(value: dict[str, Any], expected_schema: str) -> None:
    label = "remote /ready"
    require_string(value, "service", label, expected="pay-service")
    require_true(value, "ready", label)
    require_string(value, "expected_schema_marker", label, expected=expected_schema)
    for field in ("database", "schema"):
        component = require_object(value, field, label)
        require_true(component, "ok", f"{label}.{field}")
        if "detail" in component and component["detail"] is not None:
            fail(f"{label}.{field}.detail is unexpected while the component is healthy")


def write_report(path: pathlib.Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to overwrite certification report: {path}")
    if not path.parent.is_dir() or path.parent.is_symlink():
        fail(
            "certification report parent must be an existing non-symlink directory: "
            f"{path.parent}"
        )
    created = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        fail(f"could not write certification report {path}: {error}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    default_repo = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Verify an exact Bullnym release and read-only remote readiness facts."
    )
    parser.add_argument("--repo-root", type=pathlib.Path, default=default_repo)
    parser.add_argument("--release-record", type=pathlib.Path, required=True)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--pwa-dir", type=pathlib.Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--expected-pwa-sha256", required=True)
    parser.add_argument("--expected-schema-marker", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help="allow HTTP only when the origin hostname is loopback (fixture use)",
    )
    parser.add_argument(
        "--write-report",
        type=pathlib.Path,
        help="persist the otherwise stdout-only JSON report",
    )
    parser.add_argument(
        "--allow-report-write",
        action="store_true",
        help="explicitly authorize creating --write-report (never overwrites)",
    )
    return parser.parse_args(argv)


def certify(args: argparse.Namespace) -> dict[str, Any]:
    expected_commit = require_hex(args.expected_commit, SHA1_RE, "expected commit")
    expected_artifact = require_hex(
        args.expected_artifact_sha256, SHA256_RE, "expected artifact SHA-256"
    )
    expected_pwa = require_hex(args.expected_pwa_sha256, SHA256_RE, "expected PWA SHA-256")
    expected_schema = args.expected_schema_marker
    if SCHEMA_MARKER_RE.fullmatch(expected_schema) is None:
        fail("expected schema marker must have the form NNN_lowercase_name")
    if not (0.1 <= args.timeout_seconds <= 30.0):
        fail("timeout seconds must be between 0.1 and 30")
    if args.allow_report_write and args.write_report is None:
        fail("--allow-report-write requires --write-report")
    if args.write_report is not None and not args.allow_report_write:
        fail("--write-report is a mutation and requires --allow-report-write")

    repo = args.repo_root.absolute()
    release_record = args.release_record.absolute()
    binary = args.binary.absolute()
    pwa_dir = args.pwa_dir.absolute()
    base_url = normalize_base_url(args.base_url, args.allow_loopback_http)

    check_repo(repo, expected_commit, expected_schema)
    verified_record, original_record_digest = verify_release_record(repo, release_record, binary)
    expected_crate_version = check_release_fields(
        verified_record,
        expected_commit=expected_commit,
        expected_artifact=expected_artifact,
        expected_pwa=expected_pwa,
        expected_schema=expected_schema,
    )
    if sha256_file(binary) != expected_artifact:
        fail("release binary bytes do not match expected artifact SHA-256")
    if hash_content_tree(repo, pwa_dir) != expected_pwa:
        fail("PWA content does not match expected SHA-256")

    probe = PublicProbe(base_url, args.timeout_seconds)
    version_before = check_version(
        strict_json(probe.get("/version", json_response=True)[0], "remote /version"),
        expected_commit=expected_commit,
        expected_crate_version=expected_crate_version,
        expected_schema=expected_schema,
        expected_runtime_mode=CURRENT_RUNTIME_MODE,
    )
    health, _ = probe.get("/health", json_response=False)
    try:
        health_text = health.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"remote /health is not UTF-8: {error}")
    if health_text != "ok":
        fail(f"remote /health body is {health_text!r}, expected exact 'ok'")
    check_ready(
        strict_json(probe.get("/ready", json_response=True)[0], "remote /ready"),
        expected_schema,
    )
    version_after = check_version(
        strict_json(probe.get("/version", json_response=True)[0], "remote /version"),
        expected_commit=expected_commit,
        expected_crate_version=expected_crate_version,
        expected_schema=expected_schema,
        expected_runtime_mode=CURRENT_RUNTIME_MODE,
    )
    if version_after != version_before:
        fail("remote /version changed while the certification probes ran")

    # Bracket network probing with the same immutable local facts. This catches
    # a checkout, record, binary, or PWA change during the certification run.
    check_repo(repo, expected_commit, expected_schema)
    if sha256_file(release_record) != original_record_digest:
        fail("release record changed while certification probes ran")
    if sha256_file(binary) != expected_artifact:
        fail("release binary changed while certification probes ran")
    if hash_content_tree(repo, pwa_dir) != expected_pwa:
        fail("PWA content changed while certification probes ran")

    return {
        "format": "bullnym-deployment-certification-v1",
        "status": "passed",
        "mode": "read_only",
        "provider_calls": 0,
        "funds_moved": 0,
        "durable_report_write_authorized": args.write_report is not None,
        "remote_origin": base_url,
        "server_commit": expected_commit,
        "crate_version": expected_crate_version,
        "release_artifact_sha256": expected_artifact,
        "pwa_content_sha256": expected_pwa,
        "schema_marker": expected_schema,
        "runtime_mode": CURRENT_RUNTIME_MODE,
        "public_name_policy": CURRENT_PUBLIC_NAME_POLICY,
        "remote_gets": ["/version", "/health", "/ready", "/version"],
        "local_release_verification": "bullnym-release-v1",
    }


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        report = certify(args)
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if args.write_report is not None:
            write_report(args.write_report.absolute(), payload)
        sys.stdout.buffer.write(payload)
        return 0
    except CertificationError as error:
        print(f"deployment certification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
