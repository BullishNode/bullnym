#!/usr/bin/env python3
"""Deterministic fault tests for certify-deployment.py."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from typing import Any


SOURCE_ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNNER = SOURCE_ROOT / "scripts" / "certify-deployment.py"
CONTENT_HASHER = SOURCE_ROOT / "scripts" / "content-sha256.py"
SCHEMA = "123_certification_fixture"
BOLTZ_COMMIT = "b" * 40


class ProbeState:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.redirect_path: str | None = None
        self.raw_responses: dict[str, tuple[int, str, bytes]] = {}
        self.version: dict[str, Any] = {}
        self.ready: dict[str, Any] = {}


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    server: "ProbeServer"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        self.server.state.requests.append(
            (self.command, self.path, {key.lower(): value for key, value in self.headers.items()})
        )
        if self.server.state.redirect_path == self.path:
            self.send_response(302)
            self.send_header("Location", "/health")
            self.end_headers()
            return

        raw = self.server.state.raw_responses.get(self.path)
        if raw is not None:
            status, content_type, body = raw
        elif self.path == "/version":
            status = 200
            content_type = "application/json"
            body = json.dumps(self.server.state.version, sort_keys=True).encode()
        elif self.path == "/ready":
            status = 200
            content_type = "application/json"
            body = json.dumps(self.server.state.ready, sort_keys=True).encode()
        elif self.path == "/health":
            status = 200
            content_type = "text/plain; charset=utf-8"
            body = b"ok"
        else:
            status = 404
            content_type = "text/plain"
            body = b"not found"

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class ProbeServer(http.server.ThreadingHTTPServer):
    def __init__(self, state: ProbeState) -> None:
        super().__init__(("127.0.0.1", 0), ProbeHandler)
        self.state = state


class CertificationFixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.repo = root / "repo"
        self.artifacts = root / "artifacts"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "migrations").mkdir()
        self.artifacts.mkdir()

        shutil.copy2(CONTENT_HASHER, self.repo / "scripts" / "content-sha256.py")
        verifier = self.repo / "scripts" / "verify-release-record.sh"
        verifier.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
record=$1
binary=$2
repo=$3
python3 - "$record" "$binary" "$repo" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

record_path = pathlib.Path(sys.argv[1])
binary = pathlib.Path(sys.argv[2])
repo = pathlib.Path(sys.argv[3])
document = json.loads(record_path.read_text())
head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
if document.get("artifact_name") != binary.name:
    raise SystemExit("fixture verifier: artifact name mismatch")
if document.get("artifact_sha256") != digest:
    raise SystemExit("fixture verifier: artifact digest mismatch")
build = document.get("build", {})
if build.get("build_commit") != head:
    raise SystemExit("fixture verifier: commit mismatch")
document["verification"] = {
    "status": "verified",
    "method": "bullnym-release-v1",
    "artifact_sha256": digest,
    "bullnym_commit": head,
    "boltz_client_commit": build.get("boltz_client_commit"),
}
record_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\\n")
PY
"""
        )
        verifier.chmod(0o755)
        (self.repo / "migrations" / f"{SCHEMA}.sql").write_text("SELECT 1;\n")

        subprocess.run(["git", "init", "--quiet", self.repo], check=True)
        subprocess.run(
            ["git", "-C", self.repo, "config", "user.email", "fixture@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self.repo, "config", "user.name", "Certification Fixture"],
            check=True,
        )
        subprocess.run(["git", "-C", self.repo, "add", "."], check=True)
        subprocess.run(
            ["git", "-C", self.repo, "commit", "--quiet", "-m", "fixture"], check=True
        )
        self.commit = subprocess.check_output(
            ["git", "-C", self.repo, "rev-parse", "HEAD"], text=True
        ).strip()

        self.binary = self.artifacts / "pay-service"
        self.binary.write_bytes(b"#!/usr/bin/env bash\nexit 0\n")
        self.binary.chmod(0o755)
        self.artifact_digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

        self.pwa = self.artifacts / "pwa"
        self.pwa.mkdir()
        self.pwa.chmod(0o755)
        (self.pwa / "index.html").write_text("<p>certification fixture</p>\n")
        (self.pwa / "index.html").chmod(0o644)
        self.pwa_digest = subprocess.check_output(
            [CONTENT_HASHER, self.pwa], text=True
        ).strip()

        self.record = self.artifacts / "release.json"
        self.document = {
            "artifact_name": self.binary.name,
            "artifact_sha256": self.artifact_digest,
            "build": {
                "service": "pay-service",
                "crate_version": "1.0.0",
                "build_commit": self.commit,
                "build_profile": "release",
                "build_source_state": "clean",
                "boltz_client_repository": "https://github.com/BullishNode/boltz-rust.git",
                "boltz_client_commit": BOLTZ_COMMIT,
                "boltz_client_verification": "wrapper-built",
                "pwa_content_sha256": self.pwa_digest,
                "expected_schema_marker": SCHEMA,
                "rustc_version": "rustc 1.92.0",
                "cargo_version": "cargo 1.92.0",
                "build_target": "x86_64-unknown-linux-gnu",
            },
            "verification": {"status": "pending"},
        }
        self.write_document()

    def write_document(self) -> None:
        self.record.write_text(json.dumps(self.document, indent=2, sort_keys=True) + "\n")


class CertifyDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bullnym-certify-test-")
        self.fixture = CertificationFixture(pathlib.Path(self.temporary.name))
        self.state = ProbeState()
        self.state.version = {
            "service": "pay-service",
            "crate_version": "1.0.0",
            "build_commit": self.fixture.commit,
            "build_branch": "unknown",
            "build_time": "unknown",
            "build_dirty": "false",
            "runtime_mode": "production",
            "expected_schema_marker": SCHEMA,
            "public_name_policy": "permanent_names_v1",
        }
        self.state.ready = {
            "service": "pay-service",
            "ready": True,
            "expected_schema_marker": SCHEMA,
            "database": {"ok": True},
            "schema": {"ok": True},
        }
        self.server = ProbeServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def command(self, *extra: str) -> list[str]:
        return [
            str(RUNNER),
            "--repo-root",
            str(self.fixture.repo),
            "--release-record",
            str(self.fixture.record),
            "--binary",
            str(self.fixture.binary),
            "--pwa-dir",
            str(self.fixture.pwa),
            "--base-url",
            self.base_url,
            "--expected-commit",
            self.fixture.commit,
            "--expected-artifact-sha256",
            self.fixture.artifact_digest,
            "--expected-pwa-sha256",
            self.fixture.pwa_digest,
            "--expected-schema-marker",
            SCHEMA,
            "--allow-loopback-http",
            *extra,
        ]

    def run_certification(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(*extra),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def assert_failed(self, result: subprocess.CompletedProcess[str], term: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("deployment certification failed:", result.stderr)
        self.assertIn(term, result.stderr)

    def test_success_is_read_only_and_uses_only_bounded_public_gets(self) -> None:
        before_record = self.fixture.record.read_bytes()
        before_status = subprocess.check_output(
            ["git", "-C", self.fixture.repo, "status", "--porcelain=v1"], text=True
        )

        result = self.run_certification()

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["mode"], "read_only")
        self.assertEqual(report["provider_calls"], 0)
        self.assertEqual(report["funds_moved"], 0)
        self.assertEqual(self.fixture.record.read_bytes(), before_record)
        self.assertEqual(
            subprocess.check_output(
                ["git", "-C", self.fixture.repo, "status", "--porcelain=v1"],
                text=True,
            ),
            before_status,
        )
        self.assertEqual(
            [(method, path) for method, path, _ in self.state.requests],
            [
                ("GET", "/version"),
                ("GET", "/health"),
                ("GET", "/ready"),
                ("GET", "/version"),
            ],
        )
        for _, _, headers in self.state.requests:
            self.assertNotIn("authorization", headers)
            self.assertNotIn("cookie", headers)

    def test_remote_mismatch_and_unknown_facts_fail_closed(self) -> None:
        cases = [
            ("crate", self.state.version, "crate_version", "unknown", "crate_version"),
            ("commit", self.state.version, "build_commit", "c" * 40, "build_commit"),
            ("dirty", self.state.version, "build_dirty", "unknown", "build_dirty"),
            ("runtime", self.state.version, "runtime_mode", "unknown", "runtime_mode"),
            (
                "name policy",
                self.state.version,
                "public_name_policy",
                "mutable_names_v0",
                "public_name_policy",
            ),
            ("ready", self.state.ready, "ready", False, "ready must be true"),
            (
                "database",
                self.state.ready["database"],
                "ok",
                False,
                "database.ok must be true",
            ),
            (
                "schema marker",
                self.state.ready,
                "expected_schema_marker",
                "122_old",
                "expected_schema_marker",
            ),
        ]
        for label, mapping, field, replacement, expected_error in cases:
            with self.subTest(label=label):
                original = mapping[field]
                mapping[field] = replacement
                self.state.requests.clear()
                result = self.run_certification()
                self.assert_failed(result, expected_error)
                mapping[field] = original

    def test_malformed_duplicate_and_redirected_remote_evidence_is_refused(self) -> None:
        cases = [
            (
                "malformed",
                (200, "application/json", b"{not-json}"),
                "not valid UTF-8 JSON",
            ),
            (
                "duplicate",
                (200, "application/json", b'{"service":"pay-service","service":"other"}'),
                "duplicate JSON field",
            ),
            (
                "wrong content type",
                (200, "text/html", json.dumps(self.state.version).encode()),
                "content type",
            ),
        ]
        for label, response, expected_error in cases:
            with self.subTest(label=label):
                self.state.raw_responses["/version"] = response
                result = self.run_certification()
                self.assert_failed(result, expected_error)
                self.state.raw_responses.clear()

        self.state.redirect_path = "/version"
        result = self.run_certification()
        self.assert_failed(result, "redirects and failures are refused")

    def test_local_artifact_pwa_dirty_and_duplicate_record_evidence_is_refused(self) -> None:
        self.fixture.binary.write_bytes(self.fixture.binary.read_bytes() + b"# changed\n")
        result = self.run_certification()
        self.assert_failed(result, "release-record verifier")
        self.fixture.binary.write_bytes(b"#!/usr/bin/env bash\nexit 0\n")
        self.fixture.binary.chmod(0o755)

        (self.fixture.pwa / "index.html").write_text("changed\n")
        result = self.run_certification()
        self.assert_failed(result, "PWA content")
        (self.fixture.pwa / "index.html").write_text("<p>certification fixture</p>\n")

        (self.fixture.repo / "untracked").write_text("dirty\n")
        result = self.run_certification()
        self.assert_failed(result, "worktree is dirty")
        (self.fixture.repo / "untracked").unlink()

        document = json.dumps(self.fixture.document, sort_keys=True)
        duplicate = document[:-1] + ',"artifact_sha256":"' + self.fixture.artifact_digest + '"}'
        self.fixture.record.write_text(duplicate)
        result = self.run_certification()
        self.assert_failed(result, "duplicate JSON field")
        self.fixture.write_document()

    def test_pwa_permission_policy_rejects_deployment_regression(self) -> None:
        index = self.fixture.pwa / "index.html"
        index.chmod(0o600)
        result = self.run_certification()
        self.assert_failed(result, "mode 0600")
        self.assertIn("readable independently of its owner", result.stderr)

        index.chmod(0o644)
        self.fixture.pwa.chmod(0o700)
        result = self.run_certification()
        self.assert_failed(result, "mode 0700")
        self.assertIn("traversable independently of its owner", result.stderr)

        self.fixture.pwa.chmod(0o755)
        result = self.run_certification()
        self.assertEqual(result.returncode, 0, result.stderr)

        index.chmod(0o664)
        self.fixture.pwa.chmod(0o775)
        result = self.run_certification()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_http_is_fixture_only_and_report_writes_need_explicit_authority(self) -> None:
        command = self.command()
        url_index = command.index("--base-url") + 1
        command[url_index] = "http://example.com"
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)
        self.assert_failed(result, "plain HTTP is allowed only for loopback")

        report_path = pathlib.Path(self.temporary.name) / "certification.json"
        result = self.run_certification("--write-report", str(report_path))
        self.assert_failed(result, "requires --allow-report-write")
        self.assertFalse(report_path.exists())

        result = self.run_certification(
            "--write-report", str(report_path), "--allow-report-write"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(report_path.read_text()), json.loads(result.stdout))
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)

        result = self.run_certification(
            "--write-report", str(report_path), "--allow-report-write"
        )
        self.assert_failed(result, "refusing to overwrite")


if __name__ == "__main__":
    unittest.main(verbosity=2)
