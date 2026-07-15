# Deployment certification preflight

`scripts/certify-deployment.py` binds one clean Bullnym checkout, one verified
release record, one executable, one PWA content tree, and one serving origin to
operator-supplied exact identities. It is the read-only Phase 12 gate after a
release is built and again after it is installed. It does not build, deploy,
migrate, restart, contact Boltz or a fee/price backend, create payment
instructions, or move funds.

The operator must supply all four release authorities. The runner never infers
them from the candidate it is checking:

- the full lowercase Bullnym commit;
- the release artifact SHA-256;
- the framed PWA content SHA-256 produced by `scripts/content-sha256.py`;
- the exact schema marker expected for that release.

The schema value is intentionally a parameter. Do not edit this script merely
because the migration tip advances.

## Read-only invocation

Run from the exact clean checkout that produced the release. The paths may
name staged release files before deployment or the installed files during the
post-deployment gate.

```bash
scripts/certify-deployment.py \
  --repo-root /path/to/exact-clean-bullnym \
  --release-record /path/to/pay-service.release.json \
  --binary /path/to/pay-service \
  --pwa-dir /path/to/deployed-or-staged/pwa/dist \
  --base-url https://pay2.bull-wallet.com \
  --expected-commit "$EXPECTED_BULLNYM_COMMIT" \
  --expected-artifact-sha256 "$EXPECTED_ARTIFACT_SHA256" \
  --expected-pwa-sha256 "$EXPECTED_PWA_SHA256" \
  --expected-schema-marker "$EXPECTED_SCHEMA_MARKER"
```

Plain HTTP is refused. `--allow-loopback-http` exists only for a loopback mock
origin and cannot authorize HTTP to a non-loopback host.

The runner copies the release record to a private temporary directory before
calling `scripts/verify-release-record.sh`. That reuses the supported local
provenance verifier without changing the supplied record. It then checks the
actual executable bytes and PWA tree against the four explicit authorities.
The clean checkout, record, executable, and PWA facts are checked again after
the network probes so a concurrent local change fails the run.

The remote side is restricted to these bounded unauthenticated requests, in
this order:

1. `GET /version`;
2. `GET /health`;
3. `GET /ready`;
4. `GET /version` again.

Redirects, non-JSON component responses, duplicate JSON fields, oversized
bodies, an exact health body other than `ok`, and any mismatch fail closed.
Both version samples must agree. The current-only public contract requires an
exact clean commit, the supplied schema, `runtime_mode: production`, and
`public_name_policy: permanent_names_v1`. Readiness must report the database
and complete schema/journal boundary healthy.

`/ready` intentionally does not expose private per-rail admission or worker
reason codes. Use the deployment runbook's process-digest check and private
startup/worker/admission logs as separate evidence; this preflight does not
weaken or duplicate those gates. In particular, a passing public preflight is
not authority to bypass a closed money-admission fact.

## Output and mutation boundary

On success the command writes a deterministic JSON report to standard output.
The report explicitly records zero provider calls and zero funds moved. There
is no mutating HTTP, provider, wallet, payment, database, service, or deployment
mode.

Persisting a report is the runner's only supported mutation and requires an
explicit flag pair:

```bash
scripts/certify-deployment.py ... \
  --write-report /secure/evidence/certification.json \
  --allow-report-write
```

The destination parent must already exist. A report is created mode `0600` and
an existing path is never overwritten. Without both flags, the default remains
stdout-only and read-only.

Run the deterministic local fault suite with:

```bash
scripts/test-certify-deployment.py
```
