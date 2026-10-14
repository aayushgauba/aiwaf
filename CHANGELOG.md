# Changelog

## Python 1.1.8 / Rust-Python 0.2.7 / Node.js 1.1.5 / WASM 0.2.5 / Java 1.3.5 — prepared release

- Update package versions and matching native dependency requirements for the next release.
- Remove benchmark/profiling utilities and consolidate release documentation into README/CHANGELOG.
- Remove the deprecated Rust floating-point module import.
- Use blocklist/allowlist in Python, JavaScript, Rust/WASM, Java, CLI help and
  website documentation. Retain prior import, method and command aliases.
- Preserve existing CSV filenames, Django database/model identity, stored legacy
  reason tags and native wire compatibility. Accept older configuration exports
  without discarding blocks or exemptions.

## Python 1.1.7 / aiwaf-rust 0.2.6 — native honeypot cache

- Add opt-in Redis and supplied-cache honeypot timing to Flask and FastAPI's
  native pipelines. FastAPI runs cache-backed native checks in its worker thread
  pool. CSV remains the default in both adapters; other policies are unchanged.

- Default Django native honeypot timing to Django's configured cache, with an
  optional `honeypot_cache_alias`. Explicit CSV and native memory remain available.
- Delegate timestamp I/O to Django while Rust owns timing, TTL validation,
  exemptions, and block decisions. Other native policy stores retain CSV behavior.
- Return generic HTTP 503 for cache failures or invalid state. Reject DummyCache
  and configured ignored cache errors; warn when LocMemCache isolates workers.
- Leave expiry cleanup to cache TTL so a stale POST cannot delete a concurrent
  GET refresh. Until the next GET or cache expiry, repeated expired-page POSTs
  continue to return 409. Existing timestamps are not migrated between backends.

## Node.js 1.1.4 / Java 1.3.4 — blocklist expiry concurrency fixes

- Make Node blocklist request checks read-only. Database cleanup deletes only
  rows still expired when the delete executes; CSV cleanup checks the latest
  rows under the same cross-process lock used by blocklist writes.
- Reload Java CSV and file storage under a shared JVM and OS file lock for each
  operation. Listing filters expiry without rewriting disk; mutations preserve
  updates from other instances and processes and report persistence failures.
- Verify refreshed blocks survive cleanup and concurrent writers retain all
  unrelated blocks. These fixes are separate from offline training replay.

## Python 1.1.6 / aiwaf-rust 0.2.5 — training replay protection

- Make Flask CLI blocklist listing read-only. Expiry filtering no longer writes
  an older snapshot over blocks concurrently added or refreshed by a trainer.
- Display the canonical block date in CLI output instead of reporting Unknown
  when CSV entries use `added_date` rather than the old `timestamp` field.

- Persist Rust-owned enforcement receipts independently of blocklist expiry and
  manual unblocking. Reusing handled requests cannot extend or recreate a block.
- Apply 404 thresholds and anomaly enforcement to fresh evidence in Flask,
  FastAPI, and Django, while retaining full history for model fitting and learning.
- Serialize trainers with a cross-process file lock and atomically persist
  SHA-256 receipts. Preserve receipts across log rotation and application restarts.
- Require the matching native package; missing capabilities and corrupt receipt
  state fail visibly instead of silently allowing replay.

## Node.js dependency security updates

- Node.js 1.1.4 / WASM 0.2.4 share Rust-owned offline enforcement receipts with
  Python. Historical requests cannot extend or recreate handled blocks; fresh
  404 and anomaly evidence must independently satisfy enforcement thresholds.
- Persist Node receipts across restarts and serialize offline trainers. Report
  missing native APIs, invalid state, and storage failures with a CLI failure.
- Keep Java model training free of blocklist side effects, verified by a new
  runtime-state regression test. File storage concurrency is fixed separately.

- Upgrade Jest, Fastify, and the NestJS test dependencies to patched releases.
- Replace the direct deprecated glob 8 dependency with maintained glob 13.
- Remove broad transitive overrides that forced incompatible parser versions;
  apply targeted fixes for qs and the NYC loader's YAML dependency instead.
- Audit development dependencies as well as production dependencies in npm
  release validation.

## Python 1.1.4 

- Detect the single installed framework for bare CLI commands; require an
  explicit choice when detection is ambiguous. Add the `fastapi` CLI alias.
- Reuse existing project and user CSV directories in the Flask management CLI.
- Standardize framework CSV initialization on shared policy files. Import
  legacy runtime CSV data at startup, preserving expiry times and metadata,
  retaining original sources and backups, and preventing migration replay.
- Preserve keyword frequencies and runtime history in auxiliary metadata.
- Use UTF-8 for Python fallback CSV I/O to match Rust reads and writes.
- Retain `aiwaf-rust>=0.2.3`; no new native API is required for these changes.

## Next releases — ELv2 migration

- Python and Node.js 1.1.2, Rust/Python and WASM 0.2.2, and Java 1.3.3 adopt
  standard Elastic License 2.0 for original project code, with retained MIT
  contributions and separately licensed IPinfo Lite data identified in NOTICE.
- Preserve the earlier MIT permissions and notices; do not retroactively
  replace licenses on previously distributed releases.
- Include LICENSE, NOTICE, and licenses/ in release packaging, and align
  package license metadata and WASM generation with the new terms.
- Synchronize the Python runtime version with its package metadata. The
  internal Rust core crate advances to 0.2.1.

See the [README license section](README.md#license) for version boundaries
and the release automation section for validation requirements.

## Java 1.3.0

- Hardened Redis operation with fail-open/fail-closed policies, bounded
  connection and pool waits, latency/pool diagnostics, non-blocking key scans,
  and state-schema compatibility guards for rolling upgrades. Java 1.3
  explicitly supports standalone Redis and rejects Sentinel/Cluster modes.

## Java 1.2.0

- Added scoped per-engine storage contexts and a Redis backend with atomic,
  distributed rate-limit, honeypot, UUID-score, and anomaly-history state.
- Aligned path, IP, geo-only, and route-level logging exemption behavior with
  Python.
- Added Python-style JSON configuration loading, environment overrides, deep
  merge, validation, saving, and broader Spring property coverage.
- Aligned Java defaults for private-IP exemptions and anomaly detection with
  Python.
- Added Spring Boot servlet auto-configuration with live MVC route, annotation,
  and JPA UUID-field discovery.
- Load generated path manifests at runtime while preserving explicit path-rule
  precedence.
- Replaced the external `mmdblookup` process with the native Java MaxMind DB
  reader and bounded country caching.
- Added Python-compatible reputation weights, metadata, and progressive
  15-minute, 1-hour, and 24-hour default blocks; explicit permanent blocking
  remains available.
- Added Spring property and environment configuration for the new runtime
  behavior.

## 1.0.8

- Require `aiwaf-rust>=0.2.1` for the optional Rust extra.
- Normalize HTTP headers before Rust validation so valid FastAPI requests are not blocked.
- Skip the Rust header validator when FastAPI's Rust path is disabled.

## 1.0.7

- Added reputation-based IP blocking with weighted offenses, progressive
  temporary blocks, expiration handling, and richer stored metadata.
- Added automatic legacy blocklist compatibility and backend-aware migration
  commands for Django, Flask, and FastAPI.
- Added legacy CSV schema detection and safe conversion of imported permanent
  blocks.
- Added request payload-field inference to generated path manifests.
- Enabled installed `aiwaf_rust` capabilities automatically, with Python
  fallback when the extension or a specific capability is unavailable.
