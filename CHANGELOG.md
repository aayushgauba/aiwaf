# Changelog

## Node.js dependency security updates

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

See [release notes](docs/releases/2026-10-elv2.md) for version boundaries and
release validation. These candidates have not been published.

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
- Added automatic legacy blacklist compatibility and backend-aware migration
  commands for Django, Flask, and FastAPI.
- Added legacy CSV schema detection and safe conversion of imported permanent
  blocks.
- Added request payload-field inference to generated path manifests.
- Enabled installed `aiwaf_rust` capabilities automatically, with Python
  fallback when the extension or a specific capability is unavailable.
