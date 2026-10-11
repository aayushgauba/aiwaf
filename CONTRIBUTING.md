# Contributing to AIWAF

AIWAF is a monorepo containing independently published Python, JavaScript, Rust, WebAssembly, and Java packages.

## Licensing

New contributions to ELv2-covered code are submitted under the Elastic License 2.0 in LICENSE unless another applicable license is explicitly documented and accepted. Contributors retain their copyrights; submission is not a copyright assignment. Identify third-party material and preserve its license and attribution. Existing MIT contributions and the IPinfo Lite database retain the terms in NOTICE. Release artifacts must include LICENSE, NOTICE, and licenses/. Do not replace previously published MIT artifacts with differently licensed copies at the same version.

## Repository layout

- `py/aiwaf/`: Python package source (imported as `aiwaf`)
- `js/`: JavaScript package source (published as `aiwaf`)
- `rust/`: Rust accelerator and WebAssembly source
- `java/`: Java 17 package source
- `tests/`: Python tests
- `examples/`: focused Python examples
- `.github/workflows/`: package-specific CI and publishing

## Python development

Create a virtual environment and install the package with its framework adapters:

```bash
python -m venv .venv
python -m pip install -e ".[django,flask,fastapi]"
python -m pip install pytest httpx
```

Run every Python and JavaScript test group from the repository root:

```bash
python aiwaf_test.py
```

Use `--python-only` or `--js-only` for one language. The runner keeps Django in a separate process so its global application state does not leak into the other Python adapters.

Run coverage with callable-level auditing, or run the native adapter contracts
independently:

```bash
python aiwaf_test.py --coverage
python aiwaf_test.py --rust-only
python aiwaf_test.py --wasm-only
```

`--strict-function-coverage` is the 100% Python callable target. The normal
coverage job enforces the current Python callable ratchet and JavaScript
statement, branch, function, and line thresholds so coverage cannot regress as
the remaining coverage debt is closed.

Test modules mirror production module names. For example,
`py/aiwaf/core/anomaly.py` is tested by `tests/core/test_anomaly.py`, while
`js/lib/wasmAdapter.js` is tested by `js/test/wasmAdapter.test.js`. The
monorepo runner checks this mapping before running tests and rejects any new
source module that lacks its canonical test module.

Test modules follow their source module names and adapter directories. For
example, `py/aiwaf/core/anomaly.py` is owned by
`tests/core/test_anomaly.py`; `py/aiwaf/flask/storage.py` is owned by
`tests/flask/test_storage.py`; and `js/lib/wasmAdapter.js` is owned by a
normalized `js/test/wasm-adapter.test.js`. Additional integration and regression
files may supplement the canonical module test. The monorepo runner checks this
layout before executing tests.

Python package metadata lives in `pyproject.toml`. Keep the compatibility metadata in `setup.py` synchronized when changing dependencies or versions.

## JavaScript development

```bash
cd js
npm ci
npm test
npm pack --dry-run
```

From the repository root, the equivalent commands are `python aiwaf_test.py --js-only` and `npm run test:js`.

## Releases

- Push a `python-v*` tag to build and publish `aiwaf` to PyPI.
- Push a `js-v*` tag to test and publish `aiwaf` to npm.
- Push a `rust-v*` tag to build and publish `aiwaf-rust` to PyPI.
- Push a `wasm-v*` tag to build and stage `aiwaf-wasm` on npm.
- Push a `java-v*` tag to test and publish `aiwaf-java` to Maven Central.

The workflows can also be run manually. PyPI and npm use OIDC trusted publishing; the Java workflow uses the Maven Central and GPG secrets configured in its protected environment.
