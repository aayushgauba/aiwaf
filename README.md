# AIWAF

AIWAF is a multi-runtime web application firewall toolkit for Python, Node.js, WebAssembly, and Java applications. It combines deterministic request controls with route-aware policies, reputation tracking, request logging, training pipelines, and optional Isolation Forest anomaly detection.

This is the single authoritative README for the monorepo and every published AIWAF package. Release workflows stage this file, the root `LICENSE`, `NOTICE`, and `licenses/` into package artifacts when a registry requires package-local copies.

AIWAF is a defense-in-depth component. It does not replace secure application code, authentication and authorization, dependency patching, TLS, a reverse proxy, or a managed edge WAF.

## Packages

The next local drafts add bounded Java SQL inspection, a JavaScript `bodyParser`
helper, and atomic Python Redis rate buckets. They have not been published.

For custom Node HTTP servers or middleware registered before a framework's
parser, call `aiwaf.bodyParser()` before AIWAF and before forwarding requests.
It parses JSON and URL-encoded bodies, retains the original forwarding bytes,
and rejects oversized bodies (default 64 KiB). Native Fastify/Hapi integrations
must run AIWAF after body parsing and before their proxy handler.

Java SQL inspection defaults to `security.sql_injection_mode: "block"`;
`monitor` records findings without denying requests and `off` disables it.
`AIWAF_SQL_INJECTION_MODE` provides the environment override. Inspection uses
the configured body byte limit and rejects over-budget inspection with 413.
Previously learned benign keywords no longer block ordinary Java routes.

Redis rate-cache failures now produce generic HTTP 503 responses in JavaScript
and Python rate-limit middleware. JavaScript defaults to
`AIWAF_RATE_CACHE_FAILURE_MODE: 'closed'`; explicitly setting `'open'` preserves
availability at the cost of enforcement when the cache fails. Flask rejects
invalid Redis configuration at initialization, and FastAPI rejects requests
instead of silently selecting a process-local cache. Python `rediss://` URLs
are delegated to redis-py for TLS support when that driver is installed.

Python Flask/FastAPI Redis buckets now update atomically across workers.
Django's native `django.core.cache.backends.redis.RedisCache` uses Redis
transactions while preserving its existing serialized bucket values. Memory
and other custom cache backends serialize updates within one process; use
the supported Redis backends when sharing limits across workers.

Each package is versioned and released independently.

Python 1.1.8, Rust/Python 0.2.7, Node.js 1.1.5, WASM 0.2.5, and Java 1.3.5 are local source targets. See the package table below and [CHANGELOG](CHANGELOG.md) for release changes.

| Runtime | Package | Repository version | Primary use |
| --- | --- | ---: | --- |
| Python | [`aiwaf`](https://pypi.org/project/aiwaf/) | `1.1.8` | Django, Flask, and FastAPI protection |
| Node.js | [`aiwaf`](https://www.npmjs.com/package/aiwaf) | `1.1.5` | Express and Node framework middleware |
| Rust/Python | [`aiwaf-rust`](https://pypi.org/project/aiwaf-rust/) | `0.2.7` | Native Python acceleration and JSON model inference |
| WebAssembly | [`aiwaf-wasm`](https://www.npmjs.com/package/aiwaf-wasm) | `0.2.5` | Rust detection and model primitives for JavaScript |
| Java | `io.github.aiwaf-project:aiwaf-java` | `1.3.5` | Spring MVC and Jakarta Servlet protection |

Supported framework integrations include Django, Flask, FastAPI, Express, Fastify, Hapi, Koa, NestJS, Next.js API routes, AdonisJS, Sails.js, Spring MVC, and Jakarta Servlet.

## What AIWAF provides

- IP blocklist, exemption, reputation, expiry, and progressive-block handling
- Sliding-window rate limiting and flood detection
- Header, method, request-size, content-type, and parameter validation
- Static and learned malicious keyword detection
- Honeypot field and form-timing checks
- UUID probing and tamper detection
- GeoIP allow/block policies using the bundled MMDB data
- Route manifests, path-specific overrides, and decorator/annotation exemptions
- Memory, file, CSV, SQLite, database, and cache-backed runtime state, depending on the runtime
- Structured request logging and offline training
- Six-feature anomaly models with Rust, JavaScript, and Java implementations
- Required Rust runtime for Python 1.1.4 and optional WebAssembly acceleration for Node.js

The runtimes share policy intent and training feature names, but their framework adapters and model implementations remain language-native. Model artifacts are not generally interchangeable across languages.

## Repository layout

```text
.
├── py/aiwaf/                       Python package and adapters
├── js/                             Node.js package and adapters
├── rust/                           Rust core and Python bindings
│   └── crates/aiwaf_wasm/          WebAssembly bindings
├── java/                           Java 17 package
├── tests/                          Python integration and parity tests
├── examples/                       Focused Python examples
├── .github/workflows/              Tests, security checks, and releases
├── README.md                       Canonical project documentation
└── LICENSE                         Canonical Elastic License 2.0 (see NOTICE)
```

## Quick installation

Choose the package for the application runtime:

```bash
# Python core or a framework extra
pip install aiwaf
pip install "aiwaf[django]"
pip install "aiwaf[flask]"
pip install "aiwaf[fastapi]"

# Backward-compatible alias; Python 1.1.8 already installs aiwaf-rust
pip install "aiwaf[rust]"

# Node.js middleware
npm install aiwaf

# Standalone WebAssembly bindings
npm install aiwaf-wasm
```

Java 1.3.5, after it is published to Maven Central:

```xml
<dependency>
  <groupId>io.github.aiwaf-project</groupId>
  <artifactId>aiwaf-java</artifactId>
  <version>1.3.5</version>
</dependency>
```

## Python package

The Python package requires Python 3.10 or newer. Framework dependencies are optional, so install only the extra needed by the application.

Python 1.1.8 requires `aiwaf-rust>=0.2.7`; the `rust` extra remains an installation
alias. Publish the matching Rust wheel with `NativeCSVPipeline` support before
the Python release. The Rust release workflow builds Linux x86_64/aarch64,
musl x86_64, macOS x86_64/arm64 and Windows x86_64 wheels and checks the native
pipeline API. Windows and WSL builds are checked locally; the other wheel
targets must pass CI before publication.

### Rust-owned CSV pipeline

The complete CSV request pipeline is available through explicit adapters below.
Install it **instead of the existing eight-middleware chain**. The existing
`AIWAF` adapters remain available for compatibility with custom stores and hooks;
they do not switch automatically to this pipeline.

Rust owns the immutable configuration, enforcement order, SQL and keyword
inspection, geo and blocklist decisions, rate buckets, form timing state, UUID
scores, anomaly inference/history, keyword learning and CSV logging. Python
supplies framework routing/authentication facts, obtains GeoIP country data,
buffers a bounded body prefix and constructs responses. Each request crosses
into the engine once before the handler and once when its response is available.
The engine never calls Python policy callbacks or falls back to Python execution.
Missing native support, unsupported settings and invalid CSV schemas fail at
startup.

```python
# Flask
from flask import Flask
from aiwaf.flask import NativeAIWAF

app = Flask(__name__)
NativeAIWAF(app, config={"data_dir": "aiwaf_data"})
```

```python
# FastAPI / pure ASGI
from fastapi import FastAPI
from aiwaf.fast import NativeAIWAFMiddleware

app = FastAPI()
app.add_middleware(NativeAIWAFMiddleware, config={"data_dir": "aiwaf_data"})
```

```python
# Django settings: replace the existing AIWAF middleware entries
AIWAF_CSV_PIPELINE = {"data_dir": "aiwaf_data"}
MIDDLEWARE = [
    # Keep the application's other middleware in the required order.
    "aiwaf.django.csv_pipeline.NativeAIWAFMiddleware",
]
```

The configuration uses a dedicated lowercase profile; existing uppercase
framework settings, `AIWAFConfig` dictionaries, PATH_RULES, manifests, custom
stores and policy callbacks are not imported into it. Unknown keys are rejected.
Route decorators for full/partial exemptions and required middleware are read
once. Required decorators override decorator exemptions; profile-level path/IP
exemptions remain global. The profile is immutable: construct a new engine and
reload workers to change it.

Common profile keys and defaults:

| Setting | Default / meaning |
| --- | --- |
| `enabled` | All eight names: `geo_block`, `ip_keyword_block`, `rate_limit`, `ai_anomaly`, `honeypot`, `uuid_tamper`, `header_validation`, `logging` |
| `data_dir` | `aiwaf_data`; policy CSVs use the shared allowlist/blocklist/keyword/geo/path schemas |
| `exempt_paths`, `exempt_ips` | `/health`, `/robots.txt`, `/sitemap.xml`; empty IP list. Paths are literal, case-insensitive prefixes, not globs. Stored path exemptions use the same literal-prefix rule |
| `sql_mode`, `max_bytes` | `block`, `65536`; `off` supported, `monitor` rejected. Structured JSON/form bodies and nested escaped strings are inspected with bounded traversal |
| `learning`, `top_n` | `True`, `10`; presence keywords use a sorted, stable subset instead of Python set iteration order |
| `static_keywords`, `legitimate_keywords`, `exempt_keywords`, `safe_prefixes` | Native policy defaults or explicit arrays; set route-specific safe vocabulary in the profile |
| `geo_allow`, `geo_block` | Empty lists; includes stored blocked countries. Unknown country remains allowed |
| `rate_backend`, `rate_key_mode` | `memory`, `ip_path`; `csv` shares buckets across workers; `ip` aggregates paths. Redis is rejected |
| `rate_window`, `rate_max`, `rate_flood` | `10`, `20`, `40`; throttle at 429, flood at 403 with blocklist persistence |
| `soft_block_blocklist`, `ip_blocking`, `block_duration` | `False`, `True`, reputation-based duration; explicit seconds or nonpositive permanent duration |
| `honeypot_backend` | Django defaults to `django_cache`; Flask/FastAPI and direct construction default to `csv`. Optional `memory` is local to one engine; `redis` and `cache` delegate timestamp I/O while Rust enforces timing |
| `honeypot_cache_alias` | Django-only; `default`. Uses the named `CACHES` entry for honeypot timestamps, not other policy or rate state |
| `honeypot_redis_url` | Required for `honeypot_backend="redis"`; stripped before native profile serialization. `rediss://` requires redis-py |
| `honeypot_cache_namespace` | Redis/custom cache key prefix, default `aiwaf:native:honeypot:v1`; use the same value across workers and a distinct value for unrelated applications |
| `min_form_time`, `max_page_time`, `skip_authenticated` | `1.0`, `240`, `True`; native Rust applies the timing policy |
| `uuid_score_enabled`, `uuid_window`, `uuid_threshold` | `True`, `60`, `5`; weights: `uuid_malformed_weight=5`, `uuid_not_found_weight=1`, `uuid_success_decay=2` |
| `required_headers`, `header_min_score` | `HTTP_USER_AGENT` and `HTTP_ACCEPT`, `3`; empty required list disables required-header/quality checks, retains safety caps |
| `anomaly_window`, `anomaly_keywords` | `60`, standard anomaly vocabulary; history/scoring is held in Rust per worker |
| `log_path`, `log_fsync` | `data_dir/requests.csv`, `False`; immediate CSV append, optional per-row fsync |

Pass a trained `aiwaf_rust.IsolationForest` as `model=` to Flask/FastAPI, or
set `AIWAF_CSV_PIPELINE_MODEL` in Django. Without a model, the anomaly stage
maintains history and learns suspicious 404 keywords but performs no model-based
blocking. `pipeline.native.set_model(model)` replaces the model with an owned
snapshot; `set_model(None)` disables inference. Training and management APIs
remain available through the existing Python interface.

For deployments that accept per-worker form timing, set
`"honeypot_backend": "memory"` in the native profile. Rust then holds GET
timestamps in an expiring map and evaluates/clears POST timing atomically,
avoiding a durable CSV rewrite on each GET. Timing state is isolated per engine,
is not shared across workers and resets on restart. Backend switches do not
transfer timestamps automatically. Keep `csv` for shared or persistent timing;
CSV writes remain immediately synced. Blocklist, keyword, geo and allowlist
policy files and immediate request logging keep their configured CSV behavior.

### Flask and FastAPI native honeypot cache

Both native adapters accept Redis or a supplied synchronous cache. CSV remains
their default. This changes honeypot timestamp storage only; other policies and
rate-limit backends retain their configured behavior.

```python
import os
from aiwaf.flask.csv_pipeline import NativeAIWAF

profile = {
    "data_dir": "aiwaf_data",
    "honeypot_backend": "redis",
    "honeypot_redis_url": os.environ["AIWAF_REDIS_URL"],
    "honeypot_cache_namespace": "myapp:honeypot:v1",
}
NativeAIWAF(app, config=profile)  # Flask

# FastAPI alternative:
# from aiwaf.fast.csv_pipeline import NativeAIWAFMiddleware
# app.add_middleware(NativeAIWAFMiddleware, config=profile)
```

For an existing Flask-Caching instance or another compatible object, select
`honeypot_backend="cache"` and pass `honeypot_cache=cache` to either native adapter.
The contract is `get(key)` returning a stored value or `None`, and
`set(key, value, timeout=seconds)` returning success or `None`. Explicit `False`
means failure. Methods must be synchronous, preserve a timestamp/expiry pair,
honor TTL, and propagate storage errors. Disable any ignored-error option;
no-op cache backends are unsuitable. Custom adapters must translate their own
cache's TTL argument if it differs. A local cache still isolates workers.

Rust retains timing decisions, exemptions and logical expiry. Entries have a
300-second TTL; misses/evictions permit the POST timing check, while exceptions,
invalid records and failed writes return generic HTTP 503. Expired-page POSTs
return 409 until a new GET or TTL expiry, without deleting a concurrent refresh.
FastAPI offloads the cache-backed native request check to its worker thread pool
so synchronous network I/O does not block the event loop. Pool saturation and
cache latency still affect request latency. Existing CSV/memory timing behavior
and the legacy middleware chain are unchanged.

To exercise independent workers against a dedicated test Redis instance, set
`AIWAF_TEST_REDIS_URL` and run
`python -m pytest tests/integration/test_native_honeypot_cache.py`.

### Django native honeypot cache

Starting with Python 1.1.7 / aiwaf-rust 0.2.6, Django's native middleware uses
the existing Django cache for honeypot GET timestamps by default. Rust calls a
small Python storage adapter; form timing, logical expiry, exemptions and block
decisions remain native. Other policies retain their configured CSV storage.

```python
AIWAF_CSV_PIPELINE = {
    "data_dir": "aiwaf_data",
    "honeypot_cache_alias": "default",  # optional; uses CACHES["default"]
}
```

Use a shared Django cache backend for cross-worker timing. For example, Django's
built-in Redis cache can be configured as follows (install its Redis Python
driver and configure the URL for your deployment):

```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "KEY_PREFIX": "my-service",
    },
}
```

LocMemCache remains supported with a startup warning: it is worker-local and
resets on restart. DummyCache is rejected when the honeypot stage is enabled.
Configured ignored cache errors are rejected; runtime read/write failures,
failed writes and invalid timestamp records produce generic HTTP 503, without
silently selecting memory or CSV. Cache methods must be synchronous.

Timestamp entries use a 300-second TTL and bounded, hashed client-IP keys under
Django's key prefix/version. Expired-page POSTs return 409 until a fresh GET or
TTL expiry. The pipeline does not delete an expired snapshot, so it cannot erase
a concurrent GET refresh. As before, no timestamp means the timing check allows
the POST; cache outages are distinguished from misses. Backends can evict entries
before their TTL. Changing backends does not migrate existing timestamps.

Set `"honeypot_backend": "csv"` explicitly to retain shared filesystem timing,
or `"memory"` for the per-engine Rust map. Install the matching native extension
before upgrading Django workers. Flask and FastAPI defaults are unchanged.

Flask/FastAPI accept synchronous `country_lookup(ip)` and
`authenticated(request)` callbacks for adapter facts. Default GeoIP uses the
bundled lookup. Configure authentication explicitly in these adapters when
authenticated requests should bypass honeypot timing; Django reads user/session
state, so place it after authentication/session middleware. Django function views
have no standard method declaration and are accepted conservatively; class-based
views supply their declared method facts. Anomaly history stores route eligibility
as observed at arrival; historical requests are not re-resolved after routes change.

The ASGI adapter preserves streaming bodies and finalizes enforcement/logging at
response start. Logged response time measures time to response headers rather
than stream completion. WSGI adapters finalize when the framework response is
available. Session/route handlers, response construction, GeoIP lookup and legacy
custom integrations still execute in Python; the whole Python package has not
been rewritten in Rust.

### Flask

```python
from flask import Flask
from aiwaf.flask import AIWAF

app = Flask(__name__)
AIWAF(
    app,
    middlewares=["auto"],
)

@app.get("/")
def home():
    return {"protected": True}
```

`middlewares=["all"]` enables the canonical middleware set. `auto` starts from the same set and omits checks that are not useful for the detected application signals.

### FastAPI

```python
from fastapi import FastAPI
from aiwaf.fast import AIWAF

app = FastAPI()

AIWAF(
    app,
    middlewares=["auto"],
    storage={"backend": "memory"},
    header_validation={"enabled": True, "quality_threshold": 3},
    rate_limiting={"enabled": True, "window_seconds": 10, "max_requests": 20},
    logging_middleware={
        "enabled": True,
        "log_dir": "aiwaf_logs",
        "log_format": "json",
    },
)

@app.get("/")
async def home():
    return {"protected": True}
```

### Django

Add the app and the unified middleware alias in `settings.py`:

```python
INSTALLED_APPS = [
    # ...
    "aiwaf.django",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "aiwaf.django.middleware.all",
    # ...
]
```

For explicit ordering, replace the alias with the individual middleware classes:

```python
MIDDLEWARE = [
    "aiwaf.django.middleware.JsonExceptionMiddleware",
    "aiwaf.django.middleware.GeoBlockMiddleware",
    "aiwaf.django.middleware.IPAndKeywordBlockMiddleware",
    "aiwaf.django.middleware.RateLimitMiddleware",
    "aiwaf.django.middleware.AIAnomalyMiddleware",
    "aiwaf.django.middleware.HoneypotTimingMiddleware",
    "aiwaf.django.middleware.UUIDTamperMiddleware",
    "aiwaf.django.middleware.HeaderValidationMiddleware",
    "aiwaf.django.middleware_logger.AIWAFLoggerMiddleware",
]
```

Protection middleware should run early. Logging should run late enough to observe the application response.

### Route manifests

`aiwaf init` imports the live application and records all registered routes in `.aiwaf/paths.json`. The `--app` value must be `module:object`, not only a module name.

```bash
# Flask application object
aiwaf init --framework flask --app app:app

# Flask application factory
aiwaf init --framework flask --app app:create_app

# FastAPI
aiwaf init --framework fastapi --app app:app

# Django
aiwaf init --framework django --settings project.settings

# Custom output
aiwaf init --framework flask --app app:app --output .aiwaf/paths.json
```

Run the command in the same environment and checkout used to start the application. If it discovers only `/` and Flask's static route, verify the imported file and live route table:

```bash
python -c "import app; print(app.__file__); print(*sorted(r.rule for r in app.app.url_map.iter_rules()), sep='\n')"
```

### Python route exemptions

Django, Flask, and FastAPI expose equivalent route helpers:

```python
from aiwaf.flask import (
    aiwaf_exempt,
    aiwaf_exempt_from,
    aiwaf_only,
    aiwaf_require_protection,
)

@app.get("/health")
@aiwaf_exempt
def health():
    return {"ok": True}

@app.post("/webhook")
@aiwaf_only("header_validation")
def webhook():
    return {"accepted": True}
```

Canonical middleware names include `header_validation`, `rate_limit`, `ip_keyword_block`, `honeypot`, `geo_block`, `uuid_tamper`, `ai_anomaly`, and `logging`.

### Python configuration

Python adapters use flat `AIWAF_*` settings or their equivalent constructor options.

| Area | Important settings |
| --- | --- |
| Training | `AIWAF_ACCESS_LOG`, `AIWAF_MIN_TRAIN_LOGS`, `AIWAF_MIN_AI_LOGS`, `AIWAF_FORCE_AI_TRAINING` |
| Rate limiting | `AIWAF_RATE_WINDOW`, `AIWAF_RATE_MAX`, `AIWAF_RATE_FLOOD` |
| Headers | `AIWAF_REQUIRED_HEADERS`, `AIWAF_HEADER_QUALITY_MIN_SCORE` |
| Honeypot | `AIWAF_MIN_FORM_TIME`, `AIWAF_MAX_PAGE_TIME` |
| UUID checks | `AIWAF_UUID_SCORE_ENABLED`, `AIWAF_UUID_SCORE_BLOCK_THRESHOLD` |
| GeoIP | `AIWAF_GEO_BLOCK_ENABLED`, `AIWAF_GEO_BLOCK_COUNTRIES`, `AIWAF_GEO_ALLOW_COUNTRIES` |
| Exemptions | `AIWAF_EXEMPT_PATHS`, `AIWAF_EXEMPT_KEYWORDS`, `AIWAF_ALLOWED_PATH_KEYWORDS` |
| Models | `AIWAF_MODEL_PATH`, `AIWAF_MODEL_STORAGE`, `AIWAF_MODEL_STORAGE_FALLBACK` |

When `aiwaf_rust` is importable, supported acceleration paths are selected automatically. Python remains the fallback when a native capability is unavailable. Persisted runtime models use JSON state; AIWAF does not load pickle, joblib, or other executable Python-object formats.

### Rust-backed CSV runtime and training

The Python package and `aiwaf-rust` provide native CSV storage,
shared policy evaluation, and training preparation for Django, Flask, and FastAPI.
Install matching Python and Rust builds and reload application workers to activate
the new capabilities. Older extensions retain the compatible Python fallback.

- **CSV storage:** bounded snapshot caches and indexed IP/key lookups avoid repeated
  parsing and copying entire tables into Python. Native readers validate file
  metadata and use shared OS locks; mutations use exclusive locks. Blocklist
  reputation updates, keyword increments/removals, exemptions, audit entries, and
  geo-list changes use atomic transactions. Unchanged policy rows skip rewriting
  and disk synchronization. Changed policy writes still synchronize to disk.
- **Request policies:** native helpers handle keyword/probe decisions, ASCII SQL
  signatures, geo decisions, rate-window filtering, form timing, UUID format
  validation, reputation scoring, wildcard/CIDR exemptions, and longest-prefix
  route plans. Flask CSV keyword retrieval, evaluation, and learning share one
  native call. SQL checks and blocklist updates retain their existing order;
  custom evaluators and unsupported Unicode behavior use the Python adapter.
- **Exemption reuse:** Flask reuses CSV exemption results within a request and
  checks file identity, size, timestamps, and configuration before each reuse.
  Changes invalidate the result; decorator checks still execute. Set
  `AIWAF_CSV_REQUEST_CACHE=False` to disable this optimization.
- **Training ingestion:** plain and gzip CSV stream directly in bounded batches,
  including quoted fields and embedded newlines. Seconds and millisecond response
  fields are normalized. Apache logs use batched extraction and native timestamp
  parsing for supported English/C-locale forms. Unsupported dates/locales and
  Unicode keyword learning retain Python behavior. Route checks are reused for
  distinct paths, and learned keywords are persisted in batches.
- **Native model preparation:** `NativeTrainingBatch` keeps features and numeric
  matrices in Rust through Isolation Forest fitting, prediction, and per-IP anomaly
  aggregation. `NativeTrainingBuilder` preserves Django's chunk/state behavior.
  Supported native model paths train without a Pandas DataFrame; older APIs and
  custom parsers retain compatibility paths.
- **Synchronous CSV logging:** a bounded cache of writer handles avoids repeated
  opens. Every row is locked and flushed before returning. File identity checks
  handle rotation/replacement, and truncation recreates the header. Rows are not
  queued in an application-side batch.

Framework hooks, request/body extraction, route discovery, session/ORM access,
response construction, datetime object/epoch conversion, training orchestration,
and model artifact serialization still run in Python. The route plan selects
middleware; framework hooks continue to execute separately in their established
order. Database and Redis backends remain separate from the CSV implementation.

Flask and Django honor `AIWAF_USE_RUST=False` or `AIWAF_RUST_CSV=False` to disable
native CSV dispatch. Outside those application contexts, use the environment
variable `AIWAF_RUST_CSV=false`. FastAPI training also honors these application
options. ISO timestamps use Python's faster C parser by default;
`AIWAF_RUST_ISO_DATES=1` opts into native ISO parsing for measurement.

Flask can opt into shared, persistent CSV rate buckets:

```python
app.config["AIWAF_RATE_CACHE_BACKEND"] = "csv"
# Optional: otherwise stored under AIWAF_DATA_DIR.
app.config["AIWAF_RATE_CSV_PATH"] = "/absolute/path/to/rate_buckets.csv"
```

CSV rate decisions trim the window, consume the request, and persist the bucket
under one native lock. Missing or disabled native support returns HTTP 503.
Memory remains the default; CSV rewrites and synchronization can be slower than
memory or Redis. Workers sharing CSV state must use compatible schemas and a
filesystem with suitable locking. Legacy Python fallback writers on Windows only
have process-local thread locks, so mixed Python/native writers need particular
care. Explicit whole-file replacements are not concurrent incremental updates.

`AIWAF_CSV_LOG_FSYNC=True` adds a disk sync per log row; the default is `False`,
matching previous Python logging durability. Without per-row sync, a system crash
can lose recently flushed OS-buffered entries. Cached handles close at process
shutdown. After requests stop, call the Flask logger's `close()` or
`aiwaf.core.native_runtime.close_csv_logs()` before deleting temporary log
directories, especially on Windows.

Check the installed extension without touching application data:

```bash
python scripts/check_native_csv_runtime.py
```

Development request batching adds `policy_sql_signatures` and
`csv_geo_policy` capabilities. Shared SQL inspection checks the first
eight ASCII strings immediately for prompt denial, then checks subsequent strings
in batches of at most 128. Unicode boundaries and inspection-limit exits flush
pending checks first, preserving first-finding order. Django, Flask, and FastAPI
use the shared path; older extensions retain single-string checks.

Flask with CSV geo state and an explicit allow/block list can read dynamic countries
and evaluate the geo policy in one native call. Django CSV and FastAPI CSV use
`csv_runtime_geo_policy` for their key/value geo state. Django additionally retains
its existing ORM country blocks; the combined call includes those countries as
extra policy input. ORM-only Django operation remains separate. FastAPI geo
middleware honors its `use_rust` option, passed from the application's Rust flags.
Dynamic-only FastAPI policy and custom getters/evaluators retain their fallback
path. Native reads respect TTLs and observe updates/removals; disabled native geo
reads refresh the Python CSV snapshot. Exemptions and blocklist writes still run
at their original stages. Rebuild the extension from this checkout to test these
unpublished capabilities.

### Request-time anomaly acceleration (development)

With a matching rebuilt extension and a real Rust Isolation Forest, Flask and
FastAPI retain request histories as immutable `NativeAnomalyHistory` snapshots.
Native code trims the time window, builds the six current features, and predicts
without exporting the numeric matrix. Records are shared between snapshots;
evaluating a response does not mutate another request's history. Existing
per-worker cache ownership and response/keyword/blocking order remain unchanged.

If the forest predicts an anomaly, Python still resolves the current route and
exemptions for each historical path. Rust then analyzes the retained records.
Dynamic route/exemption changes remain visible. Unicode paths/keywords, non-finite
current inputs, disabled native settings, older extensions, and other model types
retain the established Python-history path. Set
`AIWAF_RUST_ANOMALY_HISTORY=False` in Flask config or the FastAPI `AIWAFConfig`
object to disable native history retention; existing snapshots convert back to
tuple lists. Disabling or replacing a model also retains compatibility.

Django continues to cache serializable tuple lists, including with shared cache
backends. The shared recent-behavior bridge uses `analyze_recent_tuples` to avoid
building a dictionary per historical record. No native process-local object is
stored in Django's cache. These changes do not introduce model auto-reload or
shared histories for Flask/FastAPI.

Further request-path refinements use the existing native CSV log writer for
Flask/FastAPI anomaly training logs when supported. Each row is flushed before
returning; there is no background queue. `AIWAF_CSV_LOG_FSYNC=True` additionally
requests an OS sync for these logs, including in the Python fallback. Rust-disable
settings and older extensions retain the Python writer.

Flask reuses its routing adapter within a request while continuing to match each
path and evaluate exemptions. Route-map replacement and additions remain visible;
the `MethodNotAllowed` import was corrected so existing routes with another HTTP
method are recognized. Flask/FastAPI sweep inactive histories at most every 30
seconds during response processing, removing only histories with no entries in
the configured scoring window. Active histories remain uncapped, and a quiet
worker performs no background cleanup. Django continues to use cache timeouts.

Rust recent-behavior analysis now counts symmetric ten-second bursts with a
linear sweep after sorting finite timestamps, replacing two binary searches per
record. Non-finite timestamps retain the established search path. This shared-core
change also applies to the WASM recent-behavior API.

### Python operations

#### Experimental compiled request stage

`AIWAF_RUST_REQUEST_ENGINE=True` opts into `NativeRequestEngine` with a matching
rebuilt Rust extension. Set it in Flask/Django settings or the FastAPI `AIWAFConfig`.
It is **off by default**. This first stage combines bounded ASCII query SQL
inspection, default keyword-context evaluation, dynamic CSV keyword reads, and
keyword learning writes behind a compiled policy profile. Static policy changes
rebuild the profile; CSV state remains live. Flask/FastAPI can use one native call
for supported query requests. Django keeps SQL inspection before route resolution,
then uses the compiled keyword/CSV stage with the resolved route facts.

Framework extraction, body buffering/replay, exemptions, blocklist enforcement,
rate limits, honeypot/UUID hooks, header enforcement, and response processing keep
their existing positions. Structured SQL bodies, Unicode paths/decoding, monitor
mode, custom policy/storage hooks, custom Django converters, older extensions,
and dynamic-keyword subsets whose ranking requires Python retain the established
path. The engine does not replace the whole eight-middleware chain.

```bash
# Auto-detected CLI (one supported framework installed)
aiwaf --help
aiwaf blocklist migrate
aiwaf status

# Django management commands
python manage.py detect_and_train
python manage.py regenerate_model
python manage.py aiwaf_reset --keywords --confirm
python manage.py aiwaf_logging --status
python manage.py geo_block_country list

# Explicit adapter dispatch
aiwaf django aiwaf_list --all
aiwaf flask --help
aiwaf fast --help
aiwaf fastapi --help

# FastAPI route-aware training using the application's runtime storage
aiwaf fast train --app app:app --log-dir aiwaf_logs --disable-ai
aiwaf fast train --app app:app --log-dir aiwaf_logs --model-path model.json
```

Bare CLI commands select the single installed supported framework. If multiple
frameworks are installed, specify `aiwaf flask ...`, `aiwaf fastapi ...`, or
`aiwaf django <management-command> ...`. The `fast` alias remains supported.
Django uses its management command names, such as `aiwaf_list`.

The Flask CSV management CLI reuses existing policy files in the current project's
`aiwaf_data` (preferred) or `.aiwaf/data` before searching user and package data
directories. `AIWAF_DATA_DIR` or `aiwaf flask --data-dir /absolute/path status`
overrides discovery, including for a new directory. Set the same absolute
`AIWAF_DATA_DIR` for the Flask app and CLI when running them from different
working directories.

Flask, FastAPI, Django CSV mode, and the native Rust pipeline now use the same
policy files: `blacklist.csv`, `whitelist.csv`, `keywords.csv`,
`geo_blocked_countries.csv`, and `path_exemptions.csv`. For FastAPI, configure
`storage.backend = "csv"` and `storage.data_dir = "/absolute/path/aiwaf_data"`;
`AIWAF_DATA_DIR` also supplies the directory. Memory, JSON-file, database, and
Django ORM modes retain their existing storage behavior.

Startup imports a legacy `runtime_store.csv` in the chosen directory, or the
old default `aiwaf_data.csv` beside the project's `aiwaf_data` directory.
Existing custom `storage.file_path` settings remain accepted as migration
sources: `/path/custom.csv` maps to `/path/custom/`, while `runtime_store.csv`
maps to its parent. Prefer an explicit `data_dir` for the application and CLI.
Original legacy files remain intact, pre-import canonical files are backed up,
and a completion marker prevents replay after blocks or keywords are removed.
Existing canonical policy wins conflicts. Invalid legacy input stops startup
with an error; repair it and restart to retry an incomplete import. Stop old
workers before upgrading: subsequent writes to a legacy source are not reimported.

Keyword frequencies and non-policy runtime history are retained in
`runtime_metadata.csv`; policy enforcement reads the shared policy files.
The low-level `CSVStorage` key/value class remains available for explicit use,
but framework CSV initialization selects `PolicyCSVStorage`.

FastAPI also exposes `aiwaf.fast.trainer.train_from_logs(app, ...)`. Training
refreshes learned keywords and can write a Rust JSON model artifact. Existing
anomaly middleware instances require an explicit model reload or application
restart to use the newly trained model.

## JavaScript package

The npm package uses CommonJS and exports the Express middleware as its default function plus adapters for the other supported Node frameworks.

### Express

```javascript
const express = require('express');
const aiwaf = require('aiwaf');

const app = express();
app.use(express.json());

app.use(aiwaf({
  AIWAF_MIDDLEWARES: ['auto'],
  staticKeywords: ['.php', '.env', '.git'],
  WINDOW_SEC: 10,
  MAX_REQ: 20,
  FLOOD_REQ: 40,
  AIWAF_HEADER_VALIDATION: true,
  AIWAF_METHOD_POLICY_ENABLED: true,
  AIWAF_ALLOWED_METHODS: ['GET', 'POST', 'HEAD', 'OPTIONS']
}));

app.get('/', (req, res) => res.json({ protected: true }));
app.listen(3000);
```

Attach AIWAF after the body parser when honeypot rules inspect parsed form or JSON fields.

### Node framework adapters

| Framework | Entry point |
| --- | --- |
| Express | `aiwaf(options)` |
| Fastify | `fastify.register(aiwaf.fastify, options)` |
| Hapi | `server.register({ plugin: aiwaf.hapi, options })` |
| Koa | `app.use(aiwaf.koa(options))` |
| NestJS/Express | `aiwaf.nest(options)` or the Express middleware |
| NestJS/Fastify | `app.register(aiwaf.fastify, options)` |
| Next.js API routes | `aiwaf.next(handler, options)` |
| AdonisJS | `aiwaf.adonis(options)` |
| Sails.js | `aiwaf.sails(options)` |

### JavaScript path policies

```javascript
app.use(aiwaf({
  AIWAF_PATH_RULES: [
    { PREFIX: '/health/', DISABLE: ['header_validation', 'rate_limit'] },
    { PREFIX: '/api/public/', RATE_LIMIT: { WINDOW: 60, MAX: 300 } }
  ]
}));
```

Applications can also use `aiwaf.exempt`, `aiwaf.exemptFrom`, `aiwaf.only`, and `aiwaf.requireProtection` to build route policies.

Generate an Express route manifest after routes are registered:

```javascript
aiwaf.generateExpressManifest(app, '.aiwaf/paths.json');
```

Or generate one from a route list with the CLI:

```bash
cd js
npm run aiwaf -- manifest --framework express --routes routes.json --output .aiwaf/paths.json
```

### JavaScript configuration

| Area | Important options |
| --- | --- |
| Middleware | `AIWAF_MIDDLEWARES`, `AIWAF_DISABLE_MIDDLEWARES`, `AIWAF_PATH_RULES` |
| Rate limiting | `WINDOW_SEC`, `MAX_REQ`, `FLOOD_REQ`, `cache` |
| Headers | `AIWAF_HEADER_VALIDATION`, `AIWAF_REQUIRED_HEADERS`, `AIWAF_HEADER_QUALITY_MIN_SCORE` |
| Methods | `AIWAF_METHOD_POLICY_ENABLED`, `AIWAF_ALLOWED_METHODS` |
| Keywords | `staticKeywords`, `AIWAF_ENABLE_KEYWORD_LEARNING`, `AIWAF_DYNAMIC_TOP_N` |
| Honeypot | `HONEYPOT_FIELD`, timing settings |
| GeoIP | `AIWAF_GEO_BLOCK_ENABLED`, `AIWAF_GEO_BLOCK_COUNTRIES`, `AIWAF_GEO_ALLOW_COUNTRIES` |
| Models | `AIWAF_MODEL_STORAGE`, `AIWAF_MODEL_PATH`, `AIWAF_MODEL_CACHE_KEY` |
| Logging | `AIWAF_MIDDLEWARE_LOGGING`, `AIWAF_MIDDLEWARE_LOG_PATH`, DB/CSV options |
| WASM | `AIWAF_WASM_VALIDATION`, `AIWAF_WASM_VALIDATE_RECENT` |

AIWAF loads `aiwaf-wasm` when available and falls back to the JavaScript implementation when WASM initialization or conversion is not worthwhile. Small, object-heavy operations can be faster in JavaScript because crossing the JS/WASM boundary and serializing objects has a fixed cost. WASM is most useful for sufficiently large feature batches and model scoring workloads.

The Python filesystem CSV transactions and retained training bindings remain
PyO3-specific. Node now also has an **explicit stateful WASM request pipeline**;
its transport and filesystem I/O remain in JavaScript.

### Rust-owned Node request pipeline

Node 1.1.2 now requires `aiwaf-wasm>=0.2.2,<0.3`. From the current source checkout, build the companion package with
`NativeRequestPipeline` support before using this adapter. Registry packages may
not yet contain this new API. Publish the WASM 0.2.2 companion first; refresh the
npm lockfile's registry integrity after publication, then run Node release gates
and publish the Node package. The existing `aiwaf(options)` integration remains
the legacy path; it does not switch automatically.

```javascript
const express = require('express');
const aiwaf = require('aiwaf');

async function main() {
  const app = express();
  // Configure trust proxy for your actual deployment; the native adapter uses req.ip.
  app.use(express.json({ limit: '64kb' }));
  app.use(express.urlencoded({ extended: false, limit: '64kb' }));
  const firewall = await aiwaf.native({
    dataDir: 'aiwaf_native_data',
    profile: { rate_key_mode: 'ip_path', min_form_time: 1.0 },
    // Optional synchronous adapter facts; use your application's authentication.
    authenticated: req => Boolean(req.user),
    routeExists: req => req.path === '/api/ok'
  });
  app.use(firewall);
  app.get('/api/ok', (_req, res) => res.json({ ok: true }));
  app.listen(3000);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
```

Configuration and native API checks happen once at startup. Rust runs geo,
IP/keyword/structured SQL inspection, rate/flood, anomaly block state, honeypot,
UUID and header checks in one `begin` call. A single `finish` call owns response
observations, UUID scores, anomaly features/history/inference, bounded keyword
learning, and escaped CSV row formatting. Node normalizes framework facts,
serializes the request envelope, emits responses, and appends the returned rows
using cached file descriptors. Logging is immediate, not queued or batched.

The dedicated lowercase `profile` rejects unknown keys. It does not import legacy
settings, PATH_RULES/manifests, Redis, custom stores, UUID resolver callbacks or
ORM state. Missing native support fails startup with no JavaScript policy fallback.
Install this adapter instead of the existing chain, not alongside it. Bounded body
parsers must run first; an unparsed body with a declared length/chunked encoding
is rejected with 413 when inspection is enabled. Upload streams require another
integration path. `countryLookup(req)`, `authenticated(req)` and `routeExists(req)`
are optional synchronous fact callbacks; country defaults to unknown and route
existence to `Boolean(req.route)`. Supply accurate facts when the firewall runs
before Express resolves routes. Country headers are not implicitly trusted.

All eight stages are enabled by default. Native defaults include:

| Profile setting | Default / scope |
| --- | --- |
| `exempt_paths`, `exempt_ips` | `/health`, `/robots.txt`, `/sitemap.xml`; no IPs; literal case-insensitive path prefixes |
| `sql_mode`, `max_bytes` | `block`, `65536`; `off` supported, monitor rejected; bounded nested JSON/form values and double URL decoding |
| `static_keywords`, `dynamic_keywords`, `legitimate_keywords`, `learning` | Native vocabulary, empty dynamic set, legitimate exact route names, `true`; learned probe segments capped at 4096 |
| `geo_allow`, `geo_block`, `blocklist` | Empty; blocklist maps IP to Unix expiry seconds (`0` permanent) |
| `rate_window`, `rate_max`, `rate_flood`, `rate_key_mode` | `10` seconds, `20`, `40`, `ip_path`; `ip` also supported |
| `min_form_time`, `max_page_time`, `skip_authenticated`, `honeypot_field` | `1.0`, `240` seconds, `true`, empty field; local Rust timing state |
| `allowed_methods`, `uuid_prefix`, `uuid_window`, `uuid_threshold` | Empty method restriction, `/user/`, `60` seconds, `5` repeated UUID 404s; malformed UUID denied immediately |
| `required_headers`, `header_min_score` | `HTTP_USER_AGENT`, `HTTP_ACCEPT`; score `3`, plus header safety caps |
| `anomaly_window`, `max_history`, `max_clients`, `max_pending` | `60` seconds, `1000`, `100000`, `10000`; periodic cleanup and bounded state |
| `block_duration` | `86400` seconds for newly generated blocks |

Rate counters, honeypot timestamps, UUID scores, anomaly history and loaded policy
snapshots are local to each engine/worker and reset on restart. Blocks and learned
keywords append to dedicated `native_blocks.csv`/`native_keywords.csv`, synced
immediately, and replay at startup (`persistBlocks: false` disables this disk
history). Policy files are **not live synchronized across workers**; do not share
the native state/log files across worker processes. These schemas and block rules
are separate from legacy reputation/CLI stores. Restart/reconstruct to apply
changed policies; no backend migration or automatic legacy CSV import occurs.

`native_requests.csv` is written immediately; `logFsync` defaults to false and
optionally syncs every log row. `logPath` overrides its location. CSV formatting
and policy decisions run in Rust; Node necessarily owns actual filesystem calls.
Finalization runs on response `finish` (or `close`, recorded as 499), uses a Node
monotonic elapsed clock, and executes once per engine-owned context. Stop requests,
wait for responses, then call `firewall.close()` to release writers/WASM state.
Logging/persistence errors invoke `onError(error)` or report to stderr; an already
completed response cannot be retracted.
After rotating native log files, reload workers to reopen the cached writers;
ordinary appends do not check file metadata or reopen descriptors per request.

Pass a fitted six-feature Rust/WASM forest as `model` (from
`aiwaf.wasm.createIsolationForest` with `__aiwafWasm === true`). The engine copies
its snapshot; `firewall.setModel(model)` replaces it and `setModel(null)` disables
inference. Node's feature order remains `[pathLen, kwHits, statusIdx, responseTime,
burst, total404]`, with response time in **milliseconds**, distinct from Python's
contract. Model scoring/behavior gates at response finalization can update block
state for later requests. No model means history/learning without model blocking.
`firewall.diagnostics()` reports native activation, actual inference count and
state sizes. There are no historical request-log database reads per request.

Fastify/Hapi/Koa/Nest/Next/Adonis/Sails can select the same engine with the sole
outer option `AIWAF_NATIVE_PIPELINE: { profile: {...}, dataDir: '...' }`. Do not mix
legacy options. Fastify initializes during registration and executes at
`preValidation`; Hapi initializes during registration, begins enforcement on
`onRequest` (including unknown routes), then makes an additional native call at
`onPreHandler` for parsed-body inspection and authenticated form timing.
Koa/Adonis wrappers and Next API handlers expose `.ready`;
Nest's middleware class exposes static `.ready`; await those promises before
starting the application. Fastify/Hapi close the engine on shutdown; use the
resolved native handle's `close()` for the other wrappers. Route metadata must be
installed before enforcement; required middleware overrides decorator exemptions,
while profile-level exemptions remain global. Next integration is Node API routes,
not Edge/Fetch middleware.

Run `npm run test:native` in `js/` against the built WASM package to validate the native integrations.

### JavaScript training and operations

```bash
cd js

AIWAF_ACCESS_LOG=/path/to/access.log npm run train
npm run aiwaf -- status
npm run aiwaf -- list blocklist
npm run aiwaf -- add blocklist 203.0.113.9 "manual block"
npm run aiwaf -- add ip-exemption 203.0.113.10 "trusted monitor"
npm run aiwaf -- geo summary
npm run aiwaf -- model info
npm run aiwaf -- export aiwaf-export.json
```

Use Redis or another shared cache for consistent rate limiting across multiple Node processes. Without shared state, the in-memory fallback is process-local.

## Rust accelerator for Python

`aiwaf-rust` exposes the shared Rust core through PyO3 and ABI3 wheels for Python 3.8 and newer.

```bash
pip install aiwaf-rust
```

The module provides:

- `validate_headers` and `validate_headers_with_config`
- `KeywordMatcher` and `RouteMatcher`
- request-record construction and six-feature extraction
- incremental feature extraction with explicit state
- recent-behavior analysis
- `IsolationForest` training, scoring, prediction, retraining, and JSON state
- locked CSV storage, indexed snapshot lookups, atomic policy mutations, and
  synchronous cached log writers
- shared request policies, combined route plans, and exemption matching
- batched log/timestamp preparation, `TrainingCSVReader`,
  `NativeTrainingBatch`, and `NativeTrainingBuilder`

```python
import aiwaf_rust

reason = aiwaf_rust.validate_headers({
    "HTTP_USER_AGENT": "Mozilla/5.0",
    "HTTP_ACCEPT": "text/html",
})

forest = aiwaf_rust.IsolationForest(
    n_estimators=100,
    max_samples="auto",
    contamination="auto",
    max_features=1.0,
    bootstrap=False,
    random_state=42,
    warm_start=False,
)
forest.fit([[0.1, 1.0], [0.2, 1.1], [9.0, 9.0]])
score = forest.anomaly_score([9.0, 9.0])
state = forest.to_json()
restored = aiwaf_rust.IsolationForest.from_json(state)
```

For a local native build, stage the two canonical repository assets and run maturin:

```bash
cp README.md rust/README.md
cp LICENSE rust/LICENSE
cp NOTICE rust/NOTICE
cp -R licenses rust/
python -m pip install maturin
cd rust
maturin develop
```

The staged files are ignored by Git. Release automation performs the same staging before building wheels and the source distribution.

## WebAssembly package

`aiwaf-wasm` exposes the shared Rust core to browsers and Node-compatible bundlers.

```javascript
import init, {
  IsolationForest,
  KeywordMatcher,
  RouteMatcher,
  analyze_recent_behavior,
  extract_features,
  validate_headers,
} from 'aiwaf-wasm';

await init();

const reason = validate_headers({
  'user-agent': 'Mozilla/5.0',
  accept: 'text/html'
});

const forest = new IsolationForest({
  n_estimators: 100,
  max_samples: 'auto',
  contamination: 'auto',
  random_state: 42
});
forest.fit([[0.1, 1.0], [0.2, 1.1], [9.0, 9.0]]);
const score = forest.anomaly_score([9.0, 9.0]);
```

The WASM API includes header, URL, and content validation; keyword and route matchers; record conversion; batched feature extraction; recent-behavior analysis; and Isolation Forest lifecycle methods. Browser use requires a bundler that understands WebAssembly assets.

Build and test it locally:

```bash
cargo test --manifest-path rust/Cargo.toml --locked -p aiwaf_core
cd rust/crates/aiwaf_wasm
wasm-pack test --node
wasm-pack build --release --target bundler
cd ../..
python scripts/patch_wasm_pkg.py
cp ../LICENSE crates/aiwaf_wasm/pkg/LICENSE
cp ../NOTICE crates/aiwaf_wasm/pkg/NOTICE
cp -R ../licenses crates/aiwaf_wasm/pkg/
```

## Java package

AIWAF Java 1.3.5 targets Java 17, Spring Framework 7.0, and Jakarta Servlet 6.1. It is a native Java implementation and does not load the Rust library.

### Core engine

Use the two-stage API when the integration can observe the handler response. Deterministic controls run before the application; anomaly scoring then receives the actual status and elapsed time.

```java
import com.aiwaf.core.AiwafConfig;
import com.aiwaf.core.AiwafDecision;
import com.aiwaf.core.AiwafEngine;
import com.aiwaf.core.AiwafRequest;

import java.util.Map;
import java.util.Set;

AiwafConfig config = new AiwafConfig();
config.rateLimitEnabled = true;
config.rateLimitMax = 20;
config.rateLimitWindowSeconds = 10;

AiwafEngine engine = new AiwafEngine(config);
AiwafRequest request = new AiwafRequest(
    "GET",
    "/api/profile",
    "203.0.113.10",
    "US",
    Map.of("User-Agent", "Mozilla/5.0", "Accept", "application/json"),
    Map.of(),
    System.currentTimeMillis(),
    Set.of()
);

long started = System.currentTimeMillis();
AiwafDecision decision = engine.evaluateBeforeResponse(request);
if (decision.allowed()) {
    decision = engine.evaluateAfterResponse(
        request,
        200,
        System.currentTimeMillis() - started
    );
}
```

`evaluate(request)` remains available for request-only integrations and uses provisional response values for AI features.

### Spring MVC

Spring Boot applications are protected automatically. Adding `aiwaf-java` creates `AiwafConfig`, `AiwafEngine`, and the ordered `AiwafFilter`; discovers live MVC routes, route annotations, and JPA UUID fields; and applies request controls before the controller plus post-response scoring with the real status and timing. Set `aiwaf.enabled=false` to disable auto-configuration.

```properties
aiwaf.rate-limit.max=60
aiwaf.rate-limit.window-seconds=60
aiwaf.geo.enabled=true
aiwaf.geo.blocked-countries=CN,RU
aiwaf.path-manifest.path=.aiwaf/paths.json
# Use one namespace and shared enforcement state across application instances.
aiwaf.storage.backend=redis
aiwaf.storage.redis-url=redis://localhost:6379/0
aiwaf.storage.key-prefix=my-service
# Redis is fail-closed by default. Every wait is bounded.
aiwaf.storage.redis-failure-mode=fail_closed
aiwaf.storage.redis-connection-timeout-millis=1000
aiwaf.storage.redis-socket-timeout-millis=2000
aiwaf.storage.redis-pool-max-total=32
aiwaf.storage.redis-pool-max-idle=16
aiwaf.storage.redis-pool-min-idle=0
aiwaf.storage.redis-pool-max-wait-millis=250
```

Set `aiwaf.config-file=/etc/aiwaf/config.json` (or `AIWAF_CONFIG_FILE`) to load the same nested JSON configuration used by the Python runtime. Environment variables and Spring properties override file values. `AiwafConfigFileCore` also exposes load, save, deep-merge, and validation APIs for non-Spring applications.

Define an `AiwafConfig`, `AiwafEngine`, or `AiwafFilter` bean only when the application needs a custom replacement. For plain Spring MVC without Boot, register the filter directly; passing the application context enables the same live route discovery:

```java
@Bean
AiwafFilter aiwafFilter(AiwafEngine engine, ApplicationContext context) {
    return new AiwafFilter(engine, context);
}
```

The live mapping integration honors `@AiwafExempt`, `@AiwafExemptFrom`, `@AiwafOnly`, and `@AiwafRequireProtection` without a controller list. Do not register `AiwafInterceptor` and `AiwafFilter` as independent enforcement layers for the same request.

Committed, streaming, and asynchronous responses are recorded but are not replaced after bytes have been sent.

UUID protection uses Python-compatible weighted signals: malformed input, valid UUID requests that resolve to `404`, and successful requests that decay the score. UUID-valued query parameters and `{uuid}` route variables are supported. `SpringUuidModelLookup` optionally discovers UUID primary keys and unique UUID properties through the JPA metamodel; omit it when the application does not use JPA.

Generate a route manifest from the live Spring application rather than supplying controller methods manually:

```bash
java -cp "your-app.jar:aiwaf-java-1.3.5.jar" \
  com.aiwaf.cli.AiwafConsole init \
  --app com.example.Application \
  --output .aiwaf/paths.json
```

The command starts the application, reads every registered `RequestMappingHandlerMapping`, writes the shared `schema_version/framework/context_hash/routes` document, and then closes the temporary application context. At runtime, `AiwafEngine` loads this file automatically and appends its disabled middleware and rate-limit overrides after explicit `pathRules`, so explicit equal-prefix rules retain precedence. Set `pathManifestEnabled=false` or `aiwaf.path-manifest.enabled=false` to opt out.

### Jakarta Servlet

```java
AiwafConfig config = new AiwafConfig();
AiwafEngine engine = new AiwafEngine(config);

servletContext
    .addFilter("aiwaf", new AiwafServletFilter(engine))
    .addMappingForUrlPatterns(null, false, "/*");
```

The generic servlet filter uses request-time evaluation. Spring applications should prefer `AiwafFilter` for handler metadata and post-response scoring.

### Java configuration and models

| Area | Main `AiwafConfig` fields |
| --- | --- |
| Rate limiting | `rateLimitEnabled`, `rateLimitScope`, `rateLimitWindowSeconds`, `rateLimitMax`, `rateLimitFloodThreshold` |
| Headers | `headerValidationEnabled`, `requiredHeadersByMethod`, `minHeaderQualityScore`, size/count limits |
| Request | body, parameter, method, and content-type limits |
| Proxies | `trustedProxyCidrs`, `maxForwardedForEntries` |
| Exemptions | `exemptIps`, `exemptPaths`, `autoExemptPathPrefixes` |
| GeoIP | `geoBlockEnabled`, `geoAllowedCountries`, `geoBlockedCountries`, `geoIpDatabasePath`, cache limits |
| Route manifest | `pathManifestEnabled`, `pathManifestPath`, `pathRules` |
| UUID checks | `uuidTamperEnabled`, `uuidScoreWindowSeconds`, `uuidScoreBlockThreshold`, signal weights, `uuidParameterNames` |
| AI | `aiEnabled`, `aiModelPath`, `aiAnomalyScoreThreshold` |
| Storage | `storageBackend`, `storageFilePath`, `storageRedisUrl`, `storageKeyPrefix`, `storageRedisFailureMode`, Redis timeout and pool limits |
| Telemetry | `observabilityEnabled` |

GeoIP uses the bundled MMDB through the native Java reader; it does not require the external `mmdblookup` executable. A valid `X-Country` value is accepted only from a peer in `trustedProxyCidrs`; otherwise AIWAF resolves the client address itself. Default blocklist calls use Python-compatible reputation scoring and temporary escalation (15 minutes, 1 hour, then 24 hours). Use `BlocklistManager.blockPermanent(ip, reason)` for an explicit permanent administrative block.

`storageBackend="redis"` makes rate-limit buckets, honeypot timing, weighted UUID scores, recent-request anomaly state, blocklist data, exemptions, geo policy, and learned keywords visible to every application instance using the same key prefix. Redis enforcement updates use atomic server-side scripts. Memory, file, CSV, and SQLite engines keep request state isolated per `AiwafEngine`; constructing another engine no longer replaces an existing engine's stores. The static `RuntimeStorage` and `BlocklistManager` methods remain compatibility facades for command-line and administrative code.

The Java 1.3 Redis backend supports **standalone Redis only**. Sentinel and Cluster configurations are rejected during validation instead of silently operating with incomplete semantics. `fail_closed` is the default: an unavailable Redis instance prevents startup or raises a request-path storage failure, which results in the application denying availability rather than bypassing protection. `fail_open` permits startup and returns non-blocking enforcement fallbacks while Redis is unavailable; failed mutations return `false` at the `StorageBackend` boundary. Connection, socket, pool size, and pool wait limits are bounded and configurable. `RedisStorage.diagnostics()` reports operation/failure counts, latency, and live pool utilization.

Redis keys include a state-schema version, and each base key prefix has an atomic compatibility marker. Releases using the same schema can share state during a rolling upgrade. A runtime with an incompatible schema refuses the namespace—even in `fail_open` mode. Use a unique key prefix per application and environment; deploy an incompatible schema with a new prefix, migrate deliberately, then retire the old namespace. Serialized persistent values remain JSON within a schema version.

New Java models use the Python-aligned six-feature schema and are written as safe JSON containing the Python `aiwaf_rust.IsolationForest` state. Python can restore Java-generated forest state, and Java can load Python Rust-model artifacts. Existing signed Java binary artifacts, including nine-feature models, remain readable through the restricted legacy loader. Scikit-learn object artifacts are intentionally unsupported.

Java operational commands mirror the common Python workflow:

```bash
aiwaf-cli status
aiwaf-cli diagnose --model model.json
aiwaf-cli blocked
aiwaf-cli unblock 203.0.113.10
aiwaf-cli clear
aiwaf-cli train --events events.json --out model.json --backend java
aiwaf-cli replay --cases replay.json
aiwaf-cli model status --path model.json
aiwaf-cli logs --dir aiwaf_logs
```

Build Java from the repository root:

```bash
cd java
mvn test
mvn -Dgpg.skip=true package
```

The build produces the main, source, and Javadoc JARs under `java/target/`. The main JAR embeds the root license as `META-INF/LICENSE`. FastR training is optional and falls back to the Java trainer when R or `jsonlite` is unavailable.

### Python training replay protection

Python 1.1.6 with aiwaf-rust 0.2.5 records the evidence used by offline training
to block each IP. Rust computes SHA-256 receipts, locks concurrent trainers,
and persists `training_evidence.json` in the policy data directory. Flask,
FastAPI, and Django continue fitting models and learning keywords from history,
but block decisions use requests that have not already been handled for that IP.
Replaying old logs cannot extend an active block or recreate one after expiry
or manual removal. Fresh traffic must independently satisfy the blocking rules.

CLI listing filters expired blocks for display without rewriting its snapshot
back to the blocklist. This prevents concurrent training updates from being
erased by an older cleanup snapshot. Default first blocks last 900 seconds.

Keep the receipt file across restarts, log rotation, and blocklist clearing.
Receipts do not expire and grow with the distinct requests used in block
decisions. `AIWAF_TRAINING_STATE_DIR` can select a durable shared directory;
trainers sharing a blocklist must also share this directory. Missing native
capabilities or corrupt receipt state stop training visibly. A crash between
writing a block and committing its receipt can still require recovery; the two
writes are not a single transaction.

Receipts start with the first training run on this version. Requests processed
by older versions have no receipts, so previous enforcement cannot be inferred
retroactively. This change does not alter block durations or diagnose a block
disappearing before its expiry.

### JavaScript training replay protection

Node.js 1.1.4 with aiwaf-wasm 0.2.4 uses the same Rust receipt algorithm as
Python. The shared trainer applies this protection across JavaScript framework
adapters. The WASM `NativeTrainingEvidence` API hashes and filters evidence;
Node persists `node_training_evidence.json` in the blocklist CSV directory, or
the directory selected by `AIWAF_TRAINING_STATE_DIR`. Preserve this file across
expiry, unblocking, blocklist clearing, and log rotation. Sharing a blocklist
also requires sharing the evidence directory. Model fitting and keyword learning
still use full history; 404 and anomaly enforcement use fresh evidence only.
Log records without a valid stable timestamp are excluded from training.

The Node host serializes trainers with an exclusive lock directory. A crashed
trainer may leave `node_training_evidence.lock`; subsequent training fails
visibly rather than bypassing that lock. Remove that lock directory only after
confirming its trainer has stopped. Receipt snapshots are written and synced
before atomic replacement. As in Python, block writes and receipt commits are
separate operations, so a crash between them can still require recovery.

The CLI exits with failure for missing WASM receipt support, corrupt state, or
storage errors. Programmatic callers can await `require('aiwaf/train')()`.
Publish the matching WASM package before the Node package; `test:wasm-real`
checks receipt restoration against the installed dependency, not just a fixture.

Java's `train-model` operation fits and saves a model without adding blocklist
entries. Servlet and Spring use that shared Java core. Retraining alone therefore
cannot extend or recreate their runtime blocks; a regression test verifies this.

Blocklist expiry is also protected against concurrent updates. Node request
checks and listings do not delete expired snapshots. Explicit cleanup checks
expiry in the database DELETE, or inside the CSV mutation lock after reading
the current rows. CSV blocklist writers use the same lock and atomically replace
the file. A crashed writer can leave `<blocklist CSV path>.lock`; stop its owner
before removing that lock directory. Lock acquisition times out after 60 seconds
and reports an error rather than proceeding without protection.

Java CSV and file storage reload current data under a shared JVM and OS sidecar
lock for each operation. Reads filter expiry without rewriting disk; writes
preserve other instances' updates. OS locks release when a process exits; the
sidecar lock file stays in place and must not be removed while workers run.
File storage now incurs a reload for each operation. Restart all old workers
when upgrading so every writer participates in the locking protocol.

## Shared training schema

New training paths use these six features in this order:

1. `path_len`
2. `kw_hits`
3. `resp_time`
4. `status_idx`
5. `burst_count`
6. `total_404`

`resp_time` is expressed in seconds in feature vectors. Artifact summary fields explicitly named with `_ms` remain milliseconds.

The training lifecycle is:

1. Parse configured access logs or middleware-generated request logs.
2. Normalize request paths, status, timing, and per-IP state.
3. Extract the six features and suspicious route segments.
4. Train or update the Isolation Forest after configured volume thresholds are met.
5. Refresh learned keywords while excluding known legitimate and exempt routes.
6. Persist portable JSON forest state and runtime metadata; legacy language-specific artifacts remain read-only compatibility inputs.

Do not train directly on unreviewed sensitive request bodies or authentication headers. Treat models, logs, exported state, and MMDB files as deployment artifacts with controlled access.

## Deployment guidance

- Configure the application to trust forwarding headers only from known proxy CIDRs.
- Configure the outermost proxy to overwrite client-supplied forwarding headers.
- Use Redis, a database, or another shared backend when multiple workers must share rate-limit, blocklist, or exemption state.
- Keep health checks, static assets, and trusted webhook routes explicitly scoped instead of disabling protection globally.
- Start anomaly detection in observe-only or conservative mode and tune it with representative normal traffic.
- Rotate logs and exclude secrets, authorization headers, cookies, and personal data.
- Sign model/configuration artifacts where the runtime supports HMAC verification.
- Run AIWAF alongside normal secure-development controls and an edge/reverse-proxy layer.

## Development and tests

### Whole monorepo

Create a Python environment, install all adapters, then install Node dependencies:

```bash
python -m pip install -e ".[django,flask,fastapi,rust]"
python -m pip install pytest pytest-cov coverage httpx
npm ci --prefix js
python aiwaf_test.py --coverage
```

Focused suites:

```bash
python aiwaf_test.py --python-only
python aiwaf_test.py --rust-only
python aiwaf_test.py --js-only
python aiwaf_test.py --wasm-only
```

Java is tested separately:

```bash
cd java
mvn test
```

### Direct package commands

```bash
# Python
pytest

# Node.js
npm ci --prefix js
npm test --prefix js

# Rust core
cargo test --manifest-path rust/Cargo.toml --locked -p aiwaf_core

# Rust Python API, after installing the local wheel
pytest -q rust/tests/test_python_api.py

# Java
mvn -f java/pom.xml test
```

## Release automation

Release versions and tags must match the relevant manifest.

| Package | Manifest | Tag | Workflow |
| --- | --- | --- | --- |
| Python `aiwaf` | `pyproject.toml` | `python-v1.1.8` | `python-publish.yml` |
| npm `aiwaf` | `js/package.json` | `js-v1.1.5` | `npm-publish.yml` |
| PyPI `aiwaf-rust` | `rust/pyproject.toml` + `rust/Cargo.toml` | `rust-v0.2.7` | `rust-publish.yml` |
| npm `aiwaf-wasm` | `rust/crates/aiwaf_wasm/Cargo.toml` | `wasm-v0.2.5` | `wasm-publish.yml` |
| Maven `aiwaf-java` | `java/pom.xml` | `java-v1.3.5` | `java-publish.yml` |

Python and Rust publish to PyPI with trusted publishing. The npm workflows use npm trusted publishing and stage packages for approval. Configure the trusted publisher with organization `aiwaf-project`, repository `aiwaf`, the exact workflow filename, and the environment used by that workflow.

Java publishing uses the protected `maven-publish` environment plus `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `CENTRAL_TOKEN_USERNAME`, and `CENTRAL_TOKEN_PASSWORD`. The workflow verifies the tag, runs tests, signs the POM and all three JARs, uploads the deployment bundle, and waits for Maven Central publication.

Registry releases are immutable. Increment the relevant manifest version before publishing another release.

For this release, publish `aiwaf-rust 0.2.7` before Python `aiwaf 1.1.8`, and
`aiwaf-wasm 0.2.5` before npm `aiwaf 1.1.5`. After WASM publication, refresh the
npm lockfile against the registry to record the actual companion checksum, then
run `npm ci` and the release checks. The prepared future WASM lock entry has no
integrity checksum; it cannot be installed until that package is published.

## Security and limitations

- Deterministic controls can produce false positives when legitimate routes resemble common probes; use narrow route exemptions and regression tests.
- Language-native Isolation Forest implementations can produce different scores for identical feature rows.
- WASM object conversion has overhead and is not automatically faster than JavaScript for small calls.
- In-memory rate limits and runtime stores are local to one process.
- GeoIP data can be missing, stale, or imprecise and should not be the sole authorization control.
- Post-response blocking cannot replace data already committed or streamed to a client.
- No WAF can compensate for broken authorization or unsafe application logic.

Report vulnerabilities privately to the maintainers rather than opening a public exploit issue.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contributor setup and expectations, [`CHANGELOG.md`](CHANGELOG.md) for release history, and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for community standards.

## License

Original AIWAF project code in this checkout uses the unmodified [Elastic License 2.0](LICENSE), with separately licensed material identified in [NOTICE](NOTICE). AIWAF is the business offering these terms. ELv2 permits commercial use, modification, redistribution, and consulting, subject to its conditions. It restricts providing substantial AIWAF functionality as a hosted or managed service, bypassing license-key functionality, and removing required notices. ELv2-covered code is source available.

This migration applies to this checkout and future releases expressly distributed under ELv2. Previously distributed MIT copies retain their permissions; version numbers do not retroactively change their license. Do not republish an existing version with new licensing terms. Independently versioned packages record their license in their release artifacts.

Initial ELv2 release boundaries are Python/Node.js `1.1.2`, Rust/Python and WASM `0.2.2`, and Java `1.3.3`. Earlier MIT distributions retain their MIT permissions.

Retained MIT contributions keep their rights and notices in [licenses/MIT.txt](licenses/MIT.txt). The bundled IPinfo Lite database is provided by [IPinfo](https://ipinfo.io/) under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); ELv2 restrictions do not apply to that data. Package metadata uses an `AND` expression where separately licensed components are included; this does not offer a choice to license the entire package under MIT. Dependencies retain their respective terms.

Redistributions must include the applicable LICENSE, NOTICE, and licenses/ files. See [NOTICE](NOTICE) for historical rights, contributor notices, and attribution.
