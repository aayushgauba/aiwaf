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
Java uses Jackson 2.22.3 to address advisories affecting 2.22.2.

Python Flask/FastAPI Redis buckets now update atomically across workers.
Django's native `django.core.cache.backends.redis.RedisCache` uses Redis
transactions while preserving its existing serialized bucket values. Memory
and other custom cache backends serialize updates within one process; use
the supported Redis backends when sharing limits across workers.

Each package is versioned and released independently.

Python and Node.js 1.1.2, Rust/Python and WASM 0.2.2, and Java 1.3.3 are local release candidates; see the
[upgrade notes](docs/releases/2026-10-elv2.md).

| Runtime | Package | Repository version | Primary use |
| --- | --- | ---: | --- |
| Python | [`aiwaf`](https://pypi.org/project/aiwaf/) | `1.1.2` | Django, Flask, and FastAPI protection |
| Node.js | [`aiwaf`](https://www.npmjs.com/package/aiwaf) | `1.1.2` | Express and Node framework middleware |
| Rust/Python | [`aiwaf-rust`](https://pypi.org/project/aiwaf-rust/) | `0.2.2` | Native Python acceleration and JSON model inference |
| WebAssembly | [`aiwaf-wasm`](https://www.npmjs.com/package/aiwaf-wasm) | `0.2.2` | Rust detection and model primitives for JavaScript |
| Java | `io.github.aiwaf-project:aiwaf-java` | `1.3.3` | Spring MVC and Jakarta Servlet protection |

Supported framework integrations include Django, Flask, FastAPI, Express, Fastify, Hapi, Koa, NestJS, Next.js API routes, AdonisJS, Sails.js, Spring MVC, and Jakarta Servlet.

## What AIWAF provides

- IP blacklist, exemption, reputation, expiry, and progressive-block handling
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
- Optional Rust acceleration for Python and optional WebAssembly acceleration for Node.js

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
├── benchmarks/                     Python middleware benchmarks
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

# Python with the optional Rust accelerator
pip install "aiwaf[rust]"

# Node.js middleware
npm install aiwaf

# Standalone WebAssembly bindings
npm install aiwaf-wasm
```

Java 1.3.3, after it is published to Maven Central:

```xml
<dependency>
  <groupId>io.github.aiwaf-project</groupId>
  <artifactId>aiwaf-java</artifactId>
  <version>1.3.3</version>
</dependency>
```

## Python package

The Python package requires Python 3.10 or newer. Framework dependencies are optional, so install only the extra needed by the application.

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

### Python operations

```bash
# Unified CLI
aiwaf --help
aiwaf blacklist migrate
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
```

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

### JavaScript training and operations

```bash
cd js

AIWAF_ACCESS_LOG=/path/to/access.log npm run train
npm run aiwaf -- status
npm run aiwaf -- list blacklist
npm run aiwaf -- add blacklist 203.0.113.9 "manual block"
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

AIWAF Java 1.3.3 targets Java 17, Spring Framework 7.0, and Jakarta Servlet 6.1. It is a native Java implementation and does not load the Rust library.

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
java -cp "your-app.jar:aiwaf-java-1.3.3.jar" \
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

GeoIP uses the bundled MMDB through the native Java reader; it does not require the external `mmdblookup` executable. A valid `X-Country` value is accepted only from a peer in `trustedProxyCidrs`; otherwise AIWAF resolves the client address itself. Default blacklist calls use Python-compatible reputation scoring and temporary escalation (15 minutes, 1 hour, then 24 hours). Use `BlacklistManager.blockPermanent(ip, reason)` for an explicit permanent administrative block.

`storageBackend="redis"` makes rate-limit buckets, honeypot timing, weighted UUID scores, recent-request anomaly state, blacklist data, exemptions, geo policy, and learned keywords visible to every application instance using the same key prefix. Redis enforcement updates use atomic server-side scripts. Memory, file, CSV, and SQLite engines keep request state isolated per `AiwafEngine`; constructing another engine no longer replaces an existing engine's stores. The static `RuntimeStorage` and `BlacklistManager` methods remain compatibility facades for command-line and administrative code.

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
- Use Redis, a database, or another shared backend when multiple workers must share rate-limit, blacklist, or exemption state.
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

### Benchmark

The in-process Flask benchmark compares a baseline app, `auto` middleware selection, and the full middleware chain:

```bash
python -m benchmarks.benchmark_auto_middleware
python -m benchmarks.benchmark_auto_middleware --path-rules 250
python -m benchmarks.benchmark_auto_middleware --requests 200 --rounds 3 --warmup 50
```

Use the same machine, environment, request count, and background load when comparing results. These measurements exclude network and production-server overhead.

## Release automation

Release versions and tags must match the relevant manifest.

| Package | Manifest | Tag | Workflow |
| --- | --- | --- | --- |
| Python `aiwaf` | `pyproject.toml` | `python-v1.1.2` | `python-publish.yml` |
| npm `aiwaf` | `js/package.json` | `js-v1.1.2` | `npm-publish.yml` |
| PyPI `aiwaf-rust` | `rust/pyproject.toml` + `rust/Cargo.toml` | `rust-v0.2.2` | `rust-publish.yml` |
| npm `aiwaf-wasm` | `rust/crates/aiwaf_wasm/Cargo.toml` | `wasm-v0.2.2` | `wasm-publish.yml` |
| Maven `aiwaf-java` | `java/pom.xml` | `java-v1.3.3` | `java-publish.yml` |

Python and Rust publish to PyPI with trusted publishing. The npm workflows use npm trusted publishing and stage packages for approval. Configure the trusted publisher with organization `aiwaf-project`, repository `aiwaf`, the exact workflow filename, and the environment used by that workflow.

Java publishing uses the protected `maven-publish` environment plus `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `CENTRAL_TOKEN_USERNAME`, and `CENTRAL_TOKEN_PASSWORD`. The workflow verifies the tag, runs tests, signs the POM and all three JARs, uploads the deployment bundle, and waits for Maven Central publication.

Registry releases are immutable. Increment the relevant manifest version before publishing another release.

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

Retained MIT contributions keep their rights and notices in [licenses/MIT.txt](licenses/MIT.txt). The bundled IPinfo Lite database is provided by [IPinfo](https://ipinfo.io/) under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); ELv2 restrictions do not apply to that data. Package metadata uses an `AND` expression where separately licensed components are included; this does not offer a choice to license the entire package under MIT. Dependencies retain their respective terms.

Redistributions must include the applicable LICENSE, NOTICE, and licenses/ files. See [NOTICE](NOTICE) for historical rights, contributor notices, and attribution.
