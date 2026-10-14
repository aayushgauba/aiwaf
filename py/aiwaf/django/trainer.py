import os
import glob
import gzip
import csv
import re
from itertools import chain
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import defaultdict, Counter
import logging
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    IsolationForest = None
    SKLEARN_AVAILABLE = False
from django.conf import settings
from django.apps import apps
from django.db.models import F
from django.utils import timezone
from .utils import is_exempt_path
from .storage import get_blocklist_store, get_exemption_store, get_keyword_store
from .utils import get_exempt_paths
from .blocklist_manager import BlocklistManager
from .settings_compat import apply_legacy_settings
from .model_store import save_model_data
from .geoip import lookup_country, lookup_country_name
from ..core.constants import STATUS_IDX as CORE_STATUS_IDX
from ..core.logs import parse_log_line as core_parse_log_line, read_rotated_logs as core_read_rotated_logs
from ..core.training_pipeline import iter_training_batches, iter_csv_training_batches, aggregate_training_records, count_training_keywords, anomaly_statistics
from ..core.native_runtime import function as native_function
from .storage import _is_csv_mode
from concurrent.futures import ThreadPoolExecutor
from ..core.training import iter_batches as core_iter_batches, extract_rust_features_parallel as core_extract_rust_features_parallel
from ..core.training_features import (
    build_records as core_build_records,
    extract_raw_features as core_extract_raw_features,
    rust_payload_from_records as core_rust_payload_from_records,
    python_feature_from_record as core_python_feature_from_record,
)
from ..core.model_artifacts import rust_model_artifact, sklearn_model_artifact
from ..core.model_serialization import can_serialize_model_artifact, dump_model_artifact
from ..core.training_logic import is_malicious_context as core_is_malicious_context
from ..core.training_evidence import guard_training, current_evidence, fresh_anomaly_statistics, TrainingEvidenceError
from .storage import _resolve_csv_data_dir
from ..core.rust_backend import (
    rust_available,
    extract_features as rust_extract_features,
    supports_chunked_feature_extraction as rust_supports_chunked_features,
    extract_features_batch as rust_extract_features_batch,
    finalize_feature_state as rust_finalize_feature_state,
    rust_isolation_forest_available,
    rust_isolation_forest_class,
)

apply_legacy_settings()

logger = logging.getLogger("aiwaf.django.trainer")

#  Configuration 
LOG_PATH   = getattr(settings, 'AIWAF_ACCESS_LOG', None)
MODEL_PATH = os.path.join(os.path.dirname(__file__), "resources", "model.json")
MIN_AI_LOGS = getattr(settings, "AIWAF_MIN_AI_LOGS", 10000)
MIN_TRAIN_LOGS = getattr(settings, "AIWAF_MIN_TRAIN_LOGS", 50)

STATIC_KW  = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
STATUS_IDX = CORE_STATUS_IDX

_LOG_RX = None


def path_exists_in_django(path: str) -> bool:
    from django.urls import get_resolver
    from django.urls.resolvers import URLResolver

    candidate = path.split("?")[0].strip("/")  # Remove query params and normalize slashes
    
    # Try exact resolution first - this is the most reliable method
    try:
        get_resolver().resolve(f"/{candidate}")
        return True
    except:
        pass
    
    # Also try with trailing slash if it doesn't have one
    if not candidate.endswith("/"):
        try:
            get_resolver().resolve(f"/{candidate}/")
            return True
        except:
            pass
    
    # Try without trailing slash if it has one
    if candidate.endswith("/"):
        try:
            get_resolver().resolve(f"/{candidate.rstrip('/')}")
            return True
        except:
            pass

    # If direct resolution fails, be conservative
    # Only do basic prefix matching for known include patterns
    # but don't assume sub-paths exist just because the prefix exists
    return False


def remove_exempt_keywords() -> None:
    """Remove exempt keywords from dynamic keyword storage"""
    keyword_store = get_keyword_store()
    exempt_tokens = set()
    
    # Extract tokens from exempt paths
    for path in get_exempt_paths():
        for seg in re.split(r"\W+", path.strip("/").lower()):
            if len(seg) > 3:
                exempt_tokens.add(seg)
    
    # Add explicit exempt keywords from settings
    explicit_exempt = getattr(settings, "AIWAF_EXEMPT_KEYWORDS", [])
    exempt_tokens.update(explicit_exempt)
    
    # Add legitimate path keywords to prevent them from being learned as suspicious
    allowed_path_keywords = getattr(settings, "AIWAF_ALLOWED_PATH_KEYWORDS", [])
    exempt_tokens.update(allowed_path_keywords)
    
    # Remove exempt tokens from keyword storage
    if exempt_tokens and _is_csv_mode() and hasattr(keyword_store, 'update_keywords'):
        keyword_store.update_keywords(removed=exempt_tokens)
    else:
        for token in exempt_tokens:
            keyword_store.remove_keyword(token)
    
    if exempt_tokens:
        logger.info(f" Removed {len(exempt_tokens)} exempt keywords from learning: {list(exempt_tokens)[:10]}")


def get_legitimate_keywords() -> set:
    """Get all legitimate keywords that shouldn't be learned as suspicious"""
    from aiwaf.core.training_logic import get_default_legitimate_keywords
    legitimate = get_default_legitimate_keywords()
    
    # Extract keywords from Django URL patterns and app names
    legitimate.update(_extract_django_route_keywords())
    
    # Add from Django settings
    allowed_path_keywords = getattr(settings, "AIWAF_ALLOWED_PATH_KEYWORDS", [])
    legitimate.update(allowed_path_keywords)
    
    # Add exempt keywords
    exempt_keywords = getattr(settings, "AIWAF_EXEMPT_KEYWORDS", [])
    legitimate.update(exempt_keywords)
    
    return legitimate


def _extract_django_route_keywords() -> set:
    """Extract legitimate keywords from Django URL patterns, app names, and model names"""
    keywords = set()
    
    try:
        from django.urls import get_resolver
        from django.urls.resolvers import URLResolver, URLPattern
        from django.apps import apps
        
        # Extract from app names and labels
        for app_config in apps.get_app_configs():
            # Add app name and label - improved parsing
            if app_config.name:
                app_parts = app_config.name.lower().replace('-', '_').split('.')
                for part in app_parts:
                    for segment in re.split(r'[._-]', part):
                        if len(segment) > 2:
                            keywords.add(segment)
            
            if app_config.label and app_config.label != app_config.name:
                for segment in re.split(r'[._-]', app_config.label.lower()):
                    if len(segment) > 2:
                        keywords.add(segment)
            
            # Extract from model names in the app - improved handling
            try:
                for model in app_config.get_models():
                    model_name = model._meta.model_name.lower()
                    if len(model_name) > 2:
                        keywords.add(model_name)
                        # Add plural form
                        if not model_name.endswith('s'):
                            keywords.add(f"{model_name}s")
                    
                    # Also add verbose names if different
                    verbose_name = str(model._meta.verbose_name).lower()
                    verbose_name_plural = str(model._meta.verbose_name_plural).lower()
                    
                    for name in [verbose_name, verbose_name_plural]:
                        for segment in re.split(r'[^a-zA-Z]+', name):
                            if len(segment) > 2 and segment != model_name:
                                keywords.add(segment)
            except Exception:
                continue
        
        # Extract from URL patterns - improved extraction
        def extract_from_pattern(pattern, prefix=""):
            try:
                if isinstance(pattern, URLResolver):
                    # Handle include() patterns - check if they include legitimate apps
                    namespace = getattr(pattern, 'namespace', None)
                    if namespace:
                        for segment in re.split(r'[._-]', namespace.lower()):
                            if len(segment) > 2:
                                keywords.add(segment)
                    
                    # Extract from the pattern itself - improved logic for include() patterns
                    pattern_str = str(pattern.pattern)
                    # Get literal path segments (not regex parts)
                    literal_parts = re.findall(r'([a-zA-Z][a-zA-Z0-9_-]*)', pattern_str)
                    
                    # Get list of actual Django app names to validate against
                    app_names = set()
                    for app_config in apps.get_app_configs():
                        app_parts = app_config.name.lower().replace('-', '_').split('.')
                        for part in app_parts:
                            for segment in re.split(r'[._-]', part):
                                if len(segment) > 2:
                                    app_names.add(segment)
                        if app_config.label:
                            app_names.add(app_config.label.lower())
                    
                    # For include() patterns, be more permissive since they're routing to existing apps
                    # The key insight: if someone includes an app's URLs, the prefix is legitimate by design
                    for part in literal_parts:
                        if len(part) > 2:
                            part_lower = part.lower()
                            # For URLResolver (include patterns), be more permissive
                            # These are URL prefixes that route to actual app functionality
                            keywords.add(part_lower)
                    
                    # Recurse into nested patterns
                    try:
                        for nested_pattern in pattern.url_patterns:
                            extract_from_pattern(nested_pattern, prefix)
                    except:
                        pass
                
                elif isinstance(pattern, URLPattern):
                    # Extract from URL pattern - more comprehensive
                    pattern_str = str(pattern.pattern)
                    literal_parts = re.findall(r'([a-zA-Z][a-zA-Z0-9_-]*)', pattern_str)
                    for part in literal_parts:
                        if len(part) > 2:
                            keywords.add(part.lower())
                    
                    # Extract from view name if available
                    if hasattr(pattern.callback, '__name__'):
                        view_name = pattern.callback.__name__.lower()
                        for segment in re.split(r'[._-]', view_name):
                            if len(segment) > 2 and segment not in ['view', 'class', 'function']:
                                keywords.add(segment)
                    
                    # Extract from view class name if it's a class-based view
                    if hasattr(pattern.callback, 'view_class'):
                        class_name = pattern.callback.view_class.__name__.lower()
                        for segment in re.split(r'[._-]', class_name):
                            if len(segment) > 2 and segment not in ['view', 'class']:
                                keywords.add(segment)
            
            except Exception:
                pass
        
        # Process all URL patterns
        root_resolver = get_resolver()
        for pattern in root_resolver.url_patterns:
            extract_from_pattern(pattern)
            
    except Exception as e:
        logger.warning("Could not extract Django route keywords: %s", e, exc_info=True)
    
    # Filter out very common/generic words that might be suspicious
    # Expanded filter list
    filtered_keywords = set()
    exclude_words = {
        'www', 'com', 'org', 'net', 'int', 'str', 'obj', 'get', 'set', 'put', 'del',
        'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her',
        'was', 'one', 'our', 'out', 'day', 'had', 'has', 'his', 'how', 'man', 'new',
        'now', 'old', 'see', 'two', 'who', 'boy', 'did', 'its', 'let', 'put', 'say',
        'she', 'too', 'use', 'var', 'way', 'may', 'end', 'why', 'any', 'app', 'run'
    }
    
    for keyword in keywords:
        if (len(keyword) >= 3 and 
            keyword not in exclude_words and
            not keyword.isdigit()):
            filtered_keywords.add(keyword)
    
    if filtered_keywords:
        logger.info(f" Extracted {len(filtered_keywords)} legitimate keywords from Django routes and apps")
    
    return filtered_keywords


def _read_all_logs() -> list[str]:
    return list(_iter_all_logs())


def _read_csv_logs(path: str) -> list[str]:
    return list(_iter_csv_logs(path))


def _iter_all_logs():
    yielded = False

    if LOG_PATH and os.path.exists(LOG_PATH):
        base_and_rotated = chain([LOG_PATH], sorted(glob.glob(f"{LOG_PATH}.*")))
        for p in base_and_rotated:
            try:
                if p.endswith(".csv") or p.endswith(".csv.gz"):
                    for line in _iter_csv_logs(p):
                        yielded = True
                        yield line
                else:
                    opener = gzip.open if p.endswith(".gz") else open
                    with opener(p, "rt", errors="ignore") as f:
                        for line in f:
                            yielded = True
                            yield line
            except OSError:
                continue

    # If no log files found, fall back to RequestLog model data
    if not yielded:
        for line in _iter_logs_from_model():
            yield line


_DEFAULT_ITER_LOGS = _iter_all_logs


def _training_batches(native):
    if not native or _iter_all_logs is not _DEFAULT_ITER_LOGS or not LOG_PATH or not os.path.exists(LOG_PATH):
        yield from iter_training_batches(_iter_all_logs(), _parse, native=native)
        return
    yielded = False
    for path in chain([LOG_PATH], sorted(glob.glob(f'{LOG_PATH}.*'))):
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='ignore') as file:
                first = file.readline()
            is_csv = {'timestamp', 'ip', 'path', 'status_code'} <= set(next(csv.reader([first]), []))
            if is_csv:
                for count, records in iter_csv_training_batches(path, legacy_csv=True):
                    yielded |= bool(count)
                    yield count, records
            else:
                with opener(path, 'rt', encoding='utf-8', errors='ignore') as file:
                    for count, records in iter_training_batches(file, _parse):
                        yielded |= bool(count)
                        yield count, records
        except (OSError, ValueError) as exc:
            logger.warning('Could not read training log %s: %s', path, exc)
    if not yielded:
        yield from iter_training_batches(_iter_logs_from_model(), _parse)


def _iter_csv_logs(path: str):
    """Read CSV log files produced by AIWAFLoggerMiddleware and convert to log lines."""
    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = row.get("timestamp", "")
                if not timestamp:
                    continue
                try:
                    dt = datetime.fromisoformat(timestamp)
                except ValueError:
                    continue
                timestamp_str = dt.strftime("%d/%b/%Y:%H:%M:%S %z")
                log_line = (
                    f'{row.get("ip", "-")} - - [{timestamp_str}] '
                    f'"{row.get("method", "GET")} {row.get("path", "/")} HTTP/1.1" '
                    f'{row.get("status_code", "200")} {row.get("content_length", "-")} '
                    f'"{row.get("referer", "-")}" "{row.get("user_agent", "-")}" '
                    f'response-time={row.get("response_time", "0")}\n'
                )
                yield log_line
    except Exception:
        return


def _get_logs_from_model() -> list[str]:
    return list(_iter_logs_from_model())


def _iter_logs_from_model():
    """Get log data from RequestLog model when log files are not available"""
    try:
        # Import here to avoid circular imports
        from .models import RequestLog
        from datetime import datetime, timedelta
        
        # Get logs from the last 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        request_logs = RequestLog.objects.filter(timestamp__gte=cutoff_date).order_by('timestamp').iterator(chunk_size=2000)

        count = 0
        for log in request_logs:
            # Convert RequestLog to Apache-style log format that _parse() expects
            # Format: IP - - [timestamp] "METHOD path HTTP/1.1" status content_length "referer" "user_agent" response-time=X.X
            timestamp_str = log.timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")
            log_line = (
                f'{log.ip_address} - - [{timestamp_str}] '
                f'"{log.method} {log.path} HTTP/1.1" {log.status_code} '
                f'{log.content_length} "{log.referer}" "{log.user_agent}" '
                f'response-time={log.response_time}\n'
            )
            count += 1
            yield log_line

        logger.info(f"Loaded {count} log entries from RequestLog model")
    except Exception as e:
        logger.warning("Could not load logs from RequestLog model: %s", e, exc_info=True)
        return


def _should_use_rust_features() -> bool:
    return rust_available()


def _extract_rust_features_parallel(records, static_keywords, chunk_size, max_workers):
    return core_extract_rust_features_parallel(
        records,
        static_keywords,
        chunk_size,
        max_workers,
        rust_extract_features,
    )


_iter_batches = core_iter_batches
_python_feature_from_record = core_python_feature_from_record


def _python_features_batched(records, ip_times, static_kw, batch_size: int, parallel_enabled: bool, parallel_chunk_size: int, max_workers: int):
    if not records:
        return []

    batch_size = max(1, int(batch_size))
    parallel_chunk_size = max(1, int(parallel_chunk_size))
    max_workers = max(1, int(max_workers))

    features = []
    if parallel_enabled and max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for batch in core_iter_batches(records, batch_size):
                if len(batch) >= parallel_chunk_size:
                    features.extend(list(executor.map(lambda r: core_python_feature_from_record(r, ip_times, static_kw), batch)))
                else:
                    features.extend([core_python_feature_from_record(r, ip_times, static_kw) for r in batch])
        return features

    for batch in core_iter_batches(records, batch_size):
        features.extend([core_python_feature_from_record(r, ip_times, static_kw) for r in batch])
    return features


def _generate_feature_dicts(parsed, ip_404, ip_times):
    if parsed and _should_use_rust_features():
        raw_features = core_extract_raw_features(
            parsed, ip_404, path_exists_in_django, is_exempt_path, STATUS_IDX, STATIC_KW
        )
        if raw_features is not None and len(raw_features) == len(parsed):
            return raw_features
    records = core_build_records(parsed, ip_404, path_exists_in_django, is_exempt_path, STATUS_IDX)

    if records and _should_use_rust_features():
        rust_payload = core_rust_payload_from_records(records)

        if rust_supports_chunked_features():
            rust_chunk_size = max(1, int(getattr(settings, "AIWAF_RUST_FEATURE_CHUNK_SIZE", 5000)))
            rust_state = None
            rust_features = []
            for batch in core_iter_batches(rust_payload, rust_chunk_size):
                batch_features, rust_state = rust_extract_features_batch(batch, STATIC_KW, rust_state)
                if batch_features is not None:
                    rust_features.extend(batch_features)
            tail_features = rust_finalize_feature_state(STATIC_KW, rust_state)
            if tail_features:
                rust_features.extend(tail_features)
            if rust_features:
                return rust_features
        else:
            parallel_enabled = getattr(settings, "AIWAF_RUST_PARALLEL_FEATURES", True)
            parallel_chunk_size = max(1, int(getattr(settings, "AIWAF_RUST_PARALLEL_CHUNK_SIZE", 5000)))
            configured_workers = int(getattr(settings, "AIWAF_RUST_PARALLEL_WORKERS", 0))
            max_workers = configured_workers if configured_workers > 0 else max(1, min((os.cpu_count() or 1), 32))

            if parallel_enabled and max_workers > 1 and len(rust_payload) > parallel_chunk_size:
                parallel_features = _extract_rust_features_parallel(
                    rust_payload,
                    STATIC_KW,
                    parallel_chunk_size,
                    max_workers,
                )
                if parallel_features is not None:
                    return parallel_features

            rust_features = rust_extract_features(rust_payload, STATIC_KW)
            if rust_features is not None:
                return rust_features

    python_batch_size = int(getattr(settings, "AIWAF_PYTHON_FEATURE_BATCH_SIZE", 2000))
    python_parallel_enabled = bool(getattr(settings, "AIWAF_PYTHON_PARALLEL_FEATURES", True))
    python_parallel_chunk_size = int(getattr(settings, "AIWAF_PYTHON_PARALLEL_CHUNK_SIZE", python_batch_size))
    configured_workers = int(getattr(settings, "AIWAF_PYTHON_PARALLEL_WORKERS", 0))
    python_workers = configured_workers if configured_workers > 0 else max(1, min((os.cpu_count() or 1), 32))

    return _python_features_batched(
        records,
        ip_times,
        STATIC_KW,
        batch_size=python_batch_size,
        parallel_enabled=python_parallel_enabled,
        parallel_chunk_size=python_parallel_chunk_size,
        max_workers=python_workers,
    )


def _parse(line: str) -> dict | None:
    return core_parse_log_line(line)


_DEFAULT_PARSE = _parse


def _is_malicious_context_trainer(path: str, keyword: str, status: str = "404") -> bool:
    return core_is_malicious_context(path, keyword, status, STATIC_KW, path_exists_in_django)


def _print_geoip_summary(ips, title):
    if not ips:
        return
    db_path = getattr(
        settings,
        "AIWAF_GEOIP_DB_PATH",
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "core",
            "geolock",
            "ipinfo_lite.mmdb",
        ),
    )
    if not db_path or not os.path.exists(db_path):
        logger.info("GeoIP summary skipped: AIWAF_GEOIP_DB_PATH not set or file missing.")
        return

    counts = Counter()
    unknown = 0
    for ip in ips:
        name = lookup_country_name(ip, cache_prefix=None, cache_seconds=None)
        if name:
            counts[name] += 1
        else:
            unknown += 1

    if not counts and not unknown:
        return

    top = counts.most_common(10)
    logger.info(title)
    for code, cnt in top:
        logger.info(f"  - {code}: {cnt}")
    if unknown:
        logger.info(f"  - UNKNOWN: {unknown}")


def _print_geoip_blocklist_summary():
    blocklist_store = get_blocklist_store()
    try:
        blocked_ips = blocklist_store.get_all_blocked_ips()
    except Exception:
        blocked_ips = []

    if not blocked_ips:
        return

    _print_geoip_summary(blocked_ips, "GeoIP summary for blocked IPs (top 10):")


@guard_training(lambda *args, **kwargs: getattr(settings, 'AIWAF_TRAINING_STATE_DIR', _resolve_csv_data_dir()))
def train(disable_ai=False, force_ai=False) -> None:
    """Enhanced training with improved keyword filtering and exemption handling
    
    Args:
        disable_ai (bool): If True, skip AI model training and only do keyword learning
        force_ai (bool): If True, train AI model even with fewer than MIN_AI_LOGS
    """
    logger.info("Starting AIWAF enhanced training...")
    
    if disable_ai:
        logger.info("AI model training disabled - keyword learning only")
    
    # Remove exempt keywords first
    remove_exempt_keywords()
    
    # Remove any IPs in IPExemption from the blocklist using BlocklistManager
    exemption_store = get_exemption_store()
    
    exempted_ips = [entry['ip_address'] for entry in exemption_store.get_all()]
    if exempted_ips:
        logger.info(f"Found {len(exempted_ips)} exempted IPs - clearing from blocklist")
        for ip in exempted_ips:
            BlocklistManager.unblock(ip)
    
    parsed_count = 0
    ip_404   = defaultdict(int)
    ip_404_login = defaultdict(int)  # Track 404s on login paths separately
    ip_times = defaultdict(list)
    seen_any_lines = False
    evidence = current_evidence()
    fresh_records = []
    fresh_404, fresh_login, fresh_times = defaultdict(int), defaultdict(int), defaultdict(list)

    # Pass 1: collect aggregate stats only (no full parsed list in memory)
    use_native_preparation = _is_csv_mode() and _parse is _DEFAULT_PARSE
    exemption_cache = {}
    def _aggregate_exempt(path):
        if path not in exemption_cache:
            exemption_cache[path] = is_exempt_path(path)
        return exemption_cache[path]
    for line_count, records in _training_batches(use_native_preparation):
        seen_any_lines |= bool(line_count)
        parsed_count += len(records)
        fresh = evidence.fresh(records)
        if evidence.had_history:
            fresh_records.extend(fresh)
        fresh_errors, fresh_exempt_errors, fresh_ip_times = aggregate_training_records(fresh, _aggregate_exempt)
        for ip, count in fresh_errors.items():
            fresh_404[ip] += count
        for ip, count in fresh_exempt_errors.items():
            fresh_login[ip] += count
        for ip, values in fresh_ip_times.items():
            fresh_times[ip].extend(values)
        errors, exempt_errors, times = aggregate_training_records(records, _aggregate_exempt)
        for ip, count in errors.items():
            ip_404[ip] += count
        for ip, count in exempt_errors.items():
            ip_404_login[ip] += count
        for ip, values in times.items():
            ip_times[ip].extend(values)

    if not seen_any_lines:
        logger.info("No log lines found  check AIWAF_ACCESS_LOG setting.")
        return

    if parsed_count < MIN_TRAIN_LOGS:
        logger.info(f"Not enough log lines ({parsed_count}) for training. Need at least {MIN_TRAIN_LOGS}.")
        return

    # 3. Optional immediate 404flood blocking (only for non-login paths)
    for ip, count in fresh_404.items():
        if count >= 6:
            # Only block if they have significant non-login 404s
            login_404s = fresh_login.get(ip, 0)
            total_404s = count + login_404s
            
            # Don't block if majority of 404s are on login paths
            if count > login_404s:  # More non-login 404s than login 404s
                if getattr(settings, 'AIWAF_ENABLE_IP_BLOCKING', True) and not exemption_store.is_exempted(ip):
                    evidence.block(ip, lambda: BlocklistManager.block(ip, f"Excessive 404s (≥6 non-login, {count}/{total_404s})"))

    keyword_learning_enabled = getattr(settings, "AIWAF_ENABLE_KEYWORD_LEARNING", True)
    legitimate_keywords = get_legitimate_keywords() if keyword_learning_enabled else set()
    tokens = Counter()
    token_example_paths = defaultdict(list)

    # Pass 2: build features and keyword candidates.
    use_rust_features = _should_use_rust_features()
    rust_streaming_enabled = use_rust_features and rust_supports_chunked_features()
    builder_class = native_function('NativeTrainingBuilder') if use_native_preparation and rust_streaming_enabled else None
    native_builder = builder_class() if builder_class else None
    rust_chunk_size = max(1, int(getattr(settings, "AIWAF_RUST_FEATURE_CHUNK_SIZE", 5000)))
    if use_rust_features and not rust_streaming_enabled:
        logger.info("Rust streaming feature extraction unavailable; using single-batch Rust extraction.")
    rust_state = None
    rust_batch = [] if rust_streaming_enabled else None
    rust_payload = [] if use_rust_features else None
    feature_dicts = []

    python_batch_size = max(1, int(getattr(settings, "AIWAF_PYTHON_FEATURE_BATCH_SIZE", 2000)))
    python_parallel_enabled = bool(getattr(settings, "AIWAF_PYTHON_PARALLEL_FEATURES", True))
    python_parallel_chunk_size = max(1, int(getattr(settings, "AIWAF_PYTHON_PARALLEL_CHUNK_SIZE", python_batch_size)))
    configured_workers = int(getattr(settings, "AIWAF_PYTHON_PARALLEL_WORKERS", 0))
    python_workers = configured_workers if configured_workers > 0 else max(1, min((os.cpu_count() or 1), 32))
    python_batch = [] if not use_rust_features else None
    python_executor = (
        ThreadPoolExecutor(max_workers=python_workers)
        if (python_batch is not None and python_parallel_enabled and python_workers > 1)
        else None
    )

    known_cache = {}
    exempt_cache = {}

    def _flush_python_batch():
        nonlocal python_batch
        if not python_batch:
            return

        if python_executor is not None and len(python_batch) >= python_parallel_chunk_size:
            feature_dicts.extend(list(python_executor.map(lambda r: core_python_feature_from_record(r, ip_times, STATIC_KW), python_batch)))
        else:
            feature_dicts.extend([core_python_feature_from_record(r, ip_times, STATIC_KW) for r in python_batch])
        python_batch = []

    def _cached_exists(path):
        if path not in known_cache:
            known_cache[path] = path_exists_in_django(path)
        return known_cache[path]

    def _cached_exempt(path):
        if path not in exempt_cache:
            exempt_cache[path] = is_exempt_path(path)
        return exempt_cache[path]

    def _feature_records():
        for _, records in _training_batches(use_native_preparation):
            counts = (count_training_keywords(records, _cached_exists, _cached_exempt, STATIC_KW, legitimate_keywords)
                      if keyword_learning_enabled and use_native_preparation else None)
            if counts is not None:
                for keyword, count, examples in counts:
                    tokens[keyword] += count
                    remaining = 5 - len(token_example_paths[keyword])
                    token_example_paths[keyword].extend(examples[:remaining])
            for record in records:
                yield record, counts is not None

    for rec, keywords_counted in _feature_records():

        path = rec["path"]
        known_path = known_cache.get(path)
        if known_path is None:
            known_path = path_exists_in_django(path)
            known_cache[path] = known_path

        exempt = exempt_cache.get(path)
        if exempt is None:
            exempt = is_exempt_path(path)
            exempt_cache[path] = exempt

        kw_check = (not known_path) and (not exempt)
        status_idx = STATUS_IDX.index(rec["status"]) if rec["status"] in STATUS_IDX else -1
        if use_rust_features:
            rust_record = {
                "ip": rec["ip"],
                "path_lower": path.lower(),
                "path_len": len(path),
                "timestamp": rec["timestamp"].timestamp(),
                "response_time": rec["response_time"],
                "status_idx": status_idx,
                "kw_check": kw_check,
                "total_404": ip_404.get(rec["ip"], 0),
            }
            if rust_streaming_enabled:
                rust_batch.append(rust_record)
                if len(rust_batch) >= rust_chunk_size:
                    if native_builder is not None:
                        native_builder.add_batch(rust_batch, STATIC_KW)
                    else:
                        batch_features, rust_state = rust_extract_features_batch(rust_batch, STATIC_KW, rust_state)
                        if batch_features is not None:
                            feature_dicts.extend(batch_features)
                    rust_batch = []
            else:
                rust_payload.append(rust_record)
        else:
            python_batch.append({
                "ip": rec["ip"],
                "path_len": len(path),
                "resp_time": rec["response_time"],
                "status_idx": status_idx,
                "timestamp": rec["timestamp"],
                "path_lower": path.lower(),
                "kw_check": kw_check,
                "total_404": ip_404.get(rec["ip"], 0),
            })
            if len(python_batch) >= python_batch_size:
                _flush_python_batch()

        if keyword_learning_enabled and not keywords_counted and rec["status"].startswith(("4", "5")) and not known_path and not exempt:
            path_lower = path.lower()
            for seg in re.split(r"\W+", path_lower):
                if (len(seg) > 3 and
                    seg not in STATIC_KW and
                    seg not in legitimate_keywords and
                    _is_malicious_context_trainer(path, seg, rec["status"])):
                    tokens[seg] += 1
                    if len(token_example_paths[seg]) < 5:
                        token_example_paths[seg].append(path)

    if python_batch is not None:
        _flush_python_batch()
    if python_executor is not None:
        python_executor.shutdown(wait=True)

    if rust_streaming_enabled and rust_batch:
        if native_builder is not None:
            native_builder.add_batch(rust_batch, STATIC_KW)
        else:
            batch_features, rust_state = rust_extract_features_batch(rust_batch, STATIC_KW, rust_state)
            if batch_features is not None:
                feature_dicts.extend(batch_features)
        rust_batch = []

    if rust_streaming_enabled and native_builder is None:
        tail_features = rust_finalize_feature_state(STATIC_KW, rust_state)
        if tail_features:
            feature_dicts.extend(tail_features)

    if use_rust_features and not rust_streaming_enabled and rust_payload:
        parallel_enabled = getattr(settings, "AIWAF_RUST_PARALLEL_FEATURES", True)
        parallel_chunk_size = max(1, int(getattr(settings, "AIWAF_RUST_PARALLEL_CHUNK_SIZE", rust_chunk_size)))
        configured_workers = int(getattr(settings, "AIWAF_RUST_PARALLEL_WORKERS", 0))
        max_workers = configured_workers if configured_workers > 0 else max(1, min((os.cpu_count() or 1), 32))

        if parallel_enabled and max_workers > 1 and len(rust_payload) > parallel_chunk_size:
            parallel_features = _extract_rust_features_parallel(
                rust_payload,
                STATIC_KW,
                parallel_chunk_size,
                max_workers,
            )
            if parallel_features is None:
                feature_dicts = rust_extract_features(rust_payload, STATIC_KW) or []
            else:
                feature_dicts = parallel_features
        else:
            feature_dicts = rust_extract_features(rust_payload, STATIC_KW) or []

    if native_builder is not None:
        feature_dicts = native_builder.finish()
    if not feature_dicts:
        logger.info(" Nothing to train on  no valid log entries.")
        return

    # AI Model Training (optional)
    blocked_count = 0
    force_ai = force_ai or getattr(settings, "AIWAF_FORCE_AI_TRAINING", False)
    use_rust_ai = (_should_use_rust_features() and rust_isolation_forest_available()
                   and getattr(settings, 'AIWAF_RUST_ISOLATION_FOREST', True))
    if not disable_ai and not force_ai and parsed_count < MIN_AI_LOGS:
        logger.info(f"AI training skipped: {parsed_count} log lines < {MIN_AI_LOGS}. Falling back to keyword-only.")
        disable_ai = True

    if not disable_ai:
        if not PANDAS_AVAILABLE and not use_rust_ai:
            logger.info("AI model training skipped - pandas not available.")
            disable_ai = True
        elif not SKLEARN_AVAILABLE and not use_rust_ai:
            logger.info("AI model training skipped - scikit-learn not available and Rust backend unavailable.")
            disable_ai = True

    if not disable_ai:
        logger.info(" Training AI anomaly detection model...")
        
        try:
            contamination = getattr(settings, "AIWAF_AI_CONTAMINATION", 0.05)
            model = None
            metadata = {}

            if use_rust_ai:
                native_batch = hasattr(feature_dicts, 'fit_predict')
                feature_cols = feature_dicts.feature_columns() if native_batch else list(dict.fromkeys(key for row in feature_dicts for key in row if key != 'ip'))
                X = feature_dicts if native_batch else [[float(row.get(key, float('nan'))) for key in feature_cols] for row in feature_dicts]
                rust_cls = rust_isolation_forest_class()
                if rust_cls is None:
                    raise RuntimeError("Rust IsolationForest class unavailable")
                model = rust_cls(
                    n_estimators=getattr(settings, "AIWAF_AI_N_ESTIMATORS", 100),
                    max_samples=getattr(settings, "AIWAF_AI_MAX_SAMPLES", "auto"),
                    contamination=contamination,
                    max_features=getattr(settings, "AIWAF_AI_MAX_FEATURES", 1.0),
                    bootstrap=getattr(settings, "AIWAF_AI_BOOTSTRAP", False),
                    random_state=getattr(settings, "AIWAF_AI_RANDOM_STATE", 42),
                    warm_start=getattr(settings, "AIWAF_AI_WARM_START", False),
                )
                native_statistics = X.fit_predict(model) if native_batch else None
                if not native_batch:
                    model.fit(X)
                model_data = rust_model_artifact(model, feature_cols, len(X), "django")
                metadata = dict(model_data)
            else:
                if hasattr(feature_dicts, 'to_dicts'):
                    feature_dicts = feature_dicts.to_dicts()
                df = pd.DataFrame(feature_dicts)
                feature_cols = [c for c in df.columns if c != "ip"]
                X = df[feature_cols].astype(float).values
                model = IsolationForest(
                    contamination=contamination,
                    random_state=42
                )
                
                # Suppress sklearn warnings during training
                import warnings
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
                    model.fit(X)

                import sklearn
                model_data = sklearn_model_artifact(
                    model,
                    sklearn.__version__,
                    feature_cols,
                    len(X),
                    "django",
                )
                metadata = {
                    "sklearn_version": sklearn.__version__,
                    "created_at": model_data["created_at"],
                    "feature_count": len(feature_cols),
                    "samples_count": len(X),
                }
            if save_model_data(model_data, metadata=metadata):
                logger.info(f"Model trained on {len(X)} samples")
            else:
                fallback = getattr(settings, "AIWAF_MODEL_STORAGE_FALLBACK", True)
                if fallback and can_serialize_model_artifact(model_data):
                    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
                    dump_model_artifact(model_data, MODEL_PATH)
                    logger.info(f"Model trained on {len(X)} samples  {MODEL_PATH}")
                else:
                    logger.info("Model trained, but no safe JSON-serializable artifact was available to save.")
            if metadata.get("model_backend") == "aiwaf_rust":
                logger.info("Created with aiwaf-rust IsolationForest backend")
            else:
                logger.info(f"Created with scikit-learn v{metadata['sklearn_version']}")
            
            # Check for anomalies and intelligently decide which IPs to block
            if evidence.had_history:
                fresh_features = _generate_feature_dicts(fresh_records, fresh_404, fresh_times) if fresh_records else []
                statistics = fresh_anomaly_statistics(model, feature_cols, fresh_features)
            elif use_rust_ai and native_batch:
                statistics = native_statistics
            else:
                preds = model.predict(X)
                statistics = anomaly_statistics(feature_dicts, preds)
            anomalous_ips = set(statistics)
            
            if anomalous_ips:
                logger.info(f"Detected {len(anomalous_ips)} potentially anomalous IPs during training")
                _print_geoip_summary(anomalous_ips, "GeoIP summary for anomalous IPs (top 10):")
                
                exemption_store = get_exemption_store()
                blocklist_store = get_blocklist_store()
                
                for ip in anomalous_ips:
                    # Skip if IP is exempted
                    if not getattr(settings, 'AIWAF_ENABLE_IP_BLOCKING', True) or exemption_store.is_exempted(ip):
                        continue
                    
                    # Get this IP's behavior from the data
                    
                    # Criteria to determine if this is likely a legitimate user vs threat:
                    avg_kw_hits, max_404s, avg_burst, total_requests = statistics[ip]
                    
                    # Treat pure-burst traffic with no 404s/keywords as legitimate (e.g., polling)
                    if max_404s == 0 and avg_kw_hits == 0:
                        logger.info(f"   - {ip}: Anomalous but looks legitimate (no 404s/keywords, burst:{avg_burst:.1f}) - NOT blocking")
                        continue

                    # Don't block if it looks like legitimate behavior:
                    if (
                        avg_kw_hits < 2 and           # Not hitting many malicious keywords
                        max_404s < 10 and            # Not excessive 404s
                        avg_burst < 15 and           # Not excessive burst activity
                        total_requests < 100         # Not excessive total requests
                    ):
                        logger.info(f"   - {ip}: Anomalous but looks legitimate (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f}) - NOT blocking")
                        continue
                    
                    # Block if it shows clear signs of malicious behavior
                    blocked_count += evidence.block(ip, lambda: BlocklistManager.block(ip, f"AI anomaly + suspicious patterns (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})"))
                    logger.info(f"   - {ip}: Blocked for suspicious behavior (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})")
                
                logger.info(f"    Blocked {blocked_count}/{len(anomalous_ips)} anomalous IPs (others looked legitimate)")
        
        except TrainingEvidenceError:
            raise
        except ImportError as e:
            logger.info(f"AI model training failed - missing dependencies: {e}")
            logger.info("   Continuing with keyword learning only...")
        except Exception as e:
            logger.info(f"AI model training failed: {e}")
            logger.info("   Continuing with keyword learning only...")
    else:
        logger.info("AI model training skipped (disabled)")

    filtered_tokens = []
    if keyword_learning_enabled:
        logger.info(f"Learning keywords from {parsed_count} parsed requests...")

        keyword_store = get_keyword_store()
        top_tokens = tokens.most_common(getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10))
        
        # Additional filtering: only add keywords that appear suspicious enough AND in malicious context
        learned_from_paths = []  # Track which paths we learned from
        
        for kw, cnt in top_tokens:
            example_paths = token_example_paths.get(kw, [])
            
            # Only add if keyword appears in malicious contexts
            if (cnt >= 2 and  # Must appear at least twice
                len(kw) >= 4 and  # Must be at least 4 characters
                kw not in legitimate_keywords and  # Not in legitimate set
                example_paths and  # Has example paths
                any(_is_malicious_context_trainer(path, kw) for path in example_paths[:3])):  # Check first 3 paths
                
                filtered_tokens.append((kw, cnt))
                if not (_is_csv_mode() and hasattr(keyword_store, 'update_keywords')):
                    keyword_store.add_keyword(kw, cnt)
                learned_from_paths.extend(example_paths[:2])  # Track first 2 example paths
        if filtered_tokens and _is_csv_mode() and hasattr(keyword_store, 'update_keywords'):
            keyword_store.update_keywords(added=filtered_tokens)
        
        if filtered_tokens:
            logger.info(f"Added {len(filtered_tokens)} suspicious keywords: {[kw for kw, _ in filtered_tokens]}")
            logger.info(f"Example malicious paths learned from: {learned_from_paths[:5]}")  # Show first 5
        else:
            logger.info("No new suspicious keywords learned (good sign!)")
        
        logger.info(f"Smart keyword learning complete. Excluded {len(legitimate_keywords)} legitimate keywords.")
        logger.info(f"Used malicious context analysis to filter out false positives.")
    else:
        logger.info("Keyword learning disabled via AIWAF_ENABLE_KEYWORD_LEARNING.")

    _print_geoip_blocklist_summary()

    # Training summary
    logger.info("\n" + "="*60)
    if disable_ai:
        logger.info("AIWAF KEYWORD-ONLY TRAINING COMPLETE")
    else:
        logger.info("AIWAF ENHANCED TRAINING COMPLETE")
    logger.info("="*60)
    logger.info(f"Training Data: {parsed_count} log entries processed")
    
    if not disable_ai:
        logger.info(f"AI Model: Trained with {len(feature_cols) if 'feature_cols' in locals() else 'N/A'} features")
        logger.info(f"Blocked IPs: {blocked_count} suspicious IPs blocked")
    else:
        logger.info(f"AI Model: Disabled (keyword learning only)")
        logger.info(f"Blocked IPs: 0 (AI blocking disabled)")
        
    logger.info(f"Keywords: {len(filtered_tokens)} new suspicious keywords learned")
    logger.info(f"Exemptions: {len(exempted_ips)} IPs protected from blocking")
    
    if disable_ai:
        logger.info(f"Keyword-based protection now active with context-aware filtering!")
    else:
        logger.info(f"Enhanced protection now active with context-aware filtering!")
    logger.info("="*60)


# Compatibility aliases for callers using the previous terminology.
get_blacklist_store = get_blocklist_store
BlacklistManager = BlocklistManager
