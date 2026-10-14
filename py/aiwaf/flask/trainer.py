#!/usr/bin/env python3
"""
AI Training Module for AIWAF Flask

Replicates the Django training functionality for Flask applications.
Trains machine learning models and learns keywords from access logs.
"""

import os
import glob
import gzip
import re
import csv
import json
import logging
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Dict, Optional, Set, Any

# Try to import AI dependencies
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None

try:
    from sklearn.ensemble import IsolationForest
    import sklearn
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    IsolationForest = None
    sklearn = None

AI_AVAILABLE = PANDAS_AVAILABLE

# Flask imports
from flask import Flask, current_app

# AIWAF imports
from .storage import get_exemption_store, get_keyword_store, _get_storage_mode, _read_csv_blacklist, _get_data_dir
from .blacklist_manager import BlacklistManager
from .utils import is_exempt, is_path_exempt
from .geoip import lookup_country_name
from aiwaf.core.constants import STATUS_IDX as CORE_STATUS_IDX
from aiwaf.core.logs import parse_log_line as core_parse_log_line
from aiwaf.core.training_pipeline import parse_training_logs, iter_csv_training_batches, aggregate_training_records, learn_training_keywords, anomaly_statistics
from aiwaf.core.training_evidence import guard_training, current_evidence, fresh_anomaly_statistics, TrainingEvidenceError
from aiwaf.core.training import extract_rust_features_parallel as core_extract_rust_features_parallel
from aiwaf.core.training_logic import is_malicious_context as core_is_malicious_context
from aiwaf.core.training_features import (
    extract_native_batch,
    build_records as core_build_records,
    extract_raw_features as core_extract_raw_features,
    rust_payload_from_records as core_rust_payload_from_records,
    python_features_batched as core_python_features_batched,
)
from aiwaf.core.model_artifacts import rust_model_artifact, sklearn_model_artifact
from aiwaf.core.model_serialization import dump_model_artifact
from aiwaf.core.rust_backend import (
    rust_available,
    rust_isolation_forest_available,
    rust_isolation_forest_class as get_isolation_forest_class,
    extract_features as rust_extract_features,
    supports_chunked_feature_extraction as rust_supports_chunked_features,
    extract_features_batch as rust_extract_features_batch,
    finalize_feature_state as rust_finalize_feature_state,
)

logger = logging.getLogger(__name__)

#  Configuration 
DEFAULT_LOG_DIR = 'logs'

def get_default_model_path():
    """Get the default model path relative to the package."""
    import os
    from pathlib import Path
    
    # Get the directory where this trainer.py file is located
    trainer_dir = Path(__file__).parent
    resources_dir = trainer_dir / 'resources'
    
    # Ensure resources directory exists
    resources_dir.mkdir(exist_ok=True)
    
    return str(resources_dir / 'model.json')

DEFAULT_MODEL_PATH = get_default_model_path()

STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "config", "shell", "filemanager"]
STATUS_IDX = CORE_STATUS_IDX


def _extract_rust_features_parallel(records, static_keywords, chunk_size, max_workers):
    return core_extract_rust_features_parallel(
        records,
        static_keywords,
        chunk_size,
        max_workers,
        rust_extract_features,
    )

_LOG_RX_PATTERNS = None

class FlaskAITrainer:
    """AI Trainer for Flask AIWAF"""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self._route_keywords: Optional[Set[str]] = None
        
    def init_app(self, app: Flask):
        """Initialize with Flask app"""
        self.app = app
        
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        if self.app:
            return self.app.config.get(key, default)
        return default
    
    def path_exists_in_flask(self, path: str) -> bool:
        """Check if a path exists in Flask URL routes"""
        if not self.app:
            return False
        
        # Remove query params and normalize
        candidate = path.split("?")[0].strip("/")
        
        # Try exact resolution first
        try:
            self.app.url_map.bind("").match(f"/{candidate}", method='GET')
            return True
        except:
            pass
        
        # Try with trailing slash
        if not candidate.endswith("/"):
            try:
                self.app.url_map.bind("").match(f"/{candidate}/", method='GET')
                return True
            except:
                pass
        
        # Try without trailing slash
        if candidate.endswith("/"):
            try:
                self.app.url_map.bind("").match(f"/{candidate.rstrip('/')}", method='GET')
                return True
            except:
                pass
        
        return False
    
    def remove_exempt_keywords(self) -> None:
        """Remove exempt keywords from dynamic keyword storage"""
        keyword_store = get_keyword_store()
        exempt_tokens = set()
        
        # Extract tokens from exempt paths
        exempt_paths = self.get_config("AIWAF_EXEMPT_PATHS", set())
        for path in exempt_paths:
            for seg in re.split(r"\W+", str(path).strip("/").lower()):
                if len(seg) > 3:
                    exempt_tokens.add(seg)
        
        # Add explicit exempt keywords from settings
        explicit_exempt = self.get_config("AIWAF_EXEMPT_KEYWORDS", [])
        exempt_tokens.update(explicit_exempt)
        
        # Add legitimate path keywords
        allowed_path_keywords = self.get_config("AIWAF_ALLOWED_PATH_KEYWORDS", [])
        exempt_tokens.update(allowed_path_keywords)
        
        # Remove exempt tokens from keyword storage
        if exempt_tokens and hasattr(keyword_store, 'update_keywords'):
            keyword_store.update_keywords(removed=exempt_tokens)
        else:
            for token in exempt_tokens:
                keyword_store.remove_keyword(token)
        
        if exempt_tokens:
            logger.info(f" Removed {len(exempt_tokens)} exempt keywords from learning: {list(exempt_tokens)[:10]}")
    
    def get_legitimate_keywords(self) -> set[str]:
        """Get all legitimate keywords that shouldn't be learned as suspicious"""
        from aiwaf.core.training_logic import get_default_legitimate_keywords
        legitimate = get_default_legitimate_keywords()
        
        # Extract keywords from Flask routes
        legitimate.update(self._extract_flask_route_keywords())
        
        # Add from Flask config
        allowed_path_keywords = self.get_config("AIWAF_ALLOWED_PATH_KEYWORDS", [])
        legitimate.update(allowed_path_keywords)
        
        # Add exempt keywords
        exempt_keywords = self.get_config("AIWAF_EXEMPT_KEYWORDS", [])
        legitimate.update(exempt_keywords)
        
        return legitimate
    
    def _extract_flask_route_keywords(self) -> Set[str]:
        """Extract legitimate keywords from Flask URL patterns and blueprints"""
        if self._route_keywords is not None:
            return self._route_keywords
            
        keywords = set()
        
        if not self.app:
            self._route_keywords = keywords
            return keywords
        
        try:
            # Extract from URL rules
            for rule in self.app.url_map.iter_rules():
                # Extract from rule pattern
                rule_str = str(rule.rule)
                # Get literal path segments (not Flask variables)
                literal_parts = re.findall(r'/([a-zA-Z][a-zA-Z0-9_-]*)', rule_str)
                
                for part in literal_parts:
                    if len(part) > 2:
                        part_lower = part.lower()
                        keywords.add(part_lower)
                
                # Extract from endpoint name
                if rule.endpoint:
                    endpoint_parts = rule.endpoint.split('.')
                    for part in endpoint_parts:
                        for segment in re.split(r'[._-]', part.lower()):
                            if len(segment) > 2 and segment not in ['view', 'function']:
                                keywords.add(segment)
            
            # Extract from blueprint names
            for blueprint_name in self.app.blueprints:
                for segment in re.split(r'[._-]', blueprint_name.lower()):
                    if len(segment) > 2:
                        keywords.add(segment)
            
        except Exception as e:
            logger.info(f"Warning: Could not extract Flask route keywords: {e}")
        
        # Filter out common/generic words
        exclude_words = {
            'www', 'com', 'org', 'net', 'int', 'str', 'obj', 'get', 'set', 'put', 'del',
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her',
            'was', 'one', 'our', 'out', 'day', 'had', 'has', 'his', 'how', 'man', 'new',
            'now', 'old', 'see', 'two', 'who', 'boy', 'did', 'its', 'let', 'put', 'say',
            'she', 'too', 'use', 'var', 'way', 'may', 'end', 'why', 'any', 'app', 'run'
        }
        
        filtered_keywords = set()
        for keyword in keywords:
            if (len(keyword) >= 3 and 
                keyword not in exclude_words and
                not keyword.isdigit()):
                filtered_keywords.add(keyword)
        
        if filtered_keywords:
            logger.info(f" Extracted {len(filtered_keywords)} legitimate keywords from Flask routes")
        
        self._route_keywords = filtered_keywords
        return filtered_keywords
    
    def _read_all_logs(self) -> List[str]:
        """Read log lines from various sources"""
        lines = []
        
        # Try log files first
        log_dir = self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR)
        
        # Look for access log files
        access_log_files = [
            os.path.join(log_dir, 'access.log'),
            os.path.join(log_dir, 'aiwaf.log'),
            'access.log',
            'aiwaf.log'
        ]
        
        for log_path in access_log_files:
            if os.path.exists(log_path):
                logger.info(f" Reading logs from: {log_path}")
                with open(log_path, "r", errors="ignore") as f:
                    lines.extend(f.readlines())
                
                # Also check for rotated logs
                for p in sorted(glob.glob(f"{log_path}.*")):
                    opener = gzip.open if p.endswith(".gz") else open
                    try:
                        with opener(p, "rt", errors="ignore") as f:
                            lines.extend(f.readlines())
                    except OSError:
                        continue
                break
        
        # If no log files found, try CSV logs
        if not lines:
            lines = self._get_logs_from_csv()
        
        # If still no logs, try JSON logs
        if not lines:
            lines = self._get_logs_from_json()
        
        logger.info(f" Total log lines found: {len(lines)}")
        return lines
    
    _default_read_all = _read_all_logs

    def _load_training_csv(self):
        if getattr(self._parse, '__func__', None) is not self._default_parse.__func__:
            return None
        if getattr(self._read_all_logs, '__func__', None) is not self._default_read_all.__func__:
            return None
        root = Path(self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR))
        candidates = [root / 'access.log', root / 'aiwaf.log', Path('access.log'), Path('aiwaf.log')]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            with candidate.open(encoding='utf-8', errors='ignore') as file:
                header = file.readline()
            if not {'timestamp', 'ip', 'path', 'status_code'} <= set(next(csv.reader([header]), [])):
                return None
            parsed = []
            for file in [candidate, *sorted(candidate.parent.glob(candidate.name + '.*'))]:
                for _, batch in iter_csv_training_batches(file):
                    parsed.extend(batch)
            return parsed
        return None

    def _get_logs_from_csv(self) -> List[str]:
        """Get log data from CSV files"""
        lines = []
        log_dir = self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR)
        csv_files = glob.glob(os.path.join(log_dir, '*.csv'))
        
        for csv_file in csv_files:
            if 'access' in os.path.basename(csv_file) or 'aiwaf' in os.path.basename(csv_file):
                try:
                    with open(csv_file, 'r', newline='', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # Convert CSV to log format
                            if all(key in row for key in ['timestamp', 'ip', 'method', 'path', 'status_code']):
                                timestamp = row['timestamp']
                                ip = row['ip']
                                method = row.get('method', 'GET')
                                path = row['path']
                                status = row['status_code']
                                response_time = row.get('response_time_ms', '0')
                                user_agent = row.get('user_agent', '-')
                                referer = row.get('referer', '-')
                                
                                # Convert to Apache log format
                                log_line = (f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
                                          f'{status} 0 "{referer}" "{user_agent}" '
                                          f'response-time={float(response_time)/1000}\n')
                                lines.append(log_line)
                    
                    logger.info(f" Loaded {len(lines)} entries from CSV: {csv_file}")
                except Exception as e:
                    logger.info(f"Warning: Could not read CSV file {csv_file}: {e}")
        
        return lines
    
    def _get_logs_from_json(self) -> List[str]:
        """Get log data from JSON log files"""
        lines = []
        log_dir = self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR)
        json_files = glob.glob(os.path.join(log_dir, '*.json')) + glob.glob(os.path.join(log_dir, '*.jsonl'))
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', errors='ignore') as f:
                    for line in f:
                        try:
                            record = json.loads(line.strip())
                            
                            # Convert JSON to log format
                            if all(key in record for key in ['timestamp', 'ip', 'method', 'path', 'status_code']):
                                timestamp = record['timestamp']
                                ip = record['ip']
                                method = record.get('method', 'GET')
                                path = record['path']
                                status = record['status_code']
                                response_time = record.get('response_time', 0)
                                user_agent = record.get('user_agent', '-')
                                referer = record.get('referer', '-')
                                
                                # Convert to Apache log format
                                log_line = (f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
                                          f'{status} 0 "{referer}" "{user_agent}" '
                                          f'response-time={response_time}\n')
                                lines.append(log_line)
                        except json.JSONDecodeError:
                            continue
                
                logger.info(f" Loaded entries from JSON: {json_file}")
            except Exception as e:
                logger.info(f"Warning: Could not read JSON file {json_file}: {e}")
        
        return lines
    
    def _parse(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line using multiple regex patterns"""
        return core_parse_log_line(line)

    _default_parse = _parse
    
    def _is_malicious_context_trainer(self, path: str, keyword: str, status: str = "404") -> bool:
        return core_is_malicious_context(path, keyword, status, STATIC_KW, self.path_exists_in_flask)

    def _generate_feature_dicts(self, parsed, ip_404, ip_times):
        """Generate model feature dictionaries using Rust backends or Python fallback."""
        use_rust = rust_available()
        if getattr(self, '_native_training_handle', False):
            native_batch = extract_native_batch(parsed, ip_404, self.path_exists_in_flask,
                                                is_path_exempt, STATUS_IDX, STATIC_KW)
            if native_batch is not None:
                return native_batch
        if parsed and use_rust:
            raw_features = core_extract_raw_features(
                parsed, ip_404, self.path_exists_in_flask, is_path_exempt, STATUS_IDX, STATIC_KW
            )
            if raw_features is not None and len(raw_features) == len(parsed):
                return raw_features
        feature_dicts = []
        records = core_build_records(parsed, ip_404, self.path_exists_in_flask, is_path_exempt, STATUS_IDX)

        rust_streaming_enabled = use_rust and rust_supports_chunked_features()
        chunk_size_cfg = self.get_config(
            "AIWAF_RUST_FEATURE_CHUNK_SIZE",
            self.get_config("AIWAF_RUST_FEATURE_BATCH_SIZE", 5000),
        )
        try:
            rust_chunk_size = max(1, int(chunk_size_cfg))
        except (TypeError, ValueError):
            rust_chunk_size = 5000

        if use_rust and not rust_streaming_enabled:
            logger.info("Rust streaming feature extraction unavailable; using single-batch Rust extraction.")

        if use_rust and records:
            rust_state = None
            rust_batch = [] if rust_streaming_enabled else None
            rust_payload = [] if not rust_streaming_enabled else None
            for rust_record in core_rust_payload_from_records(records):
                if rust_streaming_enabled:
                    rust_batch.append(rust_record)
                    if len(rust_batch) >= rust_chunk_size:
                        batch_features, rust_state = rust_extract_features_batch(rust_batch, STATIC_KW, rust_state)
                        if batch_features is not None:
                            feature_dicts.extend(batch_features)
                        rust_batch = []
                else:
                    rust_payload.append(rust_record)

            if rust_streaming_enabled and rust_batch:
                batch_features, rust_state = rust_extract_features_batch(rust_batch, STATIC_KW, rust_state)
                if batch_features is not None:
                    feature_dicts.extend(batch_features)
                rust_batch = []

            if rust_streaming_enabled:
                tail_features = rust_finalize_feature_state(STATIC_KW, rust_state)
                if tail_features:
                    feature_dicts.extend(tail_features)

            if use_rust and not rust_streaming_enabled and rust_payload:
                parallel_enabled = self.get_config("AIWAF_RUST_PARALLEL_FEATURES", True)
                parallel_chunk_size = max(1, int(self.get_config("AIWAF_RUST_PARALLEL_CHUNK_SIZE", rust_chunk_size)))
                configured_workers = int(self.get_config("AIWAF_RUST_PARALLEL_WORKERS", 0))
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

        if feature_dicts:
            return feature_dicts

        try:
            python_batch_size = max(1, int(os.getenv("AIWAF_PYTHON_FEATURE_BATCH_SIZE", "5000")))
        except (TypeError, ValueError):
            python_batch_size = 5000
        try:
            python_parallel_chunk_size = max(1, int(os.getenv("AIWAF_PYTHON_PARALLEL_CHUNK_SIZE", str(python_batch_size))))
        except (TypeError, ValueError):
            python_parallel_chunk_size = python_batch_size

        python_parallel_enabled = os.getenv("AIWAF_PYTHON_PARALLEL_FEATURES", "").strip().lower() in {"1", "true", "yes", "on"}
        try:
            configured_workers = int(os.getenv("AIWAF_PYTHON_PARALLEL_WORKERS", "0"))
        except (TypeError, ValueError):
            configured_workers = 0
        max_workers = configured_workers if configured_workers > 0 else max(1, min((os.cpu_count() or 1), 32))

        return core_python_features_batched(
            records,
            ip_times,
            STATIC_KW,
            lambda items, size: (items[i:i + size] for i in range(0, len(items), size)),
            batch_size=python_batch_size,
            parallel_enabled=python_parallel_enabled,
            parallel_chunk_size=python_parallel_chunk_size,
            max_workers=max_workers,
        )
    
    @guard_training(lambda self, *args, **kwargs: self.get_config('AIWAF_TRAINING_STATE_DIR', _get_data_dir()))
    def train(self, disable_ai: bool = False) -> None:
        """Enhanced training with improved keyword filtering and exemption handling"""
        logger.info(" Starting AIWAF Flask enhanced training...")
        ai_available = AI_AVAILABLE or (
            self.get_config('AIWAF_USE_RUST', True)
            and self.get_config('AIWAF_RUST_ISOLATION_FOREST', True)
            and rust_available() and rust_isolation_forest_available())
        
        if not ai_available and not disable_ai:
            logger.info("  AI dependencies not available - switching to keyword-only mode")
            logger.info("   Install with: pip install aiwaf-flask[ai]")
            disable_ai = True
        
        if disable_ai:
            logger.info(" AI model training disabled - keyword learning only")
        
        # Remove exempt keywords first
        self.remove_exempt_keywords()
        
        # Remove any IPs in exemption from the blacklist
        # Note: Current storage system uses in-memory exemptions only
        exemption_store = get_exemption_store()
        # For now, we'll rely on the existing exemption system during blocking
        exempted_count = 0  # Since we can't easily get all exempted IPs
        
        prepared_csv = self._load_training_csv() if _get_storage_mode() == 'csv' else None
        raw_lines = self._read_all_logs() if prepared_csv is None else []
        input_count = len(raw_lines) if prepared_csv is None else len(prepared_csv)
        if not input_count:
            logger.info(" No log lines found  check AIWAF_LOG_DIR setting or log files.")
            return
        
        # Skip processing if we have too few entries
        if input_count < 50:
            logger.info(f"  Only {input_count} log entries found - need at least 50 for basic training")
            return
        
        # Check if we have enough data for AI training
        min_ai_threshold = current_app.config.get('AIWAF_MIN_AI_LOGS', 10000)
        force_ai = current_app.config.get('AIWAF_FORCE_AI', False)
        
        if not disable_ai and not force_ai and input_count < min_ai_threshold:
            logger.info(f"  Only {input_count} log entries found - need at least {min_ai_threshold} for AI training")
            logger.info("   Switching to keyword-only mode (use --force-ai to override or --disable-ai to suppress this warning)")
            disable_ai = True
        elif not disable_ai and force_ai and input_count < min_ai_threshold:
            logger.info(f"  Only {input_count} log entries found (recommended: {min_ai_threshold}+) but forcing AI training")

        logger.info(f" Parsing {input_count} log entries...")
        use_batch = (_get_storage_mode() == 'csv' and
                     getattr(self._parse, '__func__', None) is self._default_parse.__func__)
        parsed = (prepared_csv if prepared_csv is not None else parse_training_logs(raw_lines) if use_batch else
                  [record for line in raw_lines if (record := self._parse(line))])
        ip_404, ip_404_login, ip_times = aggregate_training_records(parsed, is_path_exempt)
        
        logger.info(f" Successfully parsed {len(parsed)} log entries")
        
        # Check if we have enough data
        if len(parsed) < 50:
            logger.info(f"  Only {len(parsed)} valid entries parsed - need at least 50 for basic training")
            return
        
        evidence = current_evidence()
        fresh = evidence.fresh(parsed)
        fresh_404, fresh_login, fresh_times = aggregate_training_records(fresh, is_path_exempt)
        # Fit on history, but enforce only against unconsumed requests.
        # 404 flood blocking (only for non-login paths)
        blocked_404_count = 0
        for ip, count in fresh_404.items():
            if count >= 6:
                login_404s = fresh_login.get(ip, 0)
                total_404s = count + login_404s
                
                if count > login_404s:
                    if self.get_config('AIWAF_ENABLE_IP_BLOCKING', True) and not exemption_store.is_exempted(ip):
                        blocked_404_count += evidence.block(ip, lambda: BlacklistManager.block(ip, f"Excessive 404s (>=6 non-login, {count}/{total_404s})"))
        
        if blocked_404_count > 0:
            logger.info(f" Blocked {blocked_404_count} IPs for excessive 404 errors")
        
        # Prepare feature data (prefer Rust if enabled)
        self._native_training_handle = bool(use_batch and not disable_ai
            and self.get_config('AIWAF_RUST_ISOLATION_FOREST', True))
        try:
            feature_dicts = self._generate_feature_dicts(parsed, ip_404, ip_times)
        finally:
            self._native_training_handle = False
        
        if not feature_dicts:
            logger.info(" Nothing to train on  no valid log entries.")
            return
        
        logger.info(f" Generated {len(feature_dicts)} feature vectors for training")
        
        # AI Model Training (optional)
        blocked_count = 0
        if not disable_ai and ai_available:
            logger.info(" Training AI anomaly detection model...")
            
            try:
                contamination = self.get_config("AIWAF_AI_CONTAMINATION", 0.05)
                use_rust_iforest = (
                    rust_available()
                    and self.get_config('AIWAF_USE_RUST', True)
                    and rust_isolation_forest_available()
                    and self.get_config("AIWAF_RUST_ISOLATION_FOREST", True)
                )
                if use_rust_iforest:
                    native_batch = hasattr(feature_dicts, 'fit_predict')
                    feature_cols = (feature_dicts.feature_columns() if native_batch else
                        list(dict.fromkeys(key for row in feature_dicts for key in row if key != 'ip')))
                    X = feature_dicts if native_batch else [[float(row.get(key, float('nan'))) for key in feature_cols] for row in feature_dicts]
                    model_cls = get_isolation_forest_class()
                    model = model_cls(
                        contamination=contamination,
                        random_state=42,
                    )
                    native_statistics = X.fit_predict(model) if native_batch else None
                    if not native_batch:
                        model.fit(X)
                else:
                    df = pd.DataFrame(feature_dicts)
                    feature_cols = [c for c in df.columns if c != "ip"]
                    X = df[feature_cols].astype(float).values
                    if not SKLEARN_AVAILABLE:
                        logger.info("  scikit-learn not available; cannot train sklearn IsolationForest")
                        return
                    model = IsolationForest(contamination=contamination, random_state=42)

                    # Suppress sklearn warnings during training
                    import warnings
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
                        model.fit(X)
                
                # Ensure model directory exists
                model_path = self.get_config("AIWAF_MODEL_PATH", DEFAULT_MODEL_PATH)
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                
                # Save model with metadata
                if use_rust_iforest:
                    model_data = rust_model_artifact(model, feature_cols, len(X), "flask")
                    dump_model_artifact(model_data, model_path)
                    logger.info(f" Model saved: {model_path}")
                    logger.info(f" Trained on {len(X)} samples with aiwaf-rust IsolationForest")
                else:
                    model_data = sklearn_model_artifact(
                        model,
                        sklearn.__version__,
                        feature_cols,
                        len(X),
                        "flask",
                    )
                    logger.info(" Sklearn model trained but not persisted; only JSON-safe Rust model artifacts are saved")
                    logger.info(f" Trained on {len(X)} samples with scikit-learn v{sklearn.__version__}")
                
                # Check for anomalies and intelligently decide which IPs to block
                if evidence.had_history:
                    fresh_features = self._generate_feature_dicts(fresh, fresh_404, fresh_times) if fresh else []
                    statistics = fresh_anomaly_statistics(model, feature_cols, fresh_features)
                elif use_rust_iforest and native_batch:
                    statistics = native_statistics
                else:
                    preds = model.predict(X)
                    statistics = anomaly_statistics(feature_dicts, preds)
                anomalous_ips = set(statistics)
                
                if anomalous_ips:
                    logger.info(f" Detected {len(anomalous_ips)} potentially anomalous IPs")
                    
                    exemption_store = get_exemption_store()
                    
                    for ip in anomalous_ips:
                        # Skip if IP is exempted
                        if not self.get_config('AIWAF_ENABLE_IP_BLOCKING', True) or exemption_store.is_exempted(ip):
                            continue
                        
                        # Get this IP's behavior from the data
                        # Criteria to determine if this is likely legitimate vs threat
                        avg_kw_hits, max_404s, avg_burst, total_requests = statistics[ip]
                        
                        # Don't block if it looks like legitimate behavior
                        if (
                            avg_kw_hits < 2 and           # Not hitting many malicious keywords
                            max_404s < 10 and            # Not excessive 404s
                            avg_burst < 15 and           # Not excessive burst activity
                            total_requests < 100         # Not excessive total requests
                        ):
                            logger.info(f"    {ip}: Anomalous but looks legitimate - NOT blocking")
                            continue

                        # High burst alone should not trigger blocking
                        if avg_kw_hits == 0 and max_404s == 0:
                            logger.info(f"    {ip}: Burst-only anomaly - NOT blocking")
                            continue
                        
                        # Block if it shows clear signs of malicious behavior
                        blocked_count += evidence.block(ip, lambda: BlacklistManager.block(ip, f"AI anomaly + suspicious patterns (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})"))
                        logger.info(f"    {ip}: Blocked for suspicious behavior")
                    
                    logger.info(f" Blocked {blocked_count}/{len(anomalous_ips)} anomalous IPs")
            
            except TrainingEvidenceError:
                raise
            except Exception as e:
                logger.info(f" AI model training failed: {e}")
                logger.info("   Continuing with keyword learning only...")
                disable_ai = True
        else:
            logger.info(" AI model training skipped")
            if not disable_ai:
                df = pd.DataFrame(feature_dicts)  # Still need df for some operations
        
        # Keyword Learning
        logger.info(" Learning suspicious keywords from logs...")
        
        tokens = Counter()
        legitimate_keywords = self.get_legitimate_keywords()
        
        keyword_path_exists_cache = {}
        keyword_path_exempt_cache = {}

        def _path_exists_cached(path):
            if path not in keyword_path_exists_cache:
                keyword_path_exists_cache[path] = self.path_exists_in_flask(path)
            return keyword_path_exists_cache[path]

        def _path_exempt_cached(path):
            if path not in keyword_path_exempt_cache:
                keyword_path_exempt_cache[path] = is_path_exempt(path)
            return keyword_path_exempt_cache[path]

        native_keywords = (learn_training_keywords(parsed, _path_exists_cached, _path_exempt_cached,
                           STATIC_KW, legitimate_keywords, self.get_config('AIWAF_DYNAMIC_TOP_N', 10))
                           if use_batch else None)
        for r in ([] if native_keywords is not None else parsed):
            # Only learn from suspicious requests (errors on non-existent paths)
            if (r["status"].startswith(("4", "5")) and 
                not _path_exists_cached(r["path"]) and 
                not _path_exempt_cached(r["path"])):
                
                for seg in re.split(r"\W+", r["path"].lower()):
                    if (len(seg) > 3 and 
                        seg not in STATIC_KW and 
                        seg not in legitimate_keywords and
                        self._is_malicious_context_trainer(r["path"], seg, r["status"])):
                        tokens[seg] += 1
        
        keyword_store = get_keyword_store()
        top_n = self.get_config("AIWAF_DYNAMIC_TOP_N", 10)
        top_tokens = tokens.most_common(top_n)
        
        # Filter tokens with malicious context validation
        filtered_tokens = []
        learned_from_paths = []
        
        for kw, cnt in top_tokens:
            # Find example paths where this keyword appeared
            example_paths = [r["path"] for r in parsed 
                            if kw in r["path"].lower() and 
                            r["status"].startswith(("4", "5")) and
                            not _path_exists_cached(r["path"])]
            
            # Only add if keyword appears in malicious contexts
            if (cnt >= 2 and
                len(kw) >= 4 and
                kw not in legitimate_keywords and
                example_paths and
                any(self._is_malicious_context_trainer(path, kw) for path in example_paths[:3])):
                
                filtered_tokens.append((kw, cnt))
                if not hasattr(keyword_store, 'update_keywords'):
                    keyword_store.add_keyword(kw, cnt)
                learned_from_paths.extend(example_paths[:2])

        if native_keywords is not None:
            filtered_tokens = [(keyword, count) for keyword, count, _ in native_keywords]
            learned_from_paths = [path for _, _, paths in native_keywords for path in paths]
            if not hasattr(keyword_store, 'update_keywords'):
                for keyword, count in filtered_tokens:
                    keyword_store.add_keyword(keyword, count)
        if filtered_tokens and hasattr(keyword_store, 'update_keywords'):
            keyword_store.update_keywords(added=[keyword for keyword, _ in filtered_tokens])
        
        # Training summary
        logger.info("\n" + "="*60)
        if disable_ai:
            logger.info(" AIWAF FLASK KEYWORD-ONLY TRAINING COMPLETE")
        else:
            logger.info(" AIWAF FLASK ENHANCED TRAINING COMPLETE")
        logger.info("="*60)
        logger.info(f" Training Data: {len(parsed)} log entries processed")
        
        if not disable_ai and ai_available:
            logger.info(f" AI Model: Trained with {len(feature_cols) if 'feature_cols' in locals() else 'N/A'} features")
            logger.info(f" AI Blocked IPs: {blocked_count} suspicious IPs blocked")
        else:
            logger.info(f" AI Model: Disabled (keyword learning only)")
            logger.info(f" AI Blocked IPs: 0 (AI blocking disabled)")
        
        logger.info(f" Keywords: {len(filtered_tokens)} new suspicious keywords learned")
        if filtered_tokens:
            logger.info(f"    Keywords: {[kw for kw, _ in filtered_tokens]}")
        
        logger.info(f"  Exemptions: {exempted_count} IPs protected from blocking")
        logger.info(f" 404 Blocking: {blocked_404_count} IPs blocked for excessive 404s")
        
        if disable_ai:
            logger.info(" Keyword-based protection now active with context-aware filtering!")
        else:
            logger.info(" Enhanced AI protection now active with context-aware filtering!")
        logger.info("="*60)

        try:
            _print_geoip_blocklist_summary()
        except Exception:
            pass

# Global trainer instance
_trainer = FlaskAITrainer()

def init_trainer(app: Flask):
    """Initialize the trainer with Flask app"""
    _trainer.init_app(app)

def train_from_logs(app: Optional[Flask] = None, disable_ai: bool = False):
    """Train AIWAF from logs
    
    Args:
        app: Flask application instance (optional if already initialized)
        disable_ai: If True, skip AI model training and only do keyword learning
    """
    if app:
        _trainer.init_app(app)
    
    _trainer.train(disable_ai=disable_ai)

# Convenience function for backward compatibility
def train(disable_ai: bool = False):
    """Train AIWAF from logs (requires app to be initialized first)"""
    _trainer.train(disable_ai=disable_ai)

# Legacy function for compatibility
def get_legitimate_keywords():
    """Return a set of legitimate keywords for Flask routes (legacy function)"""
    return _trainer.get_legitimate_keywords() if _trainer.app else {
        "profile", "user", "account", "settings", "dashboard", "home", "about", "contact", "help", "search", "list", "view", "edit", "create", "update", "delete", "detail", "api", "auth", "login", "logout", "register", "signup", "reset", "confirm", "activate", "verify", "page", "category", "tag", "post", "article", "blog", "news", "item", "admin", "manage", "config", "option", "preference"
    }


def _get_geoip_db_path():
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "core",
        "geolock",
        "ipinfo_lite.mmdb",
    )
    try:
        return current_app.config.get("AIWAF_GEOIP_DB_PATH", default_path)
    except Exception:
        return default_path


def _print_geoip_summary(ips, title):
    if not ips:
        return
    db_path = _get_geoip_db_path()
    if not db_path or not os.path.exists(db_path):
        print("GeoIP summary skipped: AIWAF_GEOIP_DB_PATH not set or file missing.")
        return

    counts = Counter()
    unknown = 0
    for ip in ips:
        name = lookup_country_name(ip, cache_prefix=None, cache_seconds=None, db_path=db_path)
        if name:
            counts[name] += 1
        else:
            unknown += 1

    if not counts and not unknown:
        return

    top = counts.most_common(10)
    print(title)
    for code, cnt in top:
        print(f"  - {code}: {cnt}")
    if unknown:
        print(f"  - UNKNOWN: {unknown}")


def _get_blocked_ips():
    try:
        storage_mode = _get_storage_mode()
    except Exception:
        storage_mode = "memory"

    if storage_mode == "database":
        try:
            from .db_models import BlacklistedIP
            return [row.ip for row in BlacklistedIP.query.all()]
        except Exception:
            return []

    if storage_mode == "csv":
        try:
            return list(_read_csv_blacklist().keys())
        except Exception:
            return []

    return []


def _print_geoip_blocklist_summary():
    blocked_ips = _get_blocked_ips()
    if not blocked_ips:
        return
    _print_geoip_summary(blocked_ips, "GeoIP summary for blocked IPs (top 10):")
