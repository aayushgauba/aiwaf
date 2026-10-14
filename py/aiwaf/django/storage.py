try:
    import numpy as np
except ImportError:
    np = None

try:
    import pandas as pd
except ImportError:
    pd = None
from django.conf import settings
from django.db import connection
from django.db.utils import OperationalError
from django.utils import timezone
import os
import json
import csv
import logging
import time
from collections import defaultdict
from ..core.keyword_fallback import KeywordFallbackStore
from ..core.reputation import FIRST_BLOCK_SECONDS, evaluate_reputation, format_block_reason
from ..core.storage_interfaces import BlocklistStore, ExemptionStore, KeywordStore
from ..core.storage_schema import (
    DEFAULT_DATA_DIR,
    BLOCKLIST_CSV as CORE_BLOCKLIST_CSV_NAME,
    ALLOWLIST_CSV as CORE_ALLOWLIST_CSV_NAME,
    KEYWORDS_CSV as CORE_KEYWORDS_CSV_NAME,
    PATH_EXEMPTIONS_CSV as CORE_PATH_EXEMPTIONS_CSV_NAME,
)
from ..core.runtime_storage import (
    initialize_storage as runtime_initialize_storage,
    get_blocklist_store as runtime_get_blocklist_store,
    get_exemption_store as runtime_get_exemption_store,
    get_keyword_store as runtime_get_keyword_store,
)

# Defer model imports to avoid AppRegistryNotReady during Django app loading
FeatureSample = BlocklistEntry = IPExemption = ExemptPath = DynamicKeyword = None

# Fallback storage for when Django models are unavailable
_fallback_storage_path = os.path.join(os.path.dirname(__file__), 'fallback_keywords.json')
_fallback_store = KeywordFallbackStore(_fallback_storage_path)
logger = logging.getLogger("aiwaf.django.storage")

_blocklist_columns_cache = None
_BLOCKLIST_CURRENT_COLUMNS = {
    "extended_request_info",
    "reputation_reason",
    "reasons",
    "score",
    "offenses",
    "blocked_at",
    "expires_at",
    "duration",
    "permanent",
}


def _blocklist_table_columns():
    global _blocklist_columns_cache

    if _blocklist_columns_cache is not None:
        return _blocklist_columns_cache

    _import_models()
    if BlocklistEntry is None:
        # Models/app registry not ready; don't cache a value yet.
        return {"extended_request_info"}

    try:
        table = BlocklistEntry._meta.db_table
        with connection.cursor() as cursor:
            desc = connection.introspection.get_table_description(cursor, table)
        _blocklist_columns_cache = {col.name for col in desc}
    except Exception:
        # If introspection fails, assume the column exists and let ORM handle errors.
        _blocklist_columns_cache = {"extended_request_info"}

    return _blocklist_columns_cache


def _blocklist_has_extended_request_info_column() -> bool:
    cols = _blocklist_table_columns()
    return "extended_request_info" in cols


def _blocklist_has_current_columns() -> bool:
    cols = _blocklist_table_columns()
    return _BLOCKLIST_CURRENT_COLUMNS.issubset(cols)


def _is_expired_timestamp(value) -> bool:
    if not value:
        return False
    try:
        return float(value) <= time.time()
    except (TypeError, ValueError):
        return False


def _block_ip_legacy_schema(ip, reason, extended_request_info=None):
    """Block an IP when the BlocklistEntry schema is missing newer columns.

    Uses raw SQL to avoid selecting/inserting missing columns.
    """
    _import_models()
    if BlocklistEntry is None:
        return

    cols = _blocklist_table_columns()
    qn = connection.ops.quote_name
    table = qn(BlocklistEntry._meta.db_table)

    existing = {}
    now = time.time()

    insert_cols = ["ip_address", "reason"]
    insert_vals = [ip, reason]
    update_pairs = ["reason = %s"]
    update_vals = [reason]

    if "created_at" in cols:
        insert_cols.append("created_at")
        insert_vals.append(timezone.now())
    if "extended_request_info" in cols:
        insert_cols.append("extended_request_info")
        insert_vals.append(json.dumps(extended_request_info or {}, separators=(",", ":"), ensure_ascii=False))
        if extended_request_info is not None:
            update_pairs.append(f"{qn('extended_request_info')} = %s")
            update_vals.append(json.dumps(extended_request_info, separators=(",", ":"), ensure_ascii=False))

    with connection.cursor() as cursor:
        select_cols = [column for column in ("reason", "reasons", "score", "offenses") if column in cols]
        if select_cols:
            select_sql = ", ".join(qn(column) for column in select_cols)
            cursor.execute(f"SELECT {select_sql} FROM {table} WHERE ip_address = %s LIMIT 1", [ip])
            row = cursor.fetchone()
            exists = row is not None
            if row:
                existing = dict(zip(select_cols, row))
                if isinstance(existing.get("reasons"), str):
                    try:
                        existing["reasons"] = json.loads(existing["reasons"])
                    except Exception:
                        existing["reasons"] = [existing["reasons"]]
        else:
            cursor.execute(f"SELECT 1 FROM {table} WHERE ip_address = %s LIMIT 1", [ip])
            exists = cursor.fetchone() is not None

        decision = evaluate_reputation(existing=existing, reason=reason, now=now)
        effective_duration = decision.duration or FIRST_BLOCK_SECONDS
        optional_values = {
            "reputation_reason": format_block_reason(decision),
            "reasons": json.dumps(decision.reasons, separators=(",", ":"), ensure_ascii=False),
            "score": decision.score,
            "offenses": decision.offenses,
            "blocked_at": now,
            "expires_at": now + effective_duration if effective_duration else None,
            "duration": effective_duration,
            "permanent": effective_duration is None,
        }
        for column, value in optional_values.items():
            if column in cols:
                insert_cols.append(column)
                insert_vals.append(value)
                update_pairs.append(f"{qn(column)} = %s")
                update_vals.append(value)

        if exists:
            cursor.execute(f"UPDATE {table} SET {', '.join(update_pairs)} WHERE ip_address = %s", [*update_vals, ip])
            return

        cols_sql = ", ".join(qn(c) for c in insert_cols)
        placeholders = ", ".join(["%s"] * len(insert_vals))
        cursor.execute(f"INSERT INTO {table} ({cols_sql}) VALUES ({placeholders})", insert_vals)


def _is_blocked_legacy_schema(ip):
    _import_models()
    if BlocklistEntry is None:
        return False

    cols = _blocklist_table_columns()
    qn = connection.ops.quote_name
    table = qn(BlocklistEntry._meta.db_table)
    with connection.cursor() as cursor:
        if "expires_at" in cols:
            cursor.execute(f"SELECT expires_at FROM {table} WHERE ip_address = %s LIMIT 1", [ip])
            row = cursor.fetchone()
            if row is None:
                return False
            if _is_expired_timestamp(row[0]):
                cursor.execute(f"DELETE FROM {table} WHERE ip_address = %s", [ip])
                return False
            return True
        cursor.execute(f"SELECT 1 FROM {table} WHERE ip_address = %s LIMIT 1", [ip])
        return cursor.fetchone() is not None


def _unblock_ip_legacy_schema(ip):
    _import_models()
    if BlocklistEntry is None:
        return

    qn = connection.ops.quote_name
    table = qn(BlocklistEntry._meta.db_table)
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM {table} WHERE ip_address = %s", [ip])


def _get_all_blocked_ips_legacy_schema():
    _import_models()
    if BlocklistEntry is None:
        return []

    qn = connection.ops.quote_name
    table = qn(BlocklistEntry._meta.db_table)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT ip_address FROM {table}")
        return [row[0] for row in cursor.fetchall()]


def _get_all_blocklist_entries_legacy_schema():
    _import_models()
    if BlocklistEntry is None:
        return []

    cols = _blocklist_table_columns()
    select_cols = ["ip_address", "reason"]
    for column in (
        "created_at",
        "extended_request_info",
        "reputation_reason",
        "reasons",
        "score",
        "offenses",
        "blocked_at",
        "expires_at",
        "duration",
        "permanent",
    ):
        if column in cols:
            select_cols.append(column)

    qn = connection.ops.quote_name
    table = qn(BlocklistEntry._meta.db_table)
    cols_sql = ", ".join(qn(c) for c in select_cols)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {cols_sql} FROM {table}")
        rows = cursor.fetchall()

    results = []
    for row in rows:
        item = dict(zip(select_cols, row))
        item.setdefault("extended_request_info", {})
        if isinstance(item.get("reasons"), str):
            try:
                item["reasons"] = json.loads(item["reasons"])
            except Exception:
                item["reasons"] = [item["reasons"]]
        results.append(item)
    return results


def _clear_all_blocklist_entries_legacy_schema():
    _import_models()
    if BlocklistEntry is None:
        return 0

    qn = connection.ops.quote_name
    table = qn(BlocklistEntry._meta.db_table)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = int(cursor.fetchone()[0])
        cursor.execute(f"DELETE FROM {table}")
    return count


def _import_models():
    """Import Django models only when needed and apps are ready."""
    global FeatureSample, BlocklistEntry, IPExemption, ExemptPath, DynamicKeyword
    
    if FeatureSample is not None:
        return  # Already imported
    try:
        from django.apps import apps
        if apps.ready:
            # Try multiple ways to import models
            try:
                # First try: direct import (most reliable)
                from .models import (
                    FeatureSample,
                    BlocklistEntry,
                    IPExemption,
                    ExemptPath,
                    DynamicKeyword,
                )
            except ImportError:
                # Second try: check if aiwaf app is installed under different name
                for app_config in apps.get_app_configs():
                    if 'aiwaf' in app_config.name.lower() or 'aiwaf' in app_config.label.lower():
                        try:
                            from .models import (
                                FeatureSample,
                                BlocklistEntry,
                                IPExemption,
                                ExemptPath,
                                DynamicKeyword,
                            )
                            break
                        except ImportError:
                            continue
    except (ImportError, RuntimeError, Exception) as e:
        # Log the error for debugging but don't fail silently
        logger.warning("Could not import AIWAF models: %s", e, exc_info=True)
        # Keep models as None if can't import
        pass

class ModelFeatureStore:
    @staticmethod
    def persist_rows(rows):
        """Persist feature data to Django models"""
        _import_models()
        if FeatureSample is None:
            logger.warning("Django models not available, skipping feature storage")
            return
            
        for row in rows:
            try:
                FeatureSample.objects.create(
                    ip=row[0],
                    path_len=int(row[1]),
                    kw_hits=int(row[2]),
                    resp_time=float(row[3]),
                    status_idx=int(row[4]),
                    burst_count=int(row[5]),
                    total_404=int(row[6]),
                    label=int(row[7]),
                    created_at=timezone.now()
                )
            except Exception as e:
                logger.error("Error saving feature sample: %s", e, exc_info=True)

    @staticmethod
    def get_all_data():
        """Get all feature data as DataFrame"""
        _import_models()
        if FeatureSample is None:
            return pd.DataFrame() if pd is not None else []
            
        try:
            queryset = FeatureSample.objects.all().values(
                'ip', 'path_len', 'kw_hits', 'resp_time', 
                'status_idx', 'burst_count', 'total_404', 'label'
            )
            if pd is None:
                return list(queryset)
            df = pd.DataFrame(list(queryset))
            if df.empty:
                return df
            
            feature_cols = ['path_len', 'kw_hits', 'resp_time', 'status_idx', 'burst_count', 'total_404']
            for col in feature_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
            
            return df
        except Exception as e:
            logger.error("Error loading feature data: %s", e, exc_info=True)
            return pd.DataFrame()

class ModelBlocklistStore:
    @staticmethod
    def is_blocked(ip):
        """Check if IP is in blocklist"""
        _import_models()
        if BlocklistEntry is None:
            return False
        if not _blocklist_has_current_columns():
            try:
                return _is_blocked_legacy_schema(ip)
            except Exception:
                return False
        try:
            entry = BlocklistEntry.objects.filter(ip_address=ip).first()
            if not entry:
                return False
            if _is_expired_timestamp(getattr(entry, "expires_at", None)):
                entry.delete()
                return False
            return True
        except Exception:
            return False

    @staticmethod
    def block_ip(ip, reason="Automated block", extended_request_info=None):
        """Add IP to blocklist"""
        _import_models()
        if BlocklistEntry is None:
            logger.warning("Cannot block IP %s, models not available", ip)
            return
        if not _blocklist_has_current_columns():
            try:
                _block_ip_legacy_schema(ip, reason, extended_request_info=extended_request_info)
            except Exception as e:
                logger.error("Error blocking IP %s (legacy schema): %s", ip, e, exc_info=True)
            return
        try:
            now = time.time()
            existing_obj = BlocklistEntry.objects.filter(ip_address=ip).first()
            if existing_obj and _is_expired_timestamp(getattr(existing_obj, "expires_at", None)):
                existing_obj.delete()
                existing_obj = None
            existing = {}
            if existing_obj:
                existing = {
                    "reason": existing_obj.reason,
                    "reasons": existing_obj.reasons or [],
                    "score": existing_obj.score or 0,
                    "offenses": existing_obj.offenses or 0,
                    "extended_request_info": existing_obj.extended_request_info or {},
                }
            decision = evaluate_reputation(existing=existing, reason=reason, now=now)
            effective_duration = decision.duration or FIRST_BLOCK_SECONDS
            obj, created = BlocklistEntry.objects.get_or_create(
                ip_address=ip,
                defaults={
                    'reason': reason,
                    'created_at': timezone.now(),
                    'extended_request_info': extended_request_info or {},
                    'reputation_reason': format_block_reason(decision),
                    'reasons': decision.reasons,
                    'score': decision.score,
                    'offenses': decision.offenses,
                    'blocked_at': now,
                    'expires_at': now + effective_duration if effective_duration else None,
                    'duration': effective_duration,
                    'permanent': effective_duration is None,
                }
            )
            if not created:
                obj.reason = reason
                obj.reputation_reason = format_block_reason(decision)
                obj.reasons = decision.reasons
                obj.score = decision.score
                obj.offenses = decision.offenses
                obj.blocked_at = now
                obj.expires_at = now + effective_duration if effective_duration else None
                obj.duration = effective_duration
                obj.permanent = effective_duration is None
                if extended_request_info is not None:
                    obj.extended_request_info = extended_request_info
                obj.save(update_fields=[
                    "reason",
                    "reputation_reason",
                    "reasons",
                    "score",
                    "offenses",
                    "blocked_at",
                    "expires_at",
                    "duration",
                    "permanent",
                    "extended_request_info",
                ])
        except OperationalError as e:
            # Compatibility for deployments created before extended_request_info existed.
            if "extended_request_info" in str(e):
                try:
                    _block_ip_legacy_schema(ip, reason, extended_request_info=extended_request_info)
                    return
                except Exception:
                    pass
            logger.error("Error blocking IP %s: %s", ip, e, exc_info=True)
        except Exception as e:
            logger.error("Error blocking IP %s: %s", ip, e, exc_info=True)

    @staticmethod
    def unblock_ip(ip):
        """Remove IP from blocklist"""
        _import_models()
        if BlocklistEntry is None:
            return
        if not _blocklist_has_current_columns():
            try:
                _unblock_ip_legacy_schema(ip)
            except Exception as e:
                logger.error("Error unblocking IP %s (legacy schema): %s", ip, e, exc_info=True)
            return
        try:
            BlocklistEntry.objects.filter(ip_address=ip).delete()
        except Exception as e:
            logger.error("Error unblocking IP %s: %s", ip, e, exc_info=True)

    @staticmethod
    def remove_ip(ip):
        """Remove IP from blocklist (alias for unblock_ip)"""
        ModelBlocklistStore.unblock_ip(ip)

    @staticmethod
    def add_ip(ip, reason="Automated block", extended_request_info=None):
        """Add IP to blocklist (alias for block_ip)"""
        ModelBlocklistStore.block_ip(ip, reason, extended_request_info=extended_request_info)

    @staticmethod
    def get_all_blocked_ips():
        """Get all blocked IPs"""
        _import_models()
        if BlocklistEntry is None:
            return []
        if not _blocklist_has_current_columns():
            try:
                return _get_all_blocked_ips_legacy_schema()
            except Exception:
                return []
        try:
            return list(BlocklistEntry.objects.values_list('ip_address', flat=True))
        except Exception:
            return []

    @staticmethod
    def get_all():
        """Get all blocklist entries as dictionaries"""
        _import_models()
        if BlocklistEntry is None:
            return []
        if not _blocklist_has_current_columns():
            try:
                return _get_all_blocklist_entries_legacy_schema()
            except Exception:
                return []
        try:
            return list(BlocklistEntry.objects.values(
                'ip_address',
                'reason',
                'created_at',
                'extended_request_info',
                'reputation_reason',
                'reasons',
                'score',
                'offenses',
                'blocked_at',
                'expires_at',
                'duration',
                'permanent',
            ))
        except Exception:
            return []

    @staticmethod
    def clear_all():
        """Clear all blocklist entries"""
        _import_models()
        if BlocklistEntry is None:
            return 0
        if not _blocklist_has_current_columns():
            try:
                return _clear_all_blocklist_entries_legacy_schema()
            except Exception as e:
                logger.error("Error clearing all blocklist entries (legacy schema): %s", e, exc_info=True)
                return 0
        try:
            count = BlocklistEntry.objects.count()
            BlocklistEntry.objects.all().delete()
            return count
        except Exception as e:
            logger.error("Error clearing all blocklist entries: %s", e, exc_info=True)
            return 0

class ModelExemptionStore:
    @staticmethod
    def is_exempted(ip):
        """Check if IP is exempted"""
        _import_models()
        if IPExemption is None:
            return False
        try:
            return IPExemption.objects.filter(ip_address=ip).exists()
        except Exception:
            return False

    @staticmethod
    def add_exemption(ip, reason="Manual exemption"):
        """Add IP to exemption list"""
        _import_models()
        if IPExemption is None:
            logger.warning("Cannot exempt IP %s, models not available", ip)
            return
        try:
            IPExemption.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': reason, 'created_at': timezone.now()}
            )
        except Exception as e:
            logger.error("Error exempting IP %s: %s", ip, e, exc_info=True)

    @staticmethod
    def remove_exemption(ip):
        """Remove IP from exemption list"""
        _import_models()
        if IPExemption is None:
            return
        try:
            IPExemption.objects.filter(ip_address=ip).delete()
        except Exception as e:
            logger.error("Error removing exemption for IP %s: %s", ip, e, exc_info=True)

    @staticmethod
    def remove_ip(ip):
        """Remove IP from exemption list (alias for remove_exemption)"""
        ModelExemptionStore.remove_exemption(ip)

    @staticmethod
    def add_ip(ip, reason="Manual exemption"):
        """Add IP to exemption list (alias for add_exemption)"""
        ModelExemptionStore.add_exemption(ip, reason)

    @staticmethod
    def get_all_exempted_ips():
        """Get all exempted IPs"""
        _import_models()
        if IPExemption is None:
            return []
        try:
            return list(IPExemption.objects.values_list('ip_address', flat=True))
        except Exception:
            return []

    @staticmethod
    def get_all():
        """Get all exempted IP entries as dictionaries"""
        _import_models()
        if IPExemption is None:
            return []
        try:
            return list(IPExemption.objects.values('ip_address', 'reason', 'created_at'))
        except Exception:
            return []

    @staticmethod
    def clear_all():
        """Clear all exemption entries"""
        _import_models()
        if IPExemption is None:
            return 0
        try:
            count = IPExemption.objects.count()
            IPExemption.objects.all().delete()
            return count
        except Exception as e:
            logger.error("Error clearing all exemption entries: %s", e, exc_info=True)
            return 0

class ModelPathExemptionStore:
    @staticmethod
    def is_exempted(path):
        """Check if a path is exempted"""
        _import_models()
        if ExemptPath is None:
            return False
        try:
            return ExemptPath.objects.filter(path=path, enabled=True).exists()
        except Exception:
            return False

    @staticmethod
    def add_exemption(path, reason="Manual exemption", enabled=True):
        """Add a path to the exemption list"""
        _import_models()
        if ExemptPath is None:
            logger.warning("Cannot exempt path %s, models not available", path)
            return
        try:
            ExemptPath.objects.update_or_create(
                path=path,
                defaults={"reason": reason, "enabled": enabled},
            )
        except Exception as e:
            logger.error("Error exempting path %s: %s", path, e, exc_info=True)

    @staticmethod
    def remove_exemption(path):
        """Remove a path from the exemption list"""
        _import_models()
        if ExemptPath is None:
            return
        try:
            ExemptPath.objects.filter(path=path).delete()
        except Exception as e:
            logger.error("Error removing exemption for path %s: %s", path, e, exc_info=True)

    @staticmethod
    def get_all_exempted_paths():
        """Get all exempted paths"""
        _import_models()
        if ExemptPath is None:
            return []
        try:
            return list(
                ExemptPath.objects.filter(enabled=True).values_list("path", flat=True)
            )
        except Exception:
            return []

    @staticmethod
    def get_all():
        """Get all exempted path entries as dictionaries"""
        _import_models()
        if ExemptPath is None:
            return []
        try:
            return list(ExemptPath.objects.values("path", "reason", "enabled", "created_at"))
        except Exception:
            return []

    @staticmethod
    def clear_all():
        """Clear all path exemption entries"""
        _import_models()
        if ExemptPath is None:
            return 0
        try:
            count = ExemptPath.objects.count()
            ExemptPath.objects.all().delete()
            return count
        except Exception as e:
            logger.error("Error clearing all path exemptions: %s", e, exc_info=True)
            return 0

class ModelKeywordStore:
    @staticmethod
    def add_keyword(keyword, count=1):
        """Add a keyword to the dynamic keyword list"""
        _import_models()
        if DynamicKeyword is None:
            _fallback_store.add(keyword, count)
            logger.info("Using fallback storage for keyword '%s' - Django models not available", keyword)
            return
        try:
            obj, created = DynamicKeyword.objects.get_or_create(keyword=keyword)
            if not created:
                obj.count += count
                obj.save()
            else:
                obj.count = count
                obj.save()
        except Exception as e:
            _fallback_store.add(keyword, count)
            logger.error("Database error adding keyword %s, using fallback storage: %s", keyword, e, exc_info=True)

    @staticmethod
    def remove_keyword(keyword):
        """Remove a keyword from the dynamic keyword list"""
        _import_models()
        if DynamicKeyword is None:
            return
        try:
            DynamicKeyword.objects.filter(keyword=keyword).delete()
        except Exception as e:
            logger.error("Error removing keyword %s: %s", keyword, e, exc_info=True)

    @staticmethod
    def get_top_keywords(n=10):
        """Get top N keywords by count"""
        _import_models()
        if DynamicKeyword is None:
            return [keyword for keyword, _count in _fallback_store.top(n)]
        try:
            return list(
                DynamicKeyword.objects.order_by('-count')[:n]
                .values_list('keyword', flat=True)
            )
        except Exception as e:
            logger.error("Database error getting top keywords, using fallback storage: %s", e, exc_info=True)
            return [keyword for keyword, _count in _fallback_store.top(n)]

    @staticmethod
    def get_all_keywords():
        """Get all keywords"""
        _import_models()
        if DynamicKeyword is None:
            return []
        try:
            return list(
                DynamicKeyword.objects.all().values_list('keyword', flat=True)
            )
        except Exception:
            return []

    @staticmethod
    def reset_keywords():
        """Reset all keyword counts"""
        _import_models()
        if DynamicKeyword is None:
            return
        try:
            DynamicKeyword.objects.all().delete()
        except Exception as e:
            logger.error("Error resetting keywords: %s", e, exc_info=True)

    def add_keyword_for_route(self, route, keyword, count=1):
        """Add a keyword for a specific route (fallback method)"""
        # For now, just use the general add_keyword method
        # In a full implementation, this would handle route-specific storage
        return ModelKeywordStore.add_keyword(keyword, count)
    
    def get_keywords_for_route(self, route):
        """Get keywords for a specific route (fallback method)"""
        # For now, return all keywords
        # In a full implementation, this would return route-specific keywords
        return ModelKeywordStore.get_all_keywords()

# Unified CSV/runtime compatibility for Django
def _resolve_storage_mode():
    mode = getattr(settings, "AIWAF_STORAGE_MODE", "models")
    if mode is None:
        mode = "models"
    return str(mode).strip().lower()


def _resolve_csv_data_dir():
    explicit = getattr(settings, "AIWAF_DATA_DIR", None) or getattr(settings, "AIWAF_CSV_DATA_DIR", None)
    if explicit:
        return str(explicit)
    env_dir = os.getenv("AIWAF_DATA_DIR")
    if env_dir:
        return env_dir
    return DEFAULT_DATA_DIR


def _ensure_runtime_csv_backend():
    data_dir = _resolve_csv_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    runtime_initialize_storage(backend="csv", data_dir=data_dir)
    return data_dir


def _is_csv_mode():
    return _resolve_storage_mode() == "csv"


CSV_DATA_DIR = _resolve_csv_data_dir()
BLOCKLIST_CSV = os.path.join(CSV_DATA_DIR, CORE_BLOCKLIST_CSV_NAME)
EXEMPTION_CSV = os.path.join(CSV_DATA_DIR, CORE_ALLOWLIST_CSV_NAME)
KEYWORDS_CSV = os.path.join(CSV_DATA_DIR, CORE_KEYWORDS_CSV_NAME)
PATH_EXEMPTIONS_CSV = os.path.join(CSV_DATA_DIR, CORE_PATH_EXEMPTIONS_CSV_NAME)
STORAGE_MODE = _resolve_storage_mode()


class CSVBlocklistStoreAdapter:
    @staticmethod
    def is_blocked(ip):
        return runtime_get_blocklist_store().is_blocked(ip)

    @staticmethod
    def block_ip(ip, reason="Automated block", extended_request_info=None):
        runtime_get_blocklist_store().block_ip(ip, reason, extended_request_info=extended_request_info)

    @staticmethod
    def unblock_ip(ip):
        runtime_get_blocklist_store().unblock_ip(ip)

    @staticmethod
    def add_ip(ip, reason="Automated block", extended_request_info=None):
        CSVBlocklistStoreAdapter.block_ip(ip, reason, extended_request_info=extended_request_info)

    @staticmethod
    def remove_ip(ip):
        CSVBlocklistStoreAdapter.unblock_ip(ip)

    @staticmethod
    def get_all_blocked_ips():
        return runtime_get_blocklist_store().get_blocked_ips()

    @staticmethod
    def get_all():
        rows = []
        for ip in runtime_get_blocklist_store().get_blocked_ips():
            info = runtime_get_blocklist_store().get_block_info(ip) or {}
            rows.append(
                {
                    "ip_address": ip,
                    "reason": info.get("reason", ""),
                    "created_at": info.get("blocked_at"),
                    "extended_request_info": info.get("extended_request_info") or {},
                    "reputation_reason": info.get("reputation_reason", ""),
                    "reasons": info.get("reasons", []),
                    "score": info.get("score", 0),
                    "offenses": info.get("offenses", 0),
                    "blocked_at": info.get("blocked_at"),
                    "expires_at": info.get("expires_at"),
                    "duration": info.get("duration"),
                    "permanent": info.get("permanent", False),
                }
            )
        return rows

    @staticmethod
    def clear_all():
        ips = list(runtime_get_blocklist_store().get_blocked_ips())
        for ip in ips:
            runtime_get_blocklist_store().unblock_ip(ip)
        return len(ips)


class CSVExemptionStoreAdapter:
    @staticmethod
    def is_exempted(ip):
        return runtime_get_exemption_store().is_exempted(ip)

    @staticmethod
    def add_exemption(ip, reason="Manual exemption"):
        runtime_get_exemption_store().add_ip(ip, reason)

    @staticmethod
    def remove_exemption(ip):
        runtime_get_exemption_store().remove_ip(ip)

    @staticmethod
    def add_ip(ip, reason="Manual exemption"):
        CSVExemptionStoreAdapter.add_exemption(ip, reason)

    @staticmethod
    def remove_ip(ip):
        CSVExemptionStoreAdapter.remove_exemption(ip)

    @staticmethod
    def get_all_exempted_ips():
        return list(runtime_get_exemption_store().get_exempted_ips())

    @staticmethod
    def get_all():
        return [
            {"ip_address": ip, "reason": "csv exemption", "created_at": None}
            for ip in sorted(runtime_get_exemption_store().get_exempted_ips())
        ]

    @staticmethod
    def clear_all():
        ips = list(runtime_get_exemption_store().get_exempted_ips())
        for ip in ips:
            runtime_get_exemption_store().remove_ip(ip)
        return len(ips)


class CSVKeywordStoreAdapter:
    @staticmethod
    def update_keywords(added=(), removed=()):
        runtime_get_keyword_store().update_keywords(added, removed)

    @staticmethod
    def add_keyword(keyword, count=1):
        runtime_get_keyword_store().add_keyword(keyword, count)

    @staticmethod
    def remove_keyword(keyword):
        runtime_get_keyword_store().remove_keyword(keyword)

    @staticmethod
    def get_top_keywords(n=10):
        return runtime_get_keyword_store().get_top_keywords(n)

    @staticmethod
    def get_all_keywords():
        return runtime_get_keyword_store().get_all_keywords()

    @staticmethod
    def reset_keywords():
        for keyword in runtime_get_keyword_store().get_all_keywords():
            runtime_get_keyword_store().remove_keyword(keyword)


class CSVPathExemptionStoreAdapter:
    @staticmethod
    def _read():
        data_dir = _resolve_csv_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        path = os.path.join(data_dir, CORE_PATH_EXEMPTIONS_CSV_NAME)
        rows = {}
        if not os.path.exists(path):
            return rows
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = (row.get("path") or "").strip()
                if p:
                    rows[p] = row.get("reason", "")
        return rows

    @staticmethod
    def _write(rows):
        data_dir = _resolve_csv_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        path = os.path.join(data_dir, CORE_PATH_EXEMPTIONS_CSV_NAME)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["path", "reason", "added_date"])
            for p, reason in sorted(rows.items()):
                writer.writerow([p, reason, timezone.now().isoformat()])

    @staticmethod
    def is_exempted(path):
        return str(path) in CSVPathExemptionStoreAdapter._read()

    @staticmethod
    def add_exemption(path, reason="Manual exemption", enabled=True):
        if not enabled:
            return
        rows = CSVPathExemptionStoreAdapter._read()
        rows[str(path)] = reason
        CSVPathExemptionStoreAdapter._write(rows)

    @staticmethod
    def remove_exemption(path):
        rows = CSVPathExemptionStoreAdapter._read()
        rows.pop(str(path), None)
        CSVPathExemptionStoreAdapter._write(rows)

    @staticmethod
    def get_all_exempted_paths():
        return list(CSVPathExemptionStoreAdapter._read().keys())

    @staticmethod
    def get_all():
        rows = CSVPathExemptionStoreAdapter._read()
        return [{"path": p, "reason": r, "enabled": True, "created_at": None} for p, r in rows.items()]

    @staticmethod
    def clear_all():
        rows = CSVPathExemptionStoreAdapter._read()
        CSVPathExemptionStoreAdapter._write({})
        return len(rows)


# Factory functions
def get_feature_store():
    """Get the feature store (Django models only)"""
    return ModelFeatureStore()

def get_blocklist_store() -> BlocklistStore:
    """Get the blocklist store."""
    if _is_csv_mode():
        _ensure_runtime_csv_backend()
        return CSVBlocklistStoreAdapter()
    return ModelBlocklistStore()

def get_exemption_store() -> ExemptionStore:
    """Get the exemption store."""
    if _is_csv_mode():
        _ensure_runtime_csv_backend()
        return CSVExemptionStoreAdapter()
    return ModelExemptionStore()

def get_path_exemption_store():
    """Get the path exemption store."""
    if _is_csv_mode():
        return CSVPathExemptionStoreAdapter()
    return ModelPathExemptionStore()

def get_keyword_store() -> KeywordStore:
    """Get the keyword store."""
    if _is_csv_mode():
        _ensure_runtime_csv_backend()
        return CSVKeywordStoreAdapter()
    return ModelKeywordStore()


# Compatibility aliases for callers using the previous terminology.
BlacklistStore = BlocklistStore
CORE_BLACKLIST_CSV_NAME = CORE_BLOCKLIST_CSV_NAME
CORE_WHITELIST_CSV_NAME = CORE_ALLOWLIST_CSV_NAME
runtime_get_blacklist_store = runtime_get_blocklist_store
BlacklistEntry = BlocklistEntry
ModelBlacklistStore = ModelBlocklistStore
BLACKLIST_CSV = BLOCKLIST_CSV
CSVBlacklistStoreAdapter = CSVBlocklistStoreAdapter
get_blacklist_store = get_blocklist_store
