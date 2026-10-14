"""Storage functions for AIWAF Flask with CSV, database, and in-memory fallback."""

import json
import logging
import time
from pathlib import Path
from aiwaf.core import storage_csv_impl as csv_impl
from aiwaf.core.native_runtime import csv_function
from aiwaf.core.reputation import FIRST_BLOCK_SECONDS, evaluate_reputation, format_block_reason
from aiwaf.core.storage_interfaces import ExemptionStore as ExemptionStoreProtocol, KeywordStore as KeywordStoreProtocol
from aiwaf.core.storage_schema import (
    DEFAULT_DATA_DIR,
)

try:
    from .db_models import db, AllowlistedIP, BlocklistedIP, Keyword, GeoBlockedCountry
    from flask import current_app
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# In-memory fallback storage
_memory_allowlist = set()
_memory_blocklist = {}
_memory_keywords = set()
_memory_geo_blocked_countries = set()
_memory_path_exemptions = {}

# Configure logging
logger = logging.getLogger(__name__)


def _get_storage_mode():
    """Determine storage mode: 'database', 'csv', or 'memory'."""
    try:
        from flask import current_app
        
        # First check if CSV is explicitly enabled
        if current_app.config.get('AIWAF_USE_CSV', True):
            return 'csv'
        
        # Check for database only if CSV is disabled
        if (DB_AVAILABLE and hasattr(current_app, 'extensions') and 
            'sqlalchemy' in current_app.extensions):
            return 'database'
            
    except:
        pass
    
    return 'memory'


def _database_blocklist_columns():
    """Return deployed blocklist columns without selecting through the new model."""
    from sqlalchemy import inspect

    return {
        column["name"]
        for column in inspect(db.engine).get_columns(BlocklistedIP.__tablename__)
    }


def _database_has_current_blocklist_schema():
    required = {
        "reputation_reason", "reasons", "score", "offenses", "blocked_at",
        "expires_at", "duration", "permanent",
    }
    try:
        return required.issubset(_database_blocklist_columns())
    except Exception:
        return False


def _legacy_database_is_blocklisted(ip):
    from sqlalchemy import text

    row = db.session.execute(
        text(f"SELECT 1 FROM {BlocklistedIP.__tablename__} WHERE ip = :ip LIMIT 1"),
        {"ip": ip},
    ).first()
    return row is not None


def _legacy_database_add_blocklist(ip, reason, extended_request_info=None):
    """Use only columns present in a pre-reputation SQLAlchemy table."""
    from sqlalchemy import text

    table = BlocklistedIP.__tablename__
    columns = _database_blocklist_columns()
    existing = _legacy_database_is_blocklisted(ip)
    values = {"ip": ip, "reason": reason}
    assignments = ["reason = :reason"]
    insert_columns = ["ip", "reason"]
    insert_values = [":ip", ":reason"]
    if "extended_request_info" in columns and extended_request_info is not None:
        values["extended_request_info"] = json.dumps(extended_request_info)
        assignments.append("extended_request_info = :extended_request_info")
        insert_columns.append("extended_request_info")
        insert_values.append(":extended_request_info")
    if existing:
        db.session.execute(
            text(f"UPDATE {table} SET {', '.join(assignments)} WHERE ip = :ip"),
            values,
        )
    else:
        db.session.execute(
            text(
                f"INSERT INTO {table} ({', '.join(insert_columns)}) "
                f"VALUES ({', '.join(insert_values)})"
            ),
            values,
        )
    db.session.commit()


def _legacy_database_remove_blocklist(ip):
    from sqlalchemy import text

    db.session.execute(
        text(f"DELETE FROM {BlocklistedIP.__tablename__} WHERE ip = :ip"),
        {"ip": ip},
    )
    db.session.commit()

def _get_data_dir():
    """Get data directory for CSV files."""
    try:
        from flask import current_app
        configured = current_app.config.get("AIWAF_DATA_DIR")
        if configured:
            return configured
    except:
        configured = None

    # Support env var override for test isolation / container deployment.
    env_dir = None
    try:
        import os

        env_dir = os.getenv("AIWAF_DATA_DIR")
    except Exception:
        env_dir = None

    return env_dir or DEFAULT_DATA_DIR

def _ensure_csv_files():
    """Ensure CSV files and directory exist with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.ensure_all(data_dir)

def _read_csv_allowlist():
    """Read allowlist from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_allowlist(data_dir)

def _append_csv_allowlist(ip):
    """Append IP to allowlist CSV with thread safety and atomic operations."""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_allowlist(data_dir, ip)

def _read_csv_blocklist():
    """Read blocklist from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_blocklist(data_dir)

def _append_csv_blocklist(ip, reason, extended_request_info=None):
    """Append IP to blocklist CSV with thread safety."""
    info_json = ""
    if extended_request_info:
        try:
            info_json = json.dumps(extended_request_info, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            info_json = ""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_blocklist(data_dir, ip, reason, info_json)

def _read_csv_keywords():
    """Read keywords from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_keywords(data_dir)

def _append_csv_keyword(keyword):
    """Append keyword to CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_keyword(data_dir, keyword)

def _read_csv_geo_blocked_countries():
    """Read geo blocked countries from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_geo_blocked_countries(data_dir)

def _append_csv_geo_blocked_country(country_code):
    """Append geo blocked country to CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_geo_blocked_country(data_dir, country_code)

def _rewrite_csv_geo_blocked_countries(countries):
    """Rewrite geo blocked countries CSV file with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_geo_blocked_countries(data_dir, countries)


def _read_csv_path_exemptions():
    """Read path exemptions from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_path_exemptions(data_dir)


def _append_csv_path_exemption(path, reason=None):
    """Append path exemption to CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_path_exemption(data_dir, path, reason or "")


def _rewrite_csv_path_exemptions(exemptions):
    """Rewrite path exemptions CSV file with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_path_exemptions(data_dir, exemptions)

def _rewrite_csv_blocklist(blocklist):
    """Rewrite blocklist CSV file with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_blocklist(data_dir, blocklist)

def _is_blocklist_entry_expired(entry, now=None):
    if not isinstance(entry, dict):
        return False
    expires_at = entry.get("expires_at")
    if not expires_at:
        return False
    try:
        return float(expires_at) <= (now or time.time())
    except (TypeError, ValueError):
        return False

def _blocklist_metadata(ip, reason=None, existing=None, duration=None, extended_request_info=None):
    now = time.time()
    decision = evaluate_reputation(
        existing=existing if isinstance(existing, dict) else {},
        reason=reason or "Blocked",
        now=now,
    )
    if duration is None:
        effective_duration = decision.duration or FIRST_BLOCK_SECONDS
    elif duration <= 0:
        effective_duration = None
    else:
        effective_duration = duration
    metadata = {
        "ip": ip,
        "reason": reason or "Blocked",
        "reputation_reason": format_block_reason(decision),
        "reasons": decision.reasons,
        "score": decision.score,
        "offenses": decision.offenses,
        "blocked_at": now,
        "added_date": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)),
        "duration": effective_duration,
        "expires_at": now + effective_duration if effective_duration else None,
        "permanent": effective_duration is None,
    }
    if extended_request_info is not None:
        metadata["extended_request_info"] = extended_request_info
    elif isinstance(existing, dict) and existing.get("extended_request_info") is not None:
        metadata["extended_request_info"] = existing.get("extended_request_info")
    return metadata

def _entry_to_dict(entry):
    if entry is None:
        return {}
    reasons = getattr(entry, "reasons", None)
    if not isinstance(reasons, list):
        reasons = [getattr(entry, "reason", "Blocked")]
    return {
        "reason": getattr(entry, "reason", "Blocked"),
        "reputation_reason": getattr(entry, "reputation_reason", ""),
        "reasons": reasons,
        "score": getattr(entry, "score", 0) or 0,
        "offenses": getattr(entry, "offenses", 0) or 0,
        "blocked_at": getattr(entry, "blocked_at", None),
        "duration": getattr(entry, "duration", None),
        "expires_at": getattr(entry, "expires_at", None),
        "permanent": getattr(entry, "permanent", False),
        "extended_request_info": getattr(entry, "extended_request_info", None),
    }

def _apply_entry_metadata(entry, metadata):
    for key in (
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
    ):
        if hasattr(entry, key):
            setattr(entry, key, metadata.get(key))

# Store adapters for keyword/exemption access
class ExemptionStore:
    _exempt_ips = set()
    def is_exempted(self, ip):
        return ip in self._exempt_ips
    def add_exempt(self, ip):
        self._exempt_ips.add(ip)

def get_exemption_store() -> ExemptionStoreProtocol:
    return ExemptionStore()

class KeywordStore:
    def update_keywords(self, added=(), removed=()):
        native = csv_function('csv_keywords_update') if _get_storage_mode() == 'csv' else None
        if native is not None:
            from aiwaf.core.storage_ops import now_iso
            from aiwaf.core.storage_schema import KEYWORDS_CSV
            data_dir = Path(_get_data_dir())
            csv_impl.ensure_all(data_dir)
            native(str(data_dir / KEYWORDS_CSV), now_iso(), list(added), set(removed))
            return
        for keyword in removed:
            self.remove_keyword(keyword)
        for keyword in added:
            self.add_keyword(keyword)

    def add_keyword(self, kw, count=1):
        # Note: Current implementation doesn't store count, just presence
        add_keyword(kw)
    def remove_keyword(self, kw):
        remove_keyword(kw)
    def get_top_keywords(self, n=10):
        return get_top_keywords(n)

def get_keyword_store() -> KeywordStoreProtocol:
    return KeywordStore()

# Public API functions
def is_ip_allowlisted(ip):
    """Check if IP is allowlisted."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            # Additional check to ensure database is properly initialized
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return AllowlistedIP.query.filter_by(ip=ip).first() is not None
            else:
                storage_mode = 'csv'
        except Exception:
            # Fallback to CSV on any database error
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        if csv_function('csv_contains') is not None:
            return csv_impl.contains_allowlist(Path(_get_data_dir()), ip)
        return ip in _read_csv_allowlist()
    else:
        return ip in _memory_allowlist

def add_ip_allowlist(ip):
    """Add IP to allowlist."""
    if is_ip_allowlisted(ip):
        return
    
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            db.session.add(AllowlistedIP(ip=ip))
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        _append_csv_allowlist(ip)
    else:
        _memory_allowlist.add(ip)

def remove_ip_allowlist(ip):
    """Remove IP from allowlist."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            entry = AllowlistedIP.query.filter_by(ip=ip).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
        except Exception:
            # Fallback to memory
            _memory_allowlist.discard(ip)
    elif storage_mode == 'csv':
        # For CSV, we need to rewrite the file without the IP
        if csv_impl.native_policy_list_update(Path(_get_data_dir()), csv_impl.ALLOWLIST_CSV,
                                             ip, [], True):
            return
        allowlist = _read_csv_allowlist()
        allowlist.discard(ip)
        _rewrite_csv_allowlist(allowlist)
    else:
        _memory_allowlist.discard(ip)

def _rewrite_csv_allowlist(allowlist):
    """Rewrite allowlist CSV file."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_allowlist(data_dir, allowlist)

def is_ip_blocklisted(ip):
    """Check if IP is blocklisted."""
    storage_mode = _get_storage_mode()
    now = time.time()
    
    if storage_mode == 'database':
        try:
            # Additional check to ensure database is properly initialized
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                if not _database_has_current_blocklist_schema():
                    return _legacy_database_is_blocklisted(ip)
                entry = BlocklistedIP.query.filter_by(ip=ip).first()
                if not entry:
                    return False
                if _is_blocklist_entry_expired(_entry_to_dict(entry), now=now):
                    db.session.delete(entry)
                    db.session.commit()
                    return False
                return True
            else:
                storage_mode = 'csv'
        except Exception:
            # Fallback to CSV on any database error
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        native_result = csv_impl.native_check_blocklist(Path(_get_data_dir()), ip, now)
        if native_result is not None:
            return native_result
        blocklist = _read_csv_blocklist()
        entry = blocklist.get(ip)
        if _is_blocklist_entry_expired(entry, now=now):
            blocklist.pop(ip, None)
            _rewrite_csv_blocklist(blocklist)
            return False
        return entry is not None
    else:
        entry = _memory_blocklist.get(ip)
        if _is_blocklist_entry_expired(entry, now=now):
            _memory_blocklist.pop(ip, None)
            return False
        return entry is not None

def add_ip_blocklist(ip, reason=None, extended_request_info=None, duration=None):
    """Add IP to blocklist."""
    storage_mode = _get_storage_mode()
    reason = reason or "Blocked"
    
    if storage_mode == 'database':
        try:
            if not _database_has_current_blocklist_schema():
                _legacy_database_add_blocklist(
                    ip,
                    reason,
                    extended_request_info=extended_request_info,
                )
                return
            entry = BlocklistedIP.query.filter_by(ip=ip).first()
            existing = _entry_to_dict(entry) if entry else {}
            if _is_blocklist_entry_expired(existing):
                db.session.delete(entry)
                db.session.flush()
                entry = None
                existing = {}
            metadata = _blocklist_metadata(
                ip,
                reason=reason,
                existing=existing,
                duration=duration,
                extended_request_info=extended_request_info,
            )
            if entry is None:
                entry = BlocklistedIP(ip=ip)
                db.session.add(entry)
            _apply_entry_metadata(entry, metadata)
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        if csv_impl.native_block_blocklist(Path(_get_data_dir()), ip, reason,
                                           extended_request_info, duration):
            return
        blocklist = _read_csv_blocklist()
        existing = blocklist.get(ip) or {}
        if _is_blocklist_entry_expired(existing):
            existing = {}
        blocklist[ip] = _blocklist_metadata(
            ip,
            reason=reason,
            existing=existing,
            duration=duration,
            extended_request_info=extended_request_info,
        )
        _rewrite_csv_blocklist(blocklist)
    else:
        existing = _memory_blocklist.get(ip) or {}
        if _is_blocklist_entry_expired(existing):
            existing = {}
        _memory_blocklist[ip] = _blocklist_metadata(
            ip,
            reason=reason,
            existing=existing,
            duration=duration,
            extended_request_info=extended_request_info,
        )

def remove_ip_blocklist(ip):
    """Remove IP from blocklist."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            if not _database_has_current_blocklist_schema():
                _legacy_database_remove_blocklist(ip)
                return
            entry = BlocklistedIP.query.filter_by(ip=ip).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        if csv_impl.native_remove_blocklist(Path(_get_data_dir()), ip):
            return
        # For CSV, we need to rewrite the file without the IP
        blocklist = _read_csv_blocklist()
        if ip in blocklist:
            del blocklist[ip]
            _rewrite_csv_blocklist(blocklist)
    else:
        _memory_blocklist.pop(ip, None)

def _normalize_country_code(country_code):
    if not country_code:
        return None
    normalized = str(country_code).strip().upper()
    return normalized or None

def get_geo_blocked_countries():
    """Get all geo blocked countries."""
    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return {c.country_code for c in GeoBlockedCountry.query.all()}
            storage_mode = 'csv'
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        return _read_csv_geo_blocked_countries()
    return set(_memory_geo_blocked_countries)

def is_country_geo_blocked(country_code):
    """Check if a country is geo blocked."""
    normalized = _normalize_country_code(country_code)
    if not normalized:
        return False

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return GeoBlockedCountry.query.filter_by(country_code=normalized).first() is not None
            storage_mode = 'csv'
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        countries = _read_csv_geo_blocked_countries()
        return normalized in countries
    return normalized in _memory_geo_blocked_countries

def add_geo_blocked_country(country_code):
    """Add a country to geo blocked list."""
    normalized = _normalize_country_code(country_code)
    if not normalized or is_country_geo_blocked(normalized):
        return

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            db.session.add(GeoBlockedCountry(country_code=normalized))
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        _append_csv_geo_blocked_country(normalized)
    else:
        _memory_geo_blocked_countries.add(normalized)

def remove_geo_blocked_country(country_code):
    """Remove a country from geo blocked list."""
    normalized = _normalize_country_code(country_code)
    if not normalized:
        return

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            entry = GeoBlockedCountry.query.filter_by(country_code=normalized).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        if csv_impl.native_policy_list_update(Path(_get_data_dir()), csv_impl.GEO_BLOCKED_COUNTRIES_CSV,
                                             normalized, [], True, 'upper'):
            return
        countries = _read_csv_geo_blocked_countries()
        if normalized in countries:
            countries.discard(normalized)
            _rewrite_csv_geo_blocked_countries(countries)
    else:
        _memory_geo_blocked_countries.discard(normalized)


def get_path_exemptions():
    """Get all path exemptions."""
    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        return set(_memory_path_exemptions.keys())

    if storage_mode == 'csv':
        return set(_read_csv_path_exemptions().keys())
    return set(_memory_path_exemptions.keys())


def add_path_exemption(path, reason=None):
    """Add a path exemption."""
    if not path:
        return
    normalized = str(path).strip()
    if not normalized:
        return
    key = normalized.lower()
    if key in get_path_exemptions():
        return

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        _memory_path_exemptions[key] = reason or ""
        return

    if storage_mode == 'csv':
        _append_csv_path_exemption(normalized, reason)
    else:
        _memory_path_exemptions[key] = reason or ""


def remove_path_exemption(path):
    """Remove a path exemption."""
    if not path:
        return
    normalized = str(path).strip()
    if not normalized:
        return
    key = normalized.lower()

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        _memory_path_exemptions.pop(key, None)
        return

    if storage_mode == 'csv':
        if csv_impl.native_policy_list_update(Path(_get_data_dir()), csv_impl.PATH_EXEMPTIONS_CSV,
                                             key, [], True, 'lower'):
            return
        exemptions = _read_csv_path_exemptions()
        if key in exemptions:
            exemptions.pop(key, None)
            _rewrite_csv_path_exemptions(exemptions)
    else:
        _memory_path_exemptions.pop(key, None)

def add_keyword(kw):
    """Add keyword to blocked list."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            if not Keyword.query.filter_by(keyword=kw).first():
                db.session.add(Keyword(keyword=kw))
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        keywords = _read_csv_keywords()
        if kw not in keywords:
            _append_csv_keyword(kw)
    else:
        _memory_keywords.add(kw)

def remove_keyword(keyword):
    """Remove keyword from blocked list."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            entry = Keyword.query.filter_by(keyword=keyword).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
        except Exception:
            # Fallback to memory
            _memory_keywords.discard(keyword)
    elif storage_mode == 'csv':
        # For CSV, we need to rewrite the file without the keyword
        if csv_impl.native_remove_keyword(Path(_get_data_dir()), keyword):
            return
        keywords = _read_csv_keywords()
        keywords.discard(keyword)
        _rewrite_csv_keywords(keywords)
    else:
        _memory_keywords.discard(keyword)

def _rewrite_csv_keywords(keywords):
    """Rewrite keywords CSV file."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_keywords(data_dir, keywords)

def get_top_keywords(n=10):
    """Get top keywords."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            return [k.keyword for k in Keyword.query.limit(n).all()]
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        keywords = _read_csv_keywords()
        return list(keywords)[:n]
    else:
        return list(_memory_keywords)[:n]


# Compatibility aliases for callers using the previous terminology.
is_ip_whitelisted = is_ip_allowlisted
add_ip_whitelist = add_ip_allowlist
remove_ip_whitelist = remove_ip_allowlist
is_ip_blacklisted = is_ip_blocklisted
add_ip_blacklist = add_ip_blocklist
remove_ip_blacklist = remove_ip_blocklist
