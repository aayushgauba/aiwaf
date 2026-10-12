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
    from .db_models import db, WhitelistedIP, BlacklistedIP, Keyword, GeoBlockedCountry
    from flask import current_app
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# In-memory fallback storage
_memory_whitelist = set()
_memory_blacklist = {}
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


def _database_blacklist_columns():
    """Return deployed blacklist columns without selecting through the new model."""
    from sqlalchemy import inspect

    return {
        column["name"]
        for column in inspect(db.engine).get_columns(BlacklistedIP.__tablename__)
    }


def _database_has_current_blacklist_schema():
    required = {
        "reputation_reason", "reasons", "score", "offenses", "blocked_at",
        "expires_at", "duration", "permanent",
    }
    try:
        return required.issubset(_database_blacklist_columns())
    except Exception:
        return False


def _legacy_database_is_blacklisted(ip):
    from sqlalchemy import text

    row = db.session.execute(
        text(f"SELECT 1 FROM {BlacklistedIP.__tablename__} WHERE ip = :ip LIMIT 1"),
        {"ip": ip},
    ).first()
    return row is not None


def _legacy_database_add_blacklist(ip, reason, extended_request_info=None):
    """Use only columns present in a pre-reputation SQLAlchemy table."""
    from sqlalchemy import text

    table = BlacklistedIP.__tablename__
    columns = _database_blacklist_columns()
    existing = _legacy_database_is_blacklisted(ip)
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


def _legacy_database_remove_blacklist(ip):
    from sqlalchemy import text

    db.session.execute(
        text(f"DELETE FROM {BlacklistedIP.__tablename__} WHERE ip = :ip"),
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

def _read_csv_whitelist():
    """Read whitelist from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_whitelist(data_dir)

def _append_csv_whitelist(ip):
    """Append IP to whitelist CSV with thread safety and atomic operations."""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_whitelist(data_dir, ip)

def _read_csv_blacklist():
    """Read blacklist from CSV with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.read_blacklist(data_dir)

def _append_csv_blacklist(ip, reason, extended_request_info=None):
    """Append IP to blacklist CSV with thread safety."""
    info_json = ""
    if extended_request_info:
        try:
            info_json = json.dumps(extended_request_info, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            info_json = ""
    data_dir = Path(_get_data_dir())
    return csv_impl.append_blacklist(data_dir, ip, reason, info_json)

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

def _rewrite_csv_blacklist(blacklist):
    """Rewrite blacklist CSV file with thread safety."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_blacklist(data_dir, blacklist)

def _is_blacklist_entry_expired(entry, now=None):
    if not isinstance(entry, dict):
        return False
    expires_at = entry.get("expires_at")
    if not expires_at:
        return False
    try:
        return float(expires_at) <= (now or time.time())
    except (TypeError, ValueError):
        return False

def _blacklist_metadata(ip, reason=None, existing=None, duration=None, extended_request_info=None):
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
def is_ip_whitelisted(ip):
    """Check if IP is whitelisted."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            # Additional check to ensure database is properly initialized
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return WhitelistedIP.query.filter_by(ip=ip).first() is not None
            else:
                storage_mode = 'csv'
        except Exception:
            # Fallback to CSV on any database error
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        if csv_function('csv_contains') is not None:
            return csv_impl.contains_whitelist(Path(_get_data_dir()), ip)
        return ip in _read_csv_whitelist()
    else:
        return ip in _memory_whitelist

def add_ip_whitelist(ip):
    """Add IP to whitelist."""
    if is_ip_whitelisted(ip):
        return
    
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            db.session.add(WhitelistedIP(ip=ip))
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        _append_csv_whitelist(ip)
    else:
        _memory_whitelist.add(ip)

def remove_ip_whitelist(ip):
    """Remove IP from whitelist."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            entry = WhitelistedIP.query.filter_by(ip=ip).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
        except Exception:
            # Fallback to memory
            _memory_whitelist.discard(ip)
    elif storage_mode == 'csv':
        # For CSV, we need to rewrite the file without the IP
        if csv_impl.native_policy_list_update(Path(_get_data_dir()), csv_impl.WHITELIST_CSV,
                                             ip, [], True):
            return
        whitelist = _read_csv_whitelist()
        whitelist.discard(ip)
        _rewrite_csv_whitelist(whitelist)
    else:
        _memory_whitelist.discard(ip)

def _rewrite_csv_whitelist(whitelist):
    """Rewrite whitelist CSV file."""
    data_dir = Path(_get_data_dir())
    return csv_impl.rewrite_whitelist(data_dir, whitelist)

def is_ip_blacklisted(ip):
    """Check if IP is blacklisted."""
    storage_mode = _get_storage_mode()
    now = time.time()
    
    if storage_mode == 'database':
        try:
            # Additional check to ensure database is properly initialized
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                if not _database_has_current_blacklist_schema():
                    return _legacy_database_is_blacklisted(ip)
                entry = BlacklistedIP.query.filter_by(ip=ip).first()
                if not entry:
                    return False
                if _is_blacklist_entry_expired(_entry_to_dict(entry), now=now):
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
        native_result = csv_impl.native_check_blacklist(Path(_get_data_dir()), ip, now)
        if native_result is not None:
            return native_result
        blacklist = _read_csv_blacklist()
        entry = blacklist.get(ip)
        if _is_blacklist_entry_expired(entry, now=now):
            blacklist.pop(ip, None)
            _rewrite_csv_blacklist(blacklist)
            return False
        return entry is not None
    else:
        entry = _memory_blacklist.get(ip)
        if _is_blacklist_entry_expired(entry, now=now):
            _memory_blacklist.pop(ip, None)
            return False
        return entry is not None

def add_ip_blacklist(ip, reason=None, extended_request_info=None, duration=None):
    """Add IP to blacklist."""
    storage_mode = _get_storage_mode()
    reason = reason or "Blocked"
    
    if storage_mode == 'database':
        try:
            if not _database_has_current_blacklist_schema():
                _legacy_database_add_blacklist(
                    ip,
                    reason,
                    extended_request_info=extended_request_info,
                )
                return
            entry = BlacklistedIP.query.filter_by(ip=ip).first()
            existing = _entry_to_dict(entry) if entry else {}
            if _is_blacklist_entry_expired(existing):
                db.session.delete(entry)
                db.session.flush()
                entry = None
                existing = {}
            metadata = _blacklist_metadata(
                ip,
                reason=reason,
                existing=existing,
                duration=duration,
                extended_request_info=extended_request_info,
            )
            if entry is None:
                entry = BlacklistedIP(ip=ip)
                db.session.add(entry)
            _apply_entry_metadata(entry, metadata)
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        if csv_impl.native_block_blacklist(Path(_get_data_dir()), ip, reason,
                                           extended_request_info, duration):
            return
        blacklist = _read_csv_blacklist()
        existing = blacklist.get(ip) or {}
        if _is_blacklist_entry_expired(existing):
            existing = {}
        blacklist[ip] = _blacklist_metadata(
            ip,
            reason=reason,
            existing=existing,
            duration=duration,
            extended_request_info=extended_request_info,
        )
        _rewrite_csv_blacklist(blacklist)
    else:
        existing = _memory_blacklist.get(ip) or {}
        if _is_blacklist_entry_expired(existing):
            existing = {}
        _memory_blacklist[ip] = _blacklist_metadata(
            ip,
            reason=reason,
            existing=existing,
            duration=duration,
            extended_request_info=extended_request_info,
        )

def remove_ip_blacklist(ip):
    """Remove IP from blacklist."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            if not _database_has_current_blacklist_schema():
                _legacy_database_remove_blacklist(ip)
                return
            entry = BlacklistedIP.query.filter_by(ip=ip).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        if csv_impl.native_remove_blacklist(Path(_get_data_dir()), ip):
            return
        # For CSV, we need to rewrite the file without the IP
        blacklist = _read_csv_blacklist()
        if ip in blacklist:
            del blacklist[ip]
            _rewrite_csv_blacklist(blacklist)
    else:
        _memory_blacklist.pop(ip, None)

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
