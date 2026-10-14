"""
Storage backends for AIWAF - handling blocklists, exemptions, and persistent data
"""
import time
import json
import csv
import sqlite3
import threading
from abc import ABC, abstractmethod
from typing import Set, Dict, Optional, List, Any
from pathlib import Path
import logging
from .reputation import FIRST_BLOCK_SECONDS, evaluate_reputation, format_block_reason
from .native_runtime import csv_function

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value with optional TTL."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key."""
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass
    
    @abstractmethod
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern."""
        pass


class MemoryStorage(StorageBackend):
    """In-memory storage backend with TTL support."""
    
    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        current_time = time.time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._lock:
            expired_keys = []
            for key, entry in self._data.items():
                if entry.get('expires_at') and current_time > entry['expires_at']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._data[key]
        
        self._last_cleanup = current_time
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        self._cleanup_expired()
        
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            
            # Check if expired
            if entry.get('expires_at') and time.time() > entry['expires_at']:
                del self._data[key]
                return None
            
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value with optional TTL."""
        with self._lock:
            entry = {'value': value}
            if ttl:
                entry['expires_at'] = time.time() + ttl
            
            self._data[key] = entry
            return True
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern."""
        self._cleanup_expired()
        
        with self._lock:
            if pattern == "*":
                return list(self._data.keys())
            
            # Simple pattern matching (only supports * wildcard)
            import fnmatch
            return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]


class FileStorage(StorageBackend):
    """File-based storage backend."""
    
    def __init__(self, file_path: str = "aiwaf_data.json"):
        self.file_path = Path(file_path)
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load_data()
    
    def _load_data(self):
        """Load data from file."""
        if self.file_path.exists():
            try:
                with open(self.file_path, 'r') as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load data from {self.file_path}: {e}")
                self._data = {}
    
    def _save_data(self):
        """Save data to file."""
        try:
            # Create directory if it doesn't exist
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first, then rename (atomic operation)
            temp_path = self.file_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(self._data, f, indent=2)
            
            temp_path.replace(self.file_path)
        except IOError as e:
            logger.error(f"Failed to save data to {self.file_path}: {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            
            # Check if expired
            if entry.get('expires_at') and time.time() > entry['expires_at']:
                del self._data[key]
                self._save_data()
                return None
            
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value with optional TTL."""
        with self._lock:
            entry = {'value': value}
            if ttl:
                entry['expires_at'] = time.time() + ttl
            
            self._data[key] = entry
            self._save_data()
            return True
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._save_data()
                return True
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern."""
        with self._lock:
            # Clean up expired entries first
            current_time = time.time()
            expired_keys = []
            for key, entry in self._data.items():
                if entry.get('expires_at') and current_time > entry['expires_at']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._data[key]
            
            if expired_keys:
                self._save_data()
            
            if pattern == "*":
                return list(self._data.keys())
            
            # Simple pattern matching
            import fnmatch
            return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]


class CSVStorage(StorageBackend):
    """CSV-backed key/value storage with TTL support."""

    def __init__(self, file_path: str = "aiwaf_data.csv"):
        self.file_path = Path(file_path)
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load_data()

    def _load_data(self):
        if not self.file_path.exists():
            return
        try:
            with open(self.file_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    key = row.get("key")
                    if not key:
                        continue
                    raw_value = row.get("value", "")
                    expires_raw = row.get("expires_at", "")
                    try:
                        value = json.loads(raw_value)
                    except Exception:
                        value = raw_value
                    expires_at = float(expires_raw) if expires_raw else None
                    self._data[key] = {"value": value, "expires_at": expires_at}
        except Exception as e:
            logger.warning(f"Failed to load CSV storage from {self.file_path}: {e}")
            self._data = {}

    def _save_data(self):
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.file_path.with_suffix(".tmp")
            with open(temp_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["key", "value", "expires_at"])
                writer.writeheader()
                for key, entry in self._data.items():
                    writer.writerow(
                        {
                            "key": key,
                            "value": json.dumps(entry.get("value")),
                            "expires_at": entry.get("expires_at") or "",
                        }
                    )
            temp_path.replace(self.file_path)
        except Exception as e:
            logger.error(f"Failed to save CSV storage to {self.file_path}: {e}")

    def _cleanup_expired(self):
        now = time.time()
        expired = []
        for key, entry in self._data.items():
            expires_at = entry.get("expires_at")
            if expires_at and now > expires_at:
                expired.append(key)
        for key in expired:
            del self._data[key]
        if expired:
            self._save_data()

    def get(self, key: str) -> Optional[Any]:
        native = csv_function('csv_kv_get')
        if native is not None:
            raw = native(str(self.file_path), key, time.time())
            if raw is None:
                return None
            try:
                return json.loads(raw)
            except (ValueError, TypeError):
                return raw
        with self._lock:
            self._cleanup_expired()
            entry = self._data.get(key)
            return entry.get("value") if entry else None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        native = csv_function('csv_kv_update')
        if native is not None:
            now = time.time()
            return native(str(self.file_path), key, json.dumps(value), now + ttl if ttl else None, now)
        with self._lock:
            expires_at = (time.time() + ttl) if ttl else None
            self._data[key] = {"value": value, "expires_at": expires_at}
            self._save_data()
            return True

    def delete(self, key: str) -> bool:
        native = csv_function('csv_kv_update')
        if native is not None:
            return native(str(self.file_path), key, None, None, time.time())
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._save_data()
                return True
            return False

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def get_all_keys(self, pattern: str = "*") -> List[str]:
        native = csv_function('csv_kv_keys')
        if native is not None:
            keys = native(str(self.file_path), time.time())
            if pattern == '*':
                return keys
            import fnmatch
            return [key for key in keys if fnmatch.fnmatch(key, pattern)]
        with self._lock:
            self._cleanup_expired()
            if pattern == "*":
                return list(self._data.keys())
            import fnmatch

            return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]


class DBStorage(StorageBackend):
    """SQLite-backed key/value storage with TTL support."""

    def __init__(self, file_path: str = "aiwaf_data.db"):
        self.file_path = Path(file_path)
        self._lock = threading.RLock()
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.file_path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at REAL
            )
            """
        )
        self._conn.commit()

    def _cleanup_expired(self):
        now = time.time()
        self._conn.execute("DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        self._conn.commit()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            self._cleanup_expired()
            row = self._conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
            if not row:
                return None
            try:
                return json.loads(row[0])
            except Exception:
                return row[0]

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            expires_at = (time.time() + ttl) if ttl else None
            payload = json.dumps(value)
            self._conn.execute(
                "INSERT OR REPLACE INTO kv_store (key, value, expires_at) VALUES (?, ?, ?)",
                (key, payload, expires_at),
            )
            self._conn.commit()
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM kv_store WHERE key = ?", (key,))
            self._conn.commit()
            return cur.rowcount > 0

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def get_all_keys(self, pattern: str = "*") -> List[str]:
        with self._lock:
            self._cleanup_expired()
            rows = self._conn.execute("SELECT key FROM kv_store").fetchall()
            keys = [r[0] for r in rows]
            if pattern == "*":
                return keys
            import fnmatch

            return [k for k in keys if fnmatch.fnmatch(k, pattern)]


class ExemptionStore:
    """Manages exempted IPs and patterns."""
    
    def __init__(self, storage: StorageBackend):
        self.storage = storage
        self._exempt_ips: Set[str] = set()
        self._exempt_patterns: List[str] = []
        self._load_exemptions()
    
    def _load_exemptions(self):
        """Load exemptions from storage."""
        exempt_data = self.storage.get("exemptions")
        exempt_data = exempt_data or {}
        self._exempt_ips = set(exempt_data.get('ips', []))
        self._exempt_patterns = list(exempt_data.get('patterns', []))

    def _native_update(self, operation, value, reason=""):
        if getattr(self.storage, 'policy_csv', False):
            found = self.storage.update_exemption(operation, value)
            self._load_exemptions()
            return found
        native = csv_function('csv_runtime_list_update') if isinstance(self.storage, CSVStorage) else None
        if native is None:
            return None
        found = native(str(self.storage.file_path), operation, value, reason, time.time())
        self._load_exemptions()
        return found

    def _refresh_csv(self):
        if getattr(self.storage, 'policy_csv', False) or (isinstance(self.storage, CSVStorage) and csv_function('csv_kv_get') is not None):
            self._load_exemptions()
    
    def _save_exemptions(self):
        """Save exemptions to storage."""
        exempt_data = {
            'ips': list(self._exempt_ips),
            'patterns': self._exempt_patterns
        }
        self.storage.set("exemptions", exempt_data)
    
    def add_ip(self, ip: str, reason: str = "Manual exemption"):
        """Add an IP to exemption list."""
        if self._native_update('add_ip', ip, reason) is not None:
            logger.info(f"IP {ip} added to exemption list: {reason}")
            return
        self._exempt_ips.add(ip)
        self._save_exemptions()
        
        # Log the exemption
        exemption_log = self.storage.get("exemption_log") or []
        exemption_log.append({
            'ip': ip,
            'reason': reason,
            'timestamp': time.time()
        })
        self.storage.set("exemption_log", exemption_log)
        
        logger.info(f"IP {ip} added to exemption list: {reason}")
    
    def remove_ip(self, ip: str):
        """Remove an IP from exemption list."""
        found = self._native_update('remove_ip', ip)
        if found is not None:
            return found
        if ip in self._exempt_ips:
            self._exempt_ips.remove(ip)
            self._save_exemptions()
            logger.info(f"IP {ip} removed from exemption list")
            return True
        return False
    
    def add_pattern(self, pattern: str, reason: str = "Manual exemption"):
        """Add an IP pattern to exemption list."""
        if self._native_update('add_pattern', pattern, reason) is not None:
            return
        if pattern not in self._exempt_patterns:
            self._exempt_patterns.append(pattern)
            self._save_exemptions()
            logger.info(f"Pattern {pattern} added to exemption list: {reason}")
    
    def remove_pattern(self, pattern: str):
        """Remove a pattern from exemption list."""
        found = self._native_update('remove_pattern', pattern)
        if found is not None:
            return found
        if pattern in self._exempt_patterns:
            self._exempt_patterns.remove(pattern)
            self._save_exemptions()
            logger.info(f"Pattern {pattern} removed from exemption list")
            return True
        return False
    
    def is_exempted(self, ip: str) -> bool:
        """Check if an IP is exempted."""
        from .exemptions import is_ip_exempt
        self._refresh_csv()
        return is_ip_exempt(ip, self._exempt_ips, self._exempt_patterns)
    
    def get_exempted_ips(self) -> Set[str]:
        """Get all exempted IPs."""
        self._refresh_csv()
        return self._exempt_ips.copy()
    
    def get_exempted_patterns(self) -> List[str]:
        """Get all exempted patterns."""
        self._refresh_csv()
        return self._exempt_patterns.copy()


class BlocklistStore:
    """Manages blocklisted IPs and their metadata."""
    
    def __init__(self, storage: StorageBackend):
        self.storage = storage
    
    def block_ip(
        self,
        ip: str,
        reason: str,
        duration: Optional[int] = None,
        extended_request_info: Optional[Dict[str, Any]] = None,
    ):
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
        """
        now = time.time()
        if getattr(self.storage, 'policy_csv', False):
            self.storage.block_ip(ip, reason, extended_request_info, duration)
            logger.warning(f"IP {ip} blocked: {reason}")
            return
        native = csv_function('csv_runtime_block') if isinstance(self.storage, CSVStorage) else None
        if native is not None:
            native(str(self.storage.file_path), ip, reason,
                   json.dumps(extended_request_info) if extended_request_info is not None else None,
                   now, duration)
            logger.warning(f"IP {ip} blocked: {reason}")
            return
        existing = self.get_block_info(ip) or {}
        if not isinstance(existing, dict):
            existing = {"reason": str(existing), "reasons": [str(existing)]}
        decision = evaluate_reputation(existing=existing, reason=reason, now=now)
        if duration is None:
            effective_duration = decision.duration or FIRST_BLOCK_SECONDS
        elif duration <= 0:
            effective_duration = None
        else:
            effective_duration = duration
        expires_at = now + effective_duration if effective_duration else None
        block_data = {
            'ip': ip,
            'reason': reason,
            'reputation_reason': format_block_reason(decision),
            'reasons': decision.reasons,
            'score': decision.score,
            'offenses': decision.offenses,
            'blocked_at': now,
            'duration': effective_duration,
            'expires_at': expires_at,
            'permanent': effective_duration is None
        }
        if extended_request_info is not None:
            block_data["extended_request_info"] = extended_request_info
        
        # Store the block
        self.storage.set(f"blocked:{ip}", block_data, ttl=effective_duration)
        
        # Add to block log
        block_log = self.storage.get("block_log") or []
        block_log.append(block_data)
        
        # Keep only last 1000 entries to prevent memory issues
        if len(block_log) > 1000:
            block_log = block_log[-1000:]
        
        self.storage.set("block_log", block_log)
        
        logger.warning(f"IP {ip} blocked: {reason}")
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        key = f"blocked:{ip}"
        if self.storage.exists(key):
            self.storage.delete(key)
            logger.info(f"IP {ip} unblocked")
            return True
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked."""
        return self.storage.exists(f"blocked:{ip}")
    
    def get_block_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get block information for an IP."""
        value = self.storage.get(f"blocked:{ip}")
        if value is None or isinstance(value, dict):
            return value
        # Pre-metadata runtime stores sometimes persisted only the reason string.
        return {
            "ip": ip,
            "reason": str(value),
            "reputation_reason": "legacy_blacklist",
            "reasons": ["legacy_blacklist", str(value)],
            "score": 100,
            "offenses": 1,
            "blocked_at": None,
            "expires_at": None,
            "duration": None,
            "permanent": True,
        }
    
    def get_blocked_ips(self) -> List[str]:
        """Get all currently blocked IPs."""
        blocked_keys = self.storage.get_all_keys("blocked:*")
        return [key.replace("blocked:", "") for key in blocked_keys]
    
    def get_block_stats(self) -> Dict[str, Any]:
        """Get blocking statistics."""
        blocked_ips = self.get_blocked_ips()
        block_log = self.storage.get("block_log") or []
        
        # Count blocks by reason
        reason_counts = {}
        recent_blocks = []
        current_time = time.time()
        
        for entry in block_log:
            if not isinstance(entry, dict):
                entry = {"reason": str(entry), "blocked_at": 0}
            reason = entry.get('reason', 'unknown')
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            
            # Recent blocks (last 24 hours)
            if current_time - entry.get('blocked_at', 0) < 86400:
                recent_blocks.append(entry)
        
        return {
            'total_blocked': len(blocked_ips),
            'total_blocks_all_time': len(block_log),
            'recent_blocks_24h': len(recent_blocks),
            'reason_counts': reason_counts,
            'blocked_ips': blocked_ips[:100]  # Limit for performance
        }


class KeywordStore:
    """Manages learned/suspicious keywords."""

    def __init__(self, storage: StorageBackend):
        self.storage = storage

    def update_keywords(self, added=(), removed=()):
        added = [(str(key).strip().lower(), int(count)) for key, count in added if str(key).strip()]
        removed = {str(key).strip().lower() for key in removed if str(key).strip()}
        if not added and not removed:
            return
        if getattr(self.storage, 'policy_csv', False):
            self.storage.update_keywords(added, removed)
            return
        native = csv_function('csv_runtime_keywords_update') if isinstance(self.storage, CSVStorage) else None
        if native is not None:
            native(str(self.storage.file_path), added, removed, time.time())
            return
        for key in removed:
            self.remove_keyword(key)
        for key, count in added:
            self.add_keyword(key, count)

    def add_keyword(self, keyword: str, count: int = 1):
        if not keyword:
            return
        keyword = str(keyword).strip().lower()
        if not keyword:
            return
        if getattr(self.storage, 'policy_csv', False):
            self.storage.update_keywords([(keyword, count)])
            return
        native = csv_function('csv_runtime_keyword') if isinstance(self.storage, CSVStorage) else None
        if native is not None:
            native(str(self.storage.file_path), keyword, int(count), False, time.time())
            return
        counts = self.storage.get("keyword_counts") or {}
        counts[keyword] = int(counts.get(keyword, 0)) + max(1, int(count))
        self.storage.set("keyword_counts", counts)

    def remove_keyword(self, keyword: str):
        if not keyword:
            return
        if getattr(self.storage, 'policy_csv', False):
            self.storage.update_keywords(removed=[str(keyword).strip().lower()])
            return
        native = csv_function('csv_runtime_keyword') if isinstance(self.storage, CSVStorage) else None
        if native is not None:
            native(str(self.storage.file_path), str(keyword).strip().lower(), 1, True, time.time())
            return
        counts = self.storage.get("keyword_counts") or {}
        keyword = str(keyword).strip().lower()
        if keyword in counts:
            del counts[keyword]
            self.storage.set("keyword_counts", counts)

    def get_top_keywords(self, n: int = 10):
        counts = self.storage.get("keyword_counts") or {}
        items = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        return [key for key, _ in items[: max(1, int(n))]]

    def get_all_keywords(self):
        counts = self.storage.get("keyword_counts") or {}
        return sorted(list(counts.keys()))


class GeoBlockStore:
    """Manages dynamically blocked country codes."""

    def __init__(self, storage: StorageBackend):
        self.storage = storage

    def get_countries(self) -> set[str]:
        if type(self.storage) is CSVStorage and csv_function('csv_kv_get') is None:
            # Native mutations do not populate the Python object's snapshot.
            # Refresh before fallback reads, including external removals.
            with self.storage._lock:
                self.storage._data = {}
                self.storage._load_data()
                values = self.storage.get("geo_blocked_countries") or []
        else:
            values = self.storage.get("geo_blocked_countries") or []
        return {str(v).strip().upper() for v in values if v}

    _default_get_countries = get_countries

    def evaluate_geo_policy(self, country, allow_countries, block_countries, extra_countries=()):
        """Read CSV state and decide together; custom getters/backends retain fallback."""
        from .geo_policy import GeoDecision, normalize_country_list, evaluate_geo_policy
        allow = normalize_country_list(allow_countries)
        block = normalize_country_list(block_countries)
        extra = normalize_country_list(extra_countries)
        if (getattr(self.storage, 'policy_csv', False)
                and type(self).get_countries is GeoBlockStore._default_get_countries
                and 'get_countries' not in self.__dict__):
            combined = csv_function('csv_geo_policy')
            if combined is not None:
                country = str(country or '').strip().upper()
                if country in extra and country not in allow:
                    return evaluate_geo_policy(country=country, allow_countries=allow,
                        block_countries=block, dynamic_blocked=extra)
                return GeoDecision(*combined(str(self.storage.data_dir / 'geo_blocked_countries.csv'),
                    country, allow, block))
        native = (csv_function('csv_runtime_geo_policy') if type(self.storage) is CSVStorage
                  and type(self).get_countries is GeoBlockStore._default_get_countries
                  and 'get_countries' not in self.__dict__ else None)
        if native is not None:
            result = native(str(self.storage.file_path), country or '', allow, block, extra, time.time())
            if result is not None:
                return GeoDecision(*result)
        return evaluate_geo_policy(country=country, allow_countries=allow,
            block_countries=block, dynamic_blocked=self.get_countries() | extra)

    def add_country(self, country_code: str):
        code = str(country_code or "").strip().upper()
        if not code:
            return
        if getattr(self.storage, 'policy_csv', False):
            self.storage.update_country(code, remove=False)
            return
        native = csv_function('csv_runtime_list_update') if isinstance(self.storage, CSVStorage) else None
        if native is not None:
            native(str(self.storage.file_path), 'add_country', code, '', time.time())
            return
        countries = self.get_countries()
        countries.add(code)
        self.storage.set("geo_blocked_countries", sorted(countries))

    def remove_country(self, country_code: str):
        code = str(country_code or "").strip().upper()
        if not code:
            return
        if getattr(self.storage, 'policy_csv', False):
            self.storage.update_country(code, remove=True)
            return
        native = csv_function('csv_runtime_list_update') if isinstance(self.storage, CSVStorage) else None
        if native is not None:
            native(str(self.storage.file_path), 'remove_country', code, '', time.time())
            return
        countries = self.get_countries()
        countries.discard(code)
        self.storage.set("geo_blocked_countries", sorted(countries))


# Global storage instances
_storage_backend: Optional[StorageBackend] = None
_exemption_store: Optional[ExemptionStore] = None
_blocklist_store: Optional[BlocklistStore] = None
_keyword_store: Optional[KeywordStore] = None
_geo_block_store: Optional[GeoBlockStore] = None


def initialize_storage(backend: str = "memory", **kwargs) -> StorageBackend:
    """Initialize storage backend."""
    global _storage_backend, _exemption_store, _blocklist_store, _keyword_store, _geo_block_store
    
    if backend == "memory":
        _storage_backend = MemoryStorage()
    elif backend == "file":
        file_path = kwargs.get('file_path', 'aiwaf_data.json')
        _storage_backend = FileStorage(file_path)
    elif backend == "csv":
        from .policy_csv_storage import initialize_policy_csv
        _storage_backend = initialize_policy_csv(data_dir=kwargs.get('data_dir'), file_path=kwargs.get('file_path'))
    elif backend == "db":
        file_path = kwargs.get("file_path", "aiwaf_data.db")
        _storage_backend = DBStorage(file_path)
    else:
        raise ValueError(f"Unknown storage backend: {backend}")
    
    _exemption_store = ExemptionStore(_storage_backend)
    _blocklist_store = BlocklistStore(_storage_backend)
    _keyword_store = KeywordStore(_storage_backend)
    _geo_block_store = GeoBlockStore(_storage_backend)
    
    return _storage_backend


def get_storage() -> StorageBackend:
    """Get the current storage backend."""
    global _storage_backend
    if _storage_backend is None:
        initialize_storage()
    return _storage_backend


def get_exemption_store() -> ExemptionStore:
    """Get the exemption store."""
    global _exemption_store
    if _exemption_store is None:
        initialize_storage()
    return _exemption_store


def get_blocklist_store() -> BlocklistStore:
    """Get the blocklist store."""
    global _blocklist_store
    if _blocklist_store is None:
        initialize_storage()
    return _blocklist_store


def get_keyword_store() -> KeywordStore:
    """Get keyword store."""
    global _keyword_store
    if _keyword_store is None:
        initialize_storage()
    return _keyword_store


def get_geo_block_store() -> GeoBlockStore:
    """Get geo-block country store."""
    global _geo_block_store
    if _geo_block_store is None:
        initialize_storage()
    return _geo_block_store


# Compatibility aliases for callers using the previous terminology.
BlacklistStore = BlocklistStore
get_blacklist_store = get_blocklist_store
