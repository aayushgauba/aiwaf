"""Canonical policy CSV backend for legacy framework adapters.

The key/value interface is a compatibility view, not a second policy database.
Non-policy runtime history and keyword frequencies live in an auxiliary CSV.
"""
from __future__ import annotations

import csv
import fnmatch
import hashlib
import json
import math
import os
import time
from pathlib import Path

from . import storage_csv_impl as policy
from .runtime_storage import CSVStorage, StorageBackend
from .storage_csv import file_lock
from .storage_ops import now_iso
from .storage_schema import CSV_HEADERS, DEFAULT_DATA_DIR


class PolicyCSVStorage(StorageBackend):
    policy_csv = True

    def __init__(self, data_dir=None, legacy_file=None):
        self.data_dir = Path(data_dir or os.environ.get('AIWAF_DATA_DIR') or DEFAULT_DATA_DIR).absolute()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.file_path = self.data_dir / 'runtime_metadata.csv'
        self.metadata = CSVStorage(str(self.file_path))
        self.lock_path = self.data_dir / '.policy-storage.lock'
        policy.ensure_all(self.data_dir)
        sources = ([Path(legacy_file)] if legacy_file else []) + [self.data_dir / 'runtime_store.csv']
        if self.data_dir == (Path.cwd() / DEFAULT_DATA_DIR).absolute():
            sources.append(Path.cwd() / 'aiwaf_data.csv')
        for source in dict.fromkeys(path.absolute() for path in sources):
            if source.absolute() != self.file_path and source.is_file():
                self._migrate(source.absolute())

    def _get_block(self, ip):
        entry = policy.read_blacklist_entry(self.data_dir, ip)
        if entry is None:
            return None
        expiry = entry.get('expires_at')
        if not entry.get('permanent') and expiry is not None and float(expiry) <= time.time():
            return None
        return dict(entry, ip=ip)

    def get(self, key):
        if key.startswith('blocked:'):
            return self._get_block(key[len('blocked:'):])
        if key == 'exemptions':
            values = policy.read_whitelist(self.data_dir)
            return {'ips': sorted(v for v in values if not self._is_pattern(v)),
                    'patterns': sorted(v for v in values if self._is_pattern(v))}
        if key == 'keyword_counts':
            counts = self.metadata.get(key) or {}
            return {word: int(counts.get(word, 1)) for word in policy.read_keywords(self.data_dir)}
        if key == 'geo_blocked_countries':
            return sorted(policy.read_geo_blocked_countries(self.data_dir))
        if key == 'path_exemptions':
            return policy.read_path_exemptions(self.data_dir)
        return self.metadata.get(key)

    @staticmethod
    def _is_pattern(value):
        return any(token in value for token in ('*', '?', '[', '/'))

    def set(self, key, value, ttl=None):
        with file_lock(self.lock_path, 'a+'):
            return self._set(key, value, ttl)

    def _set(self, key, value, ttl=None):
        if key.startswith('blocked:'):
            from .blacklist_migration import legacy_metadata
            ip = key[len('blocked:'):]
            entry = dict(value) if isinstance(value, dict) else legacy_metadata(value)
            if ttl is not None:
                entry['expires_at'] = time.time() + ttl
                entry['permanent'] = False
            entry.setdefault('reputation_reason', 'legacy_blacklist')
            entry.setdefault('permanent', entry.get('expires_at') is None)
            # Native list update replaces this IP while retaining other rows.
            if not policy.native_policy_list_update(self.data_dir, 'blacklist.csv', ip,
                    policy._blacklist_row(ip, entry), False):
                blocks = policy.read_blacklist(self.data_dir)
                blocks[ip] = entry
                policy.rewrite_blacklist(self.data_dir, blocks)
        elif key == 'exemptions':
            policy.rewrite_whitelist(self.data_dir, set(value.get('ips', [])) | set(value.get('patterns', [])))
        elif key == 'keyword_counts':
            policy.rewrite_keywords(self.data_dir, set(value))
            self.metadata.set(key, value)
        elif key == 'geo_blocked_countries':
            policy.rewrite_geo_blocked_countries(self.data_dir, set(value))
        elif key == 'path_exemptions':
            policy.rewrite_path_exemptions(self.data_dir, value)
        else:
            return self.metadata.set(key, value, ttl)
        return True

    def delete(self, key):
        with file_lock(self.lock_path, 'a+'):
            if key.startswith('blocked:'):
                existed = self.get(key) is not None
                ip = key[len('blocked:'):]
                if not policy.native_remove_blacklist(self.data_dir, ip):
                    blocks = policy.read_blacklist(self.data_dir)
                    blocks.pop(ip, None)
                    policy.rewrite_blacklist(self.data_dir, blocks)
                return existed
            if key in {'exemptions', 'keyword_counts', 'geo_blocked_countries', 'path_exemptions'}:
                self._set(key, {} if key != 'geo_blocked_countries' else [])
                return True
            return self.metadata.delete(key)

    def exists(self, key):
        return self.get(key) is not None

    def get_all_keys(self, pattern='*'):
        keys = set(self.metadata.get_all_keys())
        keys.update('blocked:' + ip for ip in policy.read_blacklist(self.data_dir) if self._get_block(ip))
        keys.update(('exemptions', 'keyword_counts', 'geo_blocked_countries', 'path_exemptions'))
        return sorted(key for key in keys if fnmatch.fnmatchcase(key, pattern))

    def block_ip(self, ip, reason, info=None, duration=None):
        # Same Rust reputation and CSV mutation used by Flask.
        with file_lock(self.lock_path, 'a+'):
            if not policy.native_block_blacklist(self.data_dir, ip, reason, info, duration):
                from .reputation import evaluate_reputation, format_block_reason, FIRST_BLOCK_SECONDS
                now = time.time()
                decision = evaluate_reputation(existing=self._get_block(ip) or {}, reason=reason, now=now)
                effective = (decision.duration or FIRST_BLOCK_SECONDS) if duration is None else duration
                self._set('blocked:' + ip, dict(reason=reason, reputation_reason=format_block_reason(decision),
                    reasons=decision.reasons, score=decision.score, offenses=decision.offenses,
                    blocked_at=now, duration=effective if effective > 0 else None,
                    expires_at=now + effective if effective > 0 else None, permanent=effective <= 0,
                    extended_request_info=info))
            entry = self._get_block(ip)
            history = self.metadata.get('block_log') or []
            self.metadata.set('block_log', (history + [entry])[-1000:])

    def update_exemption(self, operation, value):
        remove = operation.startswith('remove_')
        existed = value in policy.read_whitelist(self.data_dir)
        if not policy.native_policy_list_update(self.data_dir, 'whitelist.csv', value, [value, now_iso()], remove):
            with file_lock(self.lock_path, 'a+'):
                values = policy.read_whitelist(self.data_dir)
                values.discard(value) if remove else values.add(value)
                policy.rewrite_whitelist(self.data_dir, values)
        return existed if remove else True

    def update_keywords(self, added=(), removed=()):
        with file_lock(self.lock_path, 'a+'):
            counts = self.get('keyword_counts')
            for word in removed:
                counts.pop(word, None)
                if not policy.native_remove_keyword(self.data_dir, word):
                    values = policy.read_keywords(self.data_dir)
                    values.discard(word)
                    policy.rewrite_keywords(self.data_dir, values)
            for word, count in added:
                counts[word] = counts.get(word, 0) + max(1, int(count))
                policy.append_keyword(self.data_dir, word)
            self.metadata.set('keyword_counts', counts)

    def update_country(self, code, remove=False):
        if not policy.native_policy_list_update(self.data_dir, 'geo_blocked_countries.csv', code,
                [code, now_iso()], remove):
            with file_lock(self.lock_path, 'a+'):
                values = policy.read_geo_blocked_countries(self.data_dir)
                values.discard(code) if remove else values.add(code)
                policy.rewrite_geo_blocked_countries(self.data_dir, values)

    def _migrate(self, source):
        """Import once. Originals remain intact; interrupted imports are replayable."""
        identity = hashlib.sha256(str(source).encode()).hexdigest()[:16]
        marker = self.data_dir / ('.csv-migration-' + identity + '.json')
        with file_lock(self.lock_path, 'a+'):
            if marker.exists():
                return
            entries = self._read_legacy(source)  # Validate all input before mutation.
            # Snapshot canonical files before the first attempt, retained on retry.
            backup = self.data_dir / ('.csv-backup-' + identity)
            backup.mkdir(exist_ok=True)
            for name in (*CSV_HEADERS, 'runtime_metadata.csv'):
                target = self.data_dir / name
                saved = backup / name
                if target.exists() and not saved.exists():
                    with saved.open('xb') as output:
                        output.write(target.read_bytes())
            now = time.time()
            for key, (value, expiry) in entries.items():
                if expiry is not None and expiry <= now:
                    continue
                if key.startswith('blocked:'):
                    if self.get(key) is not None:
                        continue  # Existing canonical policy wins conflicts.
                    from .blacklist_migration import legacy_metadata
                    entry = dict(value) if isinstance(value, dict) else legacy_metadata(value, now=now)
                    limits = [float(v) for v in (expiry, entry.get('expires_at')) if v is not None]
                    entry['expires_at'] = min(limits) if limits else None
                    if entry['expires_at'] is not None and entry['expires_at'] <= now:
                        continue
                    entry['permanent'] = entry['expires_at'] is None
                    self._set(key, entry)
                elif key == 'exemptions':
                    existing = self.get(key)
                    self._set(key, {name: sorted(set(existing[name]) | set(value.get(name, []))) for name in ('ips', 'patterns')})
                elif key == 'keyword_counts':
                    existing = self.get(key)
                    self._set(key, {word: max(existing.get(word, 0), value.get(word, 0)) for word in existing.keys() | value.keys()})
                elif key == 'geo_blocked_countries':
                    self._set(key, sorted(set(self.get(key)) | set(value)))
                elif key == 'path_exemptions':
                    self._set(key, dict(value, **self.get(key)))
                elif self.metadata.get(key) is None:
                    self.metadata.set(key, value, ttl=(expiry - now) if expiry else None)
            temp = marker.with_suffix('.tmp')
            temp.write_text(json.dumps({'source': str(source), 'version': 1}), encoding='utf-8')
            temp.replace(marker)

    @staticmethod
    def _read_legacy(source):
        entries = {}
        with source.open(newline='', encoding='utf-8-sig') as stream:
            reader = csv.DictReader(stream, strict=True)
            if reader.fieldnames != ['key', 'value', 'expires_at']:
                raise ValueError(f'Unsupported legacy CSV header in {source}')
            for row in reader:
                if None in row or any(v is None for v in row.values()) or not row['key']:
                    raise ValueError(f'Malformed legacy CSV row in {source}')
                key = row['key']
                if key in entries:
                    raise ValueError(f'Duplicate legacy CSV key {key!r} in {source}')
                try:
                    value = json.loads(row['value'])
                except json.JSONDecodeError as error:
                    if key.startswith('blocked:'):
                        value = row['value']  # Pre-JSON block reason strings.
                    else:
                        raise ValueError(f'Invalid legacy CSV JSON for {key!r} in {source}') from error
                expiry = float(row['expires_at']) if row['expires_at'] else None
                if expiry is not None and not math.isfinite(expiry):
                    raise ValueError(f'Invalid legacy expiry in {source}')
                if key in {'exemptions', 'keyword_counts', 'path_exemptions'} and not isinstance(value, dict):
                    raise ValueError(f'Invalid legacy policy {key!r} in {source}')
                if key == 'geo_blocked_countries' and not isinstance(value, list):
                    raise ValueError(f'Invalid legacy country list in {source}')
                if key == 'keyword_counts' and any(not isinstance(k, str) or not isinstance(v, int) or v < 0 for k, v in value.items()):
                    raise ValueError(f'Invalid legacy keyword counts in {source}')
                if key == 'exemptions' and any(not isinstance(value.get(name, []), list) or
                        any(not isinstance(v, str) for v in value.get(name, [])) for name in ('ips', 'patterns')):
                    raise ValueError(f'Invalid legacy exemptions in {source}')
                if key.startswith('blocked:') and isinstance(value, dict) and value.get('expires_at') is not None:
                    if not math.isfinite(float(value['expires_at'])):
                        raise ValueError(f'Invalid legacy block expiry in {source}')
                entries[key] = (value, expiry)
        return entries


def initialize_policy_csv(*, data_dir=None, file_path=None):
    """Accept old file_path configuration while switching its policy to a directory."""
    if data_dir is None and file_path:
        source = Path(file_path)
        if source.name == 'aiwaf_data.csv':
            data_dir = os.environ.get('AIWAF_DATA_DIR') or source.parent / DEFAULT_DATA_DIR
        elif source.name in {'runtime_store.csv', 'runtime_metadata.csv'}:
            data_dir = source.parent
        else:
            # Preserve isolation between separately configured legacy files.
            data_dir = source.with_suffix('')
    return PolicyCSVStorage(data_dir=data_dir, legacy_file=file_path)
