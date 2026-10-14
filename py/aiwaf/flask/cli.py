#!/usr/bin/env python3
"""
AIWAF Flask CLI Management Tool

Provides command-line functions for managing AIWAF data:
- Add/remove IPs from allowlist/blocklist
- View current lists
- Clear data
- Import/export configurations
"""

import argparse
import sys
import json
from collections import Counter
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
import importlib
from aiwaf.core import storage_csv_impl as csv_impl

def get_storage_instance():
    """Get storage instance based on available configuration."""
    try:
        # Import storage functions directly without importing Flask dependencies
        import csv
        import os
        import time
        from pathlib import Path
        from aiwaf.core import storage_csv_impl as csv_impl
        from aiwaf.core.reputation import FIRST_BLOCK_SECONDS, evaluate_reputation, format_block_reason
        
        def _get_data_dir():
            """Get data directory path with automatic configuration."""
            try:
                from .auto_config import get_auto_configured_data_dir, print_auto_config_info
                data_dir, config_info = get_auto_configured_data_dir()
                
                # Only print detailed info in verbose mode or if explicitly requested
                if len(sys.argv) > 1 and '--verbose' in sys.argv:
                    print_auto_config_info(config_info)
                
                return data_dir
            except ImportError:
                # Fallback to original logic if auto_config not available
                return os.environ.get('AIWAF_DATA_DIR', 'aiwaf_data')
        
        def _read_csv_allowlist():
            """Read allowlist from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(parents=True, exist_ok=True)
            allowlist_file = data_dir / 'whitelist.csv'
            
            allowlist = set()
            if allowlist_file.exists():
                with open(allowlist_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            allowlist.add(row[0])
            return allowlist
        
        def _read_csv_blocklist():
            """Read blocklist from CSV."""
            data_dir = Path(_get_data_dir())
            blocklist = csv_impl.read_blocklist(data_dir)
            now = time.time()
            active = {
                ip: entry
                for ip, entry in blocklist.items()
                if not entry.get("expires_at") or float(entry.get("expires_at")) > now
            }
            # Listing is read-only. A worker/trainer may have added or refreshed
            # entries since this snapshot; rewriting it would erase those blocks.
            return active
        
        def _read_csv_keywords():
            """Read keywords from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            keywords_file = data_dir / 'keywords.csv'
            
            keywords = set()
            if keywords_file.exists():
                with open(keywords_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            keywords.add(row[0])
            return keywords

        def _read_csv_path_exemptions():
            """Read path exemptions from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            path_file = data_dir / 'path_exemptions.csv'

            exemptions = {}
            if path_file.exists():
                with open(path_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            path = row[0].strip()
                            reason = row[1].strip() if len(row) > 1 else ''
                            if path:
                                exemptions[path.lower()] = reason
            return exemptions

        def _read_csv_geo_blocked_countries():
            """Read geo blocked countries from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            countries_file = data_dir / 'geo_blocked_countries.csv'

            countries = set()
            if countries_file.exists():
                with open(countries_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            countries.add(row[0].upper())
            return countries
        
        def _append_csv_allowlist(ip):
            """Add IP to allowlist CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            allowlist_file = data_dir / 'whitelist.csv'
            
            # Check if file exists and has header
            file_exists = allowlist_file.exists()
            with open(allowlist_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['ip', 'timestamp'])
                writer.writerow([ip, datetime.now().isoformat()])
        
        def _append_csv_blocklist(ip, reason="Manual addition"):
            """Add IP to blocklist CSV."""
            data_dir = Path(_get_data_dir())
            blocklist = csv_impl.read_blocklist(data_dir)
            existing = blocklist.get(ip) or {}
            now = time.time()
            decision = evaluate_reputation(existing=existing, reason=reason, now=now)
            duration = decision.duration or FIRST_BLOCK_SECONDS
            blocklist[ip] = {
                "ip": ip,
                "reason": reason,
                "reputation_reason": format_block_reason(decision),
                "reasons": decision.reasons,
                "score": decision.score,
                "offenses": decision.offenses,
                "blocked_at": now,
                "added_date": datetime.now().isoformat(),
                "duration": duration,
                "expires_at": now + duration,
                "permanent": False,
            }
            csv_impl.rewrite_blocklist(data_dir, blocklist)

        def _rewrite_csv_blocklist(blocklist):
            """Rewrite blocklist CSV."""
            data_dir = Path(_get_data_dir())
            return csv_impl.rewrite_blocklist(data_dir, blocklist)
        
        def _append_csv_keyword(keyword):
            """Add keyword to keywords CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            keywords_file = data_dir / 'keywords.csv'
            
            # Check if file exists and has header
            file_exists = keywords_file.exists()
            with open(keywords_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['keyword', 'timestamp'])
                writer.writerow([keyword, datetime.now().isoformat()])

        def _append_csv_path_exemption(path, reason=""):
            """Add path exemption to CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            path_file = data_dir / 'path_exemptions.csv'

            file_exists = path_file.exists()
            with open(path_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['path', 'reason', 'timestamp'])
                writer.writerow([path, reason, datetime.now().isoformat()])

        def _rewrite_csv_path_exemptions(exemptions):
            """Rewrite path exemptions CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            path_file = data_dir / 'path_exemptions.csv'
            with open(path_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['path', 'reason', 'timestamp'])
                for path, reason in exemptions.items():
                    writer.writerow([path, reason, datetime.now().isoformat()])

        def _append_csv_geo_blocked_country(country_code):
            """Add country code to geo blocked countries CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            countries_file = data_dir / 'geo_blocked_countries.csv'

            file_exists = countries_file.exists()
            with open(countries_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['country', 'timestamp'])
                writer.writerow([country_code.upper(), datetime.now().isoformat()])

        def _rewrite_csv_geo_blocked_countries(countries):
            """Rewrite geo blocked countries CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            countries_file = data_dir / 'geo_blocked_countries.csv'

            with open(countries_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['country', 'timestamp'])
                for code in sorted(countries):
                    writer.writerow([code, datetime.now().isoformat()])
        
        return {
            'read_allowlist': _read_csv_allowlist,
            'read_blocklist': _read_csv_blocklist,
            'read_keywords': _read_csv_keywords,
            'read_geo_blocked_countries': _read_csv_geo_blocked_countries,
            'read_path_exemptions': _read_csv_path_exemptions,
            'add_allowlist': _append_csv_allowlist,
            'add_blocklist': _append_csv_blocklist,
            'add_keyword': _append_csv_keyword,
            'add_geo_blocked_country': _append_csv_geo_blocked_country,
            'rewrite_geo_blocked_countries': _rewrite_csv_geo_blocked_countries,
            'add_path_exemption': _append_csv_path_exemption,
            'rewrite_path_exemptions': _rewrite_csv_path_exemptions,
            'rewrite_blocklist': _rewrite_csv_blocklist,
            'data_dir': _get_data_dir,
            'mode': 'CSV'
        }
    except Exception as e:
        print(f"  Storage not available: {e}")
        return None

class AIWAFManager:
    """AIWAF management class for CLI operations."""
    
    def __init__(self, data_dir: Optional[str] = None):
        self.storage = get_storage_instance()
        if not self.storage:
            print(" No storage backend available")
            sys.exit(1)
        
        if data_dir:
            # Override data directory if specified
            import os
            os.environ['AIWAF_DATA_DIR'] = data_dir
            print(f" Using specified data directory: {data_dir}")
        else:
            # Use auto-configuration
            try:
                from .auto_config import get_auto_configured_data_dir, print_auto_config_info
                auto_dir, config_info = get_auto_configured_data_dir()
                print_auto_config_info(config_info)
            except ImportError:
                print(f" Using {self.storage['mode']} storage: {self.storage['data_dir']()}")

        from aiwaf.core.policy_csv_storage import PolicyCSVStorage
        self.policy_storage = PolicyCSVStorage(data_dir=self.storage['data_dir']())
    
    def list_allowlist(self) -> List[str]:
        """Get all allowlisted IPs."""
        try:
            allowlist = self.storage['read_allowlist']()
            return sorted(list(allowlist))
        except Exception as e:
            print(f" Error reading allowlist: {e}")
            return []
    
    def list_blocklist(self) -> Dict[str, Any]:
        """Get all blocklisted IPs with timestamps."""
        try:
            blocklist = self.storage['read_blocklist']()
            return dict(sorted(blocklist.items()))
        except Exception as e:
            print(f" Error reading blocklist: {e}")
            return {}
    
    def list_keywords(self) -> List[str]:
        """Get all blocked keywords."""
        try:
            keywords = self.storage['read_keywords']()
            return sorted(list(keywords))
        except Exception as e:
            print(f" Error reading keywords: {e}")
            return []

    def list_geo_blocked_countries(self) -> List[str]:
        """Get all geo blocked countries."""
        try:
            countries = self.storage['read_geo_blocked_countries']()
            return sorted(list(countries))
        except Exception as e:
            print(f" Error reading geo blocked countries: {e}")
            return []

    def list_path_exemptions(self) -> Dict[str, str]:
        """Get all path exemptions."""
        try:
            return dict(self.storage['read_path_exemptions']())
        except Exception as e:
            print(f" Error reading path exemptions: {e}")
            return {}

    def whois_lookup(self, target: str) -> bool:
        """Perform WHOIS lookup without touching request blocking path."""
        try:
            from .aiwaf_whois import run_whois_lookup
        except Exception:
            print(" WHOIS helper unavailable")
            return False

        try:
            result = run_whois_lookup(target)
        except ModuleNotFoundError:
            print(" python-whois is not installed. Install with: pip install python-whois")
            return False
        except Exception as e:
            print(f" WHOIS lookup failed: {e}")
            return False

        print("WHOIS result:")
        if isinstance(result, dict):
            print(json.dumps(result, indent=2, default=str))
        else:
            data = getattr(result, "__dict__", None)
            if isinstance(data, dict) and data:
                print(json.dumps(data, indent=2, default=str))
            else:
                print(str(result))
        return True
    
    def add_to_allowlist(self, ip: str) -> bool:
        """Add IP to allowlist."""
        try:
            self.storage['add_allowlist'](ip)
            print(f" Added {ip} to allowlist")
            return True
        except Exception as e:
            print(f" Error adding {ip} to allowlist: {e}")
            return False
    
    def add_to_blocklist(self, ip: str, reason: str = "Manual CLI addition") -> bool:
        """Add IP to blocklist."""
        try:
            self.storage['add_blocklist'](ip, reason)
            print(f" Added {ip} to blocklist")
            return True
        except Exception as e:
            print(f" Error adding {ip} to blocklist: {e}")
            return False
    
    def add_keyword(self, keyword: str) -> bool:
        """Add keyword to blocked list."""
        try:
            self.storage['add_keyword'](keyword)
            print(f" Added '{keyword}' to blocked keywords")
            return True
        except Exception as e:
            print(f" Error adding keyword '{keyword}': {e}")
            return False

    def add_geo_blocked_country(self, country_code: str) -> bool:
        """Add country to geo blocked list."""
        if not country_code:
            print(" Country code is required")
            return False
        code = str(country_code).strip().upper()
        try:
            current = set(self.list_geo_blocked_countries())
            if code in current:
                print(f"  {code} already blocked")
                return True
            self.storage['add_geo_blocked_country'](code)
            print(f" Blocked country added: {code}")
            return True
        except Exception as e:
            print(f" Error adding geo blocked country '{code}': {e}")
            return False

    def add_path_exemption(self, path: str, reason: str = "") -> bool:
        """Add a path exemption."""
        if not path:
            print(" Path is required")
            return False
        normalized = str(path).strip()
        if not normalized:
            print(" Path is required")
            return False
        current = self.list_path_exemptions()
        if normalized.lower() in current:
            print(f"  Already exempt: {normalized}")
            return True
        try:
            self.storage['add_path_exemption'](normalized, reason)
            print(f" Exempted path: {normalized}")
            return True
        except Exception as e:
            print(f" Error adding path exemption: {e}")
            return False

    def remove_path_exemption(self, path: str) -> bool:
        """Remove a path exemption."""
        if not path:
            print(" Path is required")
            return False
        normalized = str(path).strip()
        if not normalized:
            print(" Path is required")
            return False
        exemptions = self.list_path_exemptions()
        if normalized.lower() not in exemptions:
            print(f"  Not exempt: {normalized}")
            return False
        try:
            exemptions.pop(normalized.lower(), None)
            self.storage['rewrite_path_exemptions'](exemptions)
            print(f" Removed path exemption: {normalized}")
            return True
        except Exception as e:
            print(f" Error removing path exemption: {e}")
            return False

    def remove_geo_blocked_country(self, country_code: str) -> bool:
        """Remove country from geo blocked list."""
        if not country_code:
            print(" Country code is required")
            return False
        code = str(country_code).strip().upper()
        try:
            current = set(self.list_geo_blocked_countries())
            if code not in current:
                print(f"  {code} not found in geo blocked countries")
                return False
            current.discard(code)
            self.storage['rewrite_geo_blocked_countries'](current)
            print(f" Blocked country removed: {code}")
            return True
        except Exception as e:
            print(f" Error removing geo blocked country '{code}': {e}")
            return False
    
    def remove_from_allowlist(self, ip: str) -> bool:
        """Remove IP from allowlist."""
        try:
            data_dir = Path(self.storage['data_dir']())
            allowlist_file = data_dir / 'whitelist.csv'
            
            if not allowlist_file.exists():
                print(f" Allowlist file not found")
                return False
            
            # Read current data
            current = self.list_allowlist()
            if ip not in current:
                print(f"  {ip} not found in allowlist")
                return False
            
            # Rewrite file without the IP
            import csv
            with open(allowlist_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'timestamp'])
                for existing_ip in current:
                    if existing_ip != ip:
                        writer.writerow([existing_ip, datetime.now().isoformat()])
            
            print(f" Removed {ip} from allowlist")
            return True
        except Exception as e:
            print(f" Error removing {ip} from allowlist: {e}")
            return False
    
    def remove_from_blocklist(self, ip: str) -> bool:
        """Remove IP from blocklist."""
        try:
            current = self.list_blocklist()
            if ip not in current:
                print(f"  {ip} not found in blocklist")
                return False

            del current[ip]
            self.storage['rewrite_blocklist'](current)
            
            print(f" Removed {ip} from blocklist")
            return True
        except Exception as e:
            print(f" Error removing {ip} from blocklist: {e}")
            return False
    
    def show_stats(self):
        """Display statistics about current AIWAF data."""
        allowlist = self.list_allowlist()
        blocklist = self.list_blocklist()
        keywords = self.list_keywords()
        
        print("\n AIWAF Statistics")
        print("=" * 50)
        print(f"Allowlisted IPs: {len(allowlist)}")
        print(f"Blocklisted IPs: {len(blocklist)}")
        print(f"Blocked Keywords: {len(keywords)}")
        print(f"Storage Mode: {self.storage['mode']}")
        print(f"Data Directory: {self.storage['data_dir']()}")

    def clear_blocklist(self) -> bool:
        """Clear all blocked IPs."""
        try:
            self.storage['rewrite_blocklist']({})
            print(" Cleared blocked IPs")
            return True
        except Exception as e:
            print(f" Error clearing blocked IPs: {e}")
            return False

    def legacy_blocklist(self) -> Dict[str, Any]:
        """Get legacy-imported blocklist entries."""
        return {
            ip: entry
            for ip, entry in self.list_blocklist().items()
            if csv_impl.is_legacy_blocklist_entry(entry)
        }

    def show_legacy_blocklist(self) -> None:
        legacy = self.legacy_blocklist()
        print(f"\n Legacy Blocklist Entries ({len(legacy)}):")
        for ip, entry in legacy.items():
            print(f"   {ip} - {entry.get('reason', 'legacy_import')} ({entry.get('reputation_reason', 'legacy_blacklist')})")

    def migrate_blocklist(self) -> int:
        """Force CSV blocklist migration and report legacy entries."""
        blocklist = self.list_blocklist()
        legacy_count = len([
            entry for entry in blocklist.values()
            if csv_impl.is_legacy_blocklist_entry(entry)
        ])
        print("Legacy blocklist detected." if legacy_count else "No legacy blocklist entries detected.")
        print(f"{legacy_count} permanent entries imported.")
        if legacy_count:
            print("Options:")
            print("1. Keep as permanent")
            print("2. Convert to temporary blocks: aiwaf blocklist convert-legacy --duration 24h")
            print("3. Clear legacy blocks: aiwaf blocklist clear-legacy")
        return legacy_count

    def convert_legacy_blocklist(self, duration_seconds: Optional[int] = None, clear: bool = False) -> int:
        current = self.list_blocklist()
        changed = 0
        now = datetime.now().timestamp()
        for ip in list(current.keys()):
            entry = current[ip]
            if not csv_impl.is_legacy_blocklist_entry(entry):
                continue
            changed += 1
            if clear:
                del current[ip]
                continue
            entry["permanent"] = duration_seconds is None
            entry["duration"] = duration_seconds
            entry["expires_at"] = now + duration_seconds if duration_seconds else None
            entry["blocked_at"] = entry.get("blocked_at") or now
            entry["reputation_reason"] = "legacy_blacklist_converted" if duration_seconds else "legacy_blacklist"
            current[ip] = entry
        if changed:
            self.storage['rewrite_blocklist'](current)
        if clear:
            print(f" Cleared {changed} legacy blocklist entries")
        elif duration_seconds:
            print(f" Converted {changed} legacy entries to {duration_seconds} second temporary blocks")
        else:
            print(f" Kept {changed} legacy entries as permanent blocks")
        return changed
    
    def export_config(self, filename: str):
        """Export current configuration to JSON file."""
        try:
            config = {
                'allowlist': self.list_allowlist(),
                'blocklist': self.list_blocklist(),
                'keywords': self.list_keywords(),
                'exported_at': datetime.now().isoformat(),
                'storage_mode': self.storage['mode']
            }
            
            with open(filename, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f" Configuration exported to {filename}")
            return True
        except Exception as e:
            print(f" Error exporting configuration: {e}")
            return False
    
    def import_config(self, filename: str):
        """Import configuration from JSON file."""
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            success_count = 0
            
            # Import allowlist
            for ip in config.get('allowlist', config.get('whitelist', [])):
                if self.add_to_allowlist(ip):
                    success_count += 1
            
            # Import blocklist
            for ip, data in config.get('blocklist', config.get('blacklist', {})).items():
                reason = data.get('reason', 'Imported from config') if isinstance(data, dict) else 'Imported from config'
                if self.add_to_blocklist(ip, reason):
                    success_count += 1
            
            # Import keywords
            for keyword in config.get('keywords', []):
                if self.add_keyword(keyword):
                    success_count += 1
            
            print(f" Imported {success_count} items from {filename}")
            return True
        except Exception as e:
            print(f" Error importing configuration: {e}")
            return False
    
    def analyze_logs(self, log_dir: Optional[str] = None, log_format: str = 'combined'):
        """Analyze AIWAF logs and show statistics."""
        try:
            from .logging_middleware import analyze_access_logs
            
            if log_dir:
                actual_log_dir = log_dir
                print(f" Using specified log directory: {actual_log_dir}")
            else:
                # Use automatic log directory detection
                try:
                    from .auto_config import get_auto_configured_log_dir
                    actual_log_dir, log_config_info = get_auto_configured_log_dir()
                    print(f" Auto-configured log directory: {actual_log_dir}")
                    method = log_config_info.get('detection_method', 'unknown')
                    print(f" Log detection method: {method}")
                except ImportError:
                    # Fallback to relative path
                    actual_log_dir = 'logs'
                    print(f" Using default log directory: {actual_log_dir}")
            
            stats = analyze_access_logs(actual_log_dir, log_format)
            
            if 'error' in stats:
                print(f" {stats['error']}")
                return False
            
            print("\n AIWAF Access Log Analysis")
            print("=" * 50)
            print(f"Total Requests: {stats['total_requests']}")
            print(f"Blocked Requests: {stats['blocked_requests']}")
            print(f"Unique IPs: {len(stats.get('ips', {}))}")
            print(f"Block Rate: {(stats['blocked_requests']/stats['total_requests']*100):.1f}%" if stats['total_requests'] > 0 else "Block Rate: 0.0%")
            
            # Performance metrics
            if 'avg_response_time' in stats:
                print(f"Average Response Time: {stats['avg_response_time']:.0f}ms")
                print(f"95th Percentile Response Time: {stats.get('p95_response_time', 0):.0f}ms")
            
            # Status code distribution
            if stats.get('status_codes'):
                print(f"\n Status Code Distribution:")
                for code, count in sorted(stats['status_codes'].items()):
                    percentage = (count / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                    print(f"   {code}: {count} ({percentage:.1f}%)")
            
            # Top IPs
            if stats.get('top_ips'):
                print(f"\n Top Client IPs:")
                for ip, count in stats['top_ips'][:5]:
                    percentage = (count / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                    print(f"   {ip}: {count} requests ({percentage:.1f}%)")
            
            # Top paths
            if stats.get('top_paths'):
                print("\nMost Requested Paths:")
                for path, count in stats['top_paths'][:5]:
                    print(f"   {path}: {count} requests")
            
            # Blocked request reasons
            if stats.get('blocked_reasons'):
                print(f"\n Block Reasons:")
                for reason, count in sorted(stats['blocked_reasons'].items(), key=lambda x: x[1], reverse=True):
                    print(f"   {reason}: {count} times")
            
            # Hourly distribution
            if stats.get('hourly_distribution'):
                print(f"\n Hourly Request Distribution:")
                max_requests = max(stats['hourly_distribution'].values()) if stats['hourly_distribution'] else 1
                for hour in sorted(stats['hourly_distribution'].keys()):
                    count = stats['hourly_distribution'][hour]
                    bar_length = int((count / max_requests) * 30)  # Scale to 30 chars max
                    bar = "█" * bar_length
                    print(f"  {hour}:00 {bar:<30} {count}")
            
            return True
            
        except Exception as e:
            print(f" Error analyzing logs: {e}")
            return False

    def geoip_traffic_summary(self, log_dir: Optional[str] = None, top: int = 10, limit: int = 0):
        """Summarize request traffic by country using the GeoIP database."""
        try:
            from flask import Flask
            from .trainer import _trainer
            from .geoip import lookup_country_name

            top_n = max(1, int(top))
            max_lines = max(0, int(limit))

            if log_dir:
                actual_log_dir = log_dir
            else:
                try:
                    from .auto_config import get_auto_configured_log_dir
                    actual_log_dir, _ = get_auto_configured_log_dir()
                except ImportError:
                    actual_log_dir = 'logs'

            app = Flask(__name__)
            app.config['AIWAF_LOG_DIR'] = actual_log_dir
            _trainer.init_app(app)

            lines = _trainer._read_all_logs()
            if not lines:
                print("No log lines found  check AIWAF_LOG_DIR setting.")
                return False

            ip_counts = Counter()
            processed = 0
            for line in lines:
                rec = _trainer._parse(line)
                if not rec:
                    continue
                ip_counts[rec["ip"]] += 1
                processed += 1
                if max_lines and processed >= max_lines:
                    break

            if not ip_counts:
                print("No valid log entries to process.")
                return False

            country_counts = Counter()
            unknown = 0
            for ip, count in ip_counts.items():
                name = lookup_country_name(ip, cache_prefix="aiwaf:geo:summary:", cache_seconds=3600)
                if name:
                    country_counts[name] += count
                else:
                    unknown += count

            print(f"GeoIP traffic summary (top {top_n}):")
            for code, count in country_counts.most_common(top_n):
                print(f"  - {code}: {count}")
            if unknown:
                print(f"  - UNKNOWN: {unknown}")
            return True
        except Exception as e:
            print(f" GeoIP summary failed: {e}")
            return False
    
    def train_model(self, log_dir: Optional[str] = None, disable_ai: bool = False, 
                   min_ai_logs: int = 10000, force_ai: bool = False, verbose: bool = False):
        """Train AIWAF AI model from access logs."""
        try:
            from flask import Flask
            from .trainer import train_from_logs
            
            # Determine log directory
            if log_dir:
                actual_log_dir = log_dir
            else:
                # Use automatic log directory detection
                try:
                    from .auto_config import get_auto_configured_log_dir
                    actual_log_dir, log_config_info = get_auto_configured_log_dir()
                    if verbose:
                        method = log_config_info.get('detection_method', 'unknown')
                        print(f" Auto-configured log directory: {actual_log_dir}")
                        print(f" Log detection method: {method}")
                except ImportError:
                    # Fallback to relative path
                    actual_log_dir = 'logs'
            
            if verbose:
                print(" AIWAF Flask Training Tool")
                print("=" * 40)
                print(f"Log directory: {actual_log_dir}")
                print(f"AI training: {'disabled' if disable_ai else 'enabled'}")
                print(f"Min AI logs threshold: {min_ai_logs}")
                print(f"Force AI: {force_ai}")
                print("=" * 40)
            
            # Create minimal Flask app for training
            app = Flask(__name__)
            
            # Configure AIWAF settings
            app.config['AIWAF_LOG_DIR'] = actual_log_dir
            app.config['AIWAF_DYNAMIC_TOP_N'] = 15
            app.config['AIWAF_AI_CONTAMINATION'] = 0.05
            app.config['AIWAF_MIN_AI_LOGS'] = min_ai_logs
            app.config['AIWAF_FORCE_AI'] = force_ai
            
            # Optional settings (can be customized)
            app.config['AIWAF_EXEMPT_PATHS'] = {'/health', '/status', '/favicon.ico'}
            app.config['AIWAF_EXEMPT_KEYWORDS'] = ['health', 'status', 'ping', 'check']
            
            # Set data directory for training
            if hasattr(self, 'storage') and 'data_dir' in self.storage:
                app.config['AIWAF_DATA_DIR'] = self.storage['data_dir']()
            
            # Run training with app context
            with app.app_context():
                train_from_logs(app, disable_ai=disable_ai)
            
            if verbose:
                print("\n Training completed successfully!")
                if not disable_ai:
                    print(" AI model saved and ready for anomaly detection")
                else:
                    print(" Keyword learning completed")
                print("  Enhanced protection is now active!")
            else:
                print(" Training completed successfully!")
            
            return True
            
        except ImportError as e:
            if 'flask' in str(e).lower():
                print(" Flask is required for training. Install with: pip install flask")
            else:
                print(f" Missing training dependencies: {e}")
                if not disable_ai:
                    print(" Try with --disable-ai for keyword-only training")
            return False
        except Exception as e:
            print(f" Training failed: {e}")
            if not disable_ai:
                print(" Try with --disable-ai if AI dependencies are missing")
            return False
    
    def model_diagnostics(self, check: bool = False, retrain: bool = False, info: bool = False):
        """Run model diagnostics and management."""
        try:
            from pathlib import Path
            import warnings
            
            # Use the same model path function as trainer
            from .trainer import get_default_model_path
            model_path = Path(get_default_model_path())
            
            if info or check:
                print(" AIWAF Model Diagnostics")
                print("=" * 50)
                print(f" Model path: {model_path}")
                print(f" Model exists: {model_path.exists()}")
                
                if not model_path.exists():
                    print(" No model found")
                    if retrain:
                        print(" Proceeding with training...")
                        return self.train_model(verbose=True)
                    else:
                        print(" Run 'aiwaf train' to create a model")
                        return False
            
            if check or info:
                # Try to load and check the model
                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")
                    
                    try:
                        from aiwaf.core.model_security import is_trusted_model_path
                        from aiwaf.core.model_serialization import load_model_artifact
                        from .trainer import get_default_model_path

                        if not is_trusted_model_path(str(model_path), default_path=str(get_default_model_path())):
                            print(" Model path is not trusted; refusing to load custom artifacts by default")
                            return False

                        model_data = load_model_artifact(model_path)
                        
                        # Check for warnings
                        sklearn_warnings = [warning for warning in w 
                                          if 'sklearn' in str(warning.message).lower()]
                        
                        if sklearn_warnings:
                            print("  Sklearn version compatibility warnings:")
                            for warning in sklearn_warnings:
                                print(f"   {warning.message}")
                            
                            if check:
                                print("\n Model loads but may have compatibility issues")
                                print("   Consider retraining: aiwaf model --retrain")
                        else:
                            print(" Model loads successfully without warnings")
                        
                        if info:
                            # Show model information
                            if isinstance(model_data, dict):
                                print("\n Model Information:")
                                print(f"   Format: Enhanced (with metadata)")
                                for key, value in model_data.items():
                                    if key == 'model':
                                        print(f"   Model Type: {type(value).__name__}")
                                    else:
                                        print(f"   {key}: {value}")
                            else:
                                print("\n Model Information:")
                                print(f"   Format: Legacy (direct model)")
                                print(f"   Model Type: {type(model_data).__name__}")
                        
                        # Get file stats
                        import os
                        file_stats = os.stat(model_path)
                        file_size = file_stats.st_size
                        modified_time = datetime.fromtimestamp(file_stats.st_mtime)
                        
                        if info:
                            print(f"\n File Information:")
                            print(f"   Size: {file_size:,} bytes")
                            print(f"   Modified: {modified_time}")
                            
                            # Try to get sklearn version info
                            try:
                                import sklearn
                                print(f"   Current sklearn: {sklearn.__version__}")
                            except ImportError:
                                print(f"   Current sklearn: Not installed")
                        
                        return True
                        
                    except Exception as e:
                        print(f" Error loading model: {e}")
                        if retrain:
                            print(" Model appears corrupted, proceeding with retraining...")
                            return self.train_model(verbose=True)
                        else:
                            print(" Model may be corrupted. Try: aiwaf model --retrain")
                            return False
            
            if retrain:
                print(" Retraining model with current dependencies...")
                return self.train_model(verbose=True)
            
            return True
            
        except Exception as e:
            print(f" Model diagnostics failed: {e}")
            return False


from aiwaf.core.utils import RouteNode, normalize_path, build_tree, sorted_children

def _collect_routes(app):
    routes = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        routes.append(normalize_path(rule.rule))
    return routes


def _load_flask_app(app_path):
    module_path, _, obj = app_path.partition(":")
    if not module_path or not obj:
        raise ValueError("Use --app module:app or module:create_app")
    project_root = str(Path.cwd())
    while project_root in sys.path:
        sys.path.remove(project_root)
    sys.path.insert(0, project_root)
    module = importlib.import_module(module_path)
    target = getattr(module, obj, None)
    if target is None:
        raise ValueError(f"App not found: {app_path}")
    if callable(target) and not hasattr(target, "url_map"):
        return target()
    return target


def _resolve_target(current, arg):
    children = sorted_children(current)
    if arg.isdigit():
        idx = int(arg) - 1
        if 0 <= idx < len(children):
            return children[idx]
        return None
    for child in children:
        if child.name == arg or f"{child.name}/" == arg:
            return child
    return None


def _route_shell(app, manager):
    routes = _collect_routes(app)
    root = build_tree(routes)
    stack = [root]

    print("AIWAF route shell. Type 'help' for commands.")
    while True:
        current = stack[-1]
        prompt = f"aiwaf:{current.full_path}$ "
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not raw or raw == "ls":
            children = sorted_children(current)
            if current.is_endpoint and current is not root:
                print("(endpoint) .")
            if not children:
                print("(empty)")
                continue
            for idx, child in enumerate(children, 1):
                suffix = " (endpoint)" if child.is_endpoint else ""
                print(f"{idx}. {child.name}/{suffix}")
            continue

        parts = raw.split()
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None

        if cmd in {"quit", "exit"}:
            break
        if cmd in {"help", "?"}:
            print("AIWAF Path Shell Commands:")
            print("  ls                     # list routes at current level")
            print("  cd <index|name>        # enter a route segment")
            print("  up / cd ..             # go up one level")
            print("  pwd                    # show current path prefix")
            print("  exempt <index|name|.>  # add exemption for selection or current path")
            print("  exit                   # quit")
            continue
        if cmd in {"up", ".."}:
            if len(stack) > 1:
                stack.pop()
            continue
        if cmd == "pwd":
            print(current.full_path)
            continue
        if cmd == "cd":
            if not arg:
                print("Usage: cd <index|name>")
                continue
            if arg == "..":
                if len(stack) > 1:
                    stack.pop()
                continue
            if arg == "/":
                stack[:] = [root]
                continue
            target = _resolve_target(current, arg)
            if not target:
                print(f"Unknown target: {arg}")
                continue
            stack.append(target)
            continue
        if cmd == "exempt":
            if not arg:
                print("Usage: exempt <index|name|.>")
                continue
            target = current if arg == "." else _resolve_target(current, arg)
            if not target:
                print(f"Unknown target: {arg}")
                continue
            path = target.full_path
            existing = set(manager.list_path_exemptions().keys())
            if path.lower() in existing:
                print(f"Already exempt: {path}")
                continue
            reason = input("Reason (optional): ").strip()
            manager.add_path_exemption(path, reason=reason or "Manual exemption")
            continue

        print(f"Unknown command: {cmd}")


def main():
    """Main CLI interface."""
    def _parse_duration(value: str) -> int:
        raw = str(value or "").strip().lower()
        if not raw:
            raise argparse.ArgumentTypeError("duration is required")
        multipliers = {
            "s": 1,
            "m": 60,
            "h": 60 * 60,
            "d": 24 * 60 * 60,
        }
        suffix = raw[-1]
        if suffix in multipliers:
            number = raw[:-1]
            if not number.isdigit():
                raise argparse.ArgumentTypeError("duration must be like 900s, 15m, 24h, or 1d")
            return int(number) * multipliers[suffix]
        if raw.isdigit():
            return int(raw)
        raise argparse.ArgumentTypeError("duration must be like 900s, 15m, 24h, or 1d")

    parser = argparse.ArgumentParser(description='AIWAF Flask Management Tool')
    parser.add_argument('--data-dir', help='Custom data directory path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List commands
    list_parser = subparsers.add_parser('list', help='List current data')
    list_parser.add_argument('type', choices=['allowlist', 'blocklist', 'keywords', 'all'],
                           help='Type of data to list')
    
    # Add commands
    add_parser = subparsers.add_parser('add', help='Add item to list')
    add_parser.add_argument('type', choices=['allowlist', 'blocklist', 'keyword'],
                          help='Type of list to add to')
    add_parser.add_argument('value', help='IP address or keyword to add')
    add_parser.add_argument('--reason', help='Reason for blocklisting (blocklist only)')
    
    # Remove commands
    remove_parser = subparsers.add_parser('remove', help='Remove item from list')
    remove_parser.add_argument('type', choices=['allowlist', 'blocklist'],
                             help='Type of list to remove from')
    remove_parser.add_argument('value', help='IP address to remove')

    # Geo blocked countries commands
    geo_parser = subparsers.add_parser('geo', help='Manage geo blocked countries')
    geo_parser.add_argument('action', choices=['add', 'remove', 'list'],
                            help='Action to perform')
    geo_parser.add_argument('country', nargs='?', help='ISO country code (e.g. US)')

    # Path exemption commands
    path_parser = subparsers.add_parser('exempt-path', help='Manage path exemptions')
    path_parser.add_argument('action', choices=['add', 'remove', 'list'],
                             help='Action to perform')
    path_parser.add_argument('path', nargs='?', help='Path to exempt (e.g. /health)')
    path_parser.add_argument('--reason', default='', help='Reason for exemption')
    
    # Stats command
    subparsers.add_parser('stats', help='Show statistics')
    subparsers.add_parser('status', help='Show AIWAF status')
    subparsers.add_parser('blocked', help='List blocked IPs')
    unblock_parser = subparsers.add_parser('unblock', help='Unblock an IP address')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    subparsers.add_parser('clear', help='Clear all blocked IPs')

    blocklist_parser = subparsers.add_parser('blocklist', help='Manage blocklist migrations')
    blocklist_subparsers = blocklist_parser.add_subparsers(dest='blocklist_command')
    blocklist_migrate_parser = blocklist_subparsers.add_parser(
        'migrate', help='Detect and migrate the configured blocklist backend'
    )
    blocklist_migrate_parser.add_argument(
        '--app', help='Flask app import path for detecting SQLAlchemy/CSV configuration'
    )
    blocklist_list_parser = blocklist_subparsers.add_parser('list', help='List blocklist entries')
    blocklist_list_parser.add_argument('--legacy', action='store_true', help='Only show legacy imported entries')
    convert_parser = blocklist_subparsers.add_parser('convert-legacy', help='Convert legacy permanent blocks')
    convert_parser.add_argument('--duration', type=_parse_duration, default=24 * 60 * 60,
                                help='Temporary duration, e.g. 24h, 1d, 60m (default: 24h)')
    blocklist_subparsers.add_parser('clear-legacy', help='Clear legacy imported blocks')
    
    # Log analysis command
    logs_parser = subparsers.add_parser('logs', help='Analyze request logs')
    logs_parser.add_argument('--log-dir', help='Custom log directory path')
    logs_parser.add_argument('--format', choices=['combined', 'common', 'csv', 'json'], 
                           default='combined', help='Log format to analyze')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train AI model from logs')
    train_parser.add_argument('--log-dir', help='Custom log directory path (default: logs)')
    train_parser.add_argument('--disable-ai', action='store_true', 
                            help='Disable AI model training (keyword learning only)')
    train_parser.add_argument('--min-ai-logs', type=int, default=10000,
                            help='Minimum log lines required for AI training (default: 10000)')
    train_parser.add_argument('--force-ai', action='store_true',
                            help='Force AI training even with insufficient log data')
    train_parser.add_argument('--verbose', '-v', action='store_true',
                            help='Enable verbose output')
    
    # Model diagnostics command
    model_parser = subparsers.add_parser('model', help='Model diagnostics and management')
    model_parser.add_argument('--check', action='store_true',
                            help='Check model compatibility')
    model_parser.add_argument('--retrain', action='store_true',
                            help='Force retrain model with current dependencies')
    model_parser.add_argument('--info', action='store_true',
                            help='Show model information')
    
    # Export/Import commands
    export_parser = subparsers.add_parser('export', help='Export configuration')
    export_parser.add_argument('filename', help='Output JSON file')
    
    import_parser = subparsers.add_parser('import', help='Import configuration')
    import_parser.add_argument('filename', help='Input JSON file')

    # GeoIP summary command
    geo_summary_parser = subparsers.add_parser('geo-summary', help='GeoIP traffic summary from logs')
    geo_summary_parser.add_argument('--top', type=int, default=10,
                                    help='Number of top countries to display (default: 10)')
    geo_summary_parser.add_argument('--limit', type=int, default=0,
                                    help='Limit number of log lines processed (default: 0, no limit)')
    geo_summary_parser.add_argument('--log-dir', help='Custom log directory path (default: auto)')

    # Route shell command
    route_shell_parser = subparsers.add_parser('route-shell', help='Interactive route browser for exemptions')
    route_shell_parser.add_argument('--app', required=True, help='Flask app import path (module:app)')

    # Init path manifest command
    init_parser = subparsers.add_parser('init', help='Generate .aiwaf/paths.json from a Flask app')
    init_parser.add_argument('--app', required=True, help='Flask app import path (module:app or module:create_app)')
    init_parser.add_argument('--output', default='.aiwaf/paths.json', help='Output manifest path')

    # WHOIS command
    whois_parser = subparsers.add_parser('whois', help='Run WHOIS ownership lookup')
    whois_parser.add_argument('target', help='Domain or IP address')
    
    # Preserve old command spellings while advertising the new terminology.
    argv = list(sys.argv[1:])
    command_index = 2 if argv[:1] == ['--data-dir'] else 1 if argv and argv[0].startswith('--data-dir=') else 0
    if len(argv) > command_index and argv[command_index] == 'blacklist':
        argv[command_index] = 'blocklist'
    if len(argv) > command_index + 1 and argv[command_index] in {'list', 'add', 'remove'}:
        i = command_index + 1
        argv[i] = {'blacklist': 'blocklist', 'whitelist': 'allowlist'}.get(argv[i], argv[i])
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize manager
    manager = AIWAFManager(args.data_dir)
    
    # Execute commands
    if args.command == 'list':
        if args.type == 'allowlist' or args.type == 'all':
            allowlist = manager.list_allowlist()
            print(f"\n Allowlisted IPs ({len(allowlist)}):")
            for ip in allowlist:
                print(f"   {ip}")
        
        if args.type == 'blocklist' or args.type == 'all':
            blocklist = manager.list_blocklist()
            print(f"\n Blocklisted IPs ({len(blocklist)}):")
            for ip, data in blocklist.items():
                if isinstance(data, dict):
                    reason = data.get('reason', 'Unknown')
                    timestamp = data.get('added_date') or data.get('timestamp') or 'Unknown'
                    print(f"   {ip} - {reason} ({timestamp})")
                else:
                    print(f"   {ip}")
        
        if args.type == 'keywords' or args.type == 'all':
            keywords = manager.list_keywords()
            print(f"\n Blocked Keywords ({len(keywords)}):")
            for keyword in keywords:
                print(f"   {keyword}")
    
    elif args.command == 'add':
        if args.type == 'allowlist':
            manager.add_to_allowlist(args.value)
        elif args.type == 'blocklist':
            reason = args.reason or "Manual CLI addition"
            manager.add_to_blocklist(args.value, reason)
        elif args.type == 'keyword':
            manager.add_keyword(args.value)
    
    elif args.command == 'remove':
        if args.type == 'allowlist':
            manager.remove_from_allowlist(args.value)
        elif args.type == 'blocklist':
            manager.remove_from_blocklist(args.value)

    elif args.command == 'geo':
        if args.action == 'list':
            countries = manager.list_geo_blocked_countries()
            if countries:
                print("Blocked countries: " + ", ".join(countries))
            else:
                print("Blocked countries: (none)")
        else:
            if not args.country:
                print(" Country code is required")
                return
            if args.action == 'add':
                manager.add_geo_blocked_country(args.country)
            elif args.action == 'remove':
                manager.remove_geo_blocked_country(args.country)

    elif args.command == 'exempt-path':
        if args.action == 'list':
            exemptions = manager.list_path_exemptions()
            if exemptions:
                for path, reason in sorted(exemptions.items()):
                    suffix = f" ({reason})" if reason else ""
                    print(f"{path}{suffix}")
            else:
                print("Path exemptions: (none)")
        else:
            if not args.path:
                print(" Path is required")
                return
            if args.action == 'add':
                manager.add_path_exemption(args.path, reason=args.reason)
            elif args.action == 'remove':
                manager.remove_path_exemption(args.path)
    
    elif args.command in {'stats', 'status'}:
        manager.show_stats()

    elif args.command == 'blocked':
        blocklist = manager.list_blocklist()
        print(f"\n Blocked IPs ({len(blocklist)}):")
        for ip, data in blocklist.items():
            if isinstance(data, dict):
                reason = data.get('reason', 'Unknown')
                timestamp = data.get('added_date') or data.get('timestamp') or 'Unknown'
                expires = data.get('expires_at') or data.get('expires') or ''
                suffix = f", expires={expires}" if expires else ""
                print(f"   {ip} - {reason} ({timestamp}{suffix})")
            else:
                print(f"   {ip}")

    elif args.command == 'unblock':
        manager.remove_from_blocklist(args.ip)

    elif args.command == 'clear':
        manager.clear_blocklist()

    elif args.command == 'blocklist':
        if args.blocklist_command == 'migrate':
            if args.app:
                app = _load_flask_app(args.app)
                with app.app_context():
                    from aiwaf.flask.storage import _get_storage_mode

                    if _get_storage_mode() == "database":
                        from sqlalchemy import inspect, or_
                        from aiwaf.flask.db_models import BlocklistedIP, db

                        columns = {
                            column["name"]
                            for column in inspect(db.engine).get_columns(BlocklistedIP.__tablename__)
                        }
                        required = {
                            "reputation_reason", "reasons", "score", "offenses",
                            "blocked_at", "expires_at", "duration", "permanent",
                        }
                        missing = sorted(required - columns)
                        if missing:
                            parser.error(
                                "SQLAlchemy blocklist table is missing columns: "
                                + ", ".join(missing)
                                + ". Run `flask db migrate` and `flask db upgrade`, then rerun."
                            )
                        changed = BlocklistedIP.query.filter(
                            or_(
                                BlocklistedIP.reputation_reason == "",
                                BlocklistedIP.reputation_reason.is_(None),
                            ),
                            BlocklistedIP.blocked_at.is_(None),
                        ).update(
                            {
                                BlocklistedIP.reputation_reason: "legacy_blacklist",
                                BlocklistedIP.reasons: ["legacy_blacklist"],
                                BlocklistedIP.score: 100,
                                BlocklistedIP.offenses: 1,
                                BlocklistedIP.permanent: True,
                            },
                            synchronize_session=False,
                        )
                        db.session.commit()
                        print(f" Flask SQLAlchemy blocklist upgraded: {changed} legacy entries updated")
                    else:
                        configured_dir = app.config.get("AIWAF_DATA_DIR") or args.data_dir
                        AIWAFManager(configured_dir).migrate_blocklist()
            else:
                manager.migrate_blocklist()
        elif args.blocklist_command == 'list':
            if args.legacy:
                manager.show_legacy_blocklist()
            else:
                blocklist = manager.list_blocklist()
                print(f"\n Blocklist Entries ({len(blocklist)}):")
                for ip, data in blocklist.items():
                    print(f"   {ip} - {data.get('reason', 'Unknown') if isinstance(data, dict) else data}")
        elif args.blocklist_command == 'convert-legacy':
            manager.convert_legacy_blocklist(duration_seconds=args.duration)
        elif args.blocklist_command == 'clear-legacy':
            manager.convert_legacy_blocklist(clear=True)
        else:
            blocklist_parser.print_help()
    
    elif args.command == 'logs':
        log_format = getattr(args, 'format', 'combined')
        manager.analyze_logs(args.log_dir, log_format)
    
    elif args.command == 'train':
        manager.train_model(args.log_dir, args.disable_ai, args.min_ai_logs, args.force_ai, args.verbose)
    
    elif args.command == 'model':
        # Handle model diagnostics
        if not any([args.check, args.retrain, args.info]):
            # Default to showing info if no specific action
            args.info = True
        manager.model_diagnostics(args.check, args.retrain, args.info)
    
    elif args.command == 'export':
        manager.export_config(args.filename)
    
    elif args.command == 'import':
        manager.import_config(args.filename)

    elif args.command == 'geo-summary':
        manager.geoip_traffic_summary(args.log_dir, args.top, args.limit)

    elif args.command == 'route-shell':
        try:
            app = _load_flask_app(args.app)
        except Exception as e:
            print(f" Failed to load app: {e}")
            return
        _route_shell(app, manager)

    elif args.command == 'init':
        try:
            from aiwaf.flask.path_manifest import generate_flask_manifest

            app = _load_flask_app(args.app)
            manifest = generate_flask_manifest(app, args.output)
        except Exception as e:
            print(f" Init failed: {e}")
            return
        print(f"Generated {args.output}")
        print(f"Framework: {manifest['framework']}")
        print(f"Routes: {len(manifest.get('routes', {}))}")
        print(f"Context hash: {manifest['context_hash']}")

    elif args.command == 'whois':
        manager.whois_lookup(args.target)

if __name__ == '__main__':
    main()


# Compatibility aliases for callers using the previous terminology.
AIWAFManager.list_whitelist = AIWAFManager.__dict__['list_allowlist']
AIWAFManager.list_blacklist = AIWAFManager.__dict__['list_blocklist']
AIWAFManager.add_to_whitelist = AIWAFManager.__dict__['add_to_allowlist']
AIWAFManager.add_to_blacklist = AIWAFManager.__dict__['add_to_blocklist']
AIWAFManager.remove_from_whitelist = AIWAFManager.__dict__['remove_from_allowlist']
AIWAFManager.remove_from_blacklist = AIWAFManager.__dict__['remove_from_blocklist']
AIWAFManager.clear_blacklist = AIWAFManager.__dict__['clear_blocklist']
AIWAFManager.legacy_blacklist = AIWAFManager.__dict__['legacy_blocklist']
AIWAFManager.show_legacy_blacklist = AIWAFManager.__dict__['show_legacy_blocklist']
AIWAFManager.migrate_blacklist = AIWAFManager.__dict__['migrate_blocklist']
AIWAFManager.convert_legacy_blacklist = AIWAFManager.__dict__['convert_legacy_blocklist']
