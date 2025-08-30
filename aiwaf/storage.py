import numpy as np
import pandas as pd
from django.conf import settings
from django.utils import timezone
import os
import json
from collections import defaultdict

# Defer model imports to avoid AppRegistryNotReady during Django app loading
FeatureSample = BlacklistEntry = IPExemption = DynamicKeyword = None

# Fallback storage for when Django models are unavailable
_fallback_keywords = defaultdict(int)
_fallback_storage_path = os.path.join(os.path.dirname(__file__), 'fallback_keywords.json')

def _import_models():
    """Import Django models only when needed and apps are ready."""
    global FeatureSample, BlacklistEntry, IPExemption, DynamicKeyword
    
    if FeatureSample is not None:
        return  # Already imported
    try:
        from django.apps import apps
        if apps.ready:
            # Try multiple ways to import models
            try:
                # First try: direct import (most reliable)
                from .models import FeatureSample, BlacklistEntry, IPExemption, DynamicKeyword
            except ImportError:
                # Second try: check if aiwaf app is installed under different name
                for app_config in apps.get_app_configs():
                    if 'aiwaf' in app_config.name.lower() or 'aiwaf' in app_config.label.lower():
                        try:
                            from .models import FeatureSample, BlacklistEntry, IPExemption, DynamicKeyword
                            break
                        except ImportError:
                            continue
    except (ImportError, RuntimeError, Exception) as e:
        # Log the error for debugging but don't fail silently
        import sys
        print(f"Warning: Could not import AIWAF models: {e}", file=sys.stderr)
        # Keep models as None if can't import
        pass

class ModelFeatureStore:
    @staticmethod
    def persist_rows(rows):
        """Persist feature data to Django models"""
        _import_models()
        if FeatureSample is None:
            print("Warning: Django models not available, skipping feature storage")
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
                print(f"Error saving feature sample: {e}")

    @staticmethod
    def get_all_data():
        """Get all feature data as DataFrame"""
        _import_models()
        if FeatureSample is None:
            return pd.DataFrame()
            
        try:
            queryset = FeatureSample.objects.all().values(
                'ip', 'path_len', 'kw_hits', 'resp_time', 
                'status_idx', 'burst_count', 'total_404', 'label'
            )
            df = pd.DataFrame(list(queryset))
            if df.empty:
                return df
            
            feature_cols = ['path_len', 'kw_hits', 'resp_time', 'status_idx', 'burst_count', 'total_404']
            for col in feature_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
            
            return df
        except Exception as e:
            print(f"Error loading feature data: {e}")
            return pd.DataFrame()

class ModelBlacklistStore:
    @staticmethod
    def is_blocked(ip):
        """Check if IP is in blacklist"""
        _import_models()
        if BlacklistEntry is None:
            return False
        try:
            return BlacklistEntry.objects.filter(ip_address=ip).exists()
        except Exception:
            return False

    @staticmethod
    def block_ip(ip, reason="Automated block"):
        """Add IP to blacklist"""
        _import_models()
        if BlacklistEntry is None:
            print(f"Warning: Cannot block IP {ip}, models not available")
            return
        try:
            BlacklistEntry.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': reason, 'created_at': timezone.now()}
            )
        except Exception as e:
            print(f"Error blocking IP {ip}: {e}")

    @staticmethod
    def unblock_ip(ip):
        """Remove IP from blacklist"""
        _import_models()
        if BlacklistEntry is None:
            return
        try:
            BlacklistEntry.objects.filter(ip_address=ip).delete()
        except Exception as e:
            print(f"Error unblocking IP {ip}: {e}")

    @staticmethod
    def remove_ip(ip):
        """Remove IP from blacklist (alias for unblock_ip)"""
        ModelBlacklistStore.unblock_ip(ip)

    @staticmethod
    def add_ip(ip, reason="Automated block"):
        """Add IP to blacklist (alias for block_ip)"""
        ModelBlacklistStore.block_ip(ip, reason)

    @staticmethod
    def get_all_blocked_ips():
        """Get all blocked IPs"""
        _import_models()
        if BlacklistEntry is None:
            return []
        try:
            return list(BlacklistEntry.objects.values_list('ip_address', flat=True))
        except Exception:
            return []

    @staticmethod
    def get_all():
        """Get all blacklist entries as dictionaries"""
        _import_models()
        if BlacklistEntry is None:
            return []
        try:
            return list(BlacklistEntry.objects.values('ip_address', 'reason', 'created_at'))
        except Exception:
            return []

    @staticmethod
    def clear_all():
        """Clear all blacklist entries"""
        _import_models()
        if BlacklistEntry is None:
            return 0
        try:
            count = BlacklistEntry.objects.count()
            BlacklistEntry.objects.all().delete()
            return count
        except Exception as e:
            print(f"Error clearing all blacklist entries: {e}")
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
            print(f"Warning: Cannot exempt IP {ip}, models not available")
            return
        try:
            IPExemption.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': reason, 'created_at': timezone.now()}
            )
        except Exception as e:
            print(f"Error exempting IP {ip}: {e}")

    @staticmethod
    def remove_exemption(ip):
        """Remove IP from exemption list"""
        _import_models()
        if IPExemption is None:
            return
        try:
            IPExemption.objects.filter(ip_address=ip).delete()
        except Exception as e:
            print(f"Error removing exemption for IP {ip}: {e}")

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
            print(f"Error clearing all exemption entries: {e}")
            return 0

class ModelKeywordStore:
    @staticmethod
    def _load_fallback_keywords():
        """Load keywords from fallback JSON file"""
        global _fallback_keywords
        try:
            if os.path.exists(_fallback_storage_path):
                with open(_fallback_storage_path, 'r') as f:
                    data = json.load(f)
                    _fallback_keywords = defaultdict(int, data)
        except Exception as e:
            import sys
            print(f"Warning: Could not load fallback keywords: {e}", file=sys.stderr)
    
    @staticmethod
    def _save_fallback_keywords():
        """Save keywords to fallback JSON file"""
        try:
            with open(_fallback_storage_path, 'w') as f:
                json.dump(dict(_fallback_keywords), f, indent=2)
        except Exception as e:
            import sys
            print(f"Warning: Could not save fallback keywords: {e}", file=sys.stderr)
    
    @staticmethod
    def add_keyword(keyword, count=1):
        """Add a keyword to the dynamic keyword list"""
        _import_models()
        if DynamicKeyword is None:
            # Use fallback storage when Django models not available
            ModelKeywordStore._load_fallback_keywords()
            _fallback_keywords[keyword] += count
            ModelKeywordStore._save_fallback_keywords()
            import sys
            print(f"Info: Using fallback storage for keyword '{keyword}' - Django models not available.", file=sys.stderr)
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
            # Fallback to file storage on database error
            ModelKeywordStore._load_fallback_keywords()
            _fallback_keywords[keyword] += count
            ModelKeywordStore._save_fallback_keywords()
            import sys
            print(f"Database error adding keyword {keyword}, using fallback storage: {e}", file=sys.stderr)

    @staticmethod
    def remove_keyword(keyword):
        """Remove a keyword from the dynamic keyword list"""
        _import_models()
        if DynamicKeyword is None:
            return
        try:
            DynamicKeyword.objects.filter(keyword=keyword).delete()
        except Exception as e:
            print(f"Error removing keyword {keyword}: {e}")

    @staticmethod
    def get_top_keywords(n=10):
        """Get top N keywords by count"""
        _import_models()
        if DynamicKeyword is None:
            # Use fallback storage
            ModelKeywordStore._load_fallback_keywords()
            sorted_keywords = sorted(_fallback_keywords.items(), key=lambda x: x[1], reverse=True)
            return [keyword for keyword, count in sorted_keywords[:n]]
        try:
            return list(
                DynamicKeyword.objects.order_by('-count')[:n]
                .values_list('keyword', flat=True)
            )
        except Exception as e:
            # Fallback to file storage on database error
            ModelKeywordStore._load_fallback_keywords()
            sorted_keywords = sorted(_fallback_keywords.items(), key=lambda x: x[1], reverse=True)
            import sys
            print(f"Database error getting top keywords, using fallback storage: {e}", file=sys.stderr)
            return [keyword for keyword, count in sorted_keywords[:n]]

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
            print(f"Error resetting keywords: {e}")

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

# Factory functions that only return Django model stores
def get_feature_store():
    """Get the feature store (Django models only)"""
    return ModelFeatureStore()

def get_blacklist_store():
    """Get the blacklist store (Django models only)"""
    return ModelBlacklistStore()

def get_exemption_store():
    """Get the exemption store (Django models only)"""
    return ModelExemptionStore()

def get_keyword_store():
    """Get the keyword store (Django models only)"""
    return ModelKeywordStore()
