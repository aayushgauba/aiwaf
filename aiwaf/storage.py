import os, csv, gzip, glob
import numpy as np
import pandas as pd
from django.conf import settings
from django.utils import timezone

# Defer model imports to avoid AppRegistryNotReady during Django app loading
FeatureSample = BlacklistEntry = IPExemption = DynamicKeyword = None

def _import_models():
    """Import Django models only when needed and apps are ready."""
    global FeatureSample, BlacklistEntry, IPExemption, DynamicKeyword
    
    if FeatureSample is not None:
        return  # Already imported
    
    try:
        from django.apps import apps
        if apps.ready and apps.is_installed('aiwaf'):
            from .models import FeatureSample, BlacklistEntry, IPExemption, DynamicKeyword
    except (ImportError, RuntimeError, Exception):
        # Keep models as None if can't import
        pass

# Configuration
STORAGE_MODE = getattr(settings, "AIWAF_STORAGE_MODE", "models")  # "models" or "csv"
CSV_DATA_DIR = getattr(settings, "AIWAF_CSV_DATA_DIR", "aiwaf_data")
FEATURE_CSV = getattr(settings, "AIWAF_CSV_PATH", os.path.join(CSV_DATA_DIR, "access_samples.csv"))
BLACKLIST_CSV = os.path.join(CSV_DATA_DIR, "blacklist.csv")
EXEMPTION_CSV = os.path.join(CSV_DATA_DIR, "exemptions.csv") 
KEYWORDS_CSV = os.path.join(CSV_DATA_DIR, "keywords.csv")

CSV_HEADER = [
    "ip","path_len","kw_hits","resp_time",
    "status_idx","burst_count","total_404","label"
]

def ensure_csv_directory():
    """Ensure the CSV data directory exists"""
    if STORAGE_MODE == "csv" and not os.path.exists(CSV_DATA_DIR):
        os.makedirs(CSV_DATA_DIR)

class CsvFeatureStore:
    @staticmethod
    def persist_rows(rows):
        ensure_csv_directory()
        new_file = not os.path.exists(FEATURE_CSV)
        with open(FEATURE_CSV, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(CSV_HEADER)
            w.writerows(rows)

    @staticmethod
    def load_matrix():
        if not os.path.exists(FEATURE_CSV):
            return np.empty((0,6))
        df = pd.read_csv(
            FEATURE_CSV,
            names=CSV_HEADER,
            skiprows=1,
            engine="python",
            on_bad_lines="skip"
        )
        feature_cols = CSV_HEADER[1:7]
        df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
        return df[feature_cols].to_numpy()

class DbFeatureStore:
    @staticmethod
    def persist_rows(rows):
        _import_models()
        if FeatureSample is not None:
            objs = []
            for ip,pl,kw,rt,si,bc,t404,label in rows:
                objs.append(FeatureSample(
                    ip=ip, path_len=pl, kw_hits=kw,
                    resp_time=rt, status_idx=si,
                    burst_count=bc, total_404=t404,
                    label=label
                ))
            FeatureSample.objects.bulk_create(objs, ignore_conflicts=True)

    @staticmethod
    def load_matrix():
        _import_models()
        if FeatureSample is not None:
            qs = FeatureSample.objects.all().values_list(
                "path_len","kw_hits","resp_time","status_idx","burst_count","total_404"
            )
            return np.array(list(qs), dtype=float)
        return np.empty((0,6))

def get_store():
    if getattr(settings, "AIWAF_FEATURE_STORE", "csv") == "db":
        return DbFeatureStore
    return CsvFeatureStore


# ============= CSV Storage Classes =============

class CsvBlacklistStore:
    """CSV-based storage for IP blacklist entries"""
    
    @staticmethod
    def add_ip(ip_address, reason):
        ensure_csv_directory()
        # Check if IP already exists
        if CsvBlacklistStore.is_blocked(ip_address):
            return
        
        # Add new entry
        new_file = not os.path.exists(BLACKLIST_CSV)
        with open(BLACKLIST_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if new_file:
                writer.writerow(["ip_address", "reason", "created_at"])
            writer.writerow([ip_address, reason, timezone.now().isoformat()])
    
    @staticmethod
    def is_blocked(ip_address):
        if not os.path.exists(BLACKLIST_CSV):
            return False
        
        with open(BLACKLIST_CSV, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["ip_address"] == ip_address:
                    return True
        return False
    
    @staticmethod
    def get_all():
        """Return list of dictionaries with blacklist entries"""
        if not os.path.exists(BLACKLIST_CSV):
            return []
        
        entries = []
        with open(BLACKLIST_CSV, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
        return entries
    
    @staticmethod
    def remove_ip(ip_address):
        if not os.path.exists(BLACKLIST_CSV):
            return
        
        # Read all entries except the one to remove
        entries = []
        with open(BLACKLIST_CSV, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            entries = [row for row in reader if row["ip_address"] != ip_address]
        
        # Write back the filtered entries
        with open(BLACKLIST_CSV, "w", newline="", encoding="utf-8") as f:
            if entries:
                writer = csv.DictWriter(f, fieldnames=["ip_address", "reason", "created_at"])
                writer.writeheader()
                writer.writerows(entries)


class CsvExemptionStore:
    """CSV-based storage for IP exemption entries"""
    
    @staticmethod
    def add_ip(ip_address, reason=""):
        ensure_csv_directory()
        
        # Check if IP already exists to avoid duplicates
        if CsvExemptionStore.is_exempted(ip_address):
            return
        
        # Add new entry
        new_file = not os.path.exists(EXEMPTION_CSV)
        try:
            with open(EXEMPTION_CSV, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if new_file:
                    writer.writerow(["ip_address", "reason", "created_at"])
                writer.writerow([ip_address, reason, timezone.now().isoformat()])
        except Exception as e:
            print(f"Error writing to exemption CSV: {e}")
            print(f"File path: {EXEMPTION_CSV}")
            print(f"Directory exists: {os.path.exists(CSV_DATA_DIR)}")
            raise
    
    @staticmethod
    def is_exempted(ip_address):
        if not os.path.exists(EXEMPTION_CSV):
            # Debug: Let user know file doesn't exist
            if getattr(settings, 'DEBUG', False):
                print(f"DEBUG: Exemption CSV not found: {EXEMPTION_CSV}")
            return False
        
        try:
            with open(EXEMPTION_CSV, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader):
                    stored_ip = row.get("ip_address", "").strip()
                    if getattr(settings, 'DEBUG', False) and row_num < 5:  # Show first 5 for debug
                        print(f"DEBUG: Row {row_num}: comparing '{stored_ip}' with '{ip_address}'")
                    if stored_ip == ip_address:
                        if getattr(settings, 'DEBUG', False):
                            print(f"DEBUG: Found exemption match for {ip_address}")
                        return True
        except Exception as e:
            print(f"Error reading exemption CSV: {e}")
            return False
        
        if getattr(settings, 'DEBUG', False):
            print(f"DEBUG: No exemption found for {ip_address}")
        return False
    
    @staticmethod
    def get_all():
        """Return list of dictionaries with exemption entries"""
        if not os.path.exists(EXEMPTION_CSV):
            return []
        
        entries = []
        with open(EXEMPTION_CSV, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
        return entries
    
    @staticmethod
    def remove_ip(ip_address):
        if not os.path.exists(EXEMPTION_CSV):
            return
        
        # Read all entries except the one to remove
        entries = []
        with open(EXEMPTION_CSV, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            entries = [row for row in reader if row["ip_address"] != ip_address]
        
        # Write back the filtered entries
        with open(EXEMPTION_CSV, "w", newline="", encoding="utf-8") as f:
            if entries:
                writer = csv.DictWriter(f, fieldnames=["ip_address", "reason", "created_at"])
                writer.writeheader()
                writer.writerows(entries)


class CsvKeywordStore:
    """CSV-based storage for dynamic keywords"""
    
    @staticmethod
    def add_keyword(keyword, count=1):
        ensure_csv_directory()
        
        # Read existing keywords
        keywords = CsvKeywordStore._load_keywords()
        
        # Update or add keyword
        keywords[keyword] = keywords.get(keyword, 0) + count
        
        # Save back to file
        CsvKeywordStore._save_keywords(keywords)
    
    @staticmethod
    def get_top_keywords(limit=10):
        keywords = CsvKeywordStore._load_keywords()
        # Sort by count in descending order and return top N
        sorted_keywords = sorted(keywords.items(), key=lambda x: x[1], reverse=True)
        return [kw for kw, count in sorted_keywords[:limit]]
    
    @staticmethod
    def remove_keyword(keyword):
        keywords = CsvKeywordStore._load_keywords()
        if keyword in keywords:
            del keywords[keyword]
            CsvKeywordStore._save_keywords(keywords)
    
    @staticmethod
    def clear_all():
        if os.path.exists(KEYWORDS_CSV):
            os.remove(KEYWORDS_CSV)
    
    @staticmethod
    def _load_keywords():
        """Load keywords from CSV file as a dictionary"""
        if not os.path.exists(KEYWORDS_CSV):
            return {}
        
        keywords = {}
        with open(KEYWORDS_CSV, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                keywords[row["keyword"]] = int(row["count"])
        return keywords
    
    @staticmethod
    def _save_keywords(keywords):
        """Save keywords dictionary to CSV file"""
        with open(KEYWORDS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["keyword", "count", "last_updated"])
            for keyword, count in keywords.items():
                writer.writerow([keyword, count, timezone.now().isoformat()])


# ============= Storage Factory Functions =============

def get_blacklist_store():
    """Return appropriate blacklist storage class based on settings"""
    if STORAGE_MODE == "csv":
        return CsvBlacklistStore
    else:
        # Return a wrapper for Django models (only if models are available)
        if BlacklistEntry is not None:
            return ModelBlacklistStore
        else:
            # Fallback to CSV if models aren't available
            return CsvBlacklistStore


def get_exemption_store():
    """Return appropriate exemption storage class based on settings"""
    if getattr(settings, 'DEBUG', False):
        print(f"DEBUG: Storage mode = {STORAGE_MODE}, CSV mode = {STORAGE_MODE == 'csv'}")
    
    if STORAGE_MODE == "csv":
        if getattr(settings, 'DEBUG', False):
            print("DEBUG: Using CsvExemptionStore")
        return CsvExemptionStore
    else:
        _import_models()
        if IPExemption is not None:
            if getattr(settings, 'DEBUG', False):
                print("DEBUG: Using ModelExemptionStore")
            return ModelExemptionStore
        else:
            if getattr(settings, 'DEBUG', False):
                print("DEBUG: Falling back to CsvExemptionStore (models not available)")
            return CsvExemptionStore


def get_keyword_store():
    """Return appropriate keyword storage class based on settings"""
    if STORAGE_MODE == "csv":
        return CsvKeywordStore
    else:
        if DynamicKeyword is not None:
            return ModelKeywordStore
        else:
            return CsvKeywordStore


# ============= Django Model Wrappers =============

class ModelBlacklistStore:
    """Django model-based storage for blacklist entries"""
    
    @staticmethod
    def add_ip(ip_address, reason):
        _import_models()
        if BlacklistEntry is not None:
            BlacklistEntry.objects.get_or_create(ip_address=ip_address, defaults={"reason": reason})
    
    @staticmethod
    def is_blocked(ip_address):
        _import_models()
        if BlacklistEntry is not None:
            return BlacklistEntry.objects.filter(ip_address=ip_address).exists()
        return False
    
    @staticmethod
    def get_all():
        _import_models()
        if BlacklistEntry is not None:
            return list(BlacklistEntry.objects.values("ip_address", "reason", "created_at"))
        return []
    
    @staticmethod
    def remove_ip(ip_address):
        _import_models()
        if BlacklistEntry is not None:
            BlacklistEntry.objects.filter(ip_address=ip_address).delete()


class ModelExemptionStore:
    """Django model-based storage for exemption entries"""
    
    @staticmethod
    def add_ip(ip_address, reason=""):
        _import_models()
        if IPExemption is not None:
            IPExemption.objects.get_or_create(ip_address=ip_address, defaults={"reason": reason})
    
    @staticmethod
    def is_exempted(ip_address):
        _import_models()
        if IPExemption is not None:
            return IPExemption.objects.filter(ip_address=ip_address).exists()
        return False
    
    @staticmethod
    def get_all():
        _import_models()
        if IPExemption is not None:
            return list(IPExemption.objects.values("ip_address", "reason", "created_at"))
        return []
    
    @staticmethod
    def remove_ip(ip_address):
        _import_models()
        if IPExemption is not None:
            IPExemption.objects.filter(ip_address=ip_address).delete()


class ModelKeywordStore:
    """Django model-based storage for dynamic keywords"""
    
    @staticmethod
    def add_keyword(keyword, count=1):
        _import_models()
        if DynamicKeyword is not None:
            obj, created = DynamicKeyword.objects.get_or_create(keyword=keyword, defaults={"count": count})
            if not created:
                obj.count += count
                obj.save()
    
    @staticmethod
    def get_top_keywords(limit=10):
        _import_models()
        if DynamicKeyword is not None:
            return list(DynamicKeyword.objects.order_by("-count").values_list("keyword", flat=True)[:limit])
        return []
    
    @staticmethod
    def remove_keyword(keyword):
        _import_models()
        if DynamicKeyword is not None:
            DynamicKeyword.objects.filter(keyword=keyword).delete()
    
    @staticmethod
    def clear_all():
        _import_models()
        if DynamicKeyword is not None:
            DynamicKeyword.objects.all().delete()
