import logging
import os

from django.conf import settings
from django.core.cache import cache

try:
    from geoip2.database import Reader as GeoIPReader
    from geoip2.errors import AddressNotFoundError
    GEOIP_AVAILABLE = True
except ImportError:
    GeoIPReader = None
    AddressNotFoundError = Exception
    GEOIP_AVAILABLE = False

logger = logging.getLogger("aiwaf.geoip")


def _cache_get(cache_key):
    try:
        return cache.get(cache_key)
    except Exception:
        return None


def _cache_set(cache_key, value, timeout):
    try:
        cache.set(cache_key, value, timeout=timeout)
    except Exception:
        return


def _extract_country_from_raw(raw):
    if not isinstance(raw, dict):
        return None
    country = raw.get("country")
    if isinstance(country, dict):
        code = country.get("iso_code")
        if code:
            return code
    if isinstance(country, str) and len(country) >= 2:
        return country
    for key in ("country_code", "country_code2", "country_code3"):
        code = raw.get(key)
        if code:
            return code
    return None


def _lookup_maxmind(ip, db_path):
    if not GEOIP_AVAILABLE or not db_path:
        return None
    if not os.path.exists(db_path):
        return None
    reader = None
    try:
        reader = GeoIPReader(db_path)
        try:
            response = reader.country(ip)
            code = getattr(response.country, "iso_code", None)
            if code:
                return code
        except Exception:
            pass

        try:
            response = reader.city(ip)
            code = getattr(response.country, "iso_code", None)
            if code:
                return code
        except Exception:
            pass

        try:
            raw = reader.get(ip)
            code = _extract_country_from_raw(raw)
            if code:
                return code
        except Exception:
            return None
    except AddressNotFoundError:
        return None
    except Exception:
        return None
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass


def lookup_country(ip, cache_prefix=None, cache_seconds=3600):
    db_path = getattr(
        settings,
        "AIWAF_GEOIP_DB_PATH",
        os.path.join(os.path.dirname(__file__), "geolock", "ipinfo_lite.mmdb"),
    )
    cache_key = None
    if cache_prefix:
        cache_key = f"{cache_prefix}{ip}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

    code = _lookup_maxmind(ip, db_path)

    if cache_key and cache_seconds is not None:
        _cache_set(cache_key, code, cache_seconds)
    return code
