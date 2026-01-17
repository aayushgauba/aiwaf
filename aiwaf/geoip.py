import logging
import os

from django.conf import settings
from django.core.cache import cache

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False

try:
    from geoip2.database import Reader as GeoIPReader
    from geoip2.errors import AddressNotFoundError
    GEOIP_AVAILABLE = True
except ImportError:
    GeoIPReader = None
    AddressNotFoundError = Exception
    GEOIP_AVAILABLE = False

logger = logging.getLogger("aiwaf.geoip")


def _normalize_provider(value):
    if not value:
        return "maxmind"
    return str(value).strip().lower()


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


def _lookup_maxmind(ip, db_path):
    if not GEOIP_AVAILABLE or not db_path:
        return None
    if not os.path.exists(db_path):
        return None
    reader = None
    try:
        reader = GeoIPReader(db_path)
        response = reader.country(ip)
        code = getattr(response.country, "iso_code", None)
        return code
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


def _lookup_ipinfo(ip, endpoint, token, timeout):
    if not REQUESTS_AVAILABLE:
        return None
    global requests
    if requests is None:
        try:
            import requests as requests_module
            requests = requests_module
        except ImportError:
            return None
    base = endpoint or "https://ipinfo.io"
    base = base.rstrip("/")
    url = f"{base}/{ip}/country"
    params = {}
    if token:
        params["token"] = token
    try:
        resp = requests.get(url, params=params, timeout=timeout)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    code = (resp.text or "").strip().upper()
    if len(code) != 2:
        return None
    return code


def lookup_country(ip, cache_prefix=None, cache_seconds=3600):
    provider = _normalize_provider(getattr(settings, "AIWAF_GEO_PROVIDER", "maxmind"))
    cache_key = None
    if cache_prefix:
        cache_key = f"{cache_prefix}{provider}:{ip}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

    code = None
    if provider == "maxmind":
        db_path = getattr(settings, "AIWAF_GEOIP_DB_PATH", None)
        code = _lookup_maxmind(ip, db_path)
    elif provider == "ipinfo":
        endpoint = getattr(settings, "AIWAF_GEOIP_ENDPOINT", "https://ipinfo.io")
        token = getattr(settings, "AIWAF_GEOIP_TOKEN", None)
        timeout = getattr(settings, "AIWAF_GEOIP_TIMEOUT", 2.0)
        code = _lookup_ipinfo(ip, endpoint, token, timeout)
    else:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Unsupported geo provider: %s", provider)

    if cache_key and cache_seconds is not None:
        _cache_set(cache_key, code, cache_seconds)
    return code
