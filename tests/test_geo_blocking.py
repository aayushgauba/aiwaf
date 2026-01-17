from unittest.mock import patch

from django.test import override_settings

from .base_test import AIWAFMiddlewareTestCase


class TestGeoBlocking(AIWAFMiddlewareTestCase):
    @override_settings(
        AIWAF_GEO_BLOCK_ENABLED=True,
        AIWAF_GEO_BLOCK_COUNTRIES=["US"],
        AIWAF_GEOIP_DB_PATH="/tmp/GeoLite2-Country.mmdb",
        AIWAF_GEO_CACHE_SECONDS=0,
        AIWAF_EXEMPT_IPS=[],
    )
    def test_geo_blocking_denies_country(self):
        from aiwaf import middleware as mw

        class FakeCountry:
            iso_code = "US"

        class FakeResponse:
            country = FakeCountry()

        class FakeReader:
            def __init__(self, _path):
                pass

            def country(self, _ip):
                return FakeResponse()

        with patch("aiwaf.geoip.GEOIP_AVAILABLE", True), \
             patch("aiwaf.geoip._normalize_provider", return_value="maxmind"), \
             patch("aiwaf.geoip.GeoIPReader", FakeReader), \
             patch("aiwaf.geoip.AddressNotFoundError", Exception), \
             patch("aiwaf.geoip.os.path.exists", return_value=True):
            request = self.create_request(path="/")
            request.META["REMOTE_ADDR"] = "8.8.8.8"
            response = mw.GeoBlockMiddleware(self.mock_get_response).process_request(request)
            assert response is not None
            assert response.status_code == 403

    @override_settings(
        AIWAF_GEO_BLOCK_ENABLED=True,
        AIWAF_GEO_ALLOW_COUNTRIES=["GB"],
        AIWAF_GEOIP_DB_PATH="/tmp/GeoLite2-Country.mmdb",
        AIWAF_GEO_CACHE_SECONDS=0,
        AIWAF_EXEMPT_IPS=[],
    )
    def test_geo_allowlist_allows_country(self):
        from aiwaf import middleware as mw

        class FakeCountry:
            iso_code = "GB"

        class FakeResponse:
            country = FakeCountry()

        class FakeReader:
            def __init__(self, _path):
                pass

            def country(self, _ip):
                return FakeResponse()

        with patch("aiwaf.geoip.GEOIP_AVAILABLE", True), \
             patch("aiwaf.geoip._normalize_provider", return_value="maxmind"), \
             patch("aiwaf.geoip.GeoIPReader", FakeReader), \
             patch("aiwaf.geoip.AddressNotFoundError", Exception), \
             patch("aiwaf.geoip.os.path.exists", return_value=True):
            request = self.create_request(path="/")
            request.META["REMOTE_ADDR"] = "8.8.8.8"
            response = mw.GeoBlockMiddleware(self.mock_get_response).process_request(request)
            assert response is None

    @override_settings(
        AIWAF_GEO_BLOCK_ENABLED=True,
        AIWAF_GEO_BLOCK_COUNTRIES=["US"],
        AIWAF_GEO_PROVIDER="ipinfo",
        AIWAF_GEOIP_TOKEN="token",
        AIWAF_GEOIP_ENDPOINT="https://ipinfo.io",
        AIWAF_GEO_CACHE_SECONDS=0,
        AIWAF_EXEMPT_IPS=[],
    )
    def test_geo_blocking_ipinfo_denies_country(self):
        from aiwaf import middleware as mw

        class FakeResponse:
            status_code = 200
            text = "US\n"

        with patch("aiwaf.geoip.REQUESTS_AVAILABLE", True), \
             patch("aiwaf.geoip.requests", new=type("Req", (), {"get": lambda *args, **kwargs: FakeResponse()})()), \
             patch("aiwaf.geoip._normalize_provider", return_value="ipinfo"):
            request = self.create_request(path="/")
            request.META["REMOTE_ADDR"] = "8.8.8.8"
            response = mw.GeoBlockMiddleware(self.mock_get_response).process_request(request)
            assert response is not None
            assert response.status_code == 403

    @override_settings(
        AIWAF_GEO_BLOCK_ENABLED=True,
        AIWAF_GEO_BLOCK_COUNTRIES=["US"],
        AIWAF_GEOIP_TOKEN="token",
        AIWAF_GEOIP_ENDPOINT="https://ipinfo.io",
        AIWAF_GEO_CACHE_SECONDS=0,
        AIWAF_EXEMPT_IPS=[],
    )
    def test_geo_blocking_defaults_to_ipinfo(self):
        from aiwaf import middleware as mw

        class FakeResponse:
            status_code = 200
            text = "US\n"

        with patch("aiwaf.geoip.REQUESTS_AVAILABLE", True), \
             patch("aiwaf.geoip.requests", new=type("Req", (), {"get": lambda *args, **kwargs: FakeResponse()})()), \
             patch("aiwaf.geoip._normalize_provider", return_value="ipinfo"):
            request = self.create_request(path="/")
            request.META["REMOTE_ADDR"] = "8.8.8.8"
            response = mw.GeoBlockMiddleware(self.mock_get_response).process_request(request)
            assert response is not None
            assert response.status_code == 403
