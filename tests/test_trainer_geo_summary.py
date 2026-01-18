import io
from contextlib import redirect_stdout
from unittest.mock import patch

from django.test import override_settings

from .base_test import AIWAFTestCase


class TestTrainerGeoSummary(AIWAFTestCase):
    @override_settings(AIWAF_GEOIP_DB_PATH="/tmp/ipinfo.mmdb")
    def test_geo_summary_uses_country_names(self):
        from aiwaf import trainer

        class FakeBlacklistStore:
            def get_all_blocked_ips(self):
                return ["1.1.1.1", "8.8.8.8"]

        def fake_lookup_country_name(ip, cache_prefix=None, cache_seconds=None):
            return "United States" if ip == "8.8.8.8" else "Australia"

        buffer = io.StringIO()
        with redirect_stdout(buffer), \
             patch("aiwaf.trainer.os.path.exists", return_value=True), \
             patch("aiwaf.trainer.get_blacklist_store", return_value=FakeBlacklistStore()), \
             patch("aiwaf.trainer.lookup_country_name", side_effect=fake_lookup_country_name):
            trainer._print_geoip_blocklist_summary()

        output = buffer.getvalue()
        assert "GeoIP summary for blocked IPs" in output
        assert "United States" in output
        assert "Australia" in output

    def test_lookup_uses_default_mmdb_path(self):
        import os
        from aiwaf import geoip

        default_path = os.path.join(
            os.path.dirname(geoip.__file__),
            "geolock",
            "ipinfo_lite.mmdb",
        )

        class FakeReader:
            def __init__(self, path):
                self.path = path
                self._db_reader = self

            def get(self, _ip):
                return {"country_code": "US"}

            def close(self):
                return None

        with patch("aiwaf.geoip.GEOIP_AVAILABLE", True), \
             patch("aiwaf.geoip.GeoIPReader", FakeReader), \
             patch("aiwaf.geoip.os.path.exists", return_value=True), \
             patch("aiwaf.geoip.settings.configured", False):
            assert geoip.lookup_country("8.8.8.8") == "US"
