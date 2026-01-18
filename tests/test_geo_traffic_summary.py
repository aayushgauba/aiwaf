import io
from contextlib import redirect_stdout
from unittest.mock import patch

from django.core.management import call_command
from django.test import override_settings

from .base_test import AIWAFTestCase


class TestGeoTrafficSummary(AIWAFTestCase):
    @override_settings(AIWAF_GEOIP_DB_PATH="/tmp/ipinfo.mmdb")
    def test_geo_traffic_summary_outputs_countries(self):
        from aiwaf.management.commands import geo_traffic_summary

        def fake_parse(line):
            return {"ip": line.strip()}

        buffer = io.StringIO()
        with redirect_stdout(buffer), \
             patch.object(geo_traffic_summary, "_read_all_logs", return_value=["1.1.1.1", "8.8.8.8"]), \
             patch.object(geo_traffic_summary, "_parse", side_effect=fake_parse), \
             patch("aiwaf.management.commands.geo_traffic_summary.lookup_country_name",
                   side_effect=lambda ip, **kwargs: "Australia" if ip == "1.1.1.1" else "United States"):
            call_command("geo_traffic_summary", top=5)

        output = buffer.getvalue()
        assert "GeoIP traffic summary" in output
        assert "Australia" in output
        assert "United States" in output
