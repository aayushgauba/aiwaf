from django.test import TestCase

from aiwaf.django.models import (
    AIModelArtifact,
    BlocklistEntry,
    ExemptPath,
    GeoBlockedCountry,
    IPExemption,
    RequestLog,
)


class TestModelStrings(TestCase):
    def test_all_model_string_representations(self):
        blocked = BlocklistEntry.objects.create(ip_address="203.0.113.1", reason="test")
        exempt = IPExemption.objects.create(ip_address="203.0.113.2", reason="test")
        path = ExemptPath.objects.create(path="/health")
        request = RequestLog.objects.create(
            ip_address="203.0.113.3",
            method="GET",
            path="/",
            status_code=200,
            response_time=0.1,
        )
        artifact = AIModelArtifact.objects.create(name="test", data=b"{}")
        country = GeoBlockedCountry.objects.create(country_code="US")
        self.assertIn("203.0.113.1", str(blocked))
        self.assertIn("Exempted", str(exempt))
        self.assertIn("enabled", str(path))
        self.assertIn("GET", str(request))
        self.assertIn("test", str(artifact))
        self.assertEqual(str(country), "US")
