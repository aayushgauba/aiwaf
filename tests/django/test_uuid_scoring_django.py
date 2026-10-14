from unittest.mock import MagicMock, patch

from django.http import HttpResponseNotFound
from django.test import override_settings

from tests.django.base_test import AIWAFTestCase
from aiwaf.core.uuid_tamper import clear_uuid_score_state


class UUIDScoringDjangoTest(AIWAFTestCase):
    @override_settings(
        AIWAF_UUID_SCORE_WINDOW_SECONDS=60,
        AIWAF_UUID_SCORE_BLOCK_THRESHOLD=3,
        AIWAF_UUID_SCORE_NOT_FOUND_WEIGHT=1,
    )
    def test_uuid_404_scoring_blocks_after_threshold(self):
        clear_uuid_score_state()
        from aiwaf.django.middleware import UUIDTamperMiddleware

        request = self.create_request(
            "/items/550e8400-e29b-41d4-a716-446655440000",
            headers={"REMOTE_ADDR": "203.0.113.60"},
        )
        mw = UUIDTamperMiddleware(MagicMock())
        view_func = MagicMock()
        view_func.__module__ = "tests.fakeviews"

        with patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.get_ip", return_value="203.0.113.60"), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block, \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=True):
            for _ in range(2):
                mw.process_view(request, view_func, (), {"uuid": "550e8400-e29b-41d4-a716-446655440000"})
                mw.process_response(request, HttpResponseNotFound())
            mw.process_view(request, view_func, (), {"uuid": "550e8400-e29b-41d4-a716-446655440000"})
            try:
                mw.process_response(request, HttpResponseNotFound())
            except Exception:
                pass
        assert mock_block.called
