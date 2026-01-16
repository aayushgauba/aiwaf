from django.apps import AppConfig

class AiwafConfig(AppConfig):
    name = "aiwaf"
    verbose_name = "AI‑Driven Web Application Firewall"

    def ready(self):
        try:
            from .settings_compat import apply_legacy_settings
            apply_legacy_settings()
        except Exception:
            pass
