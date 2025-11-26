# offers/apps.py
from django.apps import AppConfig

class OffersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "offers"

    def ready(self):
        from . import signals  # noqa: F401  (forces signal registration)
