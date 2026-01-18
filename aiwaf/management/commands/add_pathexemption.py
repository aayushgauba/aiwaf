#!/usr/bin/env python3

import re
from django.core.management.base import BaseCommand
from aiwaf.storage import get_path_exemption_store


def _normalize_path(path):
    path = str(path).strip()
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path += "/"
    return path


class Command(BaseCommand):
    help = "Add a path to the exemption list using Django models"

    def add_arguments(self, parser):
        parser.add_argument("path", help="Path prefix to exempt (e.g. /myapp/api/)")
        parser.add_argument("--reason", default="Manual exemption", help="Reason for exemption")

    def handle(self, *args, **options):
        path = _normalize_path(options["path"])
        reason = options["reason"]

        self.stdout.write(f"Adding path {path} to exemption list...")
        store = get_path_exemption_store()
        store.add_exemption(path, reason=reason)

        if store.is_exempted(path):
            self.stdout.write(self.style.SUCCESS(f"✅ Successfully exempted path: {path}"))
        else:
            self.stdout.write(self.style.ERROR(f"❌ Failed to exempt path: {path}"))
