"""Compatibility import; prefer aiwaf.django.management.commands.aiwaf_migrate_blocklist."""
from importlib import import_module as _import_module
import sys as _sys
_sys.modules[__name__] = _import_module('aiwaf.django.management.commands.aiwaf_migrate_blocklist')
