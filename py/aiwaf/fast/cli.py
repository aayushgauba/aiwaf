#!/usr/bin/env python3
"""AIWAF FastAPI CLI."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

from aiwaf.flask.cli import main as _flask_cli_main


def _load_fastapi_app(app_path):
    module_path, _, obj = app_path.partition(":")
    if not module_path or not obj:
        raise ValueError("Use --app module:app or module:create_app")
    project_root = str(Path.cwd())
    while project_root in sys.path:
        sys.path.remove(project_root)
    sys.path.insert(0, project_root)
    module = importlib.import_module(module_path)
    target = getattr(module, obj, None)
    if target is None:
        raise ValueError(f"App not found: {app_path}")
    if callable(target) and not hasattr(target, "routes"):
        return target()
    return target


def _init(argv) -> None:
    parser = argparse.ArgumentParser(description="Generate AIWAF FastAPI path manifest")
    parser.add_argument("--app", required=True, help="FastAPI app import path (module:app or module:create_app)")
    parser.add_argument("--output", default=".aiwaf/paths.json", help="Output manifest path")
    args = parser.parse_args(argv)

    from aiwaf.fast.path_manifest import generate_fastapi_manifest

    app = _load_fastapi_app(args.app)
    manifest = generate_fastapi_manifest(app, args.output)
    print(f"Generated {args.output}")
    print(f"Framework: {manifest['framework']}")
    print(f"Routes: {len(manifest.get('routes', {}))}")
    print(f"Context hash: {manifest['context_hash']}")


def _migrate_blacklist(argv) -> None:
    parser = argparse.ArgumentParser(description="Upgrade the configured FastAPI blacklist backend")
    parser.add_argument("--app", help="FastAPI app import path; loads its AIWAF storage configuration")
    parser.add_argument("--backend", choices=["csv", "file", "db", "memory"], default="csv")
    parser.add_argument("--storage-path", help="Storage file when --app is not supplied")
    args = parser.parse_args(argv)

    if args.app:
        _load_fastapi_app(args.app)
    else:
        from aiwaf.core.runtime_storage import initialize_storage

        kwargs = {}
        if args.storage_path:
            kwargs["file_path"] = args.storage_path
        initialize_storage(args.backend, **kwargs)

    from aiwaf.core.blacklist_migration import migrate_runtime_storage
    from aiwaf.core.runtime_storage import get_storage

    total, changed = migrate_runtime_storage(get_storage())
    print(f"FastAPI blacklist upgraded: {changed}/{total} legacy entries updated")


def main() -> None:
    argv = list(sys.argv[1:])
    # Accept the established global --data-dir position before `train`.
    if argv and (argv[0] == 'train' or (len(argv) >= 3 and argv[0] == '--data-dir' and argv[2] == 'train')):
        _train(argv[1:] if argv[0] == 'train' else ['--data-dir', argv[1], *argv[3:]])
        return
    if argv and argv[0] == "init":
        _init(argv[1:])
        return
    if len(argv) >= 2 and argv[:2] == ["blacklist", "migrate"]:
        _migrate_blacklist(argv[2:])
        return
    _flask_cli_main()


def _train(argv):
    parser = argparse.ArgumentParser(description='Train FastAPI AIWAF using its routes and runtime storage')
    parser.add_argument('--app', required=True, help='FastAPI application import path (module:app)')
    parser.add_argument('--log-dir')
    parser.add_argument('--data-dir', help='Shared policy CSV directory (imports legacy runtime_store.csv)')
    parser.add_argument('--disable-ai', action='store_true')
    parser.add_argument('--force-ai', action='store_true')
    parser.add_argument('--min-ai-logs', type=int, default=10000)
    parser.add_argument('--model-path', help='Destination for the Rust JSON model artifact')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args(argv)
    if args.min_ai_logs < 1:
        parser.error('--min-ai-logs must be positive')
    app = _load_fastapi_app(args.app)
    if args.data_dir:
        from aiwaf.core.runtime_storage import initialize_storage
        initialize_storage('csv', data_dir=args.data_dir)
    from aiwaf.fast.trainer import train_from_logs
    import json
    result = train_from_logs(app, log_dir=args.log_dir, disable_ai=args.disable_ai,
        force_ai=args.force_ai, min_ai_logs=args.min_ai_logs, model_path=args.model_path)
    print(json.dumps({key: value for key, value in result.items() if key != 'model'}, indent=2))


if __name__ == "__main__":
    main()
