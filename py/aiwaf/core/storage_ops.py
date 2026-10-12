"""
Shared storage operation helpers (in-memory + CSV).
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .storage_csv import file_lock, safe_csv_operation
from .native_runtime import csv_function, csv_values


def ensure_csv_files(data_dir: Path, schema_headers: dict[str, list[str]]):
    def _create_files():
        data_dir.mkdir(exist_ok=True, parents=True)
        for name, headers in schema_headers.items():
            file_path = data_dir / name
            if file_path.exists():
                continue
            native = csv_function('csv_write')
            if native is not None:
                native(str(file_path), headers, [], True)
                continue
            with file_lock(file_path, "w") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
    return safe_csv_operation(_create_files)


def read_csv_set(data_dir: Path, filename: str, key_field: str, schema_headers: dict[str, list[str]]):
    def _read():
        ensure_csv_files(data_dir, schema_headers)
        csv_file = data_dir / filename
        native = csv_function('csv_read_set')
        if native is not None:
            return set(native(str(csv_file), key_field, True))
        items = set()
        with file_lock(csv_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                value = row.get(key_field, "")
                if value:
                    items.add(value.strip())
        return items
    return safe_csv_operation(_read)


def read_csv_dict(data_dir: Path, filename: str, key_field: str, value_field: str, schema_headers: dict[str, list[str]]):
    def _read():
        ensure_csv_files(data_dir, schema_headers)
        csv_file = data_dir / filename
        native = csv_function('csv_read_dict')
        if native is not None:
            return native(str(csv_file), key_field, value_field, True)
        items = {}
        with file_lock(csv_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = row.get(key_field, "")
                if not key:
                    continue
                items[key.strip()] = row.get(value_field, "")
        return items
    return safe_csv_operation(_read)


def append_csv_row(data_dir: Path, filename: str, row: list, schema_headers: dict[str, list[str]]):
    def _append():
        ensure_csv_files(data_dir, schema_headers)
        csv_file = data_dir / filename
        native = csv_function('csv_write')
        if native is not None:
            native(str(csv_file), schema_headers[filename], [csv_values(row)], True)
            return
        with file_lock(csv_file, "a") as f:
            writer = csv.writer(f)
            writer.writerow(row)
    return safe_csv_operation(_append)


def rewrite_csv_rows(data_dir: Path, filename: str, rows: list[list], schema_headers: dict[str, list[str]]):
    def _rewrite():
        ensure_csv_files(data_dir, schema_headers)
        csv_file = data_dir / filename
        native = csv_function('csv_write')
        if native is not None:
            native(str(csv_file), schema_headers[filename], [csv_values(row) for row in rows], False)
            return
        with file_lock(csv_file, "w") as f:
            writer = csv.writer(f)
            writer.writerow(schema_headers[filename])
            writer.writerows(rows)
    return safe_csv_operation(_rewrite)


def now_iso():
    return datetime.now().isoformat()
