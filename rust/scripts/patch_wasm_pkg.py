#!/usr/bin/env python3
"""Patch wasm-pack output and stage the canonical root package assets."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


KEYWORDS = [
    "wasm",
    "waf",
    "security",
    "ai",
    "anomaly-detection",
    "isolation-forest",
    "rust",
    "webassembly",
    "typescript",
]


def main(argv: list[str]) -> int:
    pkg_dir = Path("crates/aiwaf_wasm/pkg")
    src_readme = Path("../README.md")
    src_root = src_readme.parent
    pkg_json = pkg_dir / "package.json"

    if not pkg_json.exists():
        print(f"missing {pkg_json}", file=sys.stderr)
        return 1

    data = json.loads(pkg_json.read_text(encoding="utf-8"))
    data["keywords"] = KEYWORDS
    data["license"] = "Elastic-2.0"
    data["repository"] = {
        "type": "git",
        "url": "git+https://github.com/aiwaf-project/aiwaf.git",
        "directory": "rust/crates/aiwaf_wasm",
    }
    data["homepage"] = "https://github.com/aiwaf-project/aiwaf/tree/main/rust/crates/aiwaf_wasm"
    data["readme"] = "README.md"
    data["files"] = list(dict.fromkeys([
        *data.get("files", []), "README.md", "LICENSE", "NOTICE", "licenses/"
    ]))

    pkg_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    if not src_readme.is_file():
        print(f"missing canonical README: {src_readme}", file=sys.stderr)
        return 1
    shutil.copyfile(src_readme, pkg_dir / "README.md")
    for filename in ("LICENSE", "NOTICE"):
        shutil.copyfile(src_root / filename, pkg_dir / filename)
    shutil.copytree(src_root / "licenses", pkg_dir / "licenses", dirs_exist_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
