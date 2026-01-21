#!/usr/bin/env python3
"""
Manual stress-test runner for CSV logging.
Not part of the unit test suite.
"""

import os
import sys
import subprocess


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = os.path.join(repo_root, "scripts", "stress_csv_logging.py")
    cmd = [
        sys.executable,
        script,
        "--processes",
        "4",
        "--requests",
        "200",
        "--log-path",
        "aiwaf_requests.log",
        "--fresh",
    ]
    result = subprocess.run(cmd, cwd=repo_root)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
