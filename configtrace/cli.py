from __future__ import annotations

import argparse
import sys
from pathlib import Path

from configtrace.checks import run_checks


def main() -> int:
    parser = argparse.ArgumentParser(prog="configtrace", description="Check named references in deployment configuration files.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="check a project folder")
    check_parser.add_argument("project_dir", type=Path)
    args = parser.parse_args()

    try:
        findings = run_checks(args.project_dir.resolve())
    except (OSError, ValueError) as exc:
        print(f"ConfigTrace could not check this project: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print("All declared references are connected.")
        return 0

    for finding in findings:
        print(f"{finding.code} in {finding.file}: {finding.message}")
    print(f"Found {len(findings)} reference issue(s).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
