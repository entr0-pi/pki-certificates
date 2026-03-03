#!/usr/bin/env python3
"""
Initialize database/pki.db from database/pki_schema.sql.
Optionally recreates an invalid database.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize PKI SQLite database.")
    parser.add_argument(
        "--recreate-invalid",
        action="store_true",
        help="Recreate DB if file exists but missing required tables (backs up old DB).",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    backend_dir = project_root / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    import db  # noqa: WPS433 - runtime import for script path setup

    db.init_database(auto_recreate_invalid=args.recreate_invalid)
    print("Database initialized successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
