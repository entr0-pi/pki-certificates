#!/usr/bin/env python3
"""
Initialize database/pki.db from backend/schema/pki_schema.sql.
Optionally recreates an invalid database.

Why use this script:
  - Initialize the SQLite database before starting the web app manually.
  - Rebuild an invalid database from the checked-in schema when recovery is needed.
  - Run the same core DB initialization logic as the main app, but on demand.

How it works:
  - Automatically loads configuration from the repository `.env`.
  - Uses `PKI_DB_PATH` if configured; otherwise falls back to the repo default path.
  - Respects `PKI_DB_AUTO_REINIT=true`, or you can force recreation with `--recreate-invalid`.

Examples:
  python scripts/init_db.py
  python scripts/init_db.py --recreate-invalid
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize PKI SQLite database.")
    parser.add_argument(
        "--recreate-invalid",
        action="store_true",
        help="Recreate DB if file exists but missing required tables (backs up old DB).",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env", override=True)

    backend_dir = project_root / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    import db  # noqa: WPS433 - runtime import for script path setup

    auto_recreate_invalid = args.recreate_invalid or _parse_bool(
        os.environ.get("PKI_DB_AUTO_REINIT")
    )
    db.init_database(auto_recreate_invalid=auto_recreate_invalid)
    print("Database initialized successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
