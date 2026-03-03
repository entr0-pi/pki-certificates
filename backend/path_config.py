from __future__ import annotations

import os
import tempfile
from pathlib import Path


def get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _require_absolute_path(var_name: str, value: str) -> Path:
    path = Path(value.strip())
    if not path.is_absolute():
        raise ValueError(
            f"{var_name} must be an absolute path, got: {value!r}. "
            "Use an absolute filesystem path."
        )
    return path


def get_data_dir() -> Path:
    env_value = os.environ.get("PKI_DATA_DIR", "").strip()
    if env_value:
        return _require_absolute_path("PKI_DATA_DIR", env_value)
    return get_project_root() / "data"


def get_db_path() -> Path:
    env_value = os.environ.get("PKI_DB_PATH", "").strip()
    if env_value:
        return _require_absolute_path("PKI_DB_PATH", env_value)
    return get_project_root() / "database" / "pki.db"


def get_schema_path() -> Path:
    return get_project_root() / "database" / "pki_schema.sql"


def is_under_temp_dir(path: Path) -> bool:
    temp_root = Path(tempfile.gettempdir()).resolve()
    resolved = path.resolve()
    return resolved == temp_root or temp_root in resolved.parents
