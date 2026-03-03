from __future__ import annotations

import json
import os
import re
import secrets
import string
import subprocess

from datetime import datetime, timedelta, timezone
from pathlib import Path


# ---------- filesystem helpers ----------

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def touch_empty(path: Path) -> None:
    """
    Create an empty file if it doesn't exist.
    Does not overwrite existing content.
    """
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")


def write_if_missing(path: Path, content: str) -> None:
    """
    Create a file with `content` if it doesn't exist.
    Does not overwrite existing content.
    """
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def set_private_perms(private_dir: Path) -> None:
    """
    Best-effort permissions hardening:
      - On POSIX: chmod 700 on private_dir
    On Windows, chmod is limited; we skip without failing.
    """
    try:
        if os.name == "posix":
            private_dir.chmod(0o700)
    except Exception:
        pass


# ---------- crypto / misc helpers ----------

def random_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length)) + "\n"


def posix_path(p: Path) -> str:
    return p.resolve().as_posix()


def passfile_arg(p: Path) -> str:
    """
    OpenSSL -pass/-passin file:... path:
    - On Windows, native path tends to be most compatible.
    - On POSIX, use forward slashes.
    """
    rp = p.resolve()
    return str(rp) if os.name == "nt" else rp.as_posix()


def run_quiet(cmd: list[str]) -> None:
    """
    Run OpenSSL quietly (no output).
    If it fails, raise an error including captured output.
    """
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if p.returncode != 0:
        out = p.stdout or ""
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"--- openssl output ---\n{out}"
        )


def openssl(openssl_bin: str, *args: str) -> None:
    """Tiny wrapper to reduce repetition in OpenSSL calls."""
    run_quiet([openssl_bin, *args])


def load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Missing JSON: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return data


def require_keys(d: dict, keys: list[str]) -> None:
    missing = [k for k in keys if k not in d or d[k] in (None, "", [])]
    if missing:
        raise ValueError(
            f"Missing required frontend params: {', '.join(missing)}"
        )


def compute_enddate(days: int) -> str:
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y%m%d%H%M%SZ")


def parse_enddate_utc(s: str) -> datetime:
    """Parse enddate in YYYYMMDDHHMMSSZ format to datetime."""
    s = (s or "").strip()
    if not s.endswith("Z"):
        raise ValueError(f"enddate must end with 'Z' (UTC): {s!r}")
    return datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def load_policy(policy_path: Path) -> tuple[dict, set[str], set[str]]:
    """
    Load policy.json and extract allowed EC curves and ciphers.

    Returns:
        Tuple of (policy dict, allowed_curves set, allowed_ciphers set)
    """
    policy = load_json(policy_path)
    allowed_curves = {
        str(item.get("name", "")).strip()
        for item in policy.get("ec_curves", [])
        if isinstance(item, dict) and item.get("name")
    }
    allowed_ciphers = {
        str(item.get("name", "")).strip().lower()
        for item in policy.get("key_encryption_ciphers", [])
        if isinstance(item, dict) and item.get("name")
    }
    return policy, allowed_curves, allowed_ciphers


def render_template(template: str, mapping: dict[str, str]) -> str:
    out = template
    for k, v in mapping.items():
        out = out.replace("${" + k + "}", v)
    return out

def strip_empty_assignments(config_text: str) -> str:
    """
    Like Version 1, but also removes lines where the RHS is empty
    except for an inline comment.
    """

    _EMPTY_ASSIGNMENT_WITH_COMMENT = re.compile(
        r"""
        ^\s*
        (?![#;])
        (?P<key>\S[^=]*?)         # key must start with a non-space, then anything except '='
        \s*=\s*
        (?:[#;].*)?
        $
        """,
        re.VERBOSE,
    )

    out_lines = []
    for line in config_text.splitlines():
        if _EMPTY_ASSIGNMENT_WITH_COMMENT.match(line):
            continue
        out_lines.append(line)

    return "\n".join(out_lines) + ("\n" if config_text.endswith("\n") else "")
