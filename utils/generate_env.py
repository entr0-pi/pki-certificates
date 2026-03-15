#!/usr/bin/env python3
"""
Create a local .env from .env.example and fill generated PKI secrets.
Supports environment profiles (dev/production) with interactive guidance.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import secrets
import sys
from pathlib import Path


APP_SECRET_GENERATORS = {
    "PKI_ENCRYPTION_KEY": lambda: base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    "PKI_ENCRYPTION_SALT": lambda: base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    "PKI_API_KEY_ADMIN": lambda: secrets.token_urlsafe(32),
    "PKI_API_KEY_MANAGER": lambda: secrets.token_urlsafe(32),
    "PKI_API_KEY_USER": lambda: secrets.token_urlsafe(32),
    "PKI_JWT_SECRET": lambda: secrets.token_urlsafe(32),
}

PLACEHOLDER_PREFIXES = (
    "change-this",
    "your-",
    "replace-with",
)

PROFILE_DEFAULTS = {
    "dev": {
        "PKI_HOST": "127.0.0.1",
        "PKI_BASE_URL": "http://localhost:8000",
        "PKI_COOKIE_SECURE": "false",
        "PKI_COOKIE_SAMESITE": "lax",
        "PKI_LOG_LEVEL": "DEBUG",
        "NOTIFY_METHOD": "log",
    },
    "production": {
        "PKI_HOST": "0.0.0.0",
        "PKI_COOKIE_SECURE": "true",
        "PKI_COOKIE_SAMESITE": "strict",
        "PKI_LOG_LEVEL": "INFO",
    },
}

NOTIFY_CONDITIONAL_KEYS = {
    "email": ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "EMAIL_TO"],
    "webhook": ["WEBHOOK_URL"],
}

SECRET_KEYS = frozenset(APP_SECRET_GENERATORS) | {"SMTP_PASS"}


class EnvEntry:
    """Represents a single environment variable entry with metadata."""

    __slots__ = ("key", "value", "source", "comment_block")

    def __init__(
        self,
        key: str,
        value: str,
        source: str,
        comment_block: list[str] | None = None,
    ) -> None:
        self.key = key
        self.value = value
        self.source = source  # "generated" | "interactive" | "profile_default" | "kept" | "example_default"
        self.comment_block = comment_block or []


def should_replace(name: str, value: str) -> bool:
    """Check if a variable should have a generated secret."""
    if name not in APP_SECRET_GENERATORS:
        return False
    stripped = value.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    return lowered.startswith(PLACEHOLDER_PREFIXES)


def parse_example(example_path: Path) -> list[EnvEntry]:
    """Parse .env.example into EnvEntry objects, preserving comment blocks and structure."""
    entries: list[EnvEntry] = []
    comment_buffer: list[str] = []

    for line in example_path.read_text(encoding="utf-8").splitlines():
        # Blank line or comment-only line
        if not line or line.lstrip().startswith("#"):
            comment_buffer.append(line)
            continue

        # Line with KEY=VALUE
        if "=" in line:
            name, value = line.split("=", 1)
            entry = EnvEntry(
                key=name,
                value=value,
                source="example_default",
                comment_block=comment_buffer,
            )
            entries.append(entry)
            comment_buffer = []
        else:
            # Malformed line (no =), treat as comment
            comment_buffer.append(line)

    # Trailing comments
    if comment_buffer:
        entries.append(
            EnvEntry(key="", value="", source="example_default", comment_block=comment_buffer)
        )

    return entries


def load_existing_env(output_path: Path) -> dict[str, str]:
    """Load existing .env file into a dictionary."""
    if not output_path.exists():
        return {}

    existing = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        existing[name] = value

    return existing


def apply_kept_values(entries: list[EnvEntry], existing: dict[str, str]) -> None:
    """Mark values that should be kept from existing .env file as 'kept'."""
    for entry in entries:
        if entry.key and entry.key in existing:
            existing_value = existing[entry.key]
            stripped = existing_value.strip().lower()
            # Keep non-placeholder, non-blank values
            is_placeholder = not stripped or stripped.startswith(PLACEHOLDER_PREFIXES)
            if not is_placeholder:
                entry.value = existing_value
                entry.source = "kept"


def apply_secret_generators(entries: list[EnvEntry]) -> None:
    """Generate secrets for placeholder values."""
    for entry in entries:
        if should_replace(entry.key, entry.value):
            entry.value = APP_SECRET_GENERATORS[entry.key]()
            entry.source = "generated"


def apply_profile_defaults(entries: list[EnvEntry], profile: str) -> None:
    """Apply profile-specific defaults; skip 'kept' entries."""
    if profile not in PROFILE_DEFAULTS:
        return

    defaults = PROFILE_DEFAULTS[profile]
    for entry in entries:
        if entry.key in defaults and entry.source != "kept":
            entry.value = defaults[entry.key]
            entry.source = "profile_default"


def select_profile() -> str:
    """Prompt user to select a profile."""
    for _ in range(3):
        print("\nSelect environment profile:")
        print("  1) dev        – local development defaults, no SMTP required")
        print("  2) production – production hardening, prompts for required values")
        choice = input("Enter choice [1/2]: ").strip()

        if choice == "1":
            return "dev"
        elif choice == "2":
            return "production"
        else:
            print("Invalid choice. Please enter 1 or 2.")

    print("Too many invalid attempts. Exiting.", file=sys.stderr)
    sys.exit(1)


def collect_interactive(entries: list[EnvEntry], profile: str) -> None:
    """Collect interactive input for production profile."""
    if profile != "production":
        return

    # Helper to find entry by key
    def get_entry(key: str) -> EnvEntry | None:
        for e in entries:
            if e.key == key:
                return e
        return None

    # Collect PKI_BASE_URL
    print("\n--- Production Configuration ---")
    base_url_entry = get_entry("PKI_BASE_URL")
    if base_url_entry:
        current = base_url_entry.value
        prompt_text = f"PKI_BASE_URL (public URL for issued certificates) [{current}]: "
        for _ in range(3):
            value = input(prompt_text).strip()
            if not value:
                value = current
            if value and value != "http://localhost:8000":
                base_url_entry.value = value
                base_url_entry.source = "interactive"
                break
            else:
                print(
                    "WARNING: Using localhost in production is not recommended. "
                    "Please provide a real URL."
                )
        else:
            base_url_entry.value = value
            base_url_entry.source = "interactive"

    # Collect NOTIFY_METHOD
    notify_entry = get_entry("NOTIFY_METHOD")
    if notify_entry:
        current = notify_entry.value
        print(
            f"\nNOTIFY_METHOD [default: {current}] (log/email/webhook): ",
            end="",
            flush=True,
        )
        value = input().strip()
        if not value:
            value = current
        notify_entry.value = value
        notify_entry.source = "interactive"

        # Collect conditional keys
        notify_method = notify_entry.value
        if notify_method in NOTIFY_CONDITIONAL_KEYS:
            required_keys = NOTIFY_CONDITIONAL_KEYS[notify_method]
            for key in required_keys:
                entry = get_entry(key)
                if entry:
                    current_val = entry.value.strip()
                    display = current_val if current_val else "(empty)"
                    value = input(f"{key} [{display}]: ").strip()
                    if value or not current_val:
                        entry.value = value
                        entry.source = "interactive"

    # Optional keys: PKI_COOKIE_DOMAIN, PKI_DATA_DIR, PKI_DB_PATH
    optional_keys = ["PKI_COOKIE_DOMAIN", "PKI_DATA_DIR", "PKI_DB_PATH"]
    print("\n--- Optional Settings (leave blank to skip) ---")
    for key in optional_keys:
        entry = get_entry(key)
        if entry:
            current_val = entry.value.strip()
            display = current_val if current_val else "(empty)"
            value = input(f"{key} [{display}]: ").strip()
            if value:
                entry.value = value
                entry.source = "interactive"


def validate(entries: list[EnvEntry], profile: str) -> list[str]:
    """Validate environment entries; return list of warning messages."""
    warnings: list[str] = []

    # Check for remaining placeholders in secrets
    for entry in entries:
        if entry.key in APP_SECRET_GENERATORS:
            if should_replace(entry.key, entry.value):
                warnings.append(f"Secret {entry.key} still has placeholder value")

    # Production-specific checks
    if profile == "production":
        # BASE_URL should not be localhost
        for entry in entries:
            if entry.key == "PKI_BASE_URL":
                if entry.value in ("", "http://localhost:8000"):
                    warnings.append(
                        "PKI_BASE_URL should not be localhost in production"
                    )
                break

        # Check NOTIFY_METHOD dependencies
        notify_method = None
        for entry in entries:
            if entry.key == "NOTIFY_METHOD":
                notify_method = entry.value
                break

        if notify_method in NOTIFY_CONDITIONAL_KEYS:
            required_keys = NOTIFY_CONDITIONAL_KEYS[notify_method]
            for key in required_keys:
                for entry in entries:
                    if entry.key == key and not entry.value.strip():
                        warnings.append(f"NOTIFY_METHOD={notify_method} requires {key}")
                        break

    return warnings


def render_output(entries: list[EnvEntry]) -> str:
    """Reconstruct .env file from EnvEntry objects."""
    lines: list[str] = []

    for entry in entries:
        # Emit comment block (including blank lines)
        for comment in entry.comment_block:
            lines.append(comment)

        # Emit key=value (skip sentinel entries with empty key)
        if entry.key:
            lines.append(f"{entry.key}={entry.value}")

    # Ensure file ends with newline
    content = "\n".join(lines)
    if content and not content.endswith("\n"):
        content += "\n"
    return content


def print_diff(output_path: Path, new_content: str) -> None:
    """Print unified diff between existing and new .env."""
    if output_path.exists():
        existing_content = output_path.read_text(encoding="utf-8")
    else:
        existing_content = ""

    existing_lines = existing_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)

    diff = difflib.unified_diff(
        existing_lines,
        new_lines,
        fromfile=str(output_path),
        tofile=str(output_path),
        lineterm="",
    )

    print("\n--- Diff ---")
    for line in diff:
        print(line, end="")
    print()


def print_summary(entries: list[EnvEntry]) -> None:
    """Print ASCII table of environment entries."""
    # Filter out sentinel entries (empty key)
    rows = [e for e in entries if e.key]

    if not rows:
        return

    # Compute column widths
    max_key_len = max(len(r.key) for r in rows) if rows else 0
    max_source_len = max(len(r.source) for r in rows) if rows else 0
    max_value_len = 40

    col_key = max(max_key_len, 3) + 2
    col_source = max(max_source_len, 6) + 2
    col_value = max_value_len + 2

    # Header
    print("\n--- Summary ---")
    separator = "+" + "-" * (col_key - 1) + "+" + "-" * (col_source - 1) + "+" + "-" * (col_value - 1) + "+"
    header = (
        f"| {'KEY'.ljust(col_key - 2)} | {'SOURCE'.ljust(col_source - 2)} | "
        f"{'VALUE PREVIEW'.ljust(col_value - 2)} |"
    )

    print(separator)
    print(header)
    print(separator)

    # Rows
    for entry in rows:
        # Value preview (mask secrets)
        if entry.key in SECRET_KEYS:
            if entry.value:
                preview = entry.value[:6] + "***"
            else:
                preview = "(empty)"
        else:
            if entry.value:
                preview = entry.value[:40]
            else:
                preview = "(empty)"

        row = (
            f"| {entry.key.ljust(col_key - 2)} | {entry.source.ljust(col_source - 2)} | "
            f"{preview.ljust(col_value - 2)} |"
        )
        print(row)

    print(separator)


def backup_existing(output_path: Path) -> None:
    """Backup existing .env to .env.bak."""
    if output_path.exists():
        backup_path = output_path.with_suffix(".bak")
        content = output_path.read_text(encoding="utf-8")
        backup_path.write_text(content, encoding="utf-8")
        print(f"Backed up existing file to {backup_path}")


def confirm_overwrite() -> bool:
    """Prompt user to confirm overwrite."""
    response = input("Output file exists. Overwrite? [y/N]: ").strip().lower()
    return response in ("y", "yes")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create .env from .env.example and generate PKI secrets."
    )
    parser.add_argument(
        "--example",
        default=".env.example",
        help="Path to the source env example file.",
    )
    parser.add_argument(
        "--output",
        default=".env",
        help="Path to the generated env file.",
    )
    parser.add_argument(
        "--env",
        choices=["dev", "production"],
        help="Environment profile (dev/production). If omitted, prompt for selection.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print diff and summary without writing to disk.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt when overwriting existing file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    example_path = (repo_root / args.example).resolve()
    output_path = (repo_root / args.output).resolve()

    if not example_path.exists():
        print(f"Example file not found: {example_path}", file=sys.stderr)
        return 1

    # Select profile
    profile = args.env or select_profile()

    # Parse and apply transformations in order
    entries = parse_example(example_path)

    existing_values = load_existing_env(output_path)
    apply_kept_values(entries, existing_values)

    apply_secret_generators(entries)
    apply_profile_defaults(entries, profile)
    collect_interactive(entries, profile)

    # Validate
    warnings = validate(entries, profile)

    new_content = render_output(entries)

    # Dry-run mode
    if args.dry_run:
        print_diff(output_path, new_content)
        print_summary(entries)
        if warnings:
            print("\n--- Warnings ---")
            for warning in warnings:
                print(f"WARN: {warning}")
        return 0

    # Check if file exists and handle confirmation
    if output_path.exists() and not args.force:
        if not confirm_overwrite():
            print("Aborted.", file=sys.stderr)
            return 1

    # Backup and write
    if output_path.exists():
        backup_existing(output_path)

    output_path.write_text(new_content, encoding="utf-8")
    print(f"Wrote {output_path}")

    print_summary(entries)

    if warnings:
        print("\n--- Warnings ---")
        for warning in warnings:
            print(f"WARN: {warning}")

    print("\nReview non-generated settings such as SMTP and deployment paths before use.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
