#!/usr/bin/env python3
"""
Create a local .env from .env.example and fill generated PKI secrets.
"""

from __future__ import annotations

import argparse
import base64
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


def should_replace(name: str, value: str) -> bool:
    if name not in APP_SECRET_GENERATORS:
        return False
    stripped = value.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    return lowered.startswith(PLACEHOLDER_PREFIXES)


def render_env(example_path: Path) -> tuple[str, list[str]]:
    generated_keys: list[str] = []
    output_lines: list[str] = []

    for line in example_path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            output_lines.append(line)
            continue

        name, value = line.split("=", 1)
        if should_replace(name, value):
            value = APP_SECRET_GENERATORS[name]()
            generated_keys.append(name)

        output_lines.append(f"{name}={value}")

    return "\n".join(output_lines) + "\n", generated_keys


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
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
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

    if output_path.exists() and not args.force:
        print(
            f"Refusing to overwrite existing file: {output_path}\n"
            "Use --force to replace it.",
            file=sys.stderr,
        )
        return 1

    rendered_env, generated_keys = render_env(example_path)
    output_path.write_text(rendered_env, encoding="utf-8")

    print(f"Wrote {output_path}")
    if generated_keys:
        print("Generated values for:")
        for key in generated_keys:
            print(f" - {key}")
    else:
        print("No placeholder secrets required regeneration.")

    print("Review non-generated settings such as SMTP and deployment paths before use.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
