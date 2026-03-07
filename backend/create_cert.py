from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from helpers import load_json


def main() -> None:
    """
    Unified entry point for certificate creation.

    Dispatches to the appropriate script based on cert_type in the JSON config:
    - "root"          root_ca_create_crypto.py
    - "intermediate"  intermediate_ca_create_crypto.py
    - "server"        end_entity_create_crypto.py
    - "client"        end_entity_create_crypto.py
    - "email"         end_entity_create_crypto.py
    - "ocsp"          end_entity_create_crypto.py
    """
    parser = argparse.ArgumentParser(
        description="Create certificates (root CA, intermediate CA, or end-entity)."
    )
    parser.add_argument("--params", required=True, type=Path, help="Path to certificate config JSON")
    args = parser.parse_args()

    # Load config to determine certificate type
    config = load_json(args.params)
    cert_type = str(config.get("cert_type", "")).lower()

    if not cert_type:
        sys.exit(" Missing 'cert_type' in config. Must be one of: root, intermediate, server, client, email, ocsp")

    # Map cert_type to script
    script_map = {
        "root": "root_ca_create_crypto.py",
        "intermediate": "intermediate_ca_create_crypto.py",
        "server": "end_entity_create_crypto.py",
        "client": "end_entity_create_crypto.py",
        "email": "end_entity_create_crypto.py",
        "ocsp": "end_entity_create_crypto.py",
    }

    if cert_type not in script_map:
        valid_types = ", ".join(script_map.keys())
        sys.exit(f" Invalid cert_type: '{cert_type}'. Must be one of: {valid_types}")

    script = script_map[cert_type]
    script_path = Path(__file__).parent / script

    if not script_path.exists():
        sys.exit(f" Script not found: {script_path}")

    # Execute the appropriate script
    print(f" Dispatching to {script} for cert_type '{cert_type}'...\n")
    project_root = Path(__file__).parent.parent  # Go up to project root
    result = subprocess.run(
        [sys.executable, str(script_path), "--params", str(args.params)],
        cwd=project_root,
    )

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
