from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from helpers import load_json, require_keys, compute_enddate, parse_enddate_utc, load_policy
from folder import PkiLayout, ensure_password_file, init_root_workspace
from root_ca_validate import validate_and_print
import cert_crypto
import file_crypto
import secrets




def main() -> None:
    ap = argparse.ArgumentParser(description="Create Root CA using cryptography (policy/params driven).")
    ap.add_argument("--params", required=True, type=Path, help="Path to root_ca.json")
    args = ap.parse_args()

    layout = PkiLayout()

    # Read policy.json (name comes from layout) [1](https://candeloitte-my.sharepoint.com/personal/ngemin_deloitte_ca/Documents/Microsoft%20Copilot%20Chat%20Files/root_ca_validate.py)
    project_root = Path(__file__).resolve().parent.parent  # backend/root_ca_create_crypto.py -> backend -> project root
    policy_path = project_root / "backend" / layout.policy_filename
    if not policy_path.exists():
        sys.exit(f"Missing policy file at: {policy_path}")

    policy, allowed_curves, allowed_ciphers = load_policy(policy_path)
    root_defaults = policy["role_defaults"]["root"]

    # Read frontend params (root_ca.json)
    frontend = load_json(args.params)
    require_keys(frontend, ["C", "ST", "L", "O", "OU", "CN", "org_dir", "cert_name", "root_ca_password"])

    org_dir = Path(frontend["org_dir"])
    cert_name = str(frontend["cert_name"])
    artifact_name = str(frontend.get("artifact_name") or cert_name)

    ws = init_root_workspace(org_dir, cert_name, layout, artifact_name=artifact_name)

    # Prevent overwrite
    if ws["ca_exists"]:
        sys.exit(" Root CA already exists (key/csr/cert present) ")

    # Two-factor protection for root CA private key
    # 1. Generate filesystem password (stored in .pwd.enc)
    # 2. User provides password (never stored, only used to derive key)
    # 3. Effective key = HMAC-SHA256(fs_password, user_password)
    root_user_password = str(frontend["root_ca_password"])

    # Generate random filesystem password (32 bytes, base64 encoded for storage)
    fs_password_bytes = secrets.token_bytes(32)
    fs_password = fs_password_bytes.hex()

    # Store filesystem password in .pwd.enc
    cast(Path, ws["pwd_path"]).parent.mkdir(parents=True, exist_ok=True)
    file_crypto.write_encrypted(cast(Path, ws["pwd_path"]), (fs_password + "\n").encode())
    if os.name == "posix":
        cast(Path, ws["pwd_path"]).chmod(0o600)

    # Derive effective passphrase using HMAC-SHA256
    effective_passphrase = cert_crypto.derive_root_key_password(
        fs_password_bytes,
        root_user_password
    )

    # Curve/hash/enddate are policy-driven but can be overridden by params
    curve_name = str(frontend.get("eccurve") or root_defaults["ec_curve"])
    if allowed_curves and curve_name not in allowed_curves:
        sys.exit(
            f"Invalid ec_curve: {curve_name}. Allowed values from policy: {', '.join(sorted(allowed_curves))}"
        )
    req_hash = cert_crypto.parse_hash(str(root_defaults["DEFAULT_HASH_REQ"]))
    ca_hash = cert_crypto.parse_hash(str(root_defaults["DEFAULT_HASH_CA"]))

    enddate_str = str(frontend.get("enddate") or compute_enddate(int(root_defaults["DEFAULT_DAYS"])))
    not_after = parse_enddate_utc(enddate_str)

    # Build subject from root_ca.json
    subject = cert_crypto.parse_subject_dn(frontend)
    san = cert_crypto.parse_san(str(frontend.get("subjectAltName") or ""))
    pki_base_url = str(frontend.get("PKI_BASE_URL", "http://localhost:8000")).rstrip("/")
    org_id = str(frontend.get("org_id", "")).strip()
    crl_url_template = str(root_defaults.get("CRL_URL", "")).strip()
    crl_url = ""
    if crl_url_template and org_id:
        crl_url = crl_url_template.format(
            PKI_BASE_URL=pki_base_url,
            org_id=org_id,
            issuer_name=cert_name,
        )

    cipher_name = str(root_defaults.get("key_encryption_cipher", "aes256")).lower()
    if allowed_ciphers and cipher_name not in allowed_ciphers:
        sys.exit(
            f"Invalid key_encryption_cipher: {cipher_name}. "
            f"Allowed values from policy: {', '.join(sorted(allowed_ciphers))}"
        )

    # 1) Generate key
    key = cert_crypto.generate_ec_key(curve_name)
    # Encrypt root private key with effective passphrase (derived from fs_password + user_password)
    cert_crypto.save_private_key(
        key,
        cast(Path, ws["key_path"]),
        effective_passphrase,
        cipher_name
    )

    # 2) CSR
    csr = cert_crypto.create_csr(key, subject, san, req_hash)
    file_crypto.write_encrypted(cast(Path, ws["csr_path"]), csr.public_bytes(serialization.Encoding.PEM))

    # 3) Self-signed Root certificate
    now = datetime.now(timezone.utc)
    extensions = cert_crypto.build_extensions(
        role="root",
        policy=root_defaults,
        subject_key=key.public_key(),
        issuer_key=key.public_key(),  # self-signed
        san=san,
        crl_url=crl_url,
    )

    cert = cert_crypto.build_and_sign_certificate(
        subject=subject,
        issuer=subject,  # self-signed
        public_key=key.public_key(),
        issuer_key=key,
        serial_number=x509.random_serial_number(),
        not_before=now - timedelta(minutes=1),
        not_after=not_after,
        extensions=extensions,
        hash_algo=ca_hash
    )
    file_crypto.write_encrypted(cast(Path, ws["crt_path"]), cert.public_bytes(serialization.Encoding.PEM))

    # Validate + print (expects ws dict keys exactly like this)
    # Pass user_password for root CA to derive HMAC key for private key validation
    validate_and_print(
        ws,
        key_path=cast(Path, ws["key_path"]),
        cert_path=cast(Path, ws["crt_path"]),
        csr_path=cast(Path, ws["csr_path"]),
        pwd_path=cast(Path, ws["pwd_path"]),
        title=f"Key information for: {cert_name}",
        user_password=root_user_password,
    )

    print("\n Root CA created successfully!")


if __name__ == "__main__":
    main()
