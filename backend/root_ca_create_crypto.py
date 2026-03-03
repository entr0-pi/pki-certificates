from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from helpers import load_json, require_keys, compute_enddate, parse_enddate_utc, load_policy
from folder import PkiLayout, ensure_password_file, init_root_workspace
from root_ca_validate import validate_and_print
import cert_crypto
import file_crypto


def ensure_passphrase_file(pwd_path: Path) -> bytes:
    """
    Keep your old behavior:
    - If PKI_PASS is set: write it once (if missing)
    - else: reuse folder.ensure_password_file() random password behavior
    Files are encrypted at rest via file_crypto.
    """
    if not pwd_path.exists():
        env = os.environ.get("PKI_PASS")
        if env:
            pwd_path.parent.mkdir(parents=True, exist_ok=True)
            file_crypto.write_encrypted(pwd_path, (env.strip() + "\n").encode())
            if os.name == "posix":
                pwd_path.chmod(0o600)
        else:
            ensure_password_file(pwd_path)
    return file_crypto.read_encrypted(pwd_path).strip()





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
    require_keys(frontend, ["C", "ST", "L", "O", "OU", "CN", "org_dir", "cert_name"])

    org_dir = Path(frontend["org_dir"])
    cert_name = str(frontend["cert_name"])
    artifact_name = str(frontend.get("artifact_name") or cert_name)

    ws = init_root_workspace(org_dir, cert_name, layout, artifact_name=artifact_name)

    # Prevent overwrite
    if ws["ca_exists"]:
        sys.exit(" Root CA already exists (key/csr/cert present) ")

    passphrase = ensure_passphrase_file(ws["pwd_path"])

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
    cert_crypto.save_private_key(
        key,
        ws["key_path"],
        passphrase,
        cipher_name
    )

    # 2) CSR
    csr = cert_crypto.create_csr(key, subject, san, req_hash)
    file_crypto.write_encrypted(ws["csr_path"], csr.public_bytes(serialization.Encoding.PEM))

    # 3) Self-signed Root certificate
    now = datetime.now(timezone.utc)
    extensions = cert_crypto.build_extensions(
        role="root",
        policy=root_defaults,
        subject_key=key.public_key(),
        issuer_key=key.public_key(),  # self-signed
        issuer_cert=None,
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
    file_crypto.write_encrypted(ws["crt_path"], cert.public_bytes(serialization.Encoding.PEM))

    # Validate + print (expects ws dict keys exactly like this) [1](https://candeloitte-my.sharepoint.com/personal/ngemin_deloitte_ca/Documents/Microsoft%20Copilot%20Chat%20Files/root_ca_validate.py)
    validate_and_print(
        ws,
        key_path=ws["key_path"],
        cert_path=ws["crt_path"],
        csr_path=ws["csr_path"],
        pwd_path=ws["pwd_path"],
        title=f"Key information for: {cert_name}",
    )

    print("\n Root CA created successfully!")


if __name__ == "__main__":
    main()
