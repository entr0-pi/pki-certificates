from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from helpers import load_json, require_keys, compute_enddate, parse_enddate_utc, load_policy
from folder import PkiLayout, ensure_password_file, init_intermediate_workspace
from root_ca_validate import validate_and_print
import cert_crypto
import file_crypto




def main() -> None:
    ap = argparse.ArgumentParser(
        description="Create Intermediate CA using cryptography (policy/params driven)."
    )
    ap.add_argument("--params", required=True, type=Path, help="Path to intermediate_ca.json")
    args = ap.parse_args()

    layout = PkiLayout()

    # Read policy.json
    project_root = Path(__file__).resolve().parent.parent  # backend/intermediate_ca_create_crypto.py -> backend -> project root
    policy_path = project_root / "backend" / layout.policy_filename
    if not policy_path.exists():
        sys.exit(f"Missing policy file at: {policy_path}")

    policy, allowed_curves, allowed_ciphers = load_policy(policy_path)
    intermediate_defaults = policy["role_defaults"]["intermediate"]
    issuer_policy = policy["role_defaults"]["root"]

    # Read frontend params (intermediate_ca.json)
    frontend = load_json(args.params)
    require_keys(
        frontend,
        ["C", "ST", "L", "O", "OU", "CN", "org_dir", "cert_name", "issuer_name"]
    )

    org_dir = Path(frontend["org_dir"])
    cert_name = str(frontend["cert_name"])
    artifact_name = str(frontend.get("artifact_name") or cert_name)
    issuer_name = str(frontend["issuer_name"])
    issuer_artifact_name = str(frontend.get("issuer_artifact_name") or issuer_name)

    # Initialize workspace
    ws = init_intermediate_workspace(org_dir, cert_name, layout, artifact_name=artifact_name)

    # Prevent overwrite
    if ws["ca_exists"]:
        sys.exit(" Intermediate CA already exists (key/csr/cert present) ")

    # Ensure password file for intermediate CA
    ensure_password_file(ws["pwd_path"])
    passphrase = file_crypto.read_encrypted(ws["pwd_path"]).strip()

    # Construct issuer (root CA) paths from issuer_name
    # For intermediate CAs, issuer is always in the root directory
    issuer_base = org_dir / layout.root_dirname
    issuer_cert_path = issuer_base / layout.certs_dirname / f"{issuer_artifact_name}.pem.enc"
    issuer_key_path = issuer_base / layout.private_dirname / f"{issuer_artifact_name}.key.enc"
    issuer_pwd_path = issuer_base / layout.private_dirname / f"{issuer_artifact_name}.pwd.enc"

    if not issuer_cert_path.exists():
        sys.exit(f"Issuer certificate not found: {issuer_cert_path}")
    if not issuer_key_path.exists():
        sys.exit(f"Issuer key not found: {issuer_key_path}")
    if not issuer_pwd_path.exists():
        sys.exit(f"Issuer password file not found: {issuer_pwd_path}")

    issuer_passphrase = file_crypto.read_encrypted(issuer_pwd_path).strip()
    issuer_cert = cert_crypto.load_certificate(issuer_cert_path)
    issuer_key = cert_crypto.load_private_key(issuer_key_path, issuer_passphrase)

    # Curve/hash/enddate are policy-driven but can be overridden by params
    curve_name = str(frontend.get("eccurve") or intermediate_defaults["ec_curve"])
    if allowed_curves and curve_name not in allowed_curves:
        sys.exit(
            f"Invalid ec_curve: {curve_name}. Allowed values from policy: {', '.join(sorted(allowed_curves))}"
        )
    req_hash = cert_crypto.parse_hash(str(intermediate_defaults["DEFAULT_HASH_REQ"]))
    ca_hash = cert_crypto.parse_hash(str(intermediate_defaults["DEFAULT_HASH_CA"]))

    enddate_str = str(
        frontend.get("enddate") or compute_enddate(int(intermediate_defaults["DEFAULT_DAYS"]))
    )
    not_after = parse_enddate_utc(enddate_str)

    # Build subject from intermediate_ca.json
    subject = cert_crypto.parse_subject_dn(frontend)
    san = cert_crypto.parse_san(str(frontend.get("subjectAltName") or ""))
    cert_crypto.enforce_policy_subject(subject, issuer_cert.subject, issuer_policy)
    pki_base_url = str(frontend.get("PKI_BASE_URL", "http://localhost:8000")).rstrip("/")
    org_id = str(frontend.get("org_id", "")).strip()
    crl_url_template = str(intermediate_defaults.get("CRL_URL", "")).strip()
    crl_url = ""
    if crl_url_template and org_id:
        crl_url = crl_url_template.format(
            PKI_BASE_URL=pki_base_url,
            org_id=org_id,
            issuer_name=issuer_name,
        )

    cipher_name = str(intermediate_defaults.get("key_encryption_cipher", "aes256")).lower()
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

    # 3) Sign certificate with issuer (root CA)
    now = datetime.now(timezone.utc)
    extensions = cert_crypto.build_extensions(
        role="intermediate",
        policy=intermediate_defaults,
        subject_key=key.public_key(),
        issuer_key=issuer_cert.public_key(),  # Root CA's public key
        issuer_cert=issuer_cert,
        san=san,
        crl_url=crl_url,
    )

    cert = cert_crypto.build_and_sign_certificate(
        subject=subject,
        issuer=issuer_cert.subject,  # NOT self-signed - use root CA's subject
        public_key=key.public_key(),
        issuer_key=issuer_key,  # Sign with root CA's private key
        serial_number=x509.random_serial_number(),
        not_before=now - timedelta(minutes=1),
        not_after=not_after,
        extensions=extensions,
        hash_algo=ca_hash
    )
    file_crypto.write_encrypted(ws["crt_path"], cert.public_bytes(serialization.Encoding.PEM))

    # Validate + print
    validate_and_print(
        ws,
        key_path=ws["key_path"],
        cert_path=ws["crt_path"],
        csr_path=ws["csr_path"],
        pwd_path=ws["pwd_path"],
        title=f"Key information for: {cert_name}",
        issuer_cert=issuer_cert,
        is_ca=True
    )

    print(f"\n Intermediate CA created successfully!")

if __name__ == "__main__":
    main()
