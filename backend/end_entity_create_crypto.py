from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12

from helpers import load_json, require_keys, compute_enddate, parse_enddate_utc, load_policy
from folder import PkiLayout, ensure_password_file, init_end_entity_workspace
from root_ca_validate import validate_and_print
import cert_crypto
import file_crypto


def generate_pkcs12(
    cert_path: Path,
    key_path: Path,
    pwd_path: Path,
    pkcs12_path: Path,
    p12_pwd_path: Path,
) -> None:
    """
    Generate PKCS12 file from certificate and key.
    Creates a new password for the PKCS12 file.
    Compatible with: openssl pkcs12 -export -macalg sha1 -legacy

    Args:
        cert_path: Path to PEM certificate file
        key_path: Path to encrypted PEM private key file
        pwd_path: Path to password file for the private key
        pkcs12_path: Output path for PKCS12 file (.p12 or .pfx)
        p12_pwd_path: Output path for PKCS12 password file
    """
    from cryptography.hazmat.backends import default_backend
    from helpers import random_password

    # Load certificate
    cert_bytes = file_crypto.read_encrypted(cert_path)
    cert = x509.load_pem_x509_certificate(cert_bytes)

    # Load private key with its password
    key_bytes = file_crypto.read_encrypted(key_path)
    key_password = file_crypto.read_encrypted(pwd_path).strip() if pwd_path.exists() else None

    private_key = serialization.load_pem_private_key(
        key_bytes,
        password=key_password if key_password else None,
        backend=default_backend()
    )

    # Generate a new random password for PKCS12
    p12_password_str = random_password()  # Returns string with newline

    # Save PKCS12 password to file (with newline, consistent with other pwd files)
    p12_pwd_path.parent.mkdir(parents=True, exist_ok=True)
    file_crypto.write_encrypted(p12_pwd_path, p12_password_str.encode())

    # Use password WITHOUT newline for encryption
    p12_password = p12_password_str.strip().encode('utf-8')

    # Generate PKCS12 encrypted with the new password
    # Compatible with: openssl pkcs12 -export -macalg sha1 -legacy
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=None,
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password),
    )

    pkcs12_path.parent.mkdir(parents=True, exist_ok=True)
    file_crypto.write_encrypted(pkcs12_path, p12_bytes)
    print(f" PKCS12 file generated: {pkcs12_path}")
    print(f" PKCS12 password saved: {p12_pwd_path}")




def main() -> None:
    ap = argparse.ArgumentParser(
        description="Create end-entity certificate using cryptography (policy/params driven)."
    )
    ap.add_argument("--params", required=True, type=Path, help="Path to end_entity.json")
    args = ap.parse_args()

    layout = PkiLayout()

    # Read policy.json
    project_root = Path(__file__).resolve().parent.parent  # backend/end_entity_create_crypto.py -> backend -> project root
    policy_path = project_root / "backend" / layout.policy_filename
    if not policy_path.exists():
        sys.exit(f"Missing policy file at: {policy_path}")

    policy, allowed_curves, allowed_ciphers = load_policy(policy_path)

    # Read frontend params (end_entity.json)
    frontend = load_json(args.params)
    require_keys(
        frontend,
        ["C", "ST", "L", "O", "OU", "CN", "org_dir", "cert_name", "cert_type", "issuer_name"]
    )

    org_dir = Path(frontend["org_dir"])
    cert_name = str(frontend["cert_name"])
    artifact_name = str(frontend.get("artifact_name") or cert_name)
    cert_type = str(frontend["cert_type"]).lower()  # server, client, email
    issuer_name = str(frontend["issuer_name"])
    issuer_artifact_name = str(frontend.get("issuer_artifact_name") or issuer_name)
    issuer_type = str(frontend.get("issuer_type", "intermediate")).lower()  # intermediate or root

    # Map cert_type to policy role
    type_to_role = {
        "server": "end-entity-server",
        "client": "end-entity-client",
        "email": "end-entity-email",
    }

    if cert_type not in type_to_role:
        sys.exit(f"Invalid cert_type: {cert_type}. Must be one of: server, client, email")

    role = type_to_role[cert_type]
    entity_defaults = policy["role_defaults"][role]
    issuer_policy_key = "root" if issuer_type == "root" else "intermediate"
    issuer_policy = policy["role_defaults"][issuer_policy_key]

    # Initialize workspace
    ws = init_end_entity_workspace(org_dir, cert_type, cert_name, layout, artifact_name=artifact_name)

    # Prevent overwrite
    if ws["cert_exists"]:
        sys.exit(" End-entity certificate already exists (key/cert present) ")

    # Ensure password file for certificate
    ensure_password_file(ws["pwd_path"])
    passphrase = file_crypto.read_encrypted(ws["pwd_path"]).strip()

    # Construct issuer paths based on issuer_type
    # For intermediates: folder = issuer_name (cert_name), files = issuer_artifact_name (UUID)
    if issuer_type == "root":
        issuer_base = org_dir / layout.root_dirname
    elif issuer_type == "intermediate":
        issuer_base = org_dir / layout.intermediates_dirname / issuer_name
    else:
        sys.exit(f"Invalid issuer_type: {issuer_type}. Must be 'root' or 'intermediate'")

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
    curve_name = str(frontend.get("eccurve") or entity_defaults["ec_curve"])
    if allowed_curves and curve_name not in allowed_curves:
        sys.exit(
            f"Invalid ec_curve: {curve_name}. Allowed values from policy: {', '.join(sorted(allowed_curves))}"
        )
    req_hash = cert_crypto.parse_hash(str(entity_defaults["DEFAULT_HASH_REQ"]))
    ca_hash = cert_crypto.parse_hash(str(entity_defaults["DEFAULT_HASH_CA"]))

    enddate_str = str(
        frontend.get("enddate") or compute_enddate(int(entity_defaults["DEFAULT_DAYS"]))
    )
    not_after = parse_enddate_utc(enddate_str)

    # Build subject from end_entity.json
    subject = cert_crypto.parse_subject_dn(frontend)
    san = cert_crypto.parse_san(str(frontend.get("subjectAltName") or ""))
    cert_crypto.enforce_policy_subject(subject, issuer_cert.subject, issuer_policy)
    pki_base_url = str(frontend.get("PKI_BASE_URL", "http://localhost:8000")).rstrip("/")
    org_id = str(frontend.get("org_id", "")).strip()
    crl_url_template = str(entity_defaults.get("CRL_URL", "")).strip()
    crl_url = ""
    if crl_url_template and org_id:
        crl_url = crl_url_template.format(
            PKI_BASE_URL=pki_base_url,
            org_id=org_id,
            issuer_name=issuer_name,
        )

    # Validate SAN for server certificates
    if cert_type == "server" and not san:
        print("  Warning: Server certificates should have subjectAltName (SAN)")

    cipher_name = str(entity_defaults.get("key_encryption_cipher", "aes256")).lower()
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

    # 3) Sign certificate with issuer CA
    now = datetime.now(timezone.utc)
    extensions = cert_crypto.build_extensions(
        role=role,
        policy=entity_defaults,
        subject_key=key.public_key(),
        issuer_key=issuer_cert.public_key(),
        issuer_cert=issuer_cert,
        san=san,
        crl_url=crl_url,
    )

    cert = cert_crypto.build_and_sign_certificate(
        subject=subject,
        issuer=issuer_cert.subject,  # Signed by CA
        public_key=key.public_key(),
        issuer_key=issuer_key,  # Sign with CA's private key
        serial_number=x509.random_serial_number(),
        not_before=now - timedelta(minutes=1),
        not_after=not_after,
        extensions=extensions,
        hash_algo=ca_hash
    )
    file_crypto.write_encrypted(ws["crt_path"], cert.public_bytes(serialization.Encoding.PEM))

    # Generate PKCS12 file for client and email certificates only
    # (server certs typically don't need PKCS12 format)
    if cert_type in ("client", "email"):
        try:
            generate_pkcs12(
                cert_path=ws["crt_path"],
                key_path=ws["key_path"],
                pwd_path=ws["pwd_path"],
                pkcs12_path=ws["p12_path"],
                p12_pwd_path=ws["p12_pwd_path"]
            )
        except Exception as e:
            print(f" Warning: PKCS12 generation failed: {e}")

    # Parse expected ExtendedKeyUsage from policy
    expected_eku = None
    if "EXTENDEDKEYUSAGE" in entity_defaults:
        eku_str = str(entity_defaults["EXTENDEDKEYUSAGE"])
        # Parse comma-separated EKU values (e.g., "serverAuth" or "clientAuth, emailProtection")
        expected_eku = [eku.strip() for eku in eku_str.split(",")]

    # Validate + print
    validate_and_print(
        ws,
        key_path=ws["key_path"],
        cert_path=ws["crt_path"],
        csr_path=ws["csr_path"],
        pwd_path=ws["pwd_path"],
        title=f"Key information for: {cert_name}",
        issuer_cert=issuer_cert,
        is_ca=False,
        expected_eku=expected_eku
    )

    print(f"\n End-entity certificate created successfully!")


if __name__ == "__main__":
    main()
