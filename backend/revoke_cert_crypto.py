"""
Revoke certificate and generate CRL using cryptography library.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from helpers import load_json
from folder import PkiLayout
import file_crypto


# Reason mapping: DB string → x509.ReasonFlags
REASON_MAP = {
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "caCompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aaCompromise": x509.ReasonFlags.aa_compromise,
    "unspecified": x509.ReasonFlags.unspecified,
}


def parse_datetime_utc(s: str) -> datetime:
    """Parse UTC ISO timestamp (from database CURRENT_TIMESTAMP)."""
    # Database timestamps are typically YYYY-MM-DD HH:MM:SS
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)


def resolve_issuer_paths(
    org_dir: Path,
    issuer_name: str,
    issuer_artifact_name: str,
    issuer_type: str,
    layout: PkiLayout,
) -> dict[str, Path]:
    """Resolve issuer key, cert, and password paths based on issuer type.

    For intermediate CAs, uses issuer_name (cert_name) as folder name.
    Files inside use issuer_artifact_name (UUID).
    """
    if issuer_type == "root":
        issuer_base = org_dir / layout.root_dirname
    elif issuer_type == "intermediate":
        # Folder name uses cert_name, files use UUID
        issuer_base = org_dir / layout.intermediates_dirname / issuer_name
    else:
        raise ValueError(f"Invalid issuer_type: {issuer_type}")

    return {
        "crt_path": issuer_base / layout.certs_dirname / f"{issuer_artifact_name}.pem.enc",
        "key_path": issuer_base / layout.private_dirname / f"{issuer_artifact_name}.key.enc",
        "pwd_path": issuer_base / layout.private_dirname / f"{issuer_artifact_name}.pwd.enc",
        "crl_path": issuer_base / "crl" / f"{issuer_artifact_name}.crl.pem.enc",
    }


def generate_crl(
    issuer_cert_path: Path,
    issuer_key_path: Path,
    issuer_pwd_path: Path,
    crl_output_path: Path,
    revoked_list: list[dict],
) -> None:
    """
    Generate a Certificate Revocation List (CRL).

    Args:
        issuer_cert_path: Path to issuer certificate (PEM)
        issuer_key_path: Path to issuer private key (PEM)
        issuer_pwd_path: Path to issuer password file
        crl_output_path: Output path for CRL (PEM)
        revoked_list: List of dicts with keys: serial_number, revoked_at, revocation_reason
    """
    # Load issuer certificate
    if not issuer_cert_path.exists():
        raise FileNotFoundError(f"Issuer certificate not found: {issuer_cert_path}")

    issuer_cert = x509.load_pem_x509_certificate(file_crypto.read_encrypted(issuer_cert_path))

    # Load issuer private key
    if not issuer_key_path.exists():
        raise FileNotFoundError(f"Issuer private key not found: {issuer_key_path}")

    passphrase = file_crypto.read_encrypted(issuer_pwd_path).strip() if issuer_pwd_path.exists() else b""
    issuer_key = serialization.load_pem_private_key(
        file_crypto.read_encrypted(issuer_key_path),
        password=passphrase if passphrase else None,
    )

    # Build CRL
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=3650))
    )

    # Add revoked certificates
    for revoked in revoked_list:
        serial = int(revoked["serial_number"], 16)
        revoked_at = parse_datetime_utc(revoked["revoked_at"])
        reason_str = revoked.get("revocation_reason", "unspecified")
        reason_enum = REASON_MAP.get(reason_str, x509.ReasonFlags.unspecified)

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .add_extension(x509.CRLReason(reason_enum), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    # Add Authority Key Identifier extension
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )

    # Sign and write CRL
    crl = builder.sign(issuer_key, hashes.SHA384())
    crl_output_path.parent.mkdir(parents=True, exist_ok=True)
    file_crypto.write_encrypted(crl_output_path, crl.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] CRL generated: {crl_output_path}")


def main() -> None:
    """
    Entry point for CRL generation.
    Expects --params pointing to a JSON file with:
      - org_dir: Path to organization directory
      - issuer_name: Name of the issuer certificate
      - issuer_type: 'root' or 'intermediate'
      - revoked_certs: List of revoked cert dicts
    """
    ap = argparse.ArgumentParser(description="Generate CRL after certificate revocation.")
    ap.add_argument("--params", required=True, type=Path, help="Path to revocation params JSON")
    args = ap.parse_args()

    layout = PkiLayout()
    params = load_json(args.params)

    org_dir = Path(params["org_dir"])
    issuer_name = params["issuer_name"]
    issuer_artifact_name = params.get("issuer_artifact_name") or issuer_name
    issuer_type = params["issuer_type"]
    revoked_certs = params.get("revoked_certs", [])

    try:
        issuer_paths = resolve_issuer_paths(org_dir, issuer_name, issuer_artifact_name, issuer_type, layout)

        generate_crl(
            issuer_cert_path=issuer_paths["crt_path"],
            issuer_key_path=issuer_paths["key_path"],
            issuer_pwd_path=issuer_paths["pwd_path"],
            crl_output_path=issuer_paths["crl_path"],
            revoked_list=revoked_certs,
        )

    except Exception as e:
        sys.exit(f" CRL generation failed: {e}")


if __name__ == "__main__":
    main()
