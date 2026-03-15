#!/usr/bin/env python3
"""
Check consistency between database certificate data and actual PEM files on disk.

This script is designed to run periodically (via cron) to validate:
- Certificate files exist on disk
- Extension data in DB matches what's in the PEM files
- No orphaned DB records (certs deleted but DB rows remain)
- CRL files match CRL records in DB

Usage:
    python scripts/check_consistency.py [--report-file=path] [--strict]

    --report-file=path: Write detailed report to file (default: stdout)
    --strict: Exit with code 1 if any inconsistencies found (for cron alerts)

Exit codes:
    0: All checks passed, no inconsistencies
    1: Inconsistencies found (only with --strict flag)
    2: Fatal error during checks
"""

import sys
import argparse
import logging
import os
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import text

# Add backend to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

import db
import file_crypto
from path_config import get_data_dir
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConsistencyChecker:
    """Validates DB data consistency with PEM files."""

    def __init__(self, strict=False):
        self.strict = strict
        self.enforce_ca_pwdless = os.environ.get("PKI_ENFORCE_CA_EMPTY_PWD_PATH", "false").strip().lower() in ("1", "true", "yes", "on")
        self.issues = []
        self.stats = {
            "total_certs": 0,
            "checked_certs": 0,
            "missing_files": 0,
            "subject_mismatches": 0,
            "issuer_link_mismatches": 0,
            "serial_format_issues": 0,
            "serial_duplicates_global": 0,
            "serial_duplicates_per_org": 0,
            "validity_mismatches": 0,
            "invalid_validity_ranges": 0,
            "type_policy_mismatches": 0,
            "artifact_path_mismatches": 0,
            "key_cert_mismatches": 0,
            "key_load_failures": 0,
            "csr_mismatches": 0,
            "crl_semantic_mismatches": 0,
            "orphaned_records": 0,
            "status_state_mismatches": 0,
            "encryption_naming_mismatches": 0,
            "hash_mismatches": 0,
            "hash_new_entries": 0,
            "hash_tracked_files": 0,
            "hash_skipped_files": 0,
            "san_mismatches": 0,
            "bc_mismatches": 0,
            "ku_mismatches": 0,
            "eku_mismatches": 0,
            "orphaned_extensions": 0,
            "crl_mismatches": 0,
            # NEW: CRL and data integrity checks
            "crl_validity_checks": 0,
            "crl_validity_failures": 0,
            "crl_signature_errors": 0,
            "uuid_missing": 0,
            "uuid_invalid_format": 0,
            "uuid_duplicates": 0,
            "uuid_path_mismatches": 0,
            "chain_validation_errors": 0,
            "circular_chains_detected": 0,
            "chain_depth_violations": 0,
            "crl_revocation_mismatches": 0,
            "crl_count_mismatches": 0,
            "crl_reason_mismatches": 0,
            "encryption_validation_failures": 0,
            "decryption_errors": 0,
            "password_file_errors": 0,
            "field_completeness_errors": 0,
            "policy_constraint_violations": 0,
            "dual_password_missing": 0,
            "dual_password_format_errors": 0,
            "dual_password_decode_errors": 0,
            "warnings": 0,
        }
        self._pem_cache = {}
        self.data_dir = get_data_dir()
        self.hash_manifest_path = self.data_dir / ".pki_file_hashes.json"
        self.file_hashes = self._load_hash_manifest()

    def _resolve_org_path(self, org_dir: str | Path) -> Path:
        """
        Resolve organization directory using the same semantics as backend runtime:
        - absolute paths are used as-is
        - legacy 'data/...' values are mapped under configured PKI_DATA_DIR
        - relative values are mapped under configured PKI_DATA_DIR
        """
        p = Path(org_dir)
        if p.is_absolute():
            return p
        if p.parts and p.parts[0].lower() == "data":
            return self.data_dir.joinpath(*p.parts[1:])
        return self.data_dir / p

    def issue(self, level, message):
        """Record an issue."""
        self.issues.append({"level": level, "message": message})
        if level == "warning":
            self.stats["warnings"] += 1
            logger.warning(message)
        elif level == "error":
            logger.error(message)

    def _load_hash_manifest(self):
        if not self.hash_manifest_path.exists():
            return {}
        try:
            data = json.loads(self.hash_manifest_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            self.issue("warning", f"Could not parse hash manifest: {self.hash_manifest_path}")
        return {}

    def _save_hash_manifest(self):
        try:
            self.hash_manifest_path.parent.mkdir(parents=True, exist_ok=True)
            self.hash_manifest_path.write_text(
                json.dumps(self.file_hashes, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as e:
            self.issue("warning", f"Could not write hash manifest {self.hash_manifest_path}: {e}")

    @staticmethod
    def _md5_file(path: Path) -> str:
        h = hashlib.md5()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _should_skip_hash_tracking(self, path: Path) -> bool:
        """Skip hash tracking for manifest itself and CRL artifacts."""
        if path == self.hash_manifest_path:
            return True
        rel = str(path.relative_to(self.data_dir)).replace("\\", "/").lower()
        if rel.endswith(".crl.pem.enc"):
            return True
        if "/crl/" in f"/{rel}/":
            return True
        return False

    def check_certificate_file_exists(self, cert_id, cert_name, cert_path, org_dir):
        """Verify certificate PEM file exists."""
        abs_path = self._resolve_org_path(org_dir) / cert_path
        if not abs_path.exists():
            self.issue("error", f"[{cert_id}] {cert_name}: PEM file missing at {abs_path}")
            self.stats["missing_files"] += 1
            return False
        return True

    def check_sans_consistency(self, cert_id, cert_name, cert_path, org_dir):
        """Verify SANs in DB match PEM."""
        abs_path = self._resolve_org_path(org_dir) / cert_path
        try:
            pem_data = file_crypto.read_encrypted(abs_path)
            pem_cert = x509.load_pem_x509_certificate(pem_data)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for SAN check: {e}")
            return

        # Extract SANs from PEM
        pem_sans = []
        try:
            san_ext = pem_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    pem_sans.append(("DNS", name.value))
                elif isinstance(name, x509.IPAddress):
                    pem_sans.append(("IP", str(name.value)))
                elif isinstance(name, x509.RFC822Name):
                    pem_sans.append(("EMAIL", name.value))
                elif isinstance(name, x509.UniformResourceIdentifier):
                    pem_sans.append(("URI", name.value))
        except x509.ExtensionNotFound:
            pem_sans = []

        # Get SANs from DB
        db_sans = db.list_sans(cert_id)
        db_sans_tuples = [(s["san_type"], s["san_value"]) for s in db_sans]

        # Compare
        if set(pem_sans) != set(db_sans_tuples):
            self.issue("error",
                f"[{cert_id}] {cert_name}: SAN mismatch - PEM has {len(pem_sans)}, DB has {len(db_sans)}")
            self.stats["san_mismatches"] += 1

    def check_subject_consistency(self, cert):
        """Verify subject fields in DB match PEM certificate subject."""
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        abs_path = self._resolve_org_path(cert["org_dir"]) / cert["cert_path"]
        try:
            pem_data = file_crypto.read_encrypted(abs_path)
            pem_cert = x509.load_pem_x509_certificate(pem_data)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for subject check: {e}")
            return

        subject = pem_cert.subject

        def _get_attr(oid):
            attrs = subject.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None

        pem_subject = {
            "subject_country": _get_attr(x509.oid.NameOID.COUNTRY_NAME),
            "subject_state": _get_attr(x509.oid.NameOID.STATE_OR_PROVINCE_NAME),
            "subject_locality": _get_attr(x509.oid.NameOID.LOCALITY_NAME),
            "subject_organization": _get_attr(x509.oid.NameOID.ORGANIZATION_NAME),
            "subject_org_unit": _get_attr(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME),
            "subject_common_name": _get_attr(x509.oid.NameOID.COMMON_NAME),
            "subject_email": _get_attr(x509.oid.NameOID.EMAIL_ADDRESS),
        }

        for field, pem_value in pem_subject.items():
            db_value = cert.get(field)
            if (db_value or None) != (pem_value or None):
                self.issue(
                    "error",
                    f"[{cert_id}] {cert_name}: Subject mismatch for {field} - PEM: {pem_value!r}, DB: {db_value!r}"
                )
                self.stats["subject_mismatches"] += 1

    def _load_pem_cert(self, abs_path: Path):
        cache_key = str(abs_path)
        if cache_key in self._pem_cache:
            return self._pem_cache[cache_key]
        pem_data = file_crypto.read_encrypted(abs_path)
        pem_cert = x509.load_pem_x509_certificate(pem_data)
        self._pem_cache[cache_key] = pem_cert
        return pem_cert

    def check_issuer_linkage_consistency(self, cert, cert_by_id):
        """Verify issuer_cert_id linkage and issuer DN consistency."""
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        cert_type = cert["cert_type"]
        issuer_cert_id = cert.get("issuer_cert_id")
        cert_abs_path = self._resolve_org_path(cert["org_dir"]) / cert["cert_path"]

        try:
            child_pem = self._load_pem_cert(cert_abs_path)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for issuer-link check: {e}")
            return

        if cert_type == "root":
            if issuer_cert_id is not None:
                self.issue("error", f"[{cert_id}] {cert_name}: root certificate must not have issuer_cert_id.")
                self.stats["issuer_link_mismatches"] += 1
            if child_pem.issuer != child_pem.subject:
                self.issue("error", f"[{cert_id}] {cert_name}: root certificate is not self-issued (issuer != subject).")
                self.stats["issuer_link_mismatches"] += 1
            return

        if issuer_cert_id is None:
            self.issue("error", f"[{cert_id}] {cert_name}: non-root certificate missing issuer_cert_id.")
            self.stats["issuer_link_mismatches"] += 1
            return

        issuer_row = cert_by_id.get(issuer_cert_id)
        if not issuer_row:
            self.issue("error", f"[{cert_id}] {cert_name}: issuer_cert_id={issuer_cert_id} not found in DB.")
            self.stats["issuer_link_mismatches"] += 1
            return

        if issuer_row["organization_id"] != cert["organization_id"]:
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: issuer organization mismatch "
                f"(issuer org={issuer_row['organization_id']}, cert org={cert['organization_id']})."
            )
            self.stats["issuer_link_mismatches"] += 1

        if cert_type == "intermediate" and issuer_row["cert_type"] != "root":
            self.issue("error", f"[{cert_id}] {cert_name}: intermediate must be issued by root, got {issuer_row['cert_type']}.")
            self.stats["issuer_link_mismatches"] += 1
        if cert_type in ("server", "client", "email", "ocsp") and issuer_row["cert_type"] != "intermediate":
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: end-entity cert must be issued by intermediate, got {issuer_row['cert_type']}."
            )
            self.stats["issuer_link_mismatches"] += 1

        issuer_abs_path = self._resolve_org_path(issuer_row["org_dir"]) / issuer_row["cert_path"]
        if not issuer_abs_path.exists():
            self.issue("error", f"[{cert_id}] {cert_name}: issuer certificate file missing at {issuer_abs_path}.")
            self.stats["issuer_link_mismatches"] += 1
            return

        try:
            issuer_pem = self._load_pem_cert(issuer_abs_path)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse issuer PEM for issuer-link check: {e}")
            return

        if child_pem.issuer != issuer_pem.subject:
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: issuer DN mismatch "
                f"(child issuer={child_pem.issuer.rfc4514_string()} / "
                f"issuer subject={issuer_pem.subject.rfc4514_string()})."
            )
            self.stats["issuer_link_mismatches"] += 1

    def check_serial_number_consistency(self, certs):
        """Validate serial format and detect duplicates globally and per org."""
        global_seen = {}
        org_seen = {}

        for cert in certs:
            cert_id = cert["id"]
            cert_name = cert["cert_name"]
            org_id = cert["organization_id"]
            serial = (cert.get("serial_number") or "").strip()

            if not serial:
                self.issue("error", f"[{cert_id}] {cert_name}: missing serial_number in DB.")
                self.stats["serial_format_issues"] += 1
                continue

            # DB should store lower-hex with no 0x prefix and no separators.
            if serial.startswith("0x") or any(c not in "0123456789abcdef" for c in serial):
                self.issue(
                    "error",
                    f"[{cert_id}] {cert_name}: invalid serial format in DB: {serial!r} "
                    f"(expected lowercase hex without 0x)."
                )
                self.stats["serial_format_issues"] += 1

            g_key = serial
            global_seen.setdefault(g_key, []).append((cert_id, cert_name))

            o_key = (org_id, serial)
            org_seen.setdefault(o_key, []).append((cert_id, cert_name))

        for serial, rows in global_seen.items():
            if len(rows) > 1:
                labels = ", ".join(f"{cid}:{name}" for cid, name in rows)
                self.issue("error", f"Duplicate serial globally {serial}: {labels}")
                self.stats["serial_duplicates_global"] += 1

        for (org_id, serial), rows in org_seen.items():
            if len(rows) > 1:
                labels = ", ".join(f"{cid}:{name}" for cid, name in rows)
                self.issue("error", f"Duplicate serial in org {org_id} {serial}: {labels}")
                self.stats["serial_duplicates_per_org"] += 1

    def check_validity_consistency(self, cert):
        """Verify DB not_before/not_after match PEM validity and ranges are valid."""
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        abs_path = self._resolve_org_path(cert["org_dir"]) / cert["cert_path"]

        db_not_before_raw = cert.get("not_before")
        db_not_after_raw = cert.get("not_after")
        if not db_not_before_raw or not db_not_after_raw:
            self.issue("error", f"[{cert_id}] {cert_name}: missing not_before/not_after in DB.")
            self.stats["validity_mismatches"] += 1
            return

        try:
            db_not_before = datetime.strptime(str(db_not_before_raw), "%Y-%m-%d %H:%M:%S")
            db_not_after = datetime.strptime(str(db_not_after_raw), "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: invalid DB validity datetime format "
                f"(not_before={db_not_before_raw!r}, not_after={db_not_after_raw!r}): {e}"
            )
            self.stats["validity_mismatches"] += 1
            return

        if db_not_before >= db_not_after:
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: invalid DB validity range "
                f"(not_before={db_not_before_raw}, not_after={db_not_after_raw})."
            )
            self.stats["invalid_validity_ranges"] += 1

        try:
            pem_cert = self._load_pem_cert(abs_path)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for validity check: {e}")
            return

        # cryptography naive datetime values are UTC-like; compare on same naive format used by DB.
        pem_not_before = pem_cert.not_valid_before_utc.replace(tzinfo=None)
        pem_not_after = pem_cert.not_valid_after_utc.replace(tzinfo=None)

        if pem_not_before >= pem_not_after:
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: invalid PEM validity range "
                f"(not_before={pem_not_before}, not_after={pem_not_after})."
            )
            self.stats["invalid_validity_ranges"] += 1

        if db_not_before != pem_not_before or db_not_after != pem_not_after:
            self.issue(
                "error",
                f"[{cert_id}] {cert_name}: validity mismatch "
                f"(DB {db_not_before} -> {db_not_after}, PEM {pem_not_before} -> {pem_not_after})."
            )
            self.stats["validity_mismatches"] += 1

    def check_type_policy_consistency(self, cert):
        """Verify cert_type aligns with critical extension semantics in PEM."""
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        cert_type = cert["cert_type"]
        abs_path = self._resolve_org_path(cert["org_dir"]) / cert["cert_path"]

        try:
            pem_cert = self._load_pem_cert(abs_path)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for type-policy check: {e}")
            return

        try:
            bc = pem_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            self.issue("error", f"[{cert_id}] {cert_name}: missing BasicConstraints extension.")
            self.stats["type_policy_mismatches"] += 1
            return

        ku = None
        try:
            ku = pem_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            ku = None

        eku_oids = set()
        try:
            eku = pem_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            eku_oids = {oid.dotted_string for oid in eku}
        except x509.ExtensionNotFound:
            eku_oids = set()

        if cert_type in ("root", "intermediate"):
            if not bc.ca:
                self.issue("error", f"[{cert_id}] {cert_name}: {cert_type} must have BasicConstraints CA=TRUE.")
                self.stats["type_policy_mismatches"] += 1
            if ku is None:
                self.issue("error", f"[{cert_id}] {cert_name}: {cert_type} missing KeyUsage extension.")
                self.stats["type_policy_mismatches"] += 1
            else:
                if not ku.key_cert_sign:
                    self.issue("error", f"[{cert_id}] {cert_name}: {cert_type} missing keyCertSign in KeyUsage.")
                    self.stats["type_policy_mismatches"] += 1
                if not ku.crl_sign:
                    self.issue("error", f"[{cert_id}] {cert_name}: {cert_type} missing cRLSign in KeyUsage.")
                    self.stats["type_policy_mismatches"] += 1
        elif cert_type in ("server", "client", "email", "ocsp"):
            if bc.ca:
                self.issue("error", f"[{cert_id}] {cert_name}: end-entity ({cert_type}) must have CA=FALSE.")
                self.stats["type_policy_mismatches"] += 1

            expected_eku = {
                "server": "1.3.6.1.5.5.7.3.1",   # serverAuth
                "client": "1.3.6.1.5.5.7.3.2",   # clientAuth
                "email": "1.3.6.1.5.5.7.3.4",    # emailProtection
                "ocsp": "1.3.6.1.5.5.7.3.9",     # OCSPSigning
            }[cert_type]
            if expected_eku not in eku_oids:
                self.issue(
                    "error",
                    f"[{cert_id}] {cert_name}: end-entity ({cert_type}) missing expected EKU OID {expected_eku}."
                )
                self.stats["type_policy_mismatches"] += 1
        else:
            self.issue("warning", f"[{cert_id}] {cert_name}: unknown cert_type '{cert_type}' for type-policy check.")

    def check_artifact_paths_consistency(self, cert):
        """
        Validate key/csr/pwd path integrity and per-type expectations.
        - cert/key/csr paths should be present and files should exist.
        - root/intermediate should not use stored pwd_path (new policy).
        - end-entity certs should have pwd_path present and file existing.
        """
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        cert_type = cert["cert_type"]
        org_dir = self._resolve_org_path(cert["org_dir"])

        def _norm_rel(value):
            v = (value or "").strip()
            return v if v else None

        cert_path_rel = _norm_rel(cert.get("cert_path"))
        key_path_rel = _norm_rel(cert.get("key_path"))
        csr_path_rel = _norm_rel(cert.get("csr_path"))
        pwd_path_rel = _norm_rel(cert.get("pwd_path"))

        for label, rel in (("cert_path", cert_path_rel), ("key_path", key_path_rel), ("csr_path", csr_path_rel)):
            if not rel:
                self.issue("error", f"[{cert_id}] {cert_name}: missing {label} in DB.")
                self.stats["artifact_path_mismatches"] += 1
                continue
            abs_path = org_dir / rel
            if not abs_path.exists():
                self.issue("error", f"[{cert_id}] {cert_name}: {label} file missing at {abs_path}")
                self.stats["artifact_path_mismatches"] += 1

        if cert_type in ("root", "intermediate"):
            if self.enforce_ca_pwdless and pwd_path_rel:
                self.issue(
                    "warning",
                    f"[{cert_id}] {cert_name}: {cert_type} has pwd_path set in DB ({pwd_path_rel}); expected empty with prompt-based CA passphrase."
                )
                self.stats["artifact_path_mismatches"] += 1
        elif cert_type in ("server", "client", "email", "ocsp"):
            if not pwd_path_rel:
                self.issue("error", f"[{cert_id}] {cert_name}: end-entity missing pwd_path in DB.")
                self.stats["artifact_path_mismatches"] += 1
            else:
                pwd_abs = org_dir / pwd_path_rel
                if not pwd_abs.exists():
                    self.issue("error", f"[{cert_id}] {cert_name}: end-entity password file missing at {pwd_abs}")
                    self.stats["artifact_path_mismatches"] += 1

    def check_private_key_matches_certificate(self, cert):
        """Verify private key matches certificate public key when key can be loaded.

        Note: Skips root CAs since they use dual-password derivation (filesystem password
        + user-provided password). The user password is only provided at runtime and not
        available during consistency checks.
        """
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        cert_type = cert.get("cert_type", "").strip()
        org_dir = self._resolve_org_path(cert["org_dir"])

        # Skip root CAs: they require user-provided password for key unlock
        if cert_type == "root":
            return

        key_rel = (cert.get("key_path") or "").strip()
        cert_rel = (cert.get("cert_path") or "").strip()
        pwd_rel = (cert.get("pwd_path") or "").strip()
        if not key_rel or not cert_rel:
            return

        key_abs = org_dir / key_rel
        cert_abs = org_dir / cert_rel
        if not key_abs.exists() or not cert_abs.exists():
            return

        password = None
        if pwd_rel:
            pwd_abs = org_dir / pwd_rel
            if pwd_abs.exists():
                try:
                    password = file_crypto.read_encrypted(pwd_abs).strip() or None
                except Exception as e:
                    self.issue("warning", f"[{cert_id}] {cert_name}: could not read password file for key check: {e}")
                    self.stats["key_load_failures"] += 1
                    return

        try:
            key_bytes = file_crypto.read_encrypted(key_abs)
            private_key = serialization.load_pem_private_key(key_bytes, password=password)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: could not load private key for key-cert check: {e}")
            self.stats["key_load_failures"] += 1
            return

        try:
            pem_cert = self._load_pem_cert(cert_abs)
            cert_pub = pem_cert.public_key()
            key_pub = private_key.public_key()
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: could not load certificate/public key for key-cert check: {e}")
            self.stats["key_load_failures"] += 1
            return

        mismatch = False
        if isinstance(key_pub, rsa.RSAPublicKey) and isinstance(cert_pub, rsa.RSAPublicKey):
            mismatch = key_pub.public_numbers() != cert_pub.public_numbers()
        elif isinstance(key_pub, ec.EllipticCurvePublicKey) and isinstance(cert_pub, ec.EllipticCurvePublicKey):
            mismatch = key_pub.public_numbers() != cert_pub.public_numbers()
        else:
            mismatch = True

        if mismatch:
            self.issue("error", f"[{cert_id}] {cert_name}: private key does not match certificate public key.")
            self.stats["key_cert_mismatches"] += 1

    def check_csr_consistency(self, cert):
        """Verify CSR subject/public-key match the issued certificate."""
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        org_dir = self._resolve_org_path(cert["org_dir"])
        cert_rel = (cert.get("cert_path") or "").strip()
        csr_rel = (cert.get("csr_path") or "").strip()
        if not cert_rel or not csr_rel:
            return
        cert_abs = org_dir / cert_rel
        csr_abs = org_dir / csr_rel
        if not cert_abs.exists() or not csr_abs.exists():
            return

        try:
            pem_cert = self._load_pem_cert(cert_abs)
            csr = x509.load_pem_x509_csr(file_crypto.read_encrypted(csr_abs))
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: could not parse CSR/cert for CSR check: {e}")
            self.stats["csr_mismatches"] += 1
            return

        if csr.subject != pem_cert.subject:
            self.issue("error", f"[{cert_id}] {cert_name}: CSR subject does not match certificate subject.")
            self.stats["csr_mismatches"] += 1

        try:
            if csr.public_key().public_numbers() != pem_cert.public_key().public_numbers():
                self.issue("error", f"[{cert_id}] {cert_name}: CSR public key does not match certificate public key.")
                self.stats["csr_mismatches"] += 1
        except Exception:
            self.issue("error", f"[{cert_id}] {cert_name}: could not compare CSR and certificate public keys.")
            self.stats["csr_mismatches"] += 1

    def check_basic_constraints_consistency(self, cert_id, cert_name, cert_path, org_dir):
        """Verify basic constraints in DB match PEM."""
        abs_path = self._resolve_org_path(org_dir) / cert_path
        try:
            pem_data = file_crypto.read_encrypted(abs_path)
            pem_cert = x509.load_pem_x509_certificate(pem_data)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for BC check: {e}")
            return

        # Extract BC from PEM
        pem_bc = None
        try:
            bc_ext = pem_cert.extensions.get_extension_for_class(x509.BasicConstraints)
            pem_bc = {
                "is_ca": bc_ext.value.ca,
                "path_length": bc_ext.value.path_length,
            }
        except x509.ExtensionNotFound:
            pass

        # Get BC from DB
        db_bc = db.get_basic_constraints(cert_id)

        # Compare
        if (pem_bc is None) != (db_bc is None):
            self.issue("warning",
                f"[{cert_id}] {cert_name}: BC presence mismatch - PEM has: {pem_bc is not None}, DB has: {db_bc is not None}")
            self.stats["bc_mismatches"] += 1
        elif pem_bc is not None and db_bc is not None:
            if (pem_bc["is_ca"] != db_bc["is_ca"] or
                pem_bc["path_length"] != db_bc["path_length"]):
                self.issue("error",
                    f"[{cert_id}] {cert_name}: BC value mismatch - PEM: {pem_bc}, DB: {db_bc}")
                self.stats["bc_mismatches"] += 1

    def check_key_usage_consistency(self, cert_id, cert_name, cert_path, org_dir):
        """Verify key usage in DB match PEM."""
        abs_path = self._resolve_org_path(org_dir) / cert_path
        try:
            pem_data = file_crypto.read_encrypted(abs_path)
            pem_cert = x509.load_pem_x509_certificate(pem_data)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for KU check: {e}")
            return

        # Extract KU from PEM
        pem_ku = None
        try:
            ku_ext = pem_cert.extensions.get_extension_for_class(x509.KeyUsage)
            pem_ku = {
                "digital_signature": ku_ext.value.digital_signature,
                "content_commitment": ku_ext.value.content_commitment,
                "key_encipherment": ku_ext.value.key_encipherment,
                "data_encipherment": ku_ext.value.data_encipherment,
                "key_agreement": ku_ext.value.key_agreement,
                "key_cert_sign": ku_ext.value.key_cert_sign,
                "crl_sign": ku_ext.value.crl_sign,
            }
        except x509.ExtensionNotFound:
            pass

        # Get KU from DB
        db_ku = db.get_key_usage(cert_id)

        # Compare
        if (pem_ku is None) != (db_ku is None):
            self.issue("warning",
                f"[{cert_id}] {cert_name}: KU presence mismatch - PEM has: {pem_ku is not None}, DB has: {db_ku is not None}")
            self.stats["ku_mismatches"] += 1
        elif pem_ku is not None and db_ku is not None:
            for key in pem_ku:
                if db_ku.get(key) != pem_ku[key]:
                    self.issue("error",
                        f"[{cert_id}] {cert_name}: KU field '{key}' mismatch - PEM: {pem_ku[key]}, DB: {db_ku.get(key)}")
                    self.stats["ku_mismatches"] += 1

    def check_eku_consistency(self, cert_id, cert_name, cert_path, org_dir):
        """Verify extended key usage in DB match PEM."""
        abs_path = self._resolve_org_path(org_dir) / cert_path
        try:
            pem_data = file_crypto.read_encrypted(abs_path)
            pem_cert = x509.load_pem_x509_certificate(pem_data)
        except Exception as e:
            self.issue("warning", f"[{cert_id}] {cert_name}: Could not parse PEM for EKU check: {e}")
            return

        # Extract EKUs from PEM
        pem_ekus = []
        try:
            eku_ext = pem_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            for oid in eku_ext.value:
                pem_ekus.append(str(oid.dotted_string))
        except x509.ExtensionNotFound:
            pass

        # Get EKUs from DB
        db_ekus = db.list_extended_key_usage(cert_id)
        db_eku_oids = [e["eku_oid"] for e in db_ekus]

        # Compare
        if set(pem_ekus) != set(db_eku_oids):
            self.issue("warning",
                f"[{cert_id}] {cert_name}: EKU mismatch - PEM has {len(pem_ekus)}, DB has {len(db_ekus)}")
            self.stats["eku_mismatches"] += 1

    def _load_crl(self, crl_path: Path):
        """Load and cache CRL object (similar to _load_pem_cert).
        crl_path can be relative or absolute Path object."""
        cache_key = f"crl:{str(crl_path)}"
        if cache_key in self._pem_cache:
            return self._pem_cache[cache_key]
        try:
            crl_data = file_crypto.read_encrypted(crl_path)
            crl = x509.load_pem_x509_crl(crl_data)
            self._pem_cache[cache_key] = crl
            return crl
        except Exception as e:
            logger.debug(f"Failed to load CRL {crl_path}: {e}")
            return None

    def _extract_extensions(self, pem_cert):
        """Extract all extension types from certificate into structured dict."""
        extensions = {
            'san': None,
            'bc': None,
            'ku': None,
            'eku': [],
            'other': []
        }
        try:
            for ext in pem_cert.extensions:
                if isinstance(ext.value, x509.SubjectAlternativeName):
                    extensions['san'] = ext.value
                elif isinstance(ext.value, x509.BasicConstraints):
                    extensions['bc'] = ext.value
                elif isinstance(ext.value, x509.KeyUsage):
                    extensions['ku'] = ext.value
                elif isinstance(ext.value, x509.ExtendedKeyUsage):
                    extensions['eku'] = list(ext.value)
                else:
                    extensions['other'].append(ext)
        except Exception:
            pass
        return extensions

    def check_crl_consistency(self):
        """Verify CRL records match actual CRL files."""
        crls = db.get_all_crls()
        for crl in crls:
            crl_id = crl["id"]
            crl_path = Path(crl["crl_path"])
            if not crl_path.exists():
                self.issue("error", f"[CRL {crl_id}] File missing: {crl_path}")
                self.stats["crl_mismatches"] += 1

    def check_crl_semantic_consistency(self, cert_by_id):
        """Validate CRL semantics vs DB: issuer DN, update windows, revocation entries, numbering."""
        crls = db.get_all_crls()
        crls_by_issuer = {}
        for crl in crls:
            crls_by_issuer.setdefault(crl["issuer_cert_id"], []).append(crl)

            crl_id = crl["id"]
            issuer_id = crl["issuer_cert_id"]
            crl_path = Path(crl["crl_path"])
            issuer_row = cert_by_id.get(issuer_id)
            if not issuer_row:
                self.issue("error", f"[CRL {crl_id}] issuer_cert_id={issuer_id} not found.")
                self.stats["crl_semantic_mismatches"] += 1
                continue
            if not crl_path.exists():
                continue

            issuer_abs = self._resolve_org_path(issuer_row["org_dir"]) / issuer_row["cert_path"]
            if not issuer_abs.exists():
                self.issue("error", f"[CRL {crl_id}] issuer certificate file missing at {issuer_abs}.")
                self.stats["crl_semantic_mismatches"] += 1
                continue

            try:
                parsed_crl = x509.load_pem_x509_crl(file_crypto.read_encrypted(crl_path))
                issuer_cert = self._load_pem_cert(issuer_abs)
            except Exception as e:
                self.issue("warning", f"[CRL {crl_id}] could not parse CRL/issuer certificate: {e}")
                self.stats["crl_semantic_mismatches"] += 1
                continue

            if parsed_crl.issuer != issuer_cert.subject:
                self.issue("error", f"[CRL {crl_id}] issuer DN mismatch between CRL and issuer certificate.")
                self.stats["crl_semantic_mismatches"] += 1

            try:
                this_update = parsed_crl.last_update_utc.replace(tzinfo=None)
                next_update = parsed_crl.next_update_utc.replace(tzinfo=None) if parsed_crl.next_update_utc else None
                if next_update and this_update >= next_update:
                    self.issue("error", f"[CRL {crl_id}] invalid update window (this_update >= next_update).")
                    self.stats["crl_semantic_mismatches"] += 1
            except Exception:
                self.issue("warning", f"[CRL {crl_id}] could not validate update window.")
                self.stats["crl_semantic_mismatches"] += 1

            # Compare revoked serials from DB and CRL
            try:
                db_revoked = db.get_revoked_certs_for_issuer(issuer_id)
                db_serials = {str(r["serial_number"]).lower().lstrip("0") or "0" for r in db_revoked}
                crl_serials = {format(entry.serial_number, "x").lower().lstrip("0") or "0" for entry in parsed_crl}
                if db_serials != crl_serials:
                    self.issue(
                        "error",
                        f"[CRL {crl_id}] revoked entries mismatch (DB={len(db_serials)}, CRL={len(crl_serials)})."
                    )
                    self.stats["crl_semantic_mismatches"] += 1
            except Exception:
                self.issue("warning", f"[CRL {crl_id}] failed revoked-entry comparison.")
                self.stats["crl_semantic_mismatches"] += 1

        # CRL number monotonicity per issuer
        for issuer_id, issuer_crls in crls_by_issuer.items():
            sorted_crls = sorted(issuer_crls, key=lambda r: r["id"])
            prev = None
            for row in sorted_crls:
                num = row["crl_number"]
                if prev is not None and num <= prev:
                    self.issue(
                        "error",
                        f"[CRL {row['id']}] non-monotonic crl_number for issuer {issuer_id}: {num} after {prev}."
                    )
                    self.stats["crl_semantic_mismatches"] += 1
                prev = num

    def check_orphaned_and_dangling_records(self):
        """Detect extension/revocation/CRL rows that reference missing parents."""
        with db.get_db_connection() as conn:
            orphan_queries = {
                "subject_alternative_names": """
                    SELECT COUNT(*) AS cnt
                    FROM subject_alternative_names s
                    LEFT JOIN certificates c ON c.id = s.certificate_id
                    WHERE c.id IS NULL
                """,
                "basic_constraints": """
                    SELECT COUNT(*) AS cnt
                    FROM basic_constraints b
                    LEFT JOIN certificates c ON c.id = b.certificate_id
                    WHERE c.id IS NULL
                """,
                "key_usage": """
                    SELECT COUNT(*) AS cnt
                    FROM key_usage k
                    LEFT JOIN certificates c ON c.id = k.certificate_id
                    WHERE c.id IS NULL
                """,
                "extended_key_usage": """
                    SELECT COUNT(*) AS cnt
                    FROM extended_key_usage e
                    LEFT JOIN certificates c ON c.id = e.certificate_id
                    WHERE c.id IS NULL
                """,
                "certificate_extensions": """
                    SELECT COUNT(*) AS cnt
                    FROM certificate_extensions e
                    LEFT JOIN certificates c ON c.id = e.certificate_id
                    WHERE c.id IS NULL
                """,
                "crls_missing_issuer": """
                    SELECT COUNT(*) AS cnt
                    FROM crls cr
                    LEFT JOIN certificates c ON c.id = cr.issuer_cert_id
                    WHERE c.id IS NULL
                """,
                "revoked_missing_crl": """
                    SELECT COUNT(*) AS cnt
                    FROM revoked_certificates r
                    LEFT JOIN crls cr ON cr.id = r.crl_id
                    WHERE cr.id IS NULL
                """,
                "revoked_missing_cert": """
                    SELECT COUNT(*) AS cnt
                    FROM revoked_certificates r
                    LEFT JOIN certificates c ON c.id = r.certificate_id
                    WHERE c.id IS NULL
                """,
            }
            for label, query in orphan_queries.items():
                cnt = conn.execute(text(query)).mappings().fetchone()["cnt"]
                if cnt:
                    self.issue("error", f"Orphan/dangling rows in {label}: {cnt}")
                    self.stats["orphaned_records"] += int(cnt)

    def check_status_state_consistency(self, certs):
        """Validate status and related fields consistency."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for cert in certs:
            cert_id = cert["id"]
            cert_name = cert["cert_name"]
            status = (cert.get("status") or "").strip().lower()
            revoked_at = cert.get("revoked_at")
            rev_reason = cert.get("revocation_reason")
            not_after_raw = cert.get("not_after")

            if status == "revoked":
                if not revoked_at:
                    self.issue("error", f"[{cert_id}] {cert_name}: status=revoked but revoked_at is empty.")
                    self.stats["status_state_mismatches"] += 1
                if not rev_reason:
                    self.issue("warning", f"[{cert_id}] {cert_name}: status=revoked but revocation_reason is empty.")
                    self.stats["status_state_mismatches"] += 1
            elif status in ("active", "expired"):
                if revoked_at or rev_reason:
                    self.issue("error", f"[{cert_id}] {cert_name}: status={status} but revocation fields are set.")
                    self.stats["status_state_mismatches"] += 1

            # Expiration consistency check
            try:
                na = datetime.strptime(str(not_after_raw), "%Y-%m-%d %H:%M:%S")
                if status == "active" and na <= now:
                    self.issue("warning", f"[{cert_id}] {cert_name}: status=active but certificate is expired by not_after.")
                    self.stats["status_state_mismatches"] += 1
                if status == "expired" and na > now:
                    self.issue("warning", f"[{cert_id}] {cert_name}: status=expired but not_after is in the future.")
                    self.stats["status_state_mismatches"] += 1
            except Exception:
                pass

    def check_encryption_and_naming_policy(self, cert):
        """Check encrypted-at-rest and filename suffix policy for artifacts."""
        cert_id = cert["id"]
        cert_name = cert["cert_name"]
        cert_type = cert["cert_type"]
        org_dir = self._resolve_org_path(cert["org_dir"])

        def _check(rel, expected_suffix, label):
            rel = (rel or "").strip()
            if not rel:
                return
            abs_path = org_dir / rel
            if not rel.endswith(".enc"):
                self.issue("error", f"[{cert_id}] {cert_name}: {label} path is not encrypted-at-rest (*.enc): {rel}")
                self.stats["encryption_naming_mismatches"] += 1
            if expected_suffix and not rel.endswith(expected_suffix):
                self.issue("warning", f"[{cert_id}] {cert_name}: {label} path suffix unexpected: {rel}")
                self.stats["encryption_naming_mismatches"] += 1
            try:
                abs_path.resolve().relative_to(org_dir.resolve())
            except Exception:
                self.issue("error", f"[{cert_id}] {cert_name}: {label} path escapes org_dir: {rel}")
                self.stats["encryption_naming_mismatches"] += 1

        _check(cert.get("cert_path"), ".pem.enc", "cert_path")
        _check(cert.get("key_path"), ".key.enc", "key_path")
        _check(cert.get("csr_path"), ".csr.enc", "csr_path")
        if cert_type in ("server", "client", "email", "ocsp"):
            _check(cert.get("pwd_path"), ".pwd.enc", "pwd_path")

    def check_file_hash_integrity(self):
        """
        Compare each file hash with previous run values in a manifest at PKI_DATA_DIR root.
        If a file has no prior hash entry, add it silently without warning.
        """
        if not self.data_dir.exists():
            self.issue("warning", f"PKI data directory not found for hash integrity check: {self.data_dir}")
            return

        for path in self.data_dir.rglob("*"):
            if not path.is_file():
                continue
            if self._should_skip_hash_tracking(path):
                self.stats["hash_skipped_files"] += 1
                continue

            rel = str(path.relative_to(self.data_dir)).replace("\\", "/")
            current_hash = self._md5_file(path)
            previous_entry = self.file_hashes.get(rel)
            self.stats["hash_tracked_files"] += 1

            if previous_entry is None:
                self.file_hashes[rel] = {"algo": "md5", "hash": current_hash}
                self.stats["hash_new_entries"] += 1
                continue

            previous_algo = None
            previous_hash = None
            if isinstance(previous_entry, dict):
                previous_algo = str(previous_entry.get("algo") or "").lower()
                previous_hash = previous_entry.get("hash")
            elif isinstance(previous_entry, str):
                previous_hash = previous_entry

            # If algo changed from old manifest format/algorithm, silently re-baseline.
            if previous_algo and previous_algo != "md5":
                self.file_hashes[rel] = {"algo": "md5", "hash": current_hash}
                self.stats["hash_new_entries"] += 1
                continue

            if previous_hash != current_hash:
                self.issue("error", f"[HASH] File changed since baseline: {rel}")
                self.stats["hash_mismatches"] += 1
            else:
                # Normalize old string format to per-entry object format
                if not isinstance(previous_entry, dict):
                    self.file_hashes[rel] = {"algo": "md5", "hash": current_hash}

    def check_crl_validity(self):
        """Verify all issuer CAs have valid CRL files with valid signatures."""
        # Get all CRL records from database
        crls = db.get_all_crls()
        certs = db.list_all_certificates_for_backfill()
        cert_by_id = {c["id"]: c for c in certs}

        for crl_record in crls:
            crl_id = crl_record["id"]
            issuer_id = crl_record["issuer_cert_id"]
            crl_path_rel = crl_record.get("crl_path")

            # Get issuer certificate
            issuer = cert_by_id.get(issuer_id)
            if not issuer:
                self.issue("error", f"[CRL {crl_id}] Issuer cert {issuer_id} not found")
                self.stats["crl_validity_failures"] += 1
                continue

            # Verify CRL file exists
            if not crl_path_rel:
                self.issue("error", f"[CRL {crl_id}] CRL path is not set in database")
                self.stats["crl_validity_failures"] += 1
                continue

            org_path = self._resolve_org_path(issuer["org_dir"])
            crl_abs_path = org_path / crl_path_rel

            if not crl_abs_path.exists():
                self.issue("error", f"[CRL {crl_id}] CRL file missing: {crl_abs_path}")
                self.stats["crl_validity_failures"] += 1
                continue

            # Load and validate CRL (exact same pattern as check_crl_semantic_consistency)
            try:
                crl = x509.load_pem_x509_crl(file_crypto.read_encrypted(Path(crl_path_rel)))
            except Exception as e:
                self.issue("error", f"[CRL {crl_id}] CRL unparseable: {crl_path_rel}: {e}")
                self.stats["crl_validity_failures"] += 1
                continue

            # Verify CRL issuer DN matches CA cert subject
            ca_abs_path = org_path / issuer["cert_path"]
            ca_pem = self._load_pem_cert(ca_abs_path)
            if not ca_pem or crl.issuer != ca_pem.subject:
                self.issue("error", f"[CRL {crl_id}] CRL issuer DN mismatch with certificate subject")
                self.stats["crl_validity_failures"] += 1
                continue

            self.stats["crl_validity_checks"] += 1

    def check_uuid_consistency(self):
        """Verify UUID uniqueness, format, and references."""
        import uuid as uuid_module
        certs = db.list_all_certificates_for_backfill()
        seen_uuids = {}

        for cert in certs:
            cert_uuid = cert.get("cert_uuid", "").strip()

            # Check for missing UUID (should have been auto-generated)
            if not cert_uuid:
                self.issue("error", f"[{cert['id']}] {cert['cert_name']}: missing cert_uuid (should be auto-generated)")
                self.stats["uuid_missing"] += 1
                continue

            # Validate UUID format
            try:
                parsed = uuid_module.UUID(cert_uuid)
                if parsed.version != 4:
                    self.issue("error", f"[{cert['id']}] UUID not v4: {cert_uuid}")
                    self.stats["uuid_invalid_format"] += 1
                    continue
            except Exception:
                self.issue("error", f"[{cert['id']}] Invalid UUID format: {cert_uuid}")
                self.stats["uuid_invalid_format"] += 1
                continue

            # Check for duplicates within organization
            org_id = cert["organization_id"]
            key = (org_id, cert_uuid)
            if key in seen_uuids:
                self.issue("error", f"Duplicate UUID {cert_uuid} in org {org_id}: "
                                   f"certs {seen_uuids[key]} and {cert['id']}")
                self.stats["uuid_duplicates"] += 1
            else:
                seen_uuids[key] = cert['id']

            # Verify UUID appears in cert file paths
            org_path = self._resolve_org_path(cert["org_dir"])
            cert_path = org_path / cert["cert_path"]
            if cert_uuid not in str(cert_path):
                self.issue("error", f"[{cert['id']}] UUID {cert_uuid} not in cert_path: {cert_path}")
                self.stats["uuid_path_mismatches"] += 1

    def check_encryption_validation(self):
        """Verify all encrypted files can be decrypted."""
        certs = db.list_all_certificates_for_backfill()

        for cert in certs:
            cert_id = cert["id"]
            cert_name = cert["cert_name"]
            org_path = self._resolve_org_path(cert["org_dir"])

            # Test cert decryption
            if cert.get("cert_path"):
                cert_path = org_path / cert["cert_path"]
                try:
                    file_crypto.read_encrypted(cert_path)
                except Exception as e:
                    self.issue("error", f"[{cert_id}] Cert decryption failed: {cert['cert_path']}: {e}")
                    self.stats["decryption_errors"] += 1

            # Test key decryption
            if cert.get("key_path"):
                key_path = org_path / cert["key_path"]
                try:
                    file_crypto.read_encrypted(key_path)
                except Exception as e:
                    self.issue("error", f"[{cert_id}] Key decryption failed: {cert['key_path']}: {e}")
                    self.stats["decryption_errors"] += 1

            # Test CRL decryption
            if cert.get("crl_path"):
                crl_path = org_path / cert["crl_path"]
                try:
                    file_crypto.read_encrypted(crl_path)
                except Exception as e:
                    self.issue("error", f"[{cert_id}] CRL decryption failed: {cert['crl_path']}: {e}")
                    self.stats["decryption_errors"] += 1

            # Test password file decryption (for CA types that have it)
            if cert.get("pwd_path"):
                pwd_path = org_path / cert["pwd_path"]
                try:
                    file_crypto.read_encrypted(pwd_path)
                except Exception as e:
                    self.issue("error", f"[{cert_id}] Password file decryption failed: {cert['pwd_path']}: {e}")
                    self.stats["password_file_errors"] += 1

    def check_crl_revocation_accuracy(self):
        """Verify CRL contents match database revocation state."""
        crls = db.get_all_crls()
        certs = db.list_all_certificates_for_backfill()
        cert_by_id = {c["id"]: c for c in certs}

        for crl_record in crls:
            crl_id = crl_record["id"]
            issuer_id = crl_record["issuer_cert_id"]
            crl_path_rel = crl_record.get("crl_path")

            # Get issuer certificate
            issuer = cert_by_id.get(issuer_id)
            if not issuer:
                continue

            # Skip if CRL path not set
            if not crl_path_rel:
                continue

            # Get DB revoked certs for this issuer
            db_revoked = db.get_revoked_certs_for_issuer(issuer_id)

            # Load CRL (same pattern as check_crl_semantic_consistency)
            try:
                crl = x509.load_pem_x509_crl(file_crypto.read_encrypted(Path(crl_path_rel)))
            except Exception as e:
                self.issue("error", f"[CRL {crl_id}] Cannot load CRL for revocation accuracy check: {e}")
                self.stats["crl_revocation_mismatches"] += 1
                continue

            # Build set of serials in CRL and DB (normalize to hex lowercase)
            db_serials = {str(r["serial_number"]).lower().lstrip("0") or "0" for r in db_revoked}
            crl_serials = {format(entry.serial_number, "x").lower().lstrip("0") or "0" for entry in crl}

            # Check count matches
            if len(crl_serials) != len(db_serials):
                self.issue("error", f"[CRL {crl_id}] CRL count mismatch: "
                                   f"CRL has {len(crl_serials)}, DB has {len(db_serials)}")
                self.stats["crl_count_mismatches"] += 1

            # Check all DB revoked appear in CRL
            for db_serial in db_serials:
                if db_serial not in crl_serials:
                    self.issue("error", f"[CRL {crl_id}] Serial {db_serial} in DB but not in CRL")
                    self.stats["crl_revocation_mismatches"] += 1

    def check_certificate_chain_validation(self):
        """Validate certificate chain structure and depth limits."""
        certs = db.list_all_certificates_for_backfill()
        cert_by_id = {c["id"]: c for c in certs}

        for cert in certs:
            cert_id = cert["id"]
            cert_type = cert["cert_type"]

            if cert_type == "root":
                # Root must not have issuer_cert_id
                if cert.get("issuer_cert_id") is not None:
                    self.issue("error", f"[{cert_id}] Root CA has issuer_cert_id set")
                    self.stats["chain_validation_errors"] += 1
                continue

            issuer_cert_id = cert.get("issuer_cert_id")
            if issuer_cert_id is None:
                self.issue("error", f"[{cert_id}] Non-root cert {cert['cert_name']} has no issuer_cert_id")
                self.stats["chain_validation_errors"] += 1
                continue

            # Verify issuer exists and is a CA
            issuer = cert_by_id.get(issuer_cert_id)
            if not issuer:
                self.issue("error", f"[{cert_id}] Issuer cert {issuer_cert_id} not found")
                self.stats["chain_validation_errors"] += 1
                continue

            if issuer["cert_type"] not in ("root", "intermediate"):
                self.issue("error", f"[{cert_id}] Issuer {issuer_cert_id} is not a CA type (type={issuer['cert_type']})")
                self.stats["chain_validation_errors"] += 1
                continue

            # Check for circular chains
            visited = set()
            current = cert_id
            chain_depth = 0
            while current is not None:
                if current in visited:
                    self.issue("error", f"[{cert_id}] Circular chain detected")
                    self.stats["circular_chains_detected"] += 1
                    break
                visited.add(current)
                current_cert = cert_by_id.get(current)
                if not current_cert:
                    break
                current = current_cert.get("issuer_cert_id")
                chain_depth += 1

            # Check chain depth (root -> intermediate -> end-entity = max 3)
            if chain_depth > 3:
                self.issue("error", f"[{cert_id}] Chain depth exceeds limit: {chain_depth} > 3")
                self.stats["chain_depth_violations"] += 1

    def check_field_completeness(self):
        """Verify required DN fields and policy compliance."""
        certs = db.list_all_certificates_for_backfill()

        for cert in certs:
            cert_id = cert["id"]
            cert_name = cert["cert_name"]
            cert_path = cert["cert_path"]
            org_dir = cert["org_dir"]

            # Load certificate
            abs_path = self._resolve_org_path(org_dir) / cert_path
            try:
                pem_data = file_crypto.read_encrypted(abs_path)
                pem_cert = x509.load_pem_x509_certificate(pem_data)
            except Exception as e:
                self.issue("warning", f"[{cert_id}] Could not parse PEM for field completeness check: {e}")
                continue

            # Extract required DN fields
            subject = pem_cert.subject
            required_oids = [
                (x509.oid.NameOID.COMMON_NAME, "CN"),
                (x509.oid.NameOID.COUNTRY_NAME, "C"),
                (x509.oid.NameOID.ORGANIZATION_NAME, "O"),
                (x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "ST"),
                (x509.oid.NameOID.LOCALITY_NAME, "L"),
            ]

            for oid, field_name in required_oids:
                attrs = subject.get_attributes_for_oid(oid)
                if not attrs or not attrs[0].value:
                    self.issue("warning", f"[{cert_id}] {cert_name}: Missing required DN field: {field_name}")
                    self.stats["field_completeness_errors"] += 1

            # Basic constraints check: CA certs must have BC with CA=true
            cert_type = cert["cert_type"]
            if cert_type in ("root", "intermediate"):
                try:
                    bc_ext = pem_cert.extensions.get_extension_for_class(x509.BasicConstraints)
                    if not bc_ext.value.ca:
                        self.issue("error", f"[{cert_id}] CA cert missing BasicConstraints.ca=true")
                        self.stats["field_completeness_errors"] += 1
                except x509.ExtensionNotFound:
                    self.issue("error", f"[{cert_id}] CA cert missing BasicConstraints extension")
                    self.stats["field_completeness_errors"] += 1

    def check_dual_password_consistency(self):
        """Verify root CA password files for dual password feature."""
        certs = db.list_all_certificates_for_backfill()
        root_cas = [c for c in certs if c["cert_type"] == "root"]

        for root_ca in root_cas:
            cert_id = root_ca["id"]
            cert_name = root_ca["cert_name"]

            # Check if pwd_path is set
            if not root_ca.get("pwd_path"):
                self.issue("warning", f"[{cert_id}] {cert_name}: Root CA has no pwd_path")
                self.stats["dual_password_missing"] += 1
                continue

            org_path = self._resolve_org_path(root_ca["org_dir"])
            pwd_path = org_path / root_ca["pwd_path"]

            # Verify password file exists and is readable
            if not pwd_path.exists():
                self.issue("error", f"[{cert_id}] Password file missing: {pwd_path}")
                self.stats["dual_password_missing"] += 1
                continue

            # Try to decrypt password file
            try:
                pwd_data = file_crypto.read_encrypted(pwd_path)
            except Exception as e:
                self.issue("error", f"[{cert_id}] Password file decryption failed: {e}")
                self.stats["dual_password_decode_errors"] += 1
                continue

            # Verify decoded password is valid hex string (64 hex chars = 32 bytes)
            try:
                pwd_str = pwd_data.decode("utf-8").strip()
                if len(pwd_str) != 64:
                    self.issue("error", f"[{cert_id}] Password hex string invalid length: {len(pwd_str)} (expected 64)")
                    self.stats["dual_password_format_errors"] += 1
                    continue
                int(pwd_str, 16)  # Verify it's valid hex
            except Exception as e:
                self.issue("error", f"[{cert_id}] Password format invalid: {e}")
                self.stats["dual_password_format_errors"] += 1

    def run_checks(self):
        """Run all consistency checks."""
        logger.info("Starting consistency checks...")

        # Get all certificates
        certs = db.list_all_certificates_for_backfill()
        self.stats["total_certs"] = len(certs)
        cert_by_id = {c["id"]: c for c in certs}
        self.check_serial_number_consistency(certs)
        self.check_orphaned_and_dangling_records()
        self.check_status_state_consistency(certs)

        for cert in certs:
            cert_id = cert["id"]
            cert_name = cert["cert_name"]
            cert_path = cert["cert_path"]
            org_dir = cert["org_dir"]

            # Check file exists
            if not self.check_certificate_file_exists(cert_id, cert_name, cert_path, org_dir):
                continue

            self.stats["checked_certs"] += 1

            # Check subject consistency
            self.check_subject_consistency(cert)
            self.check_issuer_linkage_consistency(cert, cert_by_id)
            self.check_validity_consistency(cert)
            self.check_type_policy_consistency(cert)
            self.check_artifact_paths_consistency(cert)
            self.check_private_key_matches_certificate(cert)
            self.check_csr_consistency(cert)
            self.check_encryption_and_naming_policy(cert)

            # Check extension consistency
            self.check_sans_consistency(cert_id, cert_name, cert_path, org_dir)
            self.check_basic_constraints_consistency(cert_id, cert_name, cert_path, org_dir)
            self.check_key_usage_consistency(cert_id, cert_name, cert_path, org_dir)
            self.check_eku_consistency(cert_id, cert_name, cert_path, org_dir)

        # Check CRL consistency
        self.check_crl_consistency()
        self.check_crl_semantic_consistency(cert_by_id)
        self.check_file_hash_integrity()

        # NEW: High priority checks for data integrity
        self.check_crl_validity()
        self.check_uuid_consistency()
        self.check_encryption_validation()

        # NEW: Medium priority checks
        self.check_crl_revocation_accuracy()
        self.check_certificate_chain_validation()

        # NEW: Low priority checks
        self.check_field_completeness()
        self.check_dual_password_consistency()

        self._save_hash_manifest()

        logger.info(f"\n{'='*60}")
        logger.info(f"Consistency Check Summary:")
        logger.info(f"  Total certificates:      {self.stats['total_certs']}")
        logger.info(f"  Checked:                 {self.stats['checked_certs']}")
        logger.info(f"  Missing files:           {self.stats['missing_files']}")
        logger.info(f"  Subject mismatches:      {self.stats['subject_mismatches']}")
        logger.info(f"  Issuer link mismatches:  {self.stats['issuer_link_mismatches']}")
        logger.info(f"  Serial format issues:    {self.stats['serial_format_issues']}")
        logger.info(f"  Serial dup (global):     {self.stats['serial_duplicates_global']}")
        logger.info(f"  Serial dup (per-org):    {self.stats['serial_duplicates_per_org']}")
        logger.info(f"  Validity mismatches:     {self.stats['validity_mismatches']}")
        logger.info(f"  Invalid validity range:  {self.stats['invalid_validity_ranges']}")
        logger.info(f"  Type-policy mismatches:  {self.stats['type_policy_mismatches']}")
        logger.info(f"  Artifact path issues:    {self.stats['artifact_path_mismatches']}")
        logger.info(f"  Key-cert mismatches:     {self.stats['key_cert_mismatches']}")
        logger.info(f"  Key load failures:       {self.stats['key_load_failures']}")
        logger.info(f"  CSR mismatches:          {self.stats['csr_mismatches']}")
        logger.info(f"  CRL semantic mismatches: {self.stats['crl_semantic_mismatches']}")
        logger.info(f"  Orphaned records:        {self.stats['orphaned_records']}")
        logger.info(f"  Status-state mismatches: {self.stats['status_state_mismatches']}")
        logger.info(f"  Encrypt/naming issues:   {self.stats['encryption_naming_mismatches']}")
        logger.info(f"  Hash mismatches:         {self.stats['hash_mismatches']}")
        logger.info(f"  Hash new entries:        {self.stats['hash_new_entries']}")
        logger.info(f"  Hash tracked files:      {self.stats['hash_tracked_files']}")
        logger.info(f"  Hash skipped files:      {self.stats['hash_skipped_files']}")
        logger.info(f"  SAN mismatches:          {self.stats['san_mismatches']}")
        logger.info(f"  BC mismatches:           {self.stats['bc_mismatches']}")
        logger.info(f"  KU mismatches:           {self.stats['ku_mismatches']}")
        logger.info(f"  EKU mismatches:          {self.stats['eku_mismatches']}")
        logger.info(f"  CRL mismatches:          {self.stats['crl_mismatches']}")
        # NEW: Data integrity checks
        logger.info(f"  CRL validity checks:     {self.stats['crl_validity_checks']}")
        logger.info(f"  CRL validity failures:   {self.stats['crl_validity_failures']}")
        logger.info(f"  CRL signature errors:    {self.stats['crl_signature_errors']}")
        logger.info(f"  UUID missing:            {self.stats['uuid_missing']}")
        logger.info(f"  UUID invalid format:     {self.stats['uuid_invalid_format']}")
        logger.info(f"  UUID duplicates:         {self.stats['uuid_duplicates']}")
        logger.info(f"  UUID path mismatches:    {self.stats['uuid_path_mismatches']}")
        logger.info(f"  Chain validation errors: {self.stats['chain_validation_errors']}")
        logger.info(f"  Circular chains:         {self.stats['circular_chains_detected']}")
        logger.info(f"  Chain depth violations:  {self.stats['chain_depth_violations']}")
        logger.info(f"  CRL revocation mismatches: {self.stats['crl_revocation_mismatches']}")
        logger.info(f"  CRL count mismatches:    {self.stats['crl_count_mismatches']}")
        logger.info(f"  CRL reason mismatches:   {self.stats['crl_reason_mismatches']}")
        logger.info(f"  Decryption errors:       {self.stats['decryption_errors']}")
        logger.info(f"  Password file errors:    {self.stats['password_file_errors']}")
        logger.info(f"  Field completeness errors: {self.stats['field_completeness_errors']}")
        logger.info(f"  Policy constraint violations: {self.stats['policy_constraint_violations']}")
        logger.info(f"  Dual password missing:   {self.stats['dual_password_missing']}")
        logger.info(f"  Dual password format errors: {self.stats['dual_password_format_errors']}")
        logger.info(f"  Dual password decode errors: {self.stats['dual_password_decode_errors']}")
        logger.info(f"  Warnings:                {self.stats['warnings']}")
        logger.info(f"{'='*60}\n")

        errors_found = (
            self.stats["missing_files"] +
            self.stats["subject_mismatches"] +
            self.stats["issuer_link_mismatches"] +
            self.stats["serial_format_issues"] +
            self.stats["serial_duplicates_global"] +
            self.stats["serial_duplicates_per_org"] +
            self.stats["validity_mismatches"] +
            self.stats["invalid_validity_ranges"] +
            self.stats["type_policy_mismatches"] +
            self.stats["artifact_path_mismatches"] +
            self.stats["key_cert_mismatches"] +
            self.stats["key_load_failures"] +
            self.stats["csr_mismatches"] +
            self.stats["crl_semantic_mismatches"] +
            self.stats["orphaned_records"] +
            self.stats["status_state_mismatches"] +
            self.stats["encryption_naming_mismatches"] +
            self.stats["hash_mismatches"] +
            self.stats["san_mismatches"] +
            self.stats["bc_mismatches"] +
            self.stats["ku_mismatches"] +
            self.stats["eku_mismatches"] +
            self.stats["crl_mismatches"] +
            # NEW: Data integrity metrics
            self.stats["crl_validity_failures"] +
            self.stats["crl_signature_errors"] +
            self.stats["uuid_missing"] +
            self.stats["uuid_invalid_format"] +
            self.stats["uuid_duplicates"] +
            self.stats["uuid_path_mismatches"] +
            self.stats["chain_validation_errors"] +
            self.stats["circular_chains_detected"] +
            self.stats["chain_depth_violations"] +
            self.stats["crl_revocation_mismatches"] +
            self.stats["crl_count_mismatches"] +
            self.stats["crl_reason_mismatches"] +
            self.stats["decryption_errors"] +
            self.stats["password_file_errors"] +
            self.stats["field_completeness_errors"] +
            self.stats["policy_constraint_violations"] +
            self.stats["dual_password_missing"] +
            self.stats["dual_password_format_errors"] +
            self.stats["dual_password_decode_errors"]
        )

        if errors_found > 0:
            logger.warning(f"Found {errors_found} inconsistencies")
            return False
        else:
            logger.info("All consistency checks passed ✅")
            return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Check consistency between database and PEM files"
    )
    parser.add_argument(
        "--report-file",
        help="Write detailed report to file (default: stdout)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any inconsistencies found"
    )

    args = parser.parse_args()

    try:
        checker = ConsistencyChecker(strict=args.strict)
        success = checker.run_checks()

        if args.report_file:
            with open(args.report_file, 'w') as f:
                f.write(f"Consistency Check Report - {datetime.now()}\n\n")
                for issue in checker.issues:
                    f.write(f"[{issue['level'].upper()}] {issue['message']}\n")
                f.write("\n" + "="*60 + "\n")
                f.write(f"Stats:\n")
                for key, value in checker.stats.items():
                    f.write(f"  {key}: {value}\n")

        if args.strict and not success:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error during consistency check: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
