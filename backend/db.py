"""
Database module for PKI Management System
Handles all database operations for organizations, certificates, and related entities
"""

import sqlite3
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from contextlib import contextmanager
import logging
from datetime import timezone

from sqlalchemy import create_engine, text, event
from sqlalchemy.exc import IntegrityError as SAIntegrityError

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

import file_crypto
if __package__:
    from .path_config import get_project_root, get_db_path, get_schema_path
else:
    from path_config import get_project_root, get_db_path, get_schema_path

logger = logging.getLogger(__name__)

PROJECT_ROOT = get_project_root()

# Database file path
DB_PATH = get_db_path()
SCHEMA_PATH = get_schema_path()

# Schema version this codebase expects
SCHEMA_VERSION = 1

# SQLAlchemy Engine singleton
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)

# Enable WAL mode and foreign keys for every new connection
@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _):
    dbapi_conn.execute("PRAGMA journal_mode=WAL")
    dbapi_conn.execute("PRAGMA foreign_keys=ON")


def _validate_schema_version(conn) -> None:
    """
    Check that the schema_version table exists and matches SCHEMA_VERSION.
    Raises RuntimeError on mismatch or missing table.
    Called for existing DBs only (not during fresh creation).
    conn: a SQLAlchemy connection (inside engine.begin() context).
    """
    result = conn.execute(
        text(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='schema_version'"
        )
    )
    if not result.fetchone():
        raise RuntimeError(
            "schema_version table is missing. Re-initialize the database from "
            "database/pki_schema.sql to continue."
        )
    row = conn.execute(
        text("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1")
    ).fetchone()
    if row is None:
        raise RuntimeError("schema_version table is empty. Database may be corrupt.")
    if row[0] != SCHEMA_VERSION:
        raise RuntimeError(
            f"Schema version mismatch: database is at version {row[0]}, "
            f"but this codebase expects version {SCHEMA_VERSION}."
        )


REQUIRED_TABLES = {
    "organizations", "certificates", "subject_alternative_names",
    "certificate_extensions", "basic_constraints", "key_usage",
    "extended_key_usage", "crls", "revoked_certificates",
    "certificate_audit_log", "schema_version",
}

REQUIRED_INDEXES = {
    "idx_certs_org", "idx_certs_issuer", "idx_certs_type", "idx_certs_status",
    "idx_certs_not_after", "idx_certs_serial", "idx_san_cert", "idx_ext_cert",
    "idx_audit_cert", "idx_audit_timestamp",
}


def validate_database_integrity() -> list[str]:
    """
    Run structural integrity checks on the database.

    Checks:
    1. PRAGMA foreign_keys is ON (== 1)
    2. PRAGMA journal_mode is WAL
    3. Schema version matches SCHEMA_VERSION
    4. All required tables exist
    5. All required indexes exist

    Returns:
        List of issue description strings. Empty list means healthy.
    """
    issues: list[str] = []

    with engine.connect() as conn:
        # 1. Foreign key enforcement
        fk_row = conn.execute(text("PRAGMA foreign_keys")).fetchone()
        if fk_row is None or fk_row[0] != 1:
            issues.append(
                f"PRAGMA foreign_keys is not ON (got: {fk_row[0] if fk_row else None})"
            )

        # 2. WAL mode
        wal_row = conn.execute(text("PRAGMA journal_mode")).fetchone()
        if wal_row is None or wal_row[0].lower() != "wal":
            issues.append(
                f"PRAGMA journal_mode is not WAL (got: {wal_row[0] if wal_row else None})"
            )

        # 3. Schema version
        try:
            sv_row = conn.execute(
                text("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1")
            ).fetchone()
            if sv_row is None:
                issues.append("schema_version table is empty")
            elif sv_row[0] != SCHEMA_VERSION:
                issues.append(
                    f"Schema version mismatch: DB={sv_row[0]}, expected={SCHEMA_VERSION}"
                )
        except Exception as e:
            issues.append(f"Cannot read schema_version: {e}")

        # 4. Required tables
        table_rows = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).fetchall()
        present_tables = {row[0] for row in table_rows}
        missing_tables = REQUIRED_TABLES - present_tables
        for t in sorted(missing_tables):
            issues.append(f"Missing required table: {t}")

        # 5. Required indexes
        index_rows = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='index'")
        ).fetchall()
        present_indexes = {row[0] for row in index_rows}
        missing_indexes = REQUIRED_INDEXES - present_indexes
        for i in sorted(missing_indexes):
            issues.append(f"Missing required index: {i}")

    return issues


@contextmanager
def get_db_connection():
    """
    Context manager for database connections using SQLAlchemy.
    Automatically handles connection closing and error handling.
    engine.begin() auto-commits on success and auto-rolls back on exception.
    """
    with engine.begin() as conn:
        try:
            yield conn
        except Exception as e:
            logger.error(f"Database error: {e}")
            raise


def _create_database_from_schema() -> None:
    """Create SQLite database file from schema SQL."""
    if not SCHEMA_PATH.exists():
        logger.warning(
            f"Database not found at {DB_PATH} and schema missing at {SCHEMA_PATH}."
        )
        raise FileNotFoundError(
            f"Database file not found: {DB_PATH} and schema not found: {SCHEMA_PATH}."
        )

    logger.info(f"Creating database at {DB_PATH} from schema.")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(schema_sql)
        conn.commit()


def _has_required_tables() -> bool:
    """Return True only when required core tables exist."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='organizations'")
        )
        if not result.fetchone():
            return False
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'")
        )
        return bool(result.fetchone())


def init_database(auto_recreate_invalid: bool = False):
    """
    Initialize the database if it doesn't exist.
    Uses raw sqlite3 for schema creation (views and complex constraints),
    then verifies with SQLAlchemy.
    Should be called on application startup.
    """
    if DB_PATH.exists() and DB_PATH.is_dir():
        raise RuntimeError(
            f"PKI_DB_PATH must point to a SQLite file, not a directory: {DB_PATH}. "
            "Example: C:\\pki\\database\\pki.db"
        )

    if not DB_PATH.exists():
        _create_database_from_schema()

    if not _has_required_tables():
        if auto_recreate_invalid:
            backup_path = DB_PATH.with_suffix(".invalid.bak")
            try:
                if backup_path.exists():
                    backup_path.unlink()
                DB_PATH.replace(backup_path)
            except Exception:
                logger.warning("Failed to backup invalid DB before recreate", exc_info=True)
            _create_database_from_schema()
        else:
            raise RuntimeError(
                "Database exists but is missing required tables. "
                "Set PKI_DB_AUTO_REINIT=true to recreate from database/pki_schema.sql."
            )

    # Validate schema version
    with engine.begin() as conn:
        _validate_schema_version(conn)

    # Validate database structural integrity
    issues = validate_database_integrity()
    if issues:
        for issue in issues:
            logger.error(f"Database integrity check failed: {issue}")
        raise RuntimeError(
            f"Database failed integrity checks ({len(issues)} issue(s)). "
            "See error log for details."
        )

    logger.info("Database initialized successfully")


def extract_certificate_metadata(
    org_id: int,
    cert_name: str,
    cert_type: str,
    cert_path: Path,
    key_path: Path,
    csr_path: Path,
    pwd_path: Path,
    org_dir: Path,
    issuer_cert_id: Optional[int] = None,
) -> Dict[str, Any]:
    cert = x509.load_pem_x509_certificate(file_crypto.read_encrypted(cert_path))

    def _get_attr(oid: NameOID) -> Optional[str]:
        attrs = cert.subject.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    serial_number = format(cert.serial_number, "x")
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    public_key = cert.public_key()
    key_algorithm = "EC"
    key_size = None
    ec_curve = None
    if isinstance(public_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_algorithm = "EC"
        ec_curve = public_key.curve.name

    signature_hash = None
    if cert.signature_hash_algorithm:
        signature_hash = cert.signature_hash_algorithm.name.upper()

    # Parse certificate extensions
    # OID → name mapping for EKU (matches eku_name_check constraint)
    EKU_OID_TO_NAME = {
        "1.3.6.1.5.5.7.3.1": "serverAuth",
        "1.3.6.1.5.5.7.3.2": "clientAuth",
        "1.3.6.1.5.5.7.3.3": "codeSigning",
        "1.3.6.1.5.5.7.3.4": "emailProtection",
        "1.3.6.1.5.5.7.3.8": "timeStamping",
        "1.3.6.1.5.5.7.3.9": "ocspSigning",
    }

    # Parse SANs
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append({"san_type": "DNS", "san_value": name.value})
            elif isinstance(name, x509.RFC822Name):
                sans.append({"san_type": "EMAIL", "san_value": name.value})
            elif isinstance(name, x509.IPAddress):
                sans.append({"san_type": "IP", "san_value": str(name.value)})
            elif isinstance(name, x509.UniformResourceIdentifier):
                sans.append({"san_type": "URI", "san_value": name.value})
    except x509.ExtensionNotFound:
        pass

    # Parse BasicConstraints
    basic_constraints = None
    try:
        bc_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        bc = bc_ext.value
        basic_constraints = {"is_ca": bc.ca, "path_length": bc.path_length}
    except x509.ExtensionNotFound:
        pass

    # Parse KeyUsage
    key_usage = None
    try:
        ku_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        ku = ku_ext.value
        key_usage = {
            "is_critical": ku_ext.critical,
            "digital_signature": ku.digital_signature,
            "content_commitment": ku.content_commitment,
            "key_encipherment": ku.key_encipherment,
            "data_encipherment": ku.data_encipherment,
            "key_agreement": ku.key_agreement,
            "key_cert_sign": ku.key_cert_sign,
            "crl_sign": ku.crl_sign,
            # encipher_only/decipher_only only valid when key_agreement=True
            "encipher_only": ku.encipher_only if ku.key_agreement else False,
            "decipher_only": ku.decipher_only if ku.key_agreement else False,
        }
    except x509.ExtensionNotFound:
        pass

    # Parse ExtendedKeyUsage
    extended_key_usage = []
    try:
        eku_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        )
        for oid in eku_ext.value:
            oid_str = oid.dotted_string
            eku_name = EKU_OID_TO_NAME.get(oid_str)
            if eku_name:  # Only include recognized EKUs
                extended_key_usage.append({"eku_oid": oid_str, "eku_name": eku_name})
    except x509.ExtensionNotFound:
        pass

    # Parse all extensions generically
    extensions = []
    for ext in cert.extensions:
        ext_oid = ext.oid.dotted_string
        try:
            ext_name = ext.oid._name if hasattr(ext.oid, "_name") else str(ext.oid)
        except Exception:
            ext_name = str(ext.oid)

        # Format extension value as human-readable string
        try:
            if ext_oid == "2.5.29.19":  # BasicConstraints
                bc = ext.value
                ext_value = f"CA:{bc.ca}, pathlen:{bc.path_length}" if bc.path_length else f"CA:{bc.ca}"
            elif ext_oid == "2.5.29.15":  # KeyUsage
                ku = ext.value
                flags = [f.name for f in [
                    ku.digital_signature, ku.content_commitment, ku.key_encipherment,
                    ku.data_encipherment, ku.key_agreement, ku.key_cert_sign, ku.crl_sign
                ] if f]
                ext_value = ", ".join(flags) if flags else ""
            elif ext_oid == "2.5.29.37":  # ExtendedKeyUsage
                ekus = [EKU_OID_TO_NAME.get(o.dotted_string, o.dotted_string) for o in ext.value]
                ext_value = ", ".join(ekus)
            elif ext_oid == "2.5.29.17":  # SubjectAlternativeName
                san_list = []
                for name in ext.value:
                    if isinstance(name, x509.DNSName):
                        san_list.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.RFC822Name):
                        san_list.append(f"EMAIL:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_list.append(f"IP:{str(name.value)}")
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        san_list.append(f"URI:{name.value}")
                ext_value = ", ".join(san_list)
            else:
                ext_value = repr(ext.value)[:200]  # Limit to 200 chars
        except Exception:
            ext_value = repr(ext.value)[:200]

        extensions.append({
            "extension_oid": ext_oid,
            "extension_name": ext_name,
            "is_critical": ext.critical,
            "extension_value": ext_value,
        })

    return {
        "organization_id": org_id,
        "cert_name": cert_name,
        "cert_type": cert_type,
        "issuer_cert_id": issuer_cert_id,
        "subject_country": _get_attr(NameOID.COUNTRY_NAME),
        "subject_state": _get_attr(NameOID.STATE_OR_PROVINCE_NAME),
        "subject_locality": _get_attr(NameOID.LOCALITY_NAME),
        "subject_organization": _get_attr(NameOID.ORGANIZATION_NAME),
        "subject_org_unit": _get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME),
        "subject_common_name": _get_attr(NameOID.COMMON_NAME),
        "subject_email": _get_attr(NameOID.EMAIL_ADDRESS),
        "serial_number": serial_number,
        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S"),
        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S"),
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "ec_curve": ec_curve,
        "signature_hash": signature_hash,
        "cert_path": str(cert_path.relative_to(org_dir)),
        "key_path": str(key_path.relative_to(org_dir)),
        "csr_path": str(csr_path.relative_to(org_dir)),
        "pwd_path": str(pwd_path.relative_to(org_dir)),
        "sans": sans,
        "basic_constraints": basic_constraints,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "extensions": extensions,
    }


def create_certificate(
    organization_id: int,
    cert_name: str,
    cert_type: str,
    subject_country: Optional[str],
    subject_state: Optional[str],
    subject_locality: Optional[str],
    subject_organization: Optional[str],
    subject_org_unit: Optional[str],
    subject_common_name: str,
    subject_email: Optional[str],
    serial_number: str,
    not_before: str,
    not_after: str,
    key_algorithm: str,
    key_size: Optional[int],
    ec_curve: Optional[str],
    signature_hash: Optional[str],
    cert_path: str,
    key_path: str,
    csr_path: str,
    pwd_path: str,
    issuer_cert_id: Optional[int] = None,
    cert_uuid: Optional[str] = None,
) -> int:
    cert_uuid_value = cert_uuid or str(uuid.uuid4())
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            INSERT INTO certificates (
                cert_uuid,
                organization_id,
                cert_name,
                cert_type,
                issuer_cert_id,
                subject_country,
                subject_state,
                subject_locality,
                subject_organization,
                subject_org_unit,
                subject_common_name,
                subject_email,
                serial_number,
                not_before,
                not_after,
                key_algorithm,
                key_size,
                ec_curve,
                signature_hash,
                cert_path,
                key_path,
                csr_path,
                pwd_path,
                created_at,
                updated_at
            )
            VALUES (
                :cert_uuid, :organization_id, :cert_name, :cert_type, :issuer_cert_id,
                :subject_country, :subject_state, :subject_locality, :subject_organization, :subject_org_unit, :subject_common_name, :subject_email,
                :serial_number, :not_before, :not_after,
                :key_algorithm, :key_size, :ec_curve, :signature_hash,
                :cert_path, :key_path, :csr_path, :pwd_path,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """),
            {
                "cert_uuid": cert_uuid_value,
                "organization_id": organization_id,
                "cert_name": cert_name,
                "cert_type": cert_type,
                "issuer_cert_id": issuer_cert_id,
                "subject_country": subject_country,
                "subject_state": subject_state,
                "subject_locality": subject_locality,
                "subject_organization": subject_organization,
                "subject_org_unit": subject_org_unit,
                "subject_common_name": subject_common_name,
                "subject_email": subject_email,
                "serial_number": serial_number,
                "not_before": not_before,
                "not_after": not_after,
                "key_algorithm": key_algorithm,
                "key_size": key_size,
                "ec_curve": ec_curve,
                "signature_hash": signature_hash,
                "cert_path": cert_path,
                "key_path": key_path,
                "csr_path": csr_path,
                "pwd_path": pwd_path,
            },
        )
        cert_id = result.lastrowid
        logger.info(f"Created certificate: {cert_name} (ID: {cert_id})")
        return cert_id


# ============================================================================
# EXTENSION PERSISTENCE HELPERS (Private)
# ============================================================================

def _insert_subject_alternative_names(conn, certificate_id: int, sans: list) -> None:
    """Insert SANs into subject_alternative_names table."""
    if not sans:
        return
    for san in sans:
        conn.execute(
            text("""
            INSERT INTO subject_alternative_names
            (certificate_id, san_type, san_value)
            VALUES (:cert_id, :san_type, :san_value)
            """),
            {"cert_id": certificate_id, "san_type": san["san_type"], "san_value": san["san_value"]},
        )


def _insert_basic_constraints(conn, certificate_id: int, bc: Optional[dict]) -> None:
    """Insert basic constraints into basic_constraints table (1:1 relationship)."""
    if bc is None:
        return
    conn.execute(
        text("""
        INSERT INTO basic_constraints
        (certificate_id, is_ca, path_length)
        VALUES (:cert_id, :is_ca, :path_length)
        """),
        {"cert_id": certificate_id, "is_ca": bc["is_ca"], "path_length": bc["path_length"]},
    )


def _insert_key_usage(conn, certificate_id: int, ku: Optional[dict]) -> None:
    """Insert key usage into key_usage table (1:1 relationship)."""
    if ku is None:
        return
    conn.execute(
        text("""
        INSERT INTO key_usage
        (certificate_id, is_critical, digital_signature, content_commitment,
         key_encipherment, data_encipherment, key_agreement, key_cert_sign,
         crl_sign, encipher_only, decipher_only)
        VALUES (:cert_id, :is_critical, :digital_signature, :content_commitment,
                :key_encipherment, :data_encipherment, :key_agreement, :key_cert_sign,
                :crl_sign, :encipher_only, :decipher_only)
        """),
        {
            "cert_id": certificate_id,
            "is_critical": ku["is_critical"],
            "digital_signature": ku["digital_signature"],
            "content_commitment": ku["content_commitment"],
            "key_encipherment": ku["key_encipherment"],
            "data_encipherment": ku["data_encipherment"],
            "key_agreement": ku["key_agreement"],
            "key_cert_sign": ku["key_cert_sign"],
            "crl_sign": ku["crl_sign"],
            "encipher_only": ku["encipher_only"],
            "decipher_only": ku["decipher_only"],
        },
    )


def _insert_extended_key_usages(conn, certificate_id: int, ekus: list) -> None:
    """Insert EKUs into extended_key_usage table."""
    if not ekus:
        return
    for eku in ekus:
        conn.execute(
            text("""
            INSERT INTO extended_key_usage
            (certificate_id, eku_oid, eku_name)
            VALUES (:cert_id, :eku_oid, :eku_name)
            """),
            {"cert_id": certificate_id, "eku_oid": eku["eku_oid"], "eku_name": eku["eku_name"]},
        )


def _insert_certificate_extensions(conn, certificate_id: int, exts: list) -> None:
    """Insert generic extensions into certificate_extensions table."""
    if not exts:
        return
    for ext in exts:
        conn.execute(
            text("""
            INSERT INTO certificate_extensions
            (certificate_id, extension_oid, extension_name, is_critical, extension_value)
            VALUES (:cert_id, :oid, :name, :critical, :value)
            """),
            {
                "cert_id": certificate_id,
                "oid": ext["extension_oid"],
                "name": ext["extension_name"],
                "critical": ext["is_critical"],
                "value": ext["extension_value"],
            },
        )


# ============================================================================
# CERTIFICATE CREATION WITH EXTENSIONS (Transactional wrapper)
# ============================================================================

_CERT_INSERT_KEYS = {
    "cert_uuid",
    "organization_id", "cert_name", "cert_type", "issuer_cert_id",
    "subject_country", "subject_state", "subject_locality", "subject_organization",
    "subject_org_unit", "subject_common_name", "subject_email",
    "serial_number", "not_before", "not_after",
    "key_algorithm", "key_size", "ec_curve", "signature_hash",
    "cert_path", "key_path", "csr_path", "pwd_path",
}


def create_certificate_with_extensions(cert_info: dict) -> int:
    """
    Insert certificate and all extension rows in ONE transaction.
    Returns the new certificate ID.
    If any insert fails, the entire operation rolls back (atomicity).
    """
    base_cert = {k: cert_info[k] for k in _CERT_INSERT_KEYS if k in cert_info}
    if not base_cert.get("cert_uuid"):
        base_cert["cert_uuid"] = str(uuid.uuid4())

    with engine.begin() as conn:
        # Insert base certificate row
        result = conn.execute(
            text("""
            INSERT INTO certificates (
                cert_uuid,
                organization_id, cert_name, cert_type, issuer_cert_id,
                subject_country, subject_state, subject_locality, subject_organization,
                subject_org_unit, subject_common_name, subject_email,
                serial_number, not_before, not_after,
                key_algorithm, key_size, ec_curve, signature_hash,
                cert_path, key_path, csr_path, pwd_path,
                created_at, updated_at
            )
            VALUES (
                :cert_uuid, :organization_id, :cert_name, :cert_type, :issuer_cert_id,
                :subject_country, :subject_state, :subject_locality, :subject_organization, :subject_org_unit, :subject_common_name, :subject_email,
                :serial_number, :not_before, :not_after,
                :key_algorithm, :key_size, :ec_curve, :signature_hash,
                :cert_path, :key_path, :csr_path, :pwd_path,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """),
            base_cert,
        )
        cert_id = result.lastrowid
        logger.info(f"Created certificate with extensions: {base_cert.get('cert_name')} (ID: {cert_id})")

        # Insert extension rows (all optional)
        _insert_subject_alternative_names(conn, cert_id, cert_info.get("sans", []))
        _insert_basic_constraints(conn, cert_id, cert_info.get("basic_constraints"))
        _insert_key_usage(conn, cert_id, cert_info.get("key_usage"))
        _insert_extended_key_usages(conn, cert_id, cert_info.get("extended_key_usage", []))
        _insert_certificate_extensions(conn, cert_id, cert_info.get("extensions", []))

        return cert_id


# ============================================================================
# ORGANIZATIONS
# ============================================================================

def create_organization(org_dir: str, name: str) -> int:
    """
    Insert a new organization into the database.

    Args:
        org_dir: Directory name for the organization (unique identifier)
        name: Human-readable organization name

    Returns:
        The ID of the newly created organization

    Raises:
        sqlalchemy.exc.IntegrityError: If organization with same org_dir already exists
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            INSERT INTO organizations (org_dir, name, created_at, updated_at)
            VALUES (:org_dir, :name, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """),
            {"org_dir": org_dir, "name": name}
        )
        org_id = result.lastrowid
        logger.info(f"Created organization: {org_dir} (ID: {org_id})")
        return org_id


def update_organization_dir(org_id: int, org_dir: str) -> None:
    """
    Update the org_dir (folder path) for an organization.
    Used to defer folder creation until after database insert (issue #16).

    Args:
        org_id: Organization ID to update
        org_dir: New absolute folder path

    Raises:
        sqlalchemy.exc.IntegrityError: If org_dir violates UNIQUE constraint
    """
    with get_db_connection() as conn:
        conn.execute(
            text("""
            UPDATE organizations
            SET org_dir = :org_dir, updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            """),
            {"org_dir": org_dir, "id": org_id}
        )
        logger.info(f"Updated organization {org_id} directory: {org_dir}")


def get_organization_by_dir(org_dir: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve an organization by its directory name.

    Args:
        org_dir: Organization directory name

    Returns:
        Dictionary with organization data, or None if not found
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT * FROM organizations WHERE org_dir = :org_dir"),
            {"org_dir": org_dir}
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def get_organization_by_id(org_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve an organization by its ID.

    Args:
        org_id: Organization ID

    Returns:
        Dictionary with organization data, or None if not found
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT * FROM organizations WHERE id = :id"),
            {"id": org_id}
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def list_organizations() -> List[Dict[str, Any]]:
    """
    List all organizations.

    Returns:
        List of dictionaries with organization data
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT * FROM organizations ORDER BY created_at DESC")
        )
        return [dict(row) for row in result.mappings().fetchall()]


# ============================================================================
# AUDIT LOG
# ============================================================================

def log_certificate_operation(
    certificate_id: Optional[int],
    operation: str,
    user_name: Optional[str] = None,
    details: Optional[str] = None
) -> int:
    """
    Log a certificate operation to the audit log.

    Args:
        certificate_id: Certificate ID (can be None for org-level operations)
        operation: Operation type ('created', 'revoked', 'renewed', etc.)
        user_name: Username performing the operation
        details: Additional details as JSON string

    Returns:
        The ID of the audit log entry
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            INSERT INTO certificate_audit_log
            (certificate_id, operation, operation_timestamp, user_name, details)
            VALUES (:certificate_id, :operation, CURRENT_TIMESTAMP, :user_name, :details)
            """),
            {
                "certificate_id": certificate_id,
                "operation": operation,
                "user_name": user_name,
                "details": details,
            }
        )
        log_id = result.lastrowid
        logger.info(f"Logged operation: {operation} (Log ID: {log_id})")
        return log_id


# ============================================================================
# STATISTICS
# ============================================================================

def get_recent_audit_logs(org_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Return recent certificate operations for an organization.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT
                cal.id,
                cal.operation,
                cal.operation_timestamp AS created_at,
                cal.user_name,
                cal.details,
                c.id AS certificate_id,
                c.cert_name,
                c.cert_type
            FROM certificate_audit_log cal
            JOIN certificates c ON c.id = cal.certificate_id
            WHERE c.organization_id = :org_id
            ORDER BY cal.operation_timestamp DESC, cal.id DESC
            LIMIT :limit
            """),
            {"org_id": org_id, "limit": limit},
        )
        return [dict(row) for row in result.mappings().fetchall()]


def get_certificate_hierarchy(org_id: int) -> List[Dict[str, Any]]:
    """
    Return certificate hierarchy for an organization in root->leaf order.
    Excludes revoked certificates from the hierarchy.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            WITH RECURSIVE cert_tree AS (
                SELECT
                    c.id,
                    c.cert_name,
                    c.cert_type,
                    c.subject_common_name,
                    c.issuer_cert_id,
                    0 AS level,
                    CAST(c.cert_name AS TEXT) AS path
                FROM certificates c
                WHERE c.organization_id = :org_id
                  AND c.issuer_cert_id IS NULL
                  AND c.status != 'revoked'

                UNION ALL

                SELECT
                    c.id,
                    c.cert_name,
                    c.cert_type,
                    c.subject_common_name,
                    c.issuer_cert_id,
                    ct.level + 1,
                    ct.path || ' -> ' || c.cert_name
                FROM certificates c
                JOIN cert_tree ct ON c.issuer_cert_id = ct.id
                WHERE c.organization_id = :org_id
                  AND c.status != 'revoked'
            )
            SELECT id, cert_name, cert_type, subject_common_name, issuer_cert_id, level, path
            FROM cert_tree
            ORDER BY path
            """),
            {"org_id": org_id},
        )
        return [dict(row) for row in result.mappings().fetchall()]

def get_organization_stats(org_id: int) -> Dict[str, Any]:
    """
    Get statistics for an organization.

    Args:
        org_id: Organization ID

    Returns:
        Dictionary with organization statistics
    """
    with get_db_connection() as conn:
        # Count certificates by type
        result = conn.execute(
            text("""
            SELECT cert_type, COUNT(*) as count
            FROM certificates
            WHERE organization_id = :org_id
            GROUP BY cert_type
            """),
            {"org_id": org_id}
        )
        cert_counts = {row['cert_type']: row['count'] for row in result.mappings().fetchall()}

        # Count by status
        result = conn.execute(
            text("""
            SELECT status, COUNT(*) as count
            FROM certificates
            WHERE organization_id = :org_id
            GROUP BY status
            """),
            {"org_id": org_id}
        )
        status_counts = {row['status']: row['count'] for row in result.mappings().fetchall()}

        return {
            'certificate_counts': cert_counts,
            'status_counts': status_counts,
            'total_certificates': sum(cert_counts.values())
        }


def expire_overdue_certificates() -> int:
    """
    Mark overdue active certificates as expired.

    Returns:
        Number of rows updated.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            UPDATE certificates
            SET status = 'expired',
                updated_at = CURRENT_TIMESTAMP
            WHERE status = 'active'
              AND not_after < datetime('now')
            """)
        )
        return result.rowcount or 0


def get_certificate_statistics(org_id: Optional[int] = None) -> Dict[str, int]:
    """
    Return certificate counts for dashboard summaries.

    Args:
        org_id: Optional organization ID filter. If None, returns global counts.

    Returns:
        Dict with keys: total, active, expired, revoked, superseded
    """
    params: Dict[str, Any] = {}
    where_clause = ""
    if org_id is not None:
        where_clause = "WHERE c.organization_id = :org_id"
        params["org_id"] = org_id

    with get_db_connection() as conn:
        result = conn.execute(
            text(f"""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN cs.computed_status = 'valid' THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN cs.computed_status = 'expired' THEN 1 ELSE 0 END) AS expired,
                SUM(CASE WHEN c.status = 'revoked' THEN 1 ELSE 0 END) AS revoked,
                SUM(CASE WHEN c.status = 'revoked' AND c.revocation_reason = 'superseded' THEN 1 ELSE 0 END) AS superseded
            FROM certificates c
            JOIN certificate_summary cs ON cs.id = c.id
            {where_clause}
            """),
            params,
        )
        row = result.mappings().fetchone() or {}

    return {
        "total": int(row.get("total") or 0),
        "active": int(row.get("active") or 0),
        "expired": int(row.get("expired") or 0),
        "revoked": int(row.get("revoked") or 0),
        "superseded": int(row.get("superseded") or 0),
    }


def list_certificates_by_organization(org_id: int) -> List[Dict[str, Any]]:
    """
    List certificates for an organization (most recent first).
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT *
            FROM certificates
            WHERE organization_id = :org_id
            ORDER BY created_at DESC, id DESC
            """),
            {"org_id": org_id},
        )
        return [dict(row) for row in result.mappings().fetchall()]


def get_certificate_by_id_for_organization(cert_id: int, org_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single certificate only if it belongs to the given organization.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT *
            FROM certificates
            WHERE id = :id AND organization_id = :org_id
            """),
            {"id": cert_id, "org_id": org_id},
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def revoke_certificate(cert_id: int, reason: str = "unspecified") -> bool:
    """
    Mark a certificate as revoked.

    Args:
        cert_id: Certificate ID to revoke
        reason: Revocation reason (keyCompromise, caCompromise, superseded, etc.)

    Returns:
        True if certificate was updated, False otherwise
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            UPDATE certificates
            SET status = 'revoked',
                revoked_at = CURRENT_TIMESTAMP,
                revocation_reason = :reason,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id AND status = 'active'
            """),
            {"reason": reason, "id": cert_id},
        )
        return result.rowcount > 0


def get_active_certificates_by_issuer(issuer_cert_id: int) -> List[Dict[str, Any]]:
    """
    Get all active (non-revoked) certificates signed by this issuer.
    Used to prevent revocation of a CA that still has subordinate certificates.

    Args:
        issuer_cert_id: Certificate ID of the issuer (CA)

    Returns:
        List of active certificate dictionaries
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT *
            FROM certificates
            WHERE issuer_cert_id = :issuer_cert_id AND status = 'active'
            """),
            {"issuer_cert_id": issuer_cert_id},
        )
        return [dict(row) for row in result.mappings().fetchall()]


def get_revoked_certs_for_issuer(issuer_cert_id: int) -> List[Dict[str, Any]]:
    """
    Return all revoked certificates signed by this issuer (for CRL generation).

    Args:
        issuer_cert_id: The issuer certificate ID

    Returns:
        List of revoked certificate records with serial_number, revoked_at, revocation_reason
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT id, serial_number, revoked_at, revocation_reason
            FROM certificates
            WHERE issuer_cert_id = :issuer_cert_id AND status = 'revoked'
            ORDER BY revoked_at
            """),
            {"issuer_cert_id": issuer_cert_id},
        )
        return [dict(row) for row in result.mappings().fetchall()]


def get_latest_certificate_by_name_and_type(
    org_id: int,
    cert_name: str,
    cert_type: str,
) -> Optional[Dict[str, Any]]:
    """
    Get latest certificate row for a given organization/name/type.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT *
            FROM certificates
            WHERE organization_id = :org_id AND cert_name = :cert_name AND cert_type = :cert_type
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """),
            {"org_id": org_id, "cert_name": cert_name, "cert_type": cert_type},
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def get_expiring_certificates(days_ahead: int = 90, critical_days: int = 30, warning_days: int = 60) -> List[Dict[str, Any]]:
    """
    Get all active certificates expiring within the specified days.

    Args:
        days_ahead: Number of days ahead to check (default 90)
        critical_days: Days threshold for critical alert level (default 30)
        warning_days: Days threshold for warning alert level (default 60)

    Returns:
        List of dictionaries with certificate info and alert level
    """
    with get_db_connection() as conn:
        # Get current time and expiration boundary
        now = datetime.now(timezone.utc)
        expiration_boundary = now.strftime("%Y-%m-%d %H:%M:%S")

        # Calculate days ahead timestamp (naive UTC format for SQLite comparison)
        from datetime import timedelta
        days_ahead_date = now + timedelta(days=days_ahead)
        days_ahead_iso = days_ahead_date.strftime("%Y-%m-%d %H:%M:%S")

        result = conn.execute(
            text("""
            SELECT
                c.*,
                o.name as org_name,
                o.id as org_id
            FROM certificates c
            JOIN organizations o ON c.organization_id = o.id
            WHERE c.status = 'active'
            AND c.not_after > :expiration_boundary
            AND c.not_after <= :days_ahead_iso
            ORDER BY c.not_after ASC
            """),
            {"expiration_boundary": expiration_boundary, "days_ahead_iso": days_ahead_iso},
        )

        certs = [dict(row) for row in result.mappings().fetchall()]

        # Calculate alert level for each certificate
        for cert in certs:
            not_after = datetime.fromisoformat(cert['not_after'])
            # Make timezone-aware if naive
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            days_remaining = (not_after - now).days

            if days_remaining <= critical_days:
                cert['alert_level'] = 'critical'
            elif days_remaining <= warning_days:
                cert['alert_level'] = 'warning'
            else:
                cert['alert_level'] = 'info'

            cert['days_remaining'] = days_remaining

        return certs


def check_database_health() -> Dict[str, Any]:
    """
    Check database health and return basic statistics.

    Returns:
        Dictionary with health check results
    """
    try:
        with get_db_connection() as conn:
            # Count organizations
            result = conn.execute(text("SELECT COUNT(*) as count FROM organizations"))
            org_count = result.mappings().fetchone()['count']

            # Count certificates
            result = conn.execute(text("SELECT COUNT(*) as count FROM certificates"))
            cert_count = result.mappings().fetchone()['count']

            return {
                'status': 'healthy',
                'organizations': org_count,
                'certificates': cert_count,
                'database_path': str(DB_PATH.absolute())
            }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            'status': 'unhealthy',
            'error': str(e)
        }


# ============================================================================
# EXTENSION READ FUNCTIONS
# ============================================================================

def list_sans(certificate_id: int) -> List[Dict[str, Any]]:
    """Get all SANs for a certificate."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT san_type, san_value FROM subject_alternative_names WHERE certificate_id = :cert_id"),
            {"cert_id": certificate_id},
        )
        return [dict(row) for row in result.mappings().fetchall()]


def get_basic_constraints(certificate_id: int) -> Optional[Dict[str, Any]]:
    """Get basic constraints for a certificate (or None if not set)."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT is_ca, path_length FROM basic_constraints WHERE certificate_id = :cert_id"),
            {"cert_id": certificate_id},
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def get_key_usage(certificate_id: int) -> Optional[Dict[str, Any]]:
    """Get key usage for a certificate (or None if not set)."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT is_critical, digital_signature, content_commitment, key_encipherment,
                   data_encipherment, key_agreement, key_cert_sign, crl_sign,
                   encipher_only, decipher_only
            FROM key_usage
            WHERE certificate_id = :cert_id
            """),
            {"cert_id": certificate_id},
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def list_extended_key_usage(certificate_id: int) -> List[Dict[str, Any]]:
    """Get all EKUs for a certificate."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT eku_oid, eku_name FROM extended_key_usage WHERE certificate_id = :cert_id"),
            {"cert_id": certificate_id},
        )
        return [dict(row) for row in result.mappings().fetchall()]



# ============================================================================
# CRL FUNCTIONS
# ============================================================================

def get_latest_crl_number_for_issuer(issuer_cert_id: int) -> int:
    """Get the latest CRL number for an issuer, or 0 if no CRL exists."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT MAX(crl_number) as max_crl FROM crls WHERE issuer_cert_id = :issuer_id"),
            {"issuer_id": issuer_cert_id},
        )
        row = result.mappings().fetchone()
        return row['max_crl'] if row and row['max_crl'] is not None else 0


def create_crl(
    issuer_cert_id: int,
    crl_number: int,
    this_update: str,
    next_update: str,
    crl_path: str,
) -> int:
    """Insert a CRL record. Returns the new CRL ID."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            INSERT INTO crls (issuer_cert_id, crl_number, this_update, next_update, crl_path, created_at)
            VALUES (:issuer_id, :crl_num, :this_update, :next_update, :crl_path, CURRENT_TIMESTAMP)
            """),
            {
                "issuer_id": issuer_cert_id,
                "crl_num": crl_number,
                "this_update": this_update,
                "next_update": next_update,
                "crl_path": crl_path,
            },
        )
        crl_id = result.lastrowid
        logger.info(f"Created CRL #{crl_number} for issuer {issuer_cert_id} (CRL ID: {crl_id})")
        return crl_id


def bulk_insert_revoked_certificate_entries(crl_id: int, revoked_certs: List[Dict[str, Any]]) -> None:
    """
    Insert revoked certificate entries for a CRL.
    Uses INSERT OR IGNORE to skip duplicates (UNIQUE constraint: (crl_id, certificate_id)).
    """
    if not revoked_certs:
        return
    with get_db_connection() as conn:
        for cert in revoked_certs:
            conn.execute(
                text("""
                INSERT OR IGNORE INTO revoked_certificates
                (crl_id, certificate_id, revocation_date, revocation_reason)
                VALUES (:crl_id, :cert_id, :rev_date, :rev_reason)
                """),
                {
                    "crl_id": crl_id,
                    "cert_id": cert["certificate_id"],
                    "rev_date": cert.get("revocation_date"),
                    "rev_reason": cert.get("revocation_reason"),
                },
            )
        logger.info(f"Inserted {len(revoked_certs)} revoked cert entries for CRL {crl_id}")


def get_all_crls() -> List[Dict[str, Any]]:
    """Get all CRL records from the database."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT id, issuer_cert_id, crl_number, this_update, next_update, crl_path, created_at
            FROM crls
            ORDER BY id
            """),
        )
        return [dict(row) for row in result.mappings().fetchall()]


def get_latest_crl_for_issuer(org_id: int, issuer_name: str) -> Optional[Dict[str, Any]]:
    """
    Return latest CRL row for an issuer name scoped to one organization.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT c.*
            FROM crls c
            JOIN certificates cert ON cert.id = c.issuer_cert_id
            WHERE cert.organization_id = :org_id
              AND cert.cert_name = :issuer_name
              AND cert.cert_type IN ('root', 'intermediate')
            ORDER BY c.this_update DESC, c.id DESC
            LIMIT 1
            """),
            {"org_id": org_id, "issuer_name": issuer_name},
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


def get_latest_crl_for_issuer_id(issuer_cert_id: int) -> Optional[Dict[str, Any]]:
    """
    Return latest CRL row for a specific issuer certificate id.
    """
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT id, issuer_cert_id, crl_number, this_update, next_update, crl_path, created_at
            FROM crls
            WHERE issuer_cert_id = :issuer_cert_id
            ORDER BY this_update DESC, id DESC
            LIMIT 1
            """),
            {"issuer_cert_id": issuer_cert_id},
        )
        row = result.mappings().fetchone()
        return dict(row) if row else None


# ============================================================================
# BACKFILL HELPERS
# ============================================================================

def list_all_certificates_for_backfill() -> List[Dict[str, Any]]:
    """Get all certificates with paths for backfill operations."""
    with get_db_connection() as conn:
        result = conn.execute(
            text("""
            SELECT c.id, c.cert_name, c.cert_path, c.cert_type,
                   c.status, c.revoked_at, c.revocation_reason,
                   c.serial_number,
                   c.not_before, c.not_after,
                   c.issuer_cert_id,
                   c.key_path, c.csr_path, c.pwd_path,
                   c.subject_country, c.subject_state, c.subject_locality,
                   c.subject_organization, c.subject_org_unit, c.subject_common_name, c.subject_email,
                   c.organization_id, o.org_dir
            FROM certificates c
            JOIN organizations o ON c.organization_id = o.id
            ORDER BY c.id
            """),
        )
        return [dict(row) for row in result.mappings().fetchall()]


def insert_certificate_extensions_for_existing(certificate_id: int, cert_info: dict) -> bool:
    """
    Populate extension tables for an already-inserted certificate.
    Returns True if inserted, False if already exists (idempotent).
    """
    # Check if already backfilled (basic_constraints is a good proxy)
    with get_db_connection() as conn:
        result = conn.execute(
            text("SELECT 1 FROM basic_constraints WHERE certificate_id = :cert_id LIMIT 1"),
            {"cert_id": certificate_id},
        )
        if result.fetchone():
            logger.debug(f"Certificate {certificate_id} already has extensions, skipping")
            return False  # Already done

        # Insert all extension rows using the same helpers as transaction wrapper
        _insert_subject_alternative_names(conn, certificate_id, cert_info.get("sans", []))
        _insert_basic_constraints(conn, certificate_id, cert_info.get("basic_constraints"))
        _insert_key_usage(conn, certificate_id, cert_info.get("key_usage"))
        _insert_extended_key_usages(conn, certificate_id, cert_info.get("extended_key_usage", []))
        _insert_certificate_extensions(conn, certificate_id, cert_info.get("extensions", []))

        logger.info(f"Backfilled extensions for certificate {certificate_id}")
        return True
