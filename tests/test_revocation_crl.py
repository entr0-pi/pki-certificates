"""
Revocation and CRL tests (test_revocation_crl.md spec).

Tests certificate revocation, CRL generation, and revocation state management.

Markers: integration, openssl
"""

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
import sys

# Add backend to path for imports
BACKEND_PATH = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

import file_crypto


@pytest.mark.integration
@pytest.mark.openssl
def test_root_ca_creation_produces_initial_crl(created_org, created_root_ca):
    """
    Creating a root CA should immediately generate an initial (possibly empty) CRL.
    """
    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    crl_file = org_dir / "1_root" / "crl" / f"{created_root_ca['cert_uuid']}.crl.pem.enc"

    assert crl_file.exists(), f"Root initial CRL file not found: {crl_file}"
    crl = x509.load_pem_x509_crl(file_crypto.read_encrypted(crl_file))
    assert crl is not None


@pytest.mark.integration
@pytest.mark.openssl
def test_intermediate_creation_produces_initial_crl(
    created_org, created_intermediate_ca
):
    """
    Creating an intermediate CA should immediately generate an initial (possibly empty) CRL.
    """
    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]
    crl_file = int_dir / "crl" / f"{created_intermediate_ca['cert_uuid']}.crl.pem.enc"

    assert crl_file.exists(), f"Intermediate initial CRL file not found: {crl_file}"
    crl = x509.load_pem_x509_crl(file_crypto.read_encrypted(crl_file))
    assert crl is not None


@pytest.mark.integration
def test_revoke_active_cert_updates_status(
    test_client, created_org, cert_for_revocation, db_connection
):
    """
    After POST /revoke, the certificate status changes from 'active' to 'revoked',
    and revoked_at and revocation_reason are populated.
    """
    cert_id = cert_for_revocation["cert_id"]
    org_id = created_org["org_id"]

    # Verify cert is active before revocation
    cursor = db_connection.cursor()
    cursor.execute("SELECT status FROM certificates WHERE id = ?", (cert_id,))
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == "active", f"Cert should be active before revocation, got {row[0]}"

    # Revoke the certificate
    response = test_client.post(
        f"/organizations/{org_id}/certificates/{cert_id}/revoke",
        data={"reason": "keyCompromise"},
    )
    assert response.status_code == 200, f"Revocation failed: {response.text}"

    # Verify status changed in DB
    cursor.execute(
        "SELECT status, revoked_at, revocation_reason FROM certificates WHERE id = ?",
        (cert_id,),
    )
    row = cursor.fetchone()
    assert row is not None

    status, revoked_at, reason = row
    assert status == "revoked", f"Expected status='revoked', got '{status}'"
    assert revoked_at is not None, "revoked_at should not be NULL"
    assert reason == "keyCompromise", f"Expected reason='keyCompromise', got '{reason}'"


@pytest.mark.integration
@pytest.mark.openssl
def test_revoke_cert_produces_crl_file(
    test_client, created_org, created_intermediate_ca, cert_for_revocation
):
    """
    After revocation, the CRL file exists at:
    data/<org>/2_intermediates/<intermediate_name>/crl/<intermediate_name>.crl.pem
    """
    # First revoke the certificate
    response = test_client.post(
        f"/organizations/{created_org['org_id']}/certificates/{cert_for_revocation['cert_id']}/revoke",
        data={"reason": "keyCompromise"},
    )
    assert response.status_code == 200

    # Check that CRL file exists
    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]
    crl_file = int_dir / "crl" / f"{created_intermediate_ca['cert_uuid']}.crl.pem.enc"

    assert crl_file.exists(), f"CRL file not found: {crl_file}"

    # Verify it's a valid PEM CRL
    crl_pem = file_crypto.read_encrypted(crl_file)
    try:
        crl = x509.load_pem_x509_crl(crl_pem)
        assert crl is not None, "CRL could not be parsed"
    except Exception as e:
        pytest.fail(f"Failed to parse CRL: {e}")


@pytest.mark.integration
@pytest.mark.openssl
def test_revoked_cert_serial_appears_in_crl(
    test_client, created_org, created_intermediate_ca, cert_for_revocation, db_connection
):
    """
    After revocation, the revoked certificate's serial appears in the CRL.
    """
    # Revoke the certificate
    response = test_client.post(
        f"/organizations/{created_org['org_id']}/certificates/{cert_for_revocation['cert_id']}/revoke",
        data={"reason": "keyCompromise"},
    )
    assert response.status_code == 200

    # Get the cert's serial number from DB
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT serial_number FROM certificates WHERE id = ?",
        (cert_for_revocation["cert_id"],),
    )
    row = cursor.fetchone()
    assert row is not None
    serial_hex = row[0]

    # Convert hex serial to int
    serial_int = int(serial_hex, 16)

    # Load the CRL and check if the serial is listed
    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]
    crl_file = int_dir / "crl" / f"{created_intermediate_ca['cert_uuid']}.crl.pem.enc"

    crl_pem = file_crypto.read_encrypted(crl_file)
    crl = x509.load_pem_x509_crl(crl_pem)

    # Check if the serial is in the CRL
    revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_int)
    assert revoked_cert is not None, \
        f"Revoked serial {serial_hex} ({serial_int}) not found in CRL"


@pytest.mark.integration
def test_double_revoke_returns_dashboard(
    test_client, created_org, cert_for_revocation, db_connection
):
    """
    Attempting to revoke an already-revoked certificate returns the dashboard
    (HTTP 200) without changing the DB state.
    """
    cert_id = cert_for_revocation["cert_id"]

    # First revocation
    response1 = test_client.post(
        f"/organizations/{created_org['org_id']}/certificates/{cert_id}/revoke",
        data={"reason": "keyCompromise"},
    )
    assert response1.status_code == 200

    # Get the revoked_at timestamp from DB
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT revoked_at FROM certificates WHERE id = ?",
        (cert_id,),
    )
    row = cursor.fetchone()
    first_revoked_at = row[0]

    # Second revocation attempt
    response2 = test_client.post(
        f"/organizations/{created_org['org_id']}/certificates/{cert_id}/revoke",
        data={"reason": "superseded"},
    )
    assert response2.status_code == 200

    # Verify status is still revoked and timestamp unchanged
    cursor.execute(
        "SELECT status, revoked_at FROM certificates WHERE id = ?",
        (cert_id,),
    )
    row = cursor.fetchone()
    status, second_revoked_at = row

    assert status == "revoked", f"Status should still be revoked, got {status}"
    assert second_revoked_at == first_revoked_at, \
        f"revoked_at should not change on second revocation"


@pytest.mark.unit
def test_revoke_db_function_false_for_already_revoked(
    tmp_db, patch_db_for_session, db_connection
):
    """
    Unit test: db.revoke_certificate() returns False for already-revoked cert
    because the SQL WHERE clause checks status='active'.

    This test uses a manually inserted cert to avoid relying on full fixture chain.
    """
    import db as db_module
    from datetime import datetime

    # Manually insert a test cert into the DB
    db_module.create_organization("test_org_unit", "Test Org Unit")
    org = db_module.get_organization_by_dir("test_org_unit")
    org_id = org["id"]

    cert_id = db_module.create_certificate(
        organization_id=org_id,
        cert_name="test_cert",
        cert_type="root",
        subject_country="US",
        subject_state="CA",
        subject_locality="SF",
        subject_organization="Test",
        subject_org_unit="IT",
        subject_common_name="Test",
        subject_email="test@example.com",
        serial_number="0001",
        not_before=datetime.now(),
        not_after=datetime.now(),
        key_algorithm="EC",
        key_size=256,
        ec_curve="secp256k1",
        signature_hash="sha256",
        cert_path="test.pem",
        key_path="test.key",
        csr_path="test.csr",
        pwd_path="test.pwd",
        issuer_cert_id=None,
    )

    # First revocation should return True (rowcount == 1)
    result1 = db_module.revoke_certificate(cert_id, "keyCompromise")
    assert result1 is True, "First revocation should return True"

    # Second revocation should return False (rowcount == 0, no active cert to revoke)
    result2 = db_module.revoke_certificate(cert_id, "keyCompromise")
    assert result2 is False, "Second revocation should return False (idempotent guard)"
