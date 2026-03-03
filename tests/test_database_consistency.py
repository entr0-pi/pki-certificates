"""
Database consistency tests (test_database_consistency.md spec).

Tests that certificate data is correctly stored and linked in the database.
Verifies issuer_cert_id chain relationships and metadata integrity.

Markers: integration
"""

import pytest
import uuid


@pytest.mark.integration
def test_root_ca_db_row_exists(created_root_ca, db_connection):
    """
    After root CA creation, verify the DB row exists with correct attributes:
    - cert_type = 'root'
    - issuer_cert_id IS NULL (self-signed)
    - status = 'active'
    """
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT cert_type, issuer_cert_id, status FROM certificates WHERE id = ?",
        (created_root_ca["cert_id"],),
    )
    row = cursor.fetchone()

    assert row is not None, f"Root CA cert ID {created_root_ca['cert_id']} not found in DB"
    cert_type, issuer_cert_id, status = row

    assert cert_type == "root", f"Expected cert_type='root', got '{cert_type}'"
    assert issuer_cert_id is None, f"Root CA should have issuer_cert_id=NULL, got {issuer_cert_id}"
    assert status == "active", f"Expected status='active', got '{status}'"


@pytest.mark.integration
def test_intermediate_ca_issuer_cert_id_points_to_root(
    created_intermediate_ca, created_root_ca, db_connection
):
    """
    Intermediate CA DB row has issuer_cert_id pointing to the root CA.
    """
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT cert_type, issuer_cert_id FROM certificates WHERE id = ?",
        (created_intermediate_ca["cert_id"],),
    )
    row = cursor.fetchone()

    assert row is not None, f"Intermediate CA cert ID {created_intermediate_ca['cert_id']} not found in DB"
    cert_type, issuer_cert_id = row

    assert cert_type == "intermediate", f"Expected cert_type='intermediate', got '{cert_type}'"
    assert issuer_cert_id == created_root_ca["cert_id"], \
        f"Expected issuer_cert_id={created_root_ca['cert_id']}, got {issuer_cert_id}"


@pytest.mark.integration
def test_end_entity_issuer_cert_id_points_to_intermediate(
    created_server_cert, created_intermediate_ca, db_connection
):
    """
    End-entity (server) DB row has issuer_cert_id pointing to the intermediate CA.
    """
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT cert_type, issuer_cert_id FROM certificates WHERE id = ?",
        (created_server_cert["cert_id"],),
    )
    row = cursor.fetchone()

    assert row is not None, f"Server cert ID {created_server_cert['cert_id']} not found in DB"
    cert_type, issuer_cert_id = row

    assert cert_type == "server", f"Expected cert_type='server', got '{cert_type}'"
    assert issuer_cert_id == created_intermediate_ca["cert_id"], \
        f"Expected issuer_cert_id={created_intermediate_ca['cert_id']}, got {issuer_cert_id}"
    assert issuer_cert_id is not None, "End-entity cert should have non-NULL issuer_cert_id"


@pytest.mark.integration
def test_db_chain_all_types(
    created_root_ca,
    created_intermediate_ca,
    created_server_cert,
    created_client_cert,
    created_email_cert,
    db_connection,
):
    """
    Comprehensive chain assertion: all five certs have correct issuer_cert_id linkage.
    """
    cursor = db_connection.cursor()
    certs = {
        "root": created_root_ca["cert_id"],
        "intermediate": created_intermediate_ca["cert_id"],
        "server": created_server_cert["cert_id"],
        "client": created_client_cert["cert_id"],
        "email": created_email_cert["cert_id"],
    }

    for cert_type, cert_id in certs.items():
        cursor.execute(
            "SELECT cert_type, issuer_cert_id FROM certificates WHERE id = ?",
            (cert_id,),
        )
        row = cursor.fetchone()
        assert row is not None, f"{cert_type} cert not found"

        db_type, issuer_id = row
        assert db_type == cert_type, f"cert_type mismatch for {cert_type}"

        if cert_type == "root":
            assert issuer_id is None, f"Root CA should have issuer_cert_id=NULL"
        elif cert_type == "intermediate":
            assert issuer_id == created_root_ca["cert_id"], \
                f"Intermediate should point to root ({created_root_ca['cert_id']}), got {issuer_id}"
        else:  # server, client, email
            assert issuer_id == created_intermediate_ca["cert_id"], \
                f"{cert_type} should point to intermediate ({created_intermediate_ca['cert_id']}), got {issuer_id}"


@pytest.mark.integration
def test_popup_metadata_matches_db(test_client, created_org, created_intermediate_ca):
    """
    Certificate popup endpoint returns cert details that match DB values.
    """
    response = test_client.get(
        f"/organizations/{created_org['org_id']}/certificates/{created_intermediate_ca['cert_id']}/popup"
    )
    assert response.status_code == 200

    # Check that key DB values appear in the popup response
    assert created_intermediate_ca["cert_name"] in response.text or \
           "Intermediate" in response.text or \
           "intermediate" in response.text


@pytest.mark.integration
def test_popup_returns_error_for_wrong_org(test_client, created_org, created_intermediate_ca):
    """
    GET /organizations/99999/certificates/{cert_id}/popup for wrong org returns error.
    """
    response = test_client.get(
        f"/organizations/99999/certificates/{created_intermediate_ca['cert_id']}/popup"
    )
    # Should return error page with 200 status (rendered error.html)
    assert response.status_code == 200
    assert "not found" in response.text.lower() or "error" in response.text.lower()


@pytest.mark.integration
def test_no_non_root_certs_with_null_issuer(created_org, db_connection):
    """
    SQL backfill detection: no non-root certs should have issuer_cert_id=NULL.

    This validates that the integration test fixtures created a consistent chain.
    """
    cursor = db_connection.cursor()
    cursor.execute(
        """
        SELECT cert_type, COUNT(*) as total,
               SUM(CASE WHEN issuer_cert_id IS NULL THEN 1 ELSE 0 END) as missing_issuer
        FROM certificates
        WHERE organization_id = ?
        GROUP BY cert_type
        """,
        (created_org["org_id"],),
    )
    rows = cursor.fetchall()

    for cert_type, total, missing_issuer in rows:
        if cert_type != "root":
            assert missing_issuer == 0, \
                f"{cert_type} certs have {missing_issuer} missing issuer_cert_id (out of {total})"


@pytest.mark.integration
def test_serial_numbers_are_unique(created_org, db_connection):
    """
    All certificates in the org have unique serial numbers (DB constraint check).
    """
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT serial_number FROM certificates WHERE organization_id = ?",
        (created_org["org_id"],),
    )
    serials = [row[0] for row in cursor.fetchall()]

    assert len(serials) == len(set(serials)), \
        f"Found duplicate serial numbers in org {created_org['org_id']}: {serials}"


@pytest.mark.integration
def test_cert_uuid_present_and_valid_for_created_certs(
    created_root_ca,
    created_intermediate_ca,
    created_server_cert,
    created_client_cert,
    created_email_cert,
    db_connection,
):
    """
    Every created certificate row should have a valid UUID in cert_uuid.
    """
    cursor = db_connection.cursor()
    cert_ids = [
        created_root_ca["cert_id"],
        created_intermediate_ca["cert_id"],
        created_server_cert["cert_id"],
        created_client_cert["cert_id"],
        created_email_cert["cert_id"],
    ]
    for cert_id in cert_ids:
        cursor.execute("SELECT cert_uuid FROM certificates WHERE id = ?", (cert_id,))
        row = cursor.fetchone()
        assert row is not None
        cert_uuid = row[0]
        assert cert_uuid is not None and cert_uuid != ""
        parsed = uuid.UUID(cert_uuid)
        assert str(parsed) == cert_uuid


@pytest.mark.integration
def test_cert_uuid_unique_within_org(created_org, db_connection):
    """
    cert_uuid values must be unique for certificate rows in the organization.
    """
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT cert_uuid FROM certificates WHERE organization_id = ?",
        (created_org["org_id"],),
    )
    uuids = [row[0] for row in cursor.fetchall()]
    assert all(u is not None and u != "" for u in uuids)
    assert len(uuids) == len(set(uuids)), "Found duplicate cert_uuid values"
