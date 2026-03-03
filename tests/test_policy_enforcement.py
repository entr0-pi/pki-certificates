"""
Policy enforcement tests (test_policy_enforcement.md spec).

Tests policy.json enforcement: locked fields, policy validation, and error handling.

Markers: unit (pure policy logic), integration (HTTP-based policy tests)
"""

import pytest
import json
from pathlib import Path


# =============================================================================
# Unit Tests - Pure policy logic, no HTTP or DB required
# =============================================================================


@pytest.mark.unit
def test_policy_locked_fields_root_role():
    """
    _policy_locked_fields('root') must mirror POLICY_*=match in policy.json.
    """
    from app import _policy_locked_fields

    locked = _policy_locked_fields("root")
    policy = json.loads(Path("backend/config/policy.json").read_text(encoding="utf-8"))["role_defaults"]["root"]
    key_map = {"C": "POLICY_C", "ST": "POLICY_ST", "L": "POLICY_L", "O": "POLICY_O", "OU": "POLICY_OU", "CN": "POLICY_CN", "email": "POLICY_EMAIL"}
    expected_locked = [field for field, policy_key in key_map.items() if str(policy.get(policy_key, "optional")).strip().lower() == "match"]

    assert set(locked) == set(expected_locked), f"Locked fields mismatch for root. expected={expected_locked}, got={locked}"


@pytest.mark.unit
def test_policy_locked_fields_intermediate_role():
    """
    _policy_locked_fields('intermediate') must mirror POLICY_*=match in policy.json.
    """
    from app import _policy_locked_fields

    locked = _policy_locked_fields("intermediate")
    policy = json.loads(Path("backend/config/policy.json").read_text(encoding="utf-8"))["role_defaults"]["intermediate"]
    key_map = {"C": "POLICY_C", "ST": "POLICY_ST", "L": "POLICY_L", "O": "POLICY_O", "OU": "POLICY_OU", "CN": "POLICY_CN", "email": "POLICY_EMAIL"}
    expected_locked = [field for field, policy_key in key_map.items() if str(policy.get(policy_key, "optional")).strip().lower() == "match"]

    assert set(locked) == set(expected_locked), f"Locked fields mismatch for intermediate. expected={expected_locked}, got={locked}"


@pytest.mark.unit
def test_apply_match_policy_overrides_submitted_values():
    """
    _apply_match_policy_fields() overwrites submitted values with issuer values
    for fields that have 'match' policy.
    """
    from app import _apply_match_policy_fields

    submitted_values = {
        "C": "US",
        "ST": "TX",
        "L": "Dallas",
        "O": "EvilCorp",
        "OU": "Hax",
        "CN": "attacker.com",
        "email": "",
    }

    issuer_fields = {
        "C": "CA",
        "ST": "QC",
        "L": "MTL",
        "O": "AcmeCorp",
        "OU": "IT",
        "CN": "Acme Intermediate",
        "email": "",
    }

    policy = {
        "POLICY_C": "match",
        "POLICY_ST": "match",
        "POLICY_L": "match",
        "POLICY_O": "match",
        "POLICY_OU": "supplied",
        "POLICY_CN": "supplied",
        "POLICY_EMAIL": "optional",
    }

    result = _apply_match_policy_fields(submitted_values, issuer_fields, policy)

    # Match fields should be overwritten with issuer values
    assert result["C"] == "CA", f"C should be 'CA' (issuer value), got '{result['C']}'"
    assert result["ST"] == "QC", f"ST should be 'QC' (issuer value), got '{result['ST']}'"
    assert result["L"] == "MTL", f"L should be 'MTL' (issuer value), got '{result['L']}'"
    assert result["O"] == "AcmeCorp", f"O should be 'AcmeCorp' (issuer value), got '{result['O']}'"

    # Supplied fields keep frontend values
    assert result["CN"] == "attacker.com", f"CN should keep frontend value, got '{result['CN']}'"
    assert result["OU"] == "Hax", f"OU should keep frontend value, got '{result['OU']}'"


@pytest.mark.unit
def test_apply_match_policy_preserves_supplied_fields():
    """
    _apply_match_policy_fields() preserves 'supplied' field values from the frontend.
    """
    from app import _apply_match_policy_fields

    submitted = {"C": "US", "CN": "frontend-cn", "email": ""}
    issuer = {"C": "CA", "CN": "issuer-cn", "email": ""}
    policy = {"POLICY_C": "match", "POLICY_CN": "supplied"}

    result = _apply_match_policy_fields(submitted, issuer, policy)

    assert result["C"] == "CA", "Match field C should use issuer value"
    assert result["CN"] == "frontend-cn", "Supplied field CN should keep frontend value"


@pytest.mark.unit
def test_load_role_policy_returns_correct_role():
    """
    _load_role_policy() loads policy.json and returns the correct role section.
    """
    from app import _load_role_policy

    root_policy = _load_role_policy("root")
    assert root_policy is not None, "Root role policy should not be None"
    assert "BASICCONSTRAINTS" in root_policy, "Root policy should have BASICCONSTRAINTS"
    assert "critical, CA:true, pathlen:1" in root_policy["BASICCONSTRAINTS"], \
        f"Root pathlen should be 1, got {root_policy['BASICCONSTRAINTS']}"

    ee_policy = _load_role_policy("end-entity-server")
    assert ee_policy is not None, "End-entity-server policy should not be None"
    assert "EXTENDEDKEYUSAGE" in ee_policy, "Server policy should have EXTENDEDKEYUSAGE"
    assert "serverAuth" in ee_policy["EXTENDEDKEYUSAGE"], \
        f"Server EKU should have serverAuth, got {ee_policy['EXTENDEDKEYUSAGE']}"


# =============================================================================
# Integration Tests - HTTP layer policy enforcement
# =============================================================================


@pytest.mark.integration
def test_backend_ignores_tampered_country(
    test_client, created_org, created_root_ca, created_intermediate_ca
):
    """
    Even if a POST request tampers with a policy-locked field (e.g., C='ZZ'),
    the backend's policy enforcement will override it with the issuer's value.

    Create a second intermediate CA and verify its C matches the root CA's C,
    not the tampered value.
    """
    from pathlib import Path
    from cryptography import x509

    from app import db as db_module
    import file_crypto
    org = db_module.get_organization_by_id(created_org["org_id"])
    root_row = db_module.get_certificate_by_id_for_organization(created_root_ca["cert_id"], created_org["org_id"])
    root_cert_file = Path(org["org_dir"]) / root_row["cert_path"]
    root_pem = file_crypto.read_encrypted(root_cert_file)
    root_cert = x509.load_pem_x509_certificate(root_pem)
    root_c = root_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value

    # Submit a POST with tampered C field
    from helpers import compute_enddate

    tampered_cert_name = "test_tampered_intermediate"
    response = test_client.post(
        f"/organizations/{created_org['org_id']}/intermediate-ca",
        data={
            "cert_name": tampered_cert_name,
            "C": "ZZ",  # Tampered value
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "Tampered Intermediate",
            "email": "admin@test.com",
            "eccurve": "secp384r1",
            "enddate": compute_enddate(1825),
        },
    )
    assert response.status_code == 200, f"Intermediate creation failed: {response.text}"

    # Load the created cert and verify its C matches root, not 'ZZ'
    tampered_row = db_module.get_latest_certificate_by_name_and_type(
        created_org["org_id"], tampered_cert_name, "intermediate"
    )
    tampered_cert_file = Path(org["org_dir"]) / tampered_row["cert_path"]

    tampered_pem = file_crypto.read_encrypted(tampered_cert_file)
    tampered_cert = x509.load_pem_x509_certificate(tampered_pem)
    tampered_c = tampered_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value

    assert tampered_c == root_c, \
        f"Tampered C should be overwritten to '{root_c}', but got '{tampered_c}'"


@pytest.mark.integration
def test_end_entity_rejects_root_as_issuer(test_client, created_org, created_root_ca):
    """
    POST /end-entity with issuer_type='root' is rejected.

    Only intermediate CAs can issue end-entity certs. Root issuance is not allowed.
    """
    from helpers import compute_enddate

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/end-entity",
        data={
            "cert_type": "server",
            "cert_name": "invalid_issuer",
            "issuer_type": "root",
            "issuer_name": created_root_ca["cert_name"],
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "test.com",
            "email": "",
            "subjectAltName": "DNS:test.com",
            "eccurve": "secp256k1",
            "enddate": compute_enddate(365),
        },
    )

    # Should return error page (200 with error text, not 500)
    assert response.status_code == 200
    assert "issued by an Intermediate CA" in response.text or \
           "must be issued" in response.text or \
           "intermediate" in response.text.lower()


@pytest.mark.integration
def test_end_entity_rejects_unknown_issuer_name(test_client, created_org, created_intermediate_ca):
    """
    POST /end-entity with an issuer_name that doesn't exist is rejected.
    """
    from helpers import compute_enddate

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/end-entity",
        data={
            "cert_type": "server",
            "cert_name": "unknown_issuer",
            "issuer_type": "intermediate",
            "issuer_name": "nonexistent_ca",
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "test.com",
            "email": "",
            "subjectAltName": "DNS:test.com",
            "eccurve": "secp256k1",
            "enddate": compute_enddate(365),
        },
    )

    # Should return error page
    assert response.status_code == 200
    assert "not available" in response.text.lower() or \
           "not found" in response.text.lower() or \
           "error" in response.text.lower()
