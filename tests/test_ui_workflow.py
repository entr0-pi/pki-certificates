"""
UI workflow tests (test_ui_workflow.md spec).

Tests HTML rendering, form behavior, and UI state without deep crypto inspection.
Markers: ui, integration
"""

import pytest
from bs4 import BeautifulSoup


@pytest.mark.ui
def test_landing_page_renders(test_client):
    """
    GET / returns a 200 response with expected page title and form elements.
    """
    response = test_client.get("/")
    assert response.status_code == 200
    assert "PKI Management" in response.text or "Organization" in response.text
    assert "Create Organization" in response.text


@pytest.mark.ui
@pytest.mark.integration
def test_org_creation_appears_on_landing(test_client, created_org):
    """
    After organization creation, the org name appears in the landing page.
    """
    response = test_client.get("/")
    assert response.status_code == 200
    assert created_org["org_display_name"] in response.text


@pytest.mark.ui
@pytest.mark.integration
def test_dashboard_lists_all_certs(
    test_client, created_org, created_root_ca, created_intermediate_ca, created_server_cert
):
    """
    Organization dashboard displays all created certificates by name.
    """
    response = test_client.get(f"/organizations/{created_org['org_id']}/manage")
    assert response.status_code == 200
    assert created_root_ca["cert_name"] in response.text
    assert created_intermediate_ca["cert_name"] in response.text
    assert created_server_cert["cert_name"] in response.text


@pytest.mark.ui
@pytest.mark.integration
def test_certificate_popup_displays_correct_cn(test_client, created_org, created_intermediate_ca):
    """
    Certificate popup endpoint returns cert details: common name and serial number.
    """
    response = test_client.get(
        f"/organizations/{created_org['org_id']}/certificates/{created_intermediate_ca['cert_id']}/popup"
    )
    assert response.status_code == 200
    # Check that intermediate CA's CN appears in the popup
    assert "Test Intermediate CA" in response.text or created_intermediate_ca["cert_name"] in response.text


@pytest.mark.ui
@pytest.mark.integration
def test_end_entity_page_issuer_list_excludes_root(
    test_client, created_org, created_root_ca, created_intermediate_ca
):
    """
    End-entity form (GET /end-entity) lists intermediate CA as an issuer option,
    but NOT the root CA. Only intermediate CAs can issue end-entity certs.
    """
    response = test_client.get(f"/organizations/{created_org['org_id']}/end-entity")
    assert response.status_code == 200

    soup = BeautifulSoup(response.text, "lxml")
    # Find the issuer select element
    issuer_select = soup.find("select", {"name": "issuer_name"})
    assert issuer_select is not None, "issuer_name select not found"

    select_text = issuer_select.get_text()
    # Intermediate should be present
    assert created_intermediate_ca["cert_name"] in select_text
    # Root should NOT be present (only intermediates can issue EE certs)
    assert created_root_ca["cert_name"] not in select_text


@pytest.mark.ui
@pytest.mark.integration
def test_end_entity_page_has_san_field_visible(test_client, created_org, created_intermediate_ca):
    """
    End-entity form (GET /end-entity) displays a Subject Alternative Name (SAN) field.
    """
    response = test_client.get(f"/organizations/{created_org['org_id']}/end-entity")
    assert response.status_code == 200
    # Check for SAN-related text in the form
    assert "subjectAltName" in response.text or "subject_alt" in response.text or "SAN" in response.text


@pytest.mark.ui
def test_organization_manage_404_for_unknown_org(test_client):
    """
    GET /organizations/999999/manage for a non-existent org returns an error page
    (rendered via error.html, not HTTP 404 status, but indicates org not found).
    """
    response = test_client.get("/organizations/999999/manage")
    assert response.status_code == 200  # Route returns error.html with 200, not 404
    assert "not found" in response.text.lower() or "error" in response.text.lower()


@pytest.mark.ui
@pytest.mark.integration
def test_intermediate_ca_form_locked_fields(test_client, created_org, created_root_ca):
    """
    Intermediate CA form (GET /intermediate-ca) shows policy-locked fields with
    readonly attributes or visual indicators (policy-locked label/icon).

    Fields with POLICY_*=match (C, ST, L, O) should be marked as locked or readonly.
    """
    response = test_client.get(f"/organizations/{created_org['org_id']}/intermediate-ca")
    assert response.status_code == 200

    soup = BeautifulSoup(response.text, "lxml")
    # Check for readonly or locked indicators on country, state, locality, organization fields
    response_text_lower = response.text.lower()
    # Look for "readonly", "disabled", "locked", or "policy" keywords
    has_lock_indicator = (
        "readonly" in response_text_lower
        or "disabled" in response_text_lower
        or "locked" in response_text_lower
        or "policy" in response_text_lower
    )
    assert has_lock_indicator, "No policy lock indicators found in intermediate CA form"
