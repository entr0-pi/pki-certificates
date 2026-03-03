"""RBAC configuration tests.

Tests that per-route role restrictions are loaded from rbac.json
and enforced correctly by require_roles_config().

Markers: unit (config loading), integration (HTTP enforcement)
"""
import pytest
import json
from pathlib import Path


# =============================================================================
# Unit tests — config loading and validation
# =============================================================================

@pytest.mark.unit
def test_load_rbac_config_returns_dict():
    """rbac.json loads as a dict."""
    from backend.app import _load_rbac_config
    rbac = _load_rbac_config()
    assert isinstance(rbac, dict)
    assert len(rbac) >= 12  # At minimum the 12 restricted routes


@pytest.mark.unit
def test_load_rbac_config_no_comment_keys():
    """_comment keys are stripped by _load_rbac_config()."""
    from backend.app import _load_rbac_config
    rbac = _load_rbac_config()
    assert all(not k.startswith("_") for k in rbac)


@pytest.mark.unit
def test_load_rbac_config_toolbox_admin_only():
    """GET /toolbox is restricted to admin."""
    from backend.app import _load_rbac_config
    rbac = _load_rbac_config()
    assert rbac.get("GET /toolbox") == ["admin"]


@pytest.mark.unit
def test_load_rbac_config_health_admin_and_manager():
    """GET /health is restricted to admin and manager."""
    from backend.app import _load_rbac_config
    rbac = _load_rbac_config()
    assert set(rbac.get("GET /health", [])) == {"admin", "manager"}


@pytest.mark.unit
def test_validate_rbac_config_passes_on_valid_file():
    """_validate_rbac_config() must not raise on valid rbac.json."""
    from backend.app import _validate_rbac_config
    _validate_rbac_config()


# =============================================================================
# Integration tests — HTTP enforcement
# =============================================================================

@pytest.mark.integration
def test_admin_route_returns_403_for_manager(created_org):
    """GET /toolbox (admin-only) must return 403 when called with a manager token."""
    from backend.auth import create_session_jwt, load_auth_settings
    from backend.app import app
    from fastapi.testclient import TestClient

    settings = load_auth_settings()
    manager_token = create_session_jwt("test_manager", "manager", settings)

    with TestClient(app) as manager_client:
        manager_client.cookies.set(settings.cookie_name, manager_token)
        response = manager_client.get("/toolbox")
    assert response.status_code == 403, f"Expected 403 but got {response.status_code}"


@pytest.mark.integration
def test_admin_route_allows_admin(test_client):
    """GET /toolbox (admin-only) must return 200 for admin token."""
    response = test_client.get("/toolbox")
    assert response.status_code == 200


@pytest.mark.integration
def test_admin_manager_route_allows_manager(test_client):
    """GET /health (admin+manager) returns 200 for manager — simpler than checking form."""
    from backend.auth import create_session_jwt, load_auth_settings
    from backend.app import app
    from fastapi.testclient import TestClient

    settings = load_auth_settings()
    manager_token = create_session_jwt("test_manager", "manager", settings)
    with TestClient(app) as manager_client:
        manager_client.cookies.set(settings.cookie_name, manager_token)
        # /health is simpler to test — it's admin+manager, no encryption involved
        response = manager_client.get("/health")
    assert response.status_code == 200, f"Manager should be able to access /health"


@pytest.mark.integration
def test_unrestricted_route_allows_user(test_client):
    """GET /organizations (no role restriction in rbac.json) allows user-role token."""
    from backend.auth import create_session_jwt, load_auth_settings
    from backend.app import app
    from fastapi.testclient import TestClient

    settings = load_auth_settings()
    user_token = create_session_jwt("test_user", "user", settings)
    with TestClient(app) as user_client:
        user_client.cookies.set(settings.cookie_name, user_token)
        response = user_client.get("/organizations")
    assert response.status_code == 200, f"User should be able to list organizations"


@pytest.mark.integration
def test_manager_cannot_access_admin_only_create_org(created_org):
    """POST /create-organization (admin-only) returns 403 for manager."""
    from backend.auth import create_session_jwt, load_auth_settings
    from backend.app import app
    from fastapi.testclient import TestClient

    settings = load_auth_settings()
    manager_token = create_session_jwt("test_manager", "manager", settings)
    with TestClient(app) as manager_client:
        manager_client.cookies.set(settings.cookie_name, manager_token)
        response = manager_client.post(
            "/create-organization",
            data={"org_display_name": "Should Fail"}
        )
    assert response.status_code == 403, f"Manager should not be able to create organizations"
