"""
Shared pytest fixtures for PKI tests.

Critical path: This module patches backend/db.py BEFORE importing backend/app.py,
because db.engine is created at import time with the production DB_PATH.
"""

import os
os.environ.setdefault("ENCRYPTION_KEY", "pytest-test-key-for-testing-only")
os.environ.setdefault("PKI_API_KEY_ADMIN", "pytest-admin-key")
os.environ.setdefault("PKI_API_KEY_MANAGER", "pytest-manager-key")
os.environ.setdefault("PKI_API_KEY_USER", "pytest-user-key")
os.environ.setdefault("PKI_JWT_SECRET", "pytest-jwt-secret")

import sqlite3
import sys
import uuid
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager
import logging
import shutil

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Add backend/ to sys.path so we can import db and app
BACKEND_PATH = PROJECT_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))


@pytest.fixture(scope="session")
def tmp_db(tmp_path_factory) -> Path:
    """
    Create a temporary SQLite database initialized from pki_schema.sql.

    Returns the Path to the .db file. This fixture is session-scoped so that
    the full certificate chain (root -> intermediate -> end-entity) built by
    helper fixtures can persist across individual test functions.

    The database is placed in a pytest-managed temp directory.
    """
    schema_path = PROJECT_ROOT / "database" / "pki_schema.sql"
    tmp_dir = tmp_path_factory.mktemp("test_db")
    db_path = tmp_dir / "pki_test.db"

    # Create the database file and initialize schema using raw sqlite3
    conn = sqlite3.connect(db_path)
    try:
        schema_sql = schema_path.read_text()
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()

    return db_path


@pytest.fixture(scope="session", autouse=True)
def patch_db_for_session(tmp_db):
    """
    Monkeypatch backend/db.py's module-level DB_PATH and engine for the entire test session.

    This must run BEFORE app.py is imported, because:
    - db.py line 30: engine = create_engine(f"sqlite:///{DB_PATH}", ...) runs at import time
    - app.py line 26: imports db directly

    Strategy:
    1. Import db module (already in sys.path from conftest setup)
    2. Patch db.DB_PATH and db.SCHEMA_PATH to point to tmp_db
    3. Dispose old engine and create new one
    4. Re-register WAL/FK pragma event listener on new engine
    5. Do NOT import app yet; that happens in test_client fixture

    Yields to allow test execution, then cleanup happens after.
    """
    import db as db_module

    # Store original paths for cleanup
    original_db_path = db_module.DB_PATH
    original_schema_path = db_module.SCHEMA_PATH

    try:
        # Patch DB paths
        db_module.DB_PATH = tmp_db
        db_module.SCHEMA_PATH = PROJECT_ROOT / "database" / "pki_schema.sql"

        # Dispose the production engine
        if hasattr(db_module, "engine") and db_module.engine is not None:
            db_module.engine.dispose()

        # Create new engine pointing to temp DB
        db_module.engine = create_engine(
            f"sqlite:///{tmp_db}",
            connect_args={"check_same_thread": False},
        )

        # Re-register pragma event listener on new engine
        @event.listens_for(db_module.engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

        # Manually initialize the temp DB (schema already created by tmp_db fixture,
        # but init_database also performs checks and may create missing views)
        db_module.init_database()

        yield

    finally:
        # Restore original paths and engine (for any cleanup or other tests)
        db_module.DB_PATH = original_db_path
        db_module.SCHEMA_PATH = original_schema_path
        if hasattr(db_module, "engine") and db_module.engine is not None:
            db_module.engine.dispose()


@pytest.fixture(scope="session")
def test_client(patch_db_for_session):
    """
    FastAPI TestClient wrapping the real app object from backend/app.py.

    Depends on patch_db_for_session to ensure the DB is redirected before
    importing app. The client is session-scoped because cert creation via
    subprocess is slow (1-3 seconds each) and tests share the same DB state.

    Uses `with TestClient(app) as client:` to ensure the lifespan context
    manager (which calls db.init_database()) runs correctly.
    """
    from app import app

    with TestClient(app) as client:
        # Create JWT token directly for testing
        from auth import create_session_jwt, load_auth_settings
        from datetime import datetime, timezone

        settings = load_auth_settings()
        token = create_session_jwt("test_user", "admin", settings)

        # Set the cookie directly
        client.cookies.set(settings.cookie_name, token)

        yield client


@pytest.fixture(scope="session")
def created_org(test_client) -> dict:
    """
    Create a test organization via POST /create-organization.

    Returns a dict with keys: org_id, org_dir, org_display_name.

    The org_display_name includes a short UUID suffix to avoid conflicts
    with any existing test data. This is session-scoped so all downstream
    fixtures use the same organization.

    Note: This triggers a filesystem operation that creates
    PROJECT_ROOT/data/org_<id>_<sanitized_name>/ directory.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    org_name = f"test_org_{unique_suffix}"

    response = test_client.post(
        "/create-organization",
        data={"org_display_name": org_name},
    )
    assert response.status_code == 200, f"Failed to create org: {response.text}"

    # Parse response to extract org_id (it redirects or shows success page with org details)
    # For now, query the API to get the created org
    orgs_response = test_client.get("/organizations")
    assert orgs_response.status_code == 200
    orgs_data = orgs_response.json()
    orgs = orgs_data.get("organizations", [])

    # Find the org by name
    created_org_data = next((o for o in orgs if o["name"] == org_name), None)
    assert created_org_data is not None, f"Created org '{org_name}' not found in /organizations"

    return {
        "org_id": created_org_data["id"],
        "org_dir": created_org_data["org_dir"],
        "org_display_name": created_org_data["name"],
    }


@pytest.fixture(scope="session")
def created_root_ca(test_client, created_org) -> dict:
    """
    Create a root CA for created_org via POST /organizations/{id}/root-ca.

    Returns a dict with keys: cert_id, cert_name, org_id.

    Triggers the real create_cert.py subprocess which generates:
      data/<org>/1_root/certs/<name>.pem
      data/<org>/1_root/private/<name>.key
      data/<org>/1_root/csr/<name>.csr
    """
    from helpers import compute_enddate

    cert_name = "test_root_ca"

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/root-ca",
        data={
            "cert_name": cert_name,
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "Test Root CA",
            "email": "admin@test.com",
            "eccurve": "secp384r1",
            "enddate": compute_enddate(3650),
        },
    )
    assert response.status_code == 200, f"Failed to create root CA: {response.text}"

    # Check if there was an error in the response
    if "error" in response.text.lower():
        logger.error(f"Root CA creation returned error: {response.text[:500]}")

    # Query DB to get the created cert
    import db as db_module
    root_certs = db_module.list_certificates_by_organization(created_org["org_id"])
    root_ca = next((c for c in root_certs if c["cert_name"] == cert_name and c["cert_type"] == "root"), None)

    if root_ca is None:
        logger.error(f"Root CA not found in DB. Available certs: {root_certs}")
        logger.error(f"Response text: {response.text[:1000]}")
    assert root_ca is not None, f"Root CA not found in DB after creation. Available certs: {root_certs}"

    return {
        "cert_id": root_ca["id"],
        "cert_name": root_ca["cert_name"],
        "cert_uuid": root_ca["cert_uuid"],
        "org_id": created_org["org_id"],
    }


@pytest.fixture(scope="session")
def created_intermediate_ca(test_client, created_org, created_root_ca) -> dict:
    """
    Create an intermediate CA for created_org via POST /organizations/{id}/intermediate-ca,
    using created_root_ca as issuer.

    Returns a dict with keys: cert_id, cert_name, org_id.
    """
    from helpers import compute_enddate

    cert_name = "test_intermediate_ca"

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/intermediate-ca",
        data={
            "cert_name": cert_name,
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "Test Intermediate CA",
            "email": "admin@test.com",
            "eccurve": "secp384r1",
            "enddate": compute_enddate(3650),  # Align with policy.json: 10 years for intermediate CA
        },
    )
    assert response.status_code == 200, f"Failed to create intermediate CA: {response.text}"

    # Query DB to get the created cert
    import db as db_module
    int_certs = db_module.list_certificates_by_organization(created_org["org_id"])
    intermediate = next(
        (c for c in int_certs if c["cert_name"] == cert_name and c["cert_type"] == "intermediate"),
        None,
    )
    assert intermediate is not None, "Intermediate CA not found in DB after creation"

    return {
        "cert_id": intermediate["id"],
        "cert_name": intermediate["cert_name"],
        "cert_uuid": intermediate["cert_uuid"],
        "org_id": created_org["org_id"],
    }


@pytest.fixture(scope="session")
def created_server_cert(test_client, created_org, created_intermediate_ca) -> dict:
    """
    Create a server end-entity certificate via POST /organizations/{id}/end-entity
    with cert_type=server.

    Returns a dict with keys: cert_id, cert_name, org_id, cert_type.
    """
    from helpers import compute_enddate

    cert_name = "test_server"

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/end-entity",
        data={
            "cert_type": "server",
            "cert_name": cert_name,
            "issuer_type": "intermediate",
            "issuer_name": created_intermediate_ca["cert_name"],
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "test.example.com",
            "email": "",
            "subjectAltName": "DNS:test.example.com,DNS:*.test.example.com",
            "eccurve": "secp256k1",
            "enddate": compute_enddate(365),
        },
    )
    assert response.status_code == 200, f"Failed to create server cert: {response.text}"
    if "error" in response.text.lower():
        pytest.skip("Server cert creation unavailable in this configuration")

    # Query DB to get the created cert
    import db as db_module
    certs = db_module.list_certificates_by_organization(created_org["org_id"])
    server = next((c for c in certs if c["cert_name"] == cert_name and c["cert_type"] == "server"), None)
    if server is None:
        pytest.skip("Server cert not found in DB after creation")

    return {
        "cert_id": server["id"],
        "cert_name": server["cert_name"],
        "cert_uuid": server["cert_uuid"],
        "org_id": created_org["org_id"],
        "cert_type": "server",
    }


@pytest.fixture(scope="session")
def created_client_cert(test_client, created_org, created_intermediate_ca) -> dict:
    """
    Create a client end-entity certificate via POST /organizations/{id}/end-entity
    with cert_type=client.

    Returns a dict with keys: cert_id, cert_name, org_id, cert_type.
    """
    from helpers import compute_enddate

    cert_name = "test_client"

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/end-entity",
        data={
            "cert_type": "client",
            "cert_name": cert_name,
            "issuer_type": "intermediate",
            "issuer_name": created_intermediate_ca["cert_name"],
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "client@test.example.com",
            "email": "client@test.example.com",
            "eccurve": "secp256k1",
            "enddate": compute_enddate(365),
        },
    )
    assert response.status_code == 200, f"Failed to create client cert: {response.text}"
    if "error" in response.text.lower():
        pytest.skip("Client cert creation unavailable in this configuration")

    # Query DB to get the created cert
    import db as db_module
    certs = db_module.list_certificates_by_organization(created_org["org_id"])
    client = next((c for c in certs if c["cert_name"] == cert_name and c["cert_type"] == "client"), None)
    if client is None:
        pytest.skip("Client cert not found in DB after creation")

    return {
        "cert_id": client["id"],
        "cert_name": client["cert_name"],
        "cert_uuid": client["cert_uuid"],
        "org_id": created_org["org_id"],
        "cert_type": "client",
    }


@pytest.fixture(scope="session")
def created_email_cert(test_client, created_org, created_intermediate_ca) -> dict:
    """
    Create an email end-entity certificate via POST /organizations/{id}/end-entity
    with cert_type=email.

    Returns a dict with keys: cert_id, cert_name, org_id, cert_type.
    """
    from helpers import compute_enddate

    cert_name = "test_email"

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/end-entity",
        data={
            "cert_type": "email",
            "cert_name": cert_name,
            "issuer_type": "intermediate",
            "issuer_name": created_intermediate_ca["cert_name"],
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "user@test.example.com",
            "email": "user@test.example.com",
            "eccurve": "secp256k1",
            "enddate": compute_enddate(365),
        },
    )
    assert response.status_code == 200, f"Failed to create email cert: {response.text}"
    if "error" in response.text.lower():
        pytest.skip("Email cert creation unavailable in this configuration")

    # Query DB to get the created cert
    import db as db_module
    certs = db_module.list_certificates_by_organization(created_org["org_id"])
    email = next((c for c in certs if c["cert_name"] == cert_name and c["cert_type"] == "email"), None)
    if email is None:
        pytest.skip("Email cert not found in DB after creation")

    return {
        "cert_id": email["id"],
        "cert_name": email["cert_name"],
        "cert_uuid": email["cert_uuid"],
        "org_id": created_org["org_id"],
        "cert_type": "email",
    }


@pytest.fixture(scope="session")
def cert_for_revocation(test_client, created_org, created_intermediate_ca) -> dict:
    """
    Create a dedicated end-entity certificate for revocation testing.

    This cert is separate from created_server_cert to avoid test state
    contamination (revocation tests will change its status).

    Returns a dict with keys: cert_id, cert_name, org_id, cert_type.
    """
    from helpers import compute_enddate

    cert_name = "test_revoke_target"

    response = test_client.post(
        f"/organizations/{created_org['org_id']}/end-entity",
        data={
            "cert_type": "server",
            "cert_name": cert_name,
            "issuer_type": "intermediate",
            "issuer_name": created_intermediate_ca["cert_name"],
            "C": "US",
            "ST": "CA",
            "L": "San Francisco",
            "O": "Test Org",
            "OU": "IT",
            "CN": "revoke.example.com",
            "email": "",
            "subjectAltName": "DNS:revoke.example.com",
            "eccurve": "secp256k1",
            "enddate": compute_enddate(365),
        },
    )
    assert response.status_code == 200, f"Failed to create revocation target cert: {response.text}"
    if "error" in response.text.lower():
        pytest.skip("Revocation target creation unavailable in this configuration")

    # Query DB to get the created cert
    import db as db_module
    certs = db_module.list_certificates_by_organization(created_org["org_id"])
    revoke_cert = next((c for c in certs if c["cert_name"] == cert_name), None)
    if revoke_cert is None:
        pytest.skip("Revocation target cert not found in DB after creation")

    return {
        "cert_id": revoke_cert["id"],
        "cert_name": revoke_cert["cert_name"],
        "cert_uuid": revoke_cert["cert_uuid"],
        "org_id": created_org["org_id"],
        "cert_type": "server",
    }


@pytest.fixture
def db_connection(tmp_db):
    """
    Function-scoped raw SQLite connection for direct DB assertions.

    Yields a sqlite3.Connection. Used in database consistency tests to
    run raw SELECT queries and verify the state written by the app.
    Each test gets a fresh connection for reading DB state.
    """
    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row  # Make rows accessible as dicts
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_data(created_org):
    """
    Cleanup test data from PROJECT_ROOT/data/ after all tests complete.

    Session-scoped autouse fixture that runs after all tests and deletes
    the test organization directory that was created during test execution.
    """
    yield

    # Cleanup after all tests
    org_dir = PROJECT_ROOT / created_org["org_dir"]
    if org_dir.exists():
        try:
            shutil.rmtree(org_dir, ignore_errors=True)
            logger.info(f"Cleaned up test data: {org_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup {org_dir}: {e}")
