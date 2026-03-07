"""
FastAPI application for PKI Management System
Provides web interface for certificate management operations
"""

from fastapi import FastAPI, Request, Form, Query, HTTPException
from fastapi.responses import HTMLResponse, Response, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import subprocess
from pathlib import Path
import logging
import json
import tempfile
import sys
import os
import uuid
import re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from sqlalchemy.exc import IntegrityError as SAIntegrityError

# Import ConsistencyChecker at module level to avoid sys.path manipulation in handlers
# This is done once at startup, not per-request
_scripts_path = str(Path(__file__).parent.parent / "scripts")
if _scripts_path not in sys.path:
    sys.path.insert(0, _scripts_path)

try:
    from check_consistency import ConsistencyChecker
except ImportError as e:
    logger_tmp = logging.getLogger(__name__)
    logger_tmp.warning(f"Failed to import ConsistencyChecker at module load: {e}. Consistency check endpoint will be unavailable.")
    ConsistencyChecker = None

if __package__:
    from . import db
    from . import file_crypto
    from .auth import (
        AuthConfigError,
        AuthSettings,
        create_session_jwt,
        load_auth_settings,
        resolve_role,
        verify_session_jwt,
    )
    from .helpers import compute_enddate
    from .folder import PkiLayout, init_root_workspace, init_intermediate_workspace, init_end_entity_workspace
    from .path_config import get_project_root, get_data_dir, get_db_path, is_under_temp_dir
else:
    import db
    import file_crypto
    from auth import (
        AuthConfigError,
        AuthSettings,
        create_session_jwt,
        load_auth_settings,
        resolve_role,
        verify_session_jwt,
    )
    from helpers import compute_enddate
    from folder import PkiLayout, init_root_workspace, init_intermediate_workspace, init_end_entity_workspace
    from path_config import get_project_root, get_data_dir, get_db_path, is_under_temp_dir

# Configure logging with support for PKI_LOG_LEVEL environment variable
log_level = os.environ.get("PKI_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))
logger = logging.getLogger(__name__)

# RFC 5280 valid revocation reason codes
VALID_REVOCATION_REASONS = frozenset({
    "unspecified", "keyCompromise", "caCompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold",
    "removeFromCRL", "privilegeWithdrawn", "aACompromise",
})

# Default subprocess timeout in seconds (can be overridden by environment variable)
SUBPROCESS_TIMEOUT = int(os.environ.get("PKI_SUBPROCESS_TIMEOUT_SECONDS", "120"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    Replaces deprecated on_event decorators.
    """
    # Startup
    try:
        auth_settings = load_auth_settings()
        app.state.auth_settings = auth_settings
        resolved_data_dir = get_data_dir()
        resolved_db_path = get_db_path()
        logger.info("Configured data directory: %s", resolved_data_dir)
        logger.info("Configured database path: %s", resolved_db_path)
        logger.info("Configured session duration: %s minutes", auth_settings.session_minutes)
        if is_under_temp_dir(resolved_data_dir):
            logger.warning(
                "PKI_DATA_DIR points to a temp location (%s). This is not recommended for persistent PKI data.",
                resolved_data_dir,
            )
        auto_reinit = os.environ.get("PKI_DB_AUTO_REINIT", "false").strip().lower() in ("1", "true", "yes", "on")
        db.init_database(auto_recreate_invalid=auto_reinit)
        _validate_rbac_config()
        logger.info("RBAC configuration loaded and validated")

        # Cache config files at startup to avoid re-reading on every request (issue #17)
        # Note: role_defaults (root, intermediate, end-entity) are loaded per-request as needed
        app.state.rbac_config = _load_rbac_config()
        app.state.ui_policy = _load_ui_policy()
        logger.info("Configuration caching initialized")

        logger.info("Application started successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        logger.error("Application startup aborted. Initialize DB from schema or set PKI_DB_AUTO_REINIT=true.")
        raise

    yield

    # Shutdown (if needed in the future)
    logger.info("Application shutting down")


# Initialize FastAPI app with lifespan
app = FastAPI(title="PKI Management System", lifespan=lifespan)

PROJECT_ROOT = get_project_root()
FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Mount static files
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")

# Configure Jinja2 templates
templates = Jinja2Templates(directory=str(FRONTEND_DIR / "templates"))


# Exception handler for 403 (Insufficient permissions)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc):
    """Handle HTTP exceptions, returning HTML for HTML routes and JSON for API routes."""
    if exc.status_code == 403:
        # Check if this is an HTML route
        path = request.url.path
        is_html_route = (
            path.startswith("/organizations/") and (
                "root-ca" in path or "intermediate-ca" in path or
                "end-entity" in path or "renew" in path or "manage" in path or "create-certificate" in path or
                "popup" in path or "revoke" in path or "download" in path
            )
        ) or path in {"/", "/toolbox", "/create-organization"}

        if is_html_route:
            try:
                # Return HTML 403 page
                role = getattr(request.state, "role", "unknown")
                return templates.TemplateResponse(
                    "403.html",
                    {"request": request, "role": role},
                    status_code=403,
                )
            except Exception as template_error:
                # If template rendering fails, fall back to plain HTML
                logger.warning(f"Failed to render 403.html template: {template_error}")
                return Response(
                    content=f"<html><body><h1>403 Access Denied</h1><p>Your role does not have permission to access this page.</p></body></html>",
                    status_code=403,
                    media_type="text/html",
                )
        else:
            # Return JSON 403 for API/non-HTML routes
            return JSONResponse(
                {"detail": "Insufficient permissions"},
                status_code=403,
            )

    # Default behavior: raise the exception for other status codes
    raise exc


AUTH_EXEMPT_PATHS = {"/auth/login", "/auth/session", "/auth/logout", "/healthz"}


def _is_crl_route(path: str) -> bool:
    """Check if path is a public CRL endpoint (no authentication required)."""
    return "/crl/" in path


def _requires_non_html_unauthorized(path: str) -> bool:
    if path == "/health" or path == "/organizations" or path.startswith("/api/"):
        return True
    if "/crl/" in path:
        return True
    if path.endswith("/download") or path.endswith("/private-key/plain"):
        return True
    return False


@app.middleware("http")
async def auth_session_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static/") or path in AUTH_EXEMPT_PATHS or _is_crl_route(path):
        return await call_next(request)

    settings: AuthSettings = request.app.state.auth_settings
    token = request.cookies.get(settings.cookie_name, "")
    if not token:
        if _requires_non_html_unauthorized(path):
            return Response(content="Unauthorized", status_code=401)
        return RedirectResponse(url="/auth/login", status_code=302)

    try:
        claims = verify_session_jwt(token, settings)
        request.state.auth = {"sub": claims.get("sub"), "exp": claims.get("exp"), "role": claims.get("role", "user")}
        request.state.role = claims.get("role", "user")
    except Exception:
        if _requires_non_html_unauthorized(path):
            return Response(content="Unauthorized", status_code=401)
        return RedirectResponse(url="/auth/login", status_code=302)

    return await call_next(request)


@app.middleware("http")
async def csrf_protection_middleware(request: Request, call_next):
    """CSRF protection via custom header check (issue #2).

    State-mutating requests (POST, PUT, DELETE, PATCH) require the X-Requested-With header
    OR a valid session cookie (SameSite protection is the primary defense).
    This prevents simple cross-origin form submissions.

    Note: SameSite=strict cookie is the primary CSRF defense; X-Requested-With header
    is an additional defense for AJAX requests.
    """
    if request.method in {"POST", "PUT", "DELETE", "PATCH"}:
        # Static files and auth endpoints are exempt
        if request.url.path.startswith("/static/") or request.url.path in AUTH_EXEMPT_PATHS:
            return await call_next(request)

        # CSRF check: either have X-Requested-With header OR valid session cookie
        # In practice, the SameSite cookie provides most of the protection
        settings: AuthSettings = request.app.state.auth_settings
        has_session_cookie = bool(request.cookies.get(settings.cookie_name, ""))
        x_requested_with = request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest"

        # If no session cookie (public endpoints), require CSRF header
        if not has_session_cookie and not x_requested_with:
            logger.warning(
                "CSRF check failed: missing session cookie AND X-Requested-With header for %s %s from %s",
                request.method,
                request.url.path,
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                {"detail": "Missing required X-Requested-With header or session cookie"},
                status_code=403,
            )

    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security response headers (issue #8)."""
    response = await call_next(request)

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # MIME sniffing protection
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Content Security Policy: allow self resources only
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'"
    )

    # HSTS for HTTPS connections
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    return response


# Role-based access control
def _check_role(request: Request, allowed_roles: tuple[str, ...]) -> None:
    """Check if request.state.role is in allowed_roles. Raises HTTPException if not."""
    from fastapi import HTTPException
    role = getattr(request.state, "role", "user")
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


def require_roles(*roles: str):
    """FastAPI Depends-compatible role guard."""
    from fastapi import Depends
    async def _role_check(request: Request):
        _check_role(request, roles)
    return Depends(_role_check)


def require_roles_config():
    """FastAPI Depends-compatible role guard driven by backend/config/rbac.json.

    Looks up 'METHOD /path/template' in rbac.json; absent key = any authenticated user.
    Uses cached config from app.state.rbac_config (loaded at startup).
    Usage:
        @app.get("/some/path", dependencies=[require_roles_config()])
    """
    from fastapi import Depends

    async def _rbac_check(request: Request):
        route = request.scope.get("route")
        if route is None:
            return
        key = f"{request.method} {route.path}"
        # Use cached config from startup (issue #17)
        rbac = getattr(request.app.state, "rbac_config", {})
        allowed = rbac.get(key)
        if allowed is None:
            # No RBAC rule for this endpoint - allow any authenticated user
            return
        # RBAC rule exists - check if user's role is in the allowed list
        _check_role(request, tuple(allowed))

    return Depends(_rbac_check)


def _is_route_allowed_for_role(request: Request, role: str, method: str, route_path: str) -> bool:
    """Evaluate route-level RBAC for a role (default-allow when route is missing from config)."""
    rbac = getattr(request.app.state, "rbac_config", {})
    allowed = rbac.get(f"{method.upper()} {route_path}")
    if allowed is None:
        return True
    return role in allowed


def _build_ui_permissions(request: Request, role: str) -> dict[str, bool]:
    """Expose role-aware UI action availability while backend guards remain authoritative."""
    return {
        "can_create_root": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/root-ca"),
        "can_create_intermediate": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/intermediate-ca"),
        "can_create_end_entity": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/end-entity"),
        "can_create_unified": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/create-certificate"),
        "can_renew": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/certificates/{cert_id}/renew"),
        "can_revoke": _is_route_allowed_for_role(request, role, "POST", "/organizations/{org_id}/certificates/{cert_id}/revoke"),
        "can_download_cert": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/certificates/{cert_id}/download"),
        "can_download_private_key": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/certificates/{cert_id}/private-key/plain"),
        "can_view_popup": _is_route_allowed_for_role(request, role, "GET", "/organizations/{org_id}/certificates/{cert_id}/popup"),
        "can_run_consistency": _is_route_allowed_for_role(request, role, "GET", "/api/check-consistency"),
    }


@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request):
    settings: AuthSettings = request.app.state.auth_settings
    token = request.cookies.get(settings.cookie_name, "")
    is_authenticated = False
    if token:
        try:
            verify_session_jwt(token, settings)
            is_authenticated = True
        except Exception:
            is_authenticated = False

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None, "is_authenticated": is_authenticated},
    )


@app.post("/auth/session")
async def create_auth_session(request: Request, api_key: str = Form(...)):
    settings: AuthSettings = request.app.state.auth_settings
    role = resolve_role(api_key, settings)
    if not role:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid API key."},
            status_code=401,
        )

    # Create a unique session identifier combining role and a random UUID (issue #19)
    session_id = f"{role}-{str(uuid.uuid4())}"
    token = create_session_jwt(session_id, role, settings)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.session_minutes * 60,
        path="/",
        domain=settings.cookie_domain,
    )
    return response


@app.post("/auth/logout")
async def logout_auth_session(request: Request):
    settings: AuthSettings = request.app.state.auth_settings
    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie(
        key=settings.cookie_name,
        path="/",
        domain=settings.cookie_domain,
    )
    return response


def _resolve_org_path(org_dir: str | Path) -> Path:
    """
    Resolve organization directory from DB values.
    Supports:
    - absolute paths (returned as-is)
    - legacy values like "data/org_x" (mapped under configured PKI_DATA_DIR)
    - relative values like "org_x" (mapped under configured PKI_DATA_DIR)
    """
    p = Path(org_dir)
    if p.is_absolute():
        return p
    data_root = get_data_dir()
    if p.parts and p.parts[0].lower() == "data":
        return data_root.joinpath(*p.parts[1:])
    return data_root / p


def list_end_entity_issuers(org_dir: str) -> list[dict[str, str]]:
    """
    End-entity certs must be issued by intermediate CAs only.
    Filters out revoked intermediate CAs.
    """
    layout = PkiLayout()
    org_path = _resolve_org_path(org_dir)
    issuers: list[dict[str, str]] = []

    # Get organization to fetch its ID
    org_info = db.get_organization_by_dir(org_dir)
    if not org_info:
        return issuers

    all_certs = db.list_certificates_by_organization(org_info["id"])
    for cert in all_certs:
        if cert["cert_type"] != "intermediate" or cert["status"] != "active":
            continue
        cert_path = org_path / cert["cert_path"]
        if cert_path.exists():
            issuers.append(
                {
                    "name": cert["cert_name"],
                    "type": "intermediate",
                    "display": f"{cert['cert_name']} (Intermediate CA)",
                }
            )
    return issuers


def get_latest_active_root_ca_name(org_id: int) -> str | None:
    certs = db.list_certificates_by_organization(org_id)
    roots = [c for c in certs if c["cert_type"] == "root" and c["status"] == "active"]
    if not roots:
        return None
    return roots[0]["cert_name"]


def _sanitize_cert_name(cert_name: str) -> str:
    """Remove non-alphanumeric characters except underscores and hyphens."""
    return "".join(c for c in cert_name if c.isalnum() or c in ("_", "-"))


def _get_request_user(request: Request) -> str:
    """Extract user identity from request state for audit logging."""
    return request.state.auth.get("sub", "unknown") if hasattr(request.state, "auth") else "unknown"


def _handle_renewal_revocation(org: dict, org_id: int, renewal_of_cert_id: str) -> None:
    """
    Auto-revoke the previous certificate when a renewal is created.
    Silently ignores errors to prevent renewal from failing if revocation fails.
    """
    if not (renewal_of_cert_id and renewal_of_cert_id.strip()):
        return
    try:
        old_cert_id = int(renewal_of_cert_id)
        old_cert = db.get_certificate_by_id_for_organization(old_cert_id, org_id)
        if old_cert:
            db.revoke_certificate(old_cert_id, "superseded")
            # Audit: old cert superseded by renewal
            try:
                db.log_certificate_operation(old_cert_id, "renewed", None, json.dumps({"superseded_by": "renewal"}))
            except Exception as e:
                logger.warning(f"Audit log failed (non-fatal): {e}")
            if old_cert["issuer_cert_id"]:
                issuer_cert = db.get_certificate_by_id_for_organization(old_cert["issuer_cert_id"], org_id)
                if issuer_cert:
                    _trigger_crl_regeneration(org, old_cert["issuer_cert_id"], issuer_cert)
        else:
            logger.warning(f"Renewal attempt with non-existent cert_id {old_cert_id} for org_id {org_id}")
    except (ValueError, Exception):
        pass  # Silently ignore if revocation/CRL regeneration fails


def _build_issuer_subject_map(org_dir: str, issuers: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    subject_map: dict[str, dict[str, str]] = {}
    org_info = db.get_organization_by_dir(org_dir)
    if not org_info:
        return subject_map
    certs = db.list_certificates_by_organization(org_info["id"])
    cert_by_name = {c["cert_name"]: c for c in certs if c["status"] == "active"}
    for issuer in issuers:
        cert_row = cert_by_name.get(issuer["name"])
        if not cert_row:
            continue
        cert_path = _resolve_org_path(org_dir) / cert_row["cert_path"]
        if cert_path.exists():
            subject_map[issuer["name"]] = _read_cert_subject_fields(cert_path)
    return subject_map


def _policy_locked_fields(policy_role: str) -> list[str]:
    policy = _load_role_policy(policy_role)
    locked = []
    for k in ("C", "ST", "L", "O", "OU", "CN", "email"):
        policy_key = "EMAIL" if k == "email" else k
        if str(policy.get(f"POLICY_{policy_key}", "optional")).strip().lower() == "match":
            locked.append(k)
    return locked


def _read_cert_subject_fields(cert_path: Path) -> dict[str, str]:
    cert = x509.load_pem_x509_certificate(file_crypto.read_encrypted(cert_path))
    subject = cert.subject

    def _get(oid: NameOID) -> str:
        attrs = subject.get_attributes_for_oid(oid)
        return attrs[0].value.strip() if attrs else ""

    return {
        "C": _get(NameOID.COUNTRY_NAME),
        "ST": _get(NameOID.STATE_OR_PROVINCE_NAME),
        "L": _get(NameOID.LOCALITY_NAME),
        "O": _get(NameOID.ORGANIZATION_NAME),
        "OU": _get(NameOID.ORGANIZATIONAL_UNIT_NAME),
        "CN": _get(NameOID.COMMON_NAME),
        "email": _get(NameOID.EMAIL_ADDRESS),
    }


def _load_role_policy(role: str) -> dict:
    policy_path = PROJECT_ROOT / "backend" / "config" / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    return policy["role_defaults"][role]


def _load_ui_policy() -> dict:
    """Load UI-specific configuration from policy.json."""
    policy_path = PROJECT_ROOT / "backend" / "config" / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    return policy.get("ui", {})


_KNOWN_ROLES = frozenset({"admin", "manager", "user"})
_KNOWN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


def _load_rbac_config() -> dict[str, list[str]]:
    """Load per-route role restrictions from rbac.json.

    Returns a dict mapping 'METHOD /path/template' to a list of allowed roles.
    An absent key means the route is accessible to any authenticated user.
    Follows the same json.loads(path.read_text()) pattern as _load_role_policy().
    """
    rbac_path = PROJECT_ROOT / "backend" / "config" / "rbac.json"
    raw = json.loads(rbac_path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _validate_rbac_config() -> None:
    """Validate rbac.json at startup. Raises ValueError on any misconfiguration."""
    rbac_path = PROJECT_ROOT / "backend" / "config" / "rbac.json"
    if not rbac_path.exists():
        raise ValueError(f"rbac.json not found at {rbac_path}")
    try:
        rbac = _load_rbac_config()
    except json.JSONDecodeError as exc:
        raise ValueError(f"rbac.json is not valid JSON: {exc}") from exc

    for key, roles in rbac.items():
        parts = key.split(" ", 1)
        if len(parts) != 2:
            raise ValueError(f"rbac.json: invalid key format {key!r}. Expected 'METHOD /path'.")
        method, path = parts
        if method not in _KNOWN_METHODS:
            raise ValueError(f"rbac.json: unknown HTTP method {method!r} in key {key!r}.")
        if not path.startswith("/"):
            raise ValueError(f"rbac.json: path must start with '/' in key {key!r}.")
        if not isinstance(roles, list) or not roles:
            raise ValueError(f"rbac.json: roles for {key!r} must be a non-empty list.")
        for role in roles:
            if role not in _KNOWN_ROLES:
                raise ValueError(f"rbac.json: unknown role {role!r} in key {key!r}. Known: {sorted(_KNOWN_ROLES)}.")


def _apply_match_policy_fields(
    frontend_values: dict[str, str],
    issuer_subject_fields: dict[str, str],
    issuer_policy: dict,
) -> dict[str, str]:
    """
    Override subject fields according to POLICY_*=match.
    """
    out = dict(frontend_values)
    key_map = {"C": "C", "ST": "ST", "L": "L", "O": "O", "OU": "OU", "CN": "CN", "EMAIL": "email"}
    for policy_key, form_key in key_map.items():
        rule = str(issuer_policy.get(f"POLICY_{policy_key}", "optional")).strip().lower()
        if rule == "match":
            issuer_val = issuer_subject_fields.get(form_key, "")
            if not issuer_val:
                raise ValueError(f"Issuer is missing required field for POLICY_{policy_key}=match.")
            out[form_key] = issuer_val
    return out


def _run_create_cert_subprocess(params: dict) -> str:
    """Execute backend/create_cert.py with a temporary JSON params file."""
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(params, tmp, indent=2)
            temp_path = Path(tmp.name)

        try:
            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "backend" / "create_cert.py"), "--params", str(temp_path)],
                capture_output=True,
                text=True,
                check=True,
                cwd=PROJECT_ROOT,
                timeout=SUBPROCESS_TIMEOUT,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Certificate creation subprocess failed with exit code {e.returncode}")
            logger.error(f"Subprocess stderr: {e.stderr}")
            logger.error(f"Subprocess stdout: {e.stdout}")
            raise
        except subprocess.TimeoutExpired as e:
            logger.error(f"Certificate creation subprocess timed out after {SUBPROCESS_TIMEOUT}s")
            raise TimeoutError(f"Certificate creation process timed out after {SUBPROCESS_TIMEOUT} seconds") from e
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """
    Landing page showing existing organizations and option to create new ones.
    Displays existing organizations from database and a form to create new organization.
    Also shows timeline of certificates expiring in the next 90 days.
    """
    try:
        # Keep status in sync before computing dashboard statistics
        db.expire_overdue_certificates()

        # Fetch all organizations from database
        organizations = db.list_organizations()
        org_count = len(organizations)

        # Fetch global certificate statistics from certificate_summary view
        cert_stats = db.get_certificate_statistics(org_id=None)

        # Load UI configuration for timeline window (use cached value, set at startup line 110)
        ui_policy = request.app.state.ui_policy
        dashboard_policy = ui_policy.get("dashboard", {})
        expiration_days = dashboard_policy.get("alert_window_days", 90)
        warning_days = dashboard_policy.get("warning_days", 60)
        critical_days = dashboard_policy.get("critical_days", 30)

        # Fetch expiring certificates for timeline
        expiring_certs = db.get_expiring_certificates(
            days_ahead=expiration_days,
            critical_days=critical_days,
            warning_days=warning_days
        )

        return templates.TemplateResponse(
            "landing.html",
            {
                "request": request,
                "role": getattr(request.state, "role", "user"),
                "organizations": organizations,
                "org_count": org_count,
                "stats": cert_stats,
                "expiring_certificates": expiring_certs,
                "expiration_days": expiration_days,
                "warning_days": warning_days,
                "critical_days": critical_days
            }
        )
    except Exception as e:
        logger.exception("Error loading landing page")
        # Return page with empty organization list if database error
        return templates.TemplateResponse(
            "landing.html",
            {
                "request": request,
                "role": getattr(request.state, "role", "user"),
                "organizations": [],
                "org_count": 0,
                "stats": {"total": 0, "active": 0, "expired": 0, "revoked": 0, "superseded": 0},
                "expiring_certificates": [],
                "error": "An unexpected error occurred. Please contact an administrator."
            }
        )


@app.get("/toolbox", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def toolbox_page(request: Request):
    """Toolbox landing page for future utility tools."""
    return templates.TemplateResponse("toolbox.html", {"request": request})


@app.post("/create-organization", dependencies=[require_roles_config()])
async def create_organization_endpoint(
    request: Request,
    org_display_name: str = Form(...),
):
    """
    Handle organization creation form submission.
    1. Auto-generates folder name as org_{id}_{sanitized_name}
    2. Calls backend/folder.py init to create the organization structure
    3. Inserts organization record into the database

    Args:
        org_display_name: Human-readable organization name (e.g., "Acme Corporation")
    """
    try:
        layout = PkiLayout()

        # Sanitize display name for folder component: lowercase, replace special chars with underscores
        sanitized_name = org_display_name.lower().replace(" ", "_").replace("-", "_")
        sanitized_name = "".join(c for c in sanitized_name if c.isalnum() or c == "_")
        sanitized_name = sanitized_name.strip("_")  # Remove leading/trailing underscores
        if not sanitized_name:
            raise ValueError("Organization name must contain valid characters")

        # SECURITY FIX (issue #16): Use org_id from database insert instead of pre-insert count
        # This eliminates race condition where two concurrent requests could derive the same folder name
        # Insert organization into database first to get guaranteed unique org_id
        org_id = db.create_organization(
            org_dir="",  # Will be updated below after folder is created
            name=org_display_name
        )

        # Now use the returned org_id (guaranteed unique) for folder naming
        org_name_clean = layout.org_naming_pattern.format(id=org_id, name=sanitized_name)
        org_dir_absolute = str(get_data_dir() / org_name_clean)

        # Create organization folder structure using folder.py
        try:
            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "backend" / "folder.py"), "init", org_name_clean],
                capture_output=True,
                text=True,
                check=True,
                cwd=PROJECT_ROOT,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.exception(f"Organization folder creation subprocess timed out after {SUBPROCESS_TIMEOUT}s for org_id={org_id}")
            raise TimeoutError(f"Organization creation process timed out after {SUBPROCESS_TIMEOUT} seconds")

        logger.info(f"Organization folders created: {org_name_clean}")
        logger.info(f"Output: {result.stdout}")

        # Update organization with actual folder path
        db.update_organization_dir(org_id, org_dir_absolute)

        logger.info(f"Organization saved to database with ID: {org_id}")

        # Return success page with organization details
        return templates.TemplateResponse(
            "success.html",
            {
                "request": request,
                "org_id": org_id,
                "org_name": org_dir_absolute,
                "org_display_name": org_display_name,
                "output": result.stdout,
                "db_saved": True
            }
        )

    except SAIntegrityError as e:
        logger.exception(f"Database integrity error during organization creation for {org_display_name}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization '{org_display_name}' already exists in the database.",
                "org_name": org_display_name
            }
        )
    except subprocess.CalledProcessError as e:
        logger.exception(f"Failed to create organization folders")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": "Failed to create organization folders. Please contact an administrator.",
                "org_name": org_display_name
            }
        )
    except TimeoutError as e:
        logger.exception("Organization creation subprocess timed out")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": "Organization creation process timed out. Please try again.",
                "org_name": org_display_name
            }
        )
    except Exception as e:
        logger.exception(f"Unexpected error during organization creation")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": "An unexpected error occurred. Please contact an administrator.",
                "org_name": org_display_name
            }
        )


@app.get("/healthz")
async def healthz():
    """
    Lightweight health check for container orchestrators.
    No authentication required - returns immediately when app is up.
    Used by Kubernetes, ECS, Fly.io, Cloud Run for availability probes.
    """
    return {"status": "ok"}


@app.get("/health", dependencies=[require_roles_config()])
async def health_check():
    """Health check endpoint with database status"""
    db_health = db.check_database_health()
    return {
        "status": "healthy" if db_health['status'] == 'healthy' else "degraded",
        "database": db_health
    }


@app.get("/organizations", dependencies=[require_roles_config()])
async def list_all_organizations():
    """List all organizations from the database"""
    try:
        organizations = db.list_organizations()
        return {
            "count": len(organizations),
            "organizations": organizations
        }
    except Exception as e:
        logger.error(f"Failed to list organizations: {e}")
        return {
            "error": str(e),
            "organizations": []
        }


@app.get("/organizations/{org_id}/manage", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def manage_organization(request: Request, org_id: int):
    """
    Manage organization page - shows dashboard with organization statistics.
    Always shows the dashboard; the 'Create root CA' button is hidden if root CA exists.
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    root_ca_exists = bool(get_latest_active_root_ca_name(org_id))

    # Always show dashboard
    try:
        # Load UI policy for expiration thresholds
        ui_policy = request.app.state.ui_policy
        dashboard_policy = ui_policy.get("dashboard", {})
        expiration_days = dashboard_policy.get("alert_window_days", 90)
        critical_days = dashboard_policy.get("critical_days", 30)

        stats = db.get_organization_stats(org_id)
        certificates = db.list_certificates_by_organization(org_id)
        audit_logs = db.get_recent_audit_logs(org_id, limit=20)
        hierarchy = db.get_certificate_hierarchy(org_id)
        return templates.TemplateResponse(
            "organization_dashboard.html",
            {
                "request": request,
                "organization": org,
                "stats": stats,
                "certificates": certificates,
                "audit_logs": audit_logs,
                "hierarchy": hierarchy,
                "root_ca_exists": root_ca_exists,
                "role": getattr(request.state, "role", "user"),
                "ui_permissions": _build_ui_permissions(request, getattr(request.state, "role", "user")),
                "expiration_days": expiration_days,
                "critical_days": critical_days,
            },
        )
    except Exception as e:
        logger.error(f"Error loading organization dashboard: {e}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Error loading dashboard: {str(e)}",
                "org_name": org["name"],
            },
        )


@app.get("/organizations/{org_id}/create-certificate", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def create_certificate_page(request: Request, org_id: int):
    """Unified certificate creation page with root/intermediate/end-entity modes."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    role = getattr(request.state, "role", "user")
    ui_permissions = _build_ui_permissions(request, role)
    root_ca = get_latest_active_root_ca_name(org_id)
    root_ca_exists = bool(root_ca)
    issuer_subject_fields = {}
    locked_fields_intermediate = []
    if root_ca:
        layout = PkiLayout()
        root_cert = db.get_latest_certificate_by_name_and_type(org_id, root_ca, "root")
        root_artifact = root_cert["cert_uuid"] if root_cert and root_cert.get("cert_uuid") else root_ca
        cert_path = _resolve_org_path(org["org_dir"]) / layout.root_dirname / layout.certs_dirname / f"{root_artifact}.pem.enc"
        if cert_path.exists():
            issuer_subject_fields = _read_cert_subject_fields(cert_path)
        locked_fields_intermediate = _policy_locked_fields("root")

    issuers = list_end_entity_issuers(org["org_dir"])
    issuer_subject_map = _build_issuer_subject_map(org["org_dir"], issuers)
    locked_fields_end_entity = _policy_locked_fields("intermediate")

    # Load DEFAULT_DAYS from policy for UI
    root_policy = _load_role_policy("root")
    intermediate_policy = _load_role_policy("intermediate")
    server_policy = _load_role_policy("end-entity-server")

    return templates.TemplateResponse(
        "create_certificate.html",
        {
            "request": request,
            "organization": org,
            "role": role,
            "ui_permissions": ui_permissions,
            "root_ca": root_ca,
            "root_ca_exists": root_ca_exists,
            "issuer_subject_fields": issuer_subject_fields,
            "locked_fields_intermediate": locked_fields_intermediate,
            "issuers": issuers,
            "issuer_subject_map_json": json.dumps(issuer_subject_map),
            "locked_fields_end_entity": locked_fields_end_entity,
            "default_days_root": int(root_policy["DEFAULT_DAYS"]),
            "default_days_intermediate": int(intermediate_policy["DEFAULT_DAYS"]),
            "default_days_end_entity": int(server_policy["DEFAULT_DAYS"]),
            "default_curve_root": root_policy.get("ec_curve", "secp384r1"),
            "default_curve_intermediate": intermediate_policy.get("ec_curve", "secp384r1"),
            "default_curve_end_entity": server_policy.get("ec_curve", "secp256r1"),
        },
    )


@app.get("/organizations/{org_id}/certificates/{cert_id}/popup", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def certificate_popup(request: Request, org_id: int, cert_id: int):
    """
    Popup page with certificate record details.
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
    if not cert:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Certificate ID {cert_id} not found for organization {org_id}.",
                "org_name": org["name"],
            },
        )

    # Read SANs from DB
    db_sans = db.list_sans(cert_id)
    san_str = ", ".join(f"{s['san_type']}:{s['san_value']}" for s in db_sans) if db_sans else "-"

    # Get additional extension data for template (may be None for legacy certs)
    basic_constraints = db.get_basic_constraints(cert_id)
    key_usage = db.get_key_usage(cert_id)
    ekus = db.list_extended_key_usage(cert_id)

    # Fetch issuer certificate details if issuer_cert_id is present
    issuer_cert = None
    if cert.get("issuer_cert_id"):
        issuer_cert = db.get_certificate_by_id_for_organization(
            cert["issuer_cert_id"], org_id
        )

    return templates.TemplateResponse(
        "certificate_popup.html",
        {
            "request": request,
            "organization": org,
            "certificate": cert,
            "san_str": san_str,
            "basic_constraints": basic_constraints,
            "key_usage": key_usage,
            "extended_key_usages": ekus,
            "issuer_cert": issuer_cert,
            "ui_permissions": _build_ui_permissions(
                request, getattr(request.state, "role", "user")
            ),
        },
    )


@app.get("/organizations/{org_id}/certificates/{cert_id}/renew", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def renew_certificate_page(request: Request, org_id: int, cert_id: int):
    """
    Renewal page: pre-fills all certificate data from the original,
    user only changes cert_name and enddate.
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
    if not cert:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Certificate ID {cert_id} not found for organization {org_id}.",
                "org_name": org["name"],
            },
        )

    cert_type = cert["cert_type"]
    if cert_type == "root":
        form_action = f"/organizations/{org_id}/root-ca"
    elif cert_type == "intermediate":
        form_action = f"/organizations/{org_id}/intermediate-ca"
    else:
        form_action = f"/organizations/{org_id}/end-entity"

    # Read SANs from database
    db_sans = db.list_sans(cert_id)
    san_str = ", ".join(f"{s['san_type']}:{s['san_value']}" for s in db_sans) if db_sans else ""

    # Look up issuer name for end-entity certs
    issuer_name = None
    issuer_type = None
    if cert_type in ("server", "client", "email", "ocsp") and cert.get("issuer_cert_id"):
        issuer_cert = db.get_certificate_by_id_for_organization(cert["issuer_cert_id"], org_id)
        if issuer_cert:
            issuer_name = issuer_cert["cert_name"]
            issuer_type = issuer_cert["cert_type"]

    suggested_name = cert["cert_name"]

    return templates.TemplateResponse(
        "renew_certificate.html",
        {
            "request": request,
            "organization": org,
            "certificate": cert,
            "form_action": form_action,
            "san_str": san_str,
            "issuer_name": issuer_name,
            "issuer_type": issuer_type,
            "suggested_name": suggested_name,
        },
    )


@app.get("/organizations/{org_id}/crl/{issuer_name}")
async def download_crl(org_id: int, issuer_name: str, issuer_cert_id: int | None = Query(default=None)):
    """
    Serve latest CRL file for an issuer scoped to one organization.
    """
    # Avoid route shadowing: /crl/download and /crl/bundle can be captured here.
    if issuer_name == "download":
        return await download_org_crl(org_id)
    if issuer_name == "bundle":
        return await download_org_crl_bundle(org_id)

    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    if issuer_cert_id is not None:
        issuer_cert = db.get_certificate_by_id_for_organization(issuer_cert_id, org_id)
        if not issuer_cert or issuer_cert["cert_type"] not in ("root", "intermediate"):
            return Response(content="Issuer not found", status_code=404)
        if issuer_cert["cert_name"] != issuer_name:
            return Response(content="Issuer mismatch", status_code=400)
        crl_path = _resolve_crl_path_for_cert(org, issuer_cert)
    else:
        crl_path = _resolve_issuer_crl_path(org, org_id, issuer_name)

    if not crl_path:
        return Response(content="CRL not found for issuer", status_code=404)

    crl_content = file_crypto.read_encrypted(crl_path)
    return Response(
        content=crl_content,
        media_type="application/pkix-crl",
        headers={"Content-Disposition": f'attachment; filename="{issuer_name}.crl.pem"'},
    )


def _select_preferred_crl_issuer(org_id: int) -> str | None:
    """
    Prefer active intermediate CA CRL, fallback to active root CA CRL.
    """
    certs = db.list_certificates_by_organization(org_id)
    active_intermediates = [c for c in certs if c["cert_type"] == "intermediate" and c["status"] == "active"]
    if active_intermediates:
        return active_intermediates[0]["cert_name"]

    active_roots = [c for c in certs if c["cert_type"] == "root" and c["status"] == "active"]
    if active_roots:
        return active_roots[0]["cert_name"]
    return None


def _select_available_crl_issuer(org_id: int) -> str | None:
    """
    Select first issuer that has a CRL record and file available.
    Preference order:
    1) active intermediate issuers
    2) active root issuers
    """
    certs = db.list_certificates_by_organization(org_id)
    candidates = [
        c["cert_name"]
        for c in certs
        if c["status"] == "active" and c["cert_type"] == "intermediate"
    ]
    candidates.extend(
        c["cert_name"]
        for c in certs
        if c["status"] == "active" and c["cert_type"] == "root"
    )

    org = db.get_organization_by_id(org_id)
    if not org:
        return None

    for issuer_name in candidates:
        crl_path = _resolve_issuer_crl_path(org, org_id, issuer_name)
        if crl_path and crl_path.exists():
            return issuer_name
    return None


def _resolve_issuer_crl_path(org: dict, org_id: int, issuer_name: str) -> Path | None:
    """
    Resolve CRL path for an issuer with DB-first and filesystem fallback.
    """
    # 1) DB metadata (preferred)
    crl_row = db.get_latest_crl_for_issuer(org_id, issuer_name)
    if crl_row:
        crl_path = Path(crl_row["crl_path"])
        if crl_path.exists():
            return crl_path

    # 2) Filesystem fallback for legacy/stale DB CRL metadata
    layout = PkiLayout()
    org_dir = _resolve_org_path(org["org_dir"])
    certs = db.list_certificates_by_organization(org_id)
    issuer_candidates = [
        c for c in certs
        if c["cert_name"] == issuer_name and c["cert_type"] in ("root", "intermediate")
    ]
    for issuer in issuer_candidates:
        artifact = issuer.get("cert_uuid") or issuer_name
        if issuer["cert_type"] == "root":
            path = org_dir / layout.root_dirname / "crl" / f"{artifact}.crl.pem.enc"
        else:
            # Intermediate folders use cert_name, files use UUID
            path = org_dir / layout.intermediates_dirname / issuer["cert_name"] / "crl" / f"{artifact}.crl.pem.enc"
        if path.exists():
            return path
    return None


def _resolve_crl_path_for_cert(org: dict, cert: dict) -> Path | None:
    """
    Resolve CRL path for an exact issuer certificate row (id + type + uuid).
    """
    crl_row = db.get_latest_crl_for_issuer_id(cert["id"])
    if crl_row:
        crl_path = Path(crl_row["crl_path"])
        if crl_path.exists():
            return crl_path

    layout = PkiLayout()
    org_dir = _resolve_org_path(org["org_dir"])
    artifact = cert.get("cert_uuid") or cert["cert_name"]
    if cert["cert_type"] == "root":
        path = org_dir / layout.root_dirname / "crl" / f"{artifact}.crl.pem.enc"
    elif cert["cert_type"] == "intermediate":
        # Intermediate folders use cert_name, files use UUID
        path = org_dir / layout.intermediates_dirname / cert["cert_name"] / "crl" / f"{artifact}.crl.pem.enc"
    else:
        return None
    return path if path.exists() else None


@app.get("/organizations/{org_id}/crl/download")
async def download_org_crl(org_id: int):
    """
    Download preferred organization CRL (intermediate first, then root).
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    issuer_name = _select_available_crl_issuer(org_id)
    if not issuer_name:
        preferred = _select_preferred_crl_issuer(org_id)
        if preferred:
            return Response(
                content=f"No CRL available yet for issuer '{preferred}'. Revoke a certificate first.",
                status_code=404,
            )
        return Response(content="No active issuer found for CRL download", status_code=404)

    crl_path = _resolve_issuer_crl_path(org, org_id, issuer_name)
    if not crl_path:
        return Response(content="No CRL available for preferred issuer", status_code=404)

    crl_content = file_crypto.read_encrypted(crl_path)
    return Response(
        content=crl_content,
        media_type="application/pkix-crl",
        headers={"Content-Disposition": f'attachment; filename="{issuer_name}.crl.pem"'},
    )


@app.get("/organizations/{org_id}/crl/bundle")
async def download_org_crl_bundle(org_id: int):
    """
    Download bundled CRL file:
    - preferred issuer CRL (intermediate first, then root)
    - plus root CRL when preferred issuer is not root
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    preferred_issuer = _select_preferred_crl_issuer(org_id)
    root_issuer = get_latest_active_root_ca_name(org_id)
    if not preferred_issuer:
        return Response(content="No active issuer found for CRL bundle", status_code=404)

    issuer_names: list[str] = [preferred_issuer]
    if root_issuer and root_issuer != preferred_issuer:
        issuer_names.append(root_issuer)

    crl_parts: list[bytes] = []
    missing: list[str] = []
    for issuer_name in issuer_names:
        crl_path = _resolve_issuer_crl_path(org, org_id, issuer_name)
        if not crl_path:
            missing.append(issuer_name)
            continue
        crl_parts.append(file_crypto.read_encrypted(crl_path).strip())

    if not crl_parts:
        return Response(content=f"No CRL files available for bundle. Missing: {', '.join(missing)}", status_code=404)

    bundle_name = f"crl_bundle_org_{org_id}.pem"
    bundle_content = b"\n\n".join(crl_parts) + b"\n"
    return Response(
        content=bundle_content,
        media_type="application/pkix-crl",
        headers={"Content-Disposition": f'attachment; filename="{bundle_name}"'},
    )


@app.get("/organizations/{org_id}/crl/{issuer_name}/bundle")
async def download_issuer_crl_bundle(org_id: int, issuer_name: str, issuer_cert_id: int | None = Query(default=None)):
    """
    Download bundled CRL for a specific issuer:
    - issuer CRL
    - plus root CRL when issuer is intermediate
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    certs = db.list_certificates_by_organization(org_id)
    if issuer_cert_id is not None:
        issuer_cert = next(
            (c for c in certs if c["id"] == issuer_cert_id and c["cert_type"] in ("root", "intermediate")),
            None,
        )
        if issuer_cert and issuer_cert["cert_name"] != issuer_name:
            return Response(content="Issuer mismatch", status_code=400)
    else:
        issuer_cert = next(
            (c for c in certs if c["cert_name"] == issuer_name and c["cert_type"] in ("root", "intermediate")),
            None,
        )
    if not issuer_cert:
        return Response(content="Issuer not found", status_code=404)

    root_cert = next((c for c in certs if c["cert_type"] == "root" and c["status"] == "active"), None)
    issuer_chain: list[dict] = [issuer_cert]
    if issuer_cert["cert_type"] == "intermediate" and root_cert and root_cert["id"] != issuer_cert["id"]:
        issuer_chain.append(root_cert)

    crl_parts: list[bytes] = []
    missing: list[str] = []
    for cert in issuer_chain:
        crl_path = _resolve_crl_path_for_cert(org, cert)
        if not crl_path:
            missing.append(f"{cert['cert_name']} ({cert['cert_type']})")
            continue
        crl_parts.append(file_crypto.read_encrypted(crl_path).strip())

    if not crl_parts:
        return Response(content=f"No CRL files available for bundle. Missing: {', '.join(missing)}", status_code=404)

    bundle_name = f"crl_bundle_{issuer_name}.pem"
    bundle_content = b"\n\n".join(crl_parts) + b"\n"
    return Response(
        content=bundle_content,
        media_type="application/pkix-crl",
        headers={"Content-Disposition": f'attachment; filename="{bundle_name}"'},
    )


@app.get("/organizations/{org_id}/certificates/{cert_id}/download", dependencies=[require_roles_config()])
async def download_certificate(request: Request, org_id: int, cert_id: int, format: str = "pem"):
    """
    Download certificate artifact in one of: pem, p12, chain.
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
    if not cert:
        return Response(content="Certificate not found", status_code=404)

    fmt = (format or "pem").strip().lower()
    org_dir = _resolve_org_path(org["org_dir"])

    if fmt == "pem":
        cert_path = org_dir / cert["cert_path"]
        if not cert_path.exists():
            return Response(content="PEM file not found", status_code=404)
        # Decrypt and serve PEM content
        pem_content = file_crypto.read_encrypted(cert_path)
        # Audit: PEM download
        user_name = _get_request_user(request)
        try:
            db.log_certificate_operation(cert_id, "downloaded_pem", user_name, None)
        except Exception as e:
            logger.warning(f"Audit log failed (non-fatal): {e}")
        return Response(
            content=pem_content,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="{cert["cert_name"]}.pem"'},
        )

    if fmt == "p12":
        if cert["cert_type"] not in ("client", "email"):
            return Response(content="PKCS12 is only available for client/email certificates", status_code=400)
        # P12 path: replace .pem.enc with .p12.enc
        cert_path_str = cert["cert_path"]
        p12_rel = cert_path_str.replace(".pem.enc", ".p12.enc")
        p12_path = org_dir / p12_rel
        if not p12_path.exists():
            return Response(content="PKCS12 file not found", status_code=404)
        # Decrypt and serve P12 content
        p12_content = file_crypto.read_encrypted(p12_path)
        # Audit: P12 download
        user_name = _get_request_user(request)
        try:
            db.log_certificate_operation(cert_id, "downloaded_p12", user_name, None)
        except Exception as e:
            logger.warning(f"Audit log failed (non-fatal): {e}")
        return Response(
            content=p12_content,
            media_type="application/x-pkcs12",
            headers={"Content-Disposition": f'attachment; filename="{cert["cert_name"]}.p12"'},
        )

    if fmt == "chain":
        chain_content = _build_certificate_chain_pem(org, cert, org_id)
        if chain_content is None:
            return Response(content="Unable to build certificate chain", status_code=500)
        # Audit: chain download
        user_name = _get_request_user(request)
        try:
            db.log_certificate_operation(cert_id, "downloaded_chain", user_name, None)
        except Exception as e:
            logger.warning(f"Audit log failed (non-fatal): {e}")
        return Response(
            content=chain_content,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="chain_{cert_id}.pem"'},
        )

    return Response(content="Unsupported format. Use pem, p12, or chain.", status_code=400)


@app.get("/organizations/{org_id}/certificates/{cert_id}/p12-password", dependencies=[require_roles_config()])
async def get_p12_password(request: Request, org_id: int, cert_id: int):
    """Return the PKCS12 password for a client/email certificate."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
    if not cert:
        return Response(content="Certificate not found", status_code=404)

    if cert["cert_type"] not in ("client", "email"):
        return Response(content="PKCS12 is only available for client/email certificates", status_code=400)

    org_dir = _resolve_org_path(org["org_dir"])
    # Derive password path: certs/{base}.pem.enc → private/{base}.p12.pwd.enc
    cert_path_obj = Path(cert["cert_path"])
    file_base = cert_path_obj.name.replace(".pem.enc", "")
    parts = list(cert_path_obj.parts)
    private_parts = []
    for part in parts:
        if part == "certs":
            private_parts.append("private")
            break
        private_parts.append(part)
    p12_pwd_path = org_dir / Path(*private_parts) / f"{file_base}.p12.pwd.enc"

    if not p12_pwd_path.exists():
        return Response(content="P12 password file not found", status_code=404)

    password = file_crypto.read_encrypted(p12_pwd_path).decode().strip()
    # Audit: P12 password viewed
    user_name = _get_request_user(request)
    try:
        db.log_certificate_operation(cert_id, "viewed_p12_password", user_name, None)
    except Exception as e:
        logger.warning(f"Audit log failed (non-fatal): {e}")
    return {"password": password, "cert_name": cert["cert_name"]}


@app.get("/organizations/{org_id}/certificates/{cert_id}/private-key/plain", dependencies=[require_roles_config()])
async def download_unencrypted_server_private_key(org_id: int, cert_id: int):
    """
    Download unencrypted PEM private key for server certificates only.
    """
    org = db.get_organization_by_id(org_id)
    if not org:
        return Response(content="Organization not found", status_code=404)

    cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
    if not cert:
        return Response(content="Certificate not found", status_code=404)

    if cert["cert_type"] != "server":
        return Response(content="Unencrypted private key download is only available for server certificates", status_code=400)

    org_dir = _resolve_org_path(org["org_dir"])
    key_path = org_dir / cert["key_path"]
    if not key_path.exists():
        return Response(content="Private key file not found", status_code=404)

    pwd_path = org_dir / cert["pwd_path"] if cert.get("pwd_path") else None
    passphrase = None
    if pwd_path and pwd_path.exists():
        pwd_raw = file_crypto.read_encrypted(pwd_path).strip()
        passphrase = pwd_raw if pwd_raw else None

    try:
        private_key = serialization.load_pem_private_key(
            file_crypto.read_encrypted(key_path),
            password=passphrase,
        )
        plain_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception:
        return Response(content="Failed to load/decrypt private key", status_code=500)

    return Response(
        content=plain_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{cert["cert_name"]}.key.pem"'},
    )


def _build_certificate_chain_pem(org: dict, cert: dict, org_id: int) -> bytes | None:
    chain_pems: list[bytes] = []
    current = cert
    visited_ids: set[int] = set()
    org_dir = _resolve_org_path(org["org_dir"])

    while current:
        current_id = current.get("id")
        if current_id in visited_ids:
            return None
        visited_ids.add(current_id)

        cert_path_value = current.get("cert_path")
        if not cert_path_value:
            return None

        cert_path = Path(cert_path_value)
        cert_path = cert_path if cert_path.is_absolute() else (org_dir / cert_path)
        if not cert_path.exists():
            return None

        chain_pems.append(file_crypto.read_encrypted(cert_path).strip())

        issuer_cert_id = current.get("issuer_cert_id")
        if not issuer_cert_id:
            break
        current = db.get_certificate_by_id_for_organization(issuer_cert_id, org_id)

    return b"\n\n".join(chain_pems) + b"\n"


# ============================================================================
# Helper: CRL Regeneration
# ============================================================================

def _trigger_crl_regeneration(org: dict, issuer_id: int, issuer_cert: dict) -> None:
    """
    Trigger CRL regeneration for an issuer after revocation.
    Handles subprocess call, CRL parsing, and DB persistence.
    Errors are logged but non-fatal (revocation already committed to DB).
    """
    issuer_type = issuer_cert["cert_type"]
    org_dir = str(_resolve_org_path(org["org_dir"]))

    # Build params for CRL generation
    revoked_certs = db.get_revoked_certs_for_issuer(issuer_id)
    params = {
        "org_dir": org_dir,
        "issuer_name": issuer_cert["cert_name"],
        "issuer_artifact_name": issuer_cert.get("cert_uuid") or issuer_cert["cert_name"],
        "issuer_type": issuer_type,
        "revoked_certs": revoked_certs,
    }

    # Call CRL generation script
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(params, tmp, indent=2)
            temp_path = Path(tmp.name)

        try:
            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "backend" / "revoke_cert_crypto.py"), "--params", str(temp_path)],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.exception(f"CRL generation subprocess timed out after {SUBPROCESS_TIMEOUT}s for issuer_id={issuer_id}")
            raise TimeoutError(f"CRL generation process timed out after {SUBPROCESS_TIMEOUT} seconds")

        if result.returncode == 0:
            # CRL generation succeeded, persist CRL metadata to database
            try:
                # Build CRL file path (mirrors revoke_cert_crypto.py resolve_issuer_paths logic)
                layout = PkiLayout()
                issuer_artifact_name = issuer_cert.get("cert_uuid") or issuer_cert["cert_name"]
                if issuer_type == "root":
                    crl_file = _resolve_org_path(org_dir) / layout.root_dirname / "crl" / f"{issuer_artifact_name}.crl.pem.enc"
                else:
                    # Intermediate folders use cert_name, files use UUID
                    crl_file = _resolve_org_path(org_dir) / layout.intermediates_dirname / issuer_cert["cert_name"] / "crl" / f"{issuer_artifact_name}.crl.pem.enc"

                if crl_file.exists():
                    parsed_crl = x509.load_pem_x509_crl(file_crypto.read_encrypted(crl_file))
                    this_update = parsed_crl.last_update_utc.strftime("%Y-%m-%d %H:%M:%S")
                    next_update = parsed_crl.next_update_utc.strftime("%Y-%m-%d %H:%M:%S") if parsed_crl.next_update_utc else this_update

                    # Get new CRL number
                    crl_number = db.get_latest_crl_number_for_issuer(issuer_id) + 1

                    # Insert CRL record
                    crl_id = db.create_crl(issuer_id, crl_number, this_update, next_update, str(crl_file))

                    # Insert revoked certificate entries for this CRL
                    revoked_rows = db.get_revoked_certs_for_issuer(issuer_id)
                    db.bulk_insert_revoked_certificate_entries(crl_id, [
                        {"certificate_id": r["id"], "revocation_date": r["revoked_at"],
                         "revocation_reason": r["revocation_reason"]}
                        for r in revoked_rows
                    ])

                    # Audit: CRL generated
                    try:
                        db.log_certificate_operation(
                            issuer_id,
                            "crl_generated",
                            None,
                            json.dumps({"crl_id": crl_id, "crl_number": crl_number}),
                        )
                    except Exception as e:
                        logger.warning(f"Audit log failed (non-fatal): {e}")
            except Exception as e:
                logger.warning(f"CRL table insert failed (non-fatal): {e}")
        else:
            logger.error(f"CRL generation failed: {result.stderr or result.stdout}")

    except Exception as e:
        logger.error(f"Error during CRL generation: {e}")

    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


@app.get("/organizations/{org_id}/root-ca", dependencies=[require_roles_config()])
async def root_ca_page(request: Request, org_id: int):
    """Redirect to unified certificate creation page."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    # Prevent creating multiple root CAs
    existing_root = get_latest_active_root_ca_name(org_id)
    if existing_root:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Root CA already exists for this organization: {existing_root}. Only one Root CA is allowed per organization.",
                "org_name": org["name"],
            },
        )

    return RedirectResponse(f"/organizations/{org_id}/create-certificate", status_code=302)


@app.post("/organizations/{org_id}/root-ca", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def create_root_ca(
    request: Request,
    org_id: int,
    cert_name: str = Form(...),
    C: str = Form(...),
    ST: str = Form(...),
    L: str = Form(...),
    O: str = Form(...),
    OU: str = Form(...),
    CN: str = Form(...),
    email: str = Form(""),
    subjectAltName: str = Form(""),
    enddate: str = Form(""),
    eccurve: str = Form(""),
    renewal_of_cert_id: str = Form(""),
):
    """Create Root CA for an organization and register it in the database."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    # Prevent creating multiple root CAs
    existing_root = get_latest_active_root_ca_name(org_id)
    if existing_root:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Root CA already exists for this organization: {existing_root}. Only one Root CA is allowed per organization.",
                "org_name": org["name"],
            },
        )

    # Validate email format if provided
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(status_code=422, detail="Invalid email format.")

    org_dir = str(_resolve_org_path(org["org_dir"]))
    cert_name_clean = _sanitize_cert_name(cert_name)
    cert_uuid = str(uuid.uuid4())
    if not cert_name_clean:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Invalid certificate name.",
                "org_name": org["name"],
            },
        )

    params = {
        "org_dir": org_dir,
        "org_id": org_id,
        "cert_name": cert_name_clean,
        "artifact_name": cert_uuid,
        "cert_type": "root",
        "C": C,
        "ST": ST,
        "L": L,
        "O": O,
        "OU": OU,
        "CN": CN,
        "email": email,
        "subjectAltName": subjectAltName,
        "PKI_BASE_URL": os.environ.get("PKI_BASE_URL", "http://localhost:8000"),
    }

    if enddate.strip():
        params["enddate"] = enddate.strip()
    else:
        root_policy = _load_role_policy("root")
        params["enddate"] = compute_enddate(int(root_policy["DEFAULT_DAYS"]))

    if eccurve.strip():
        params["eccurve"] = eccurve.strip()

    try:
        create_output = _run_create_cert_subprocess(params)

        layout = PkiLayout()
        ws = init_root_workspace(_resolve_org_path(org_dir), cert_name_clean, layout, artifact_name=cert_uuid)

        cert_info = db.extract_certificate_metadata(
            org_id=org_id,
            cert_name=cert_name_clean,
            cert_type="root",
            cert_path=ws["crt_path"],
            key_path=ws["key_path"],
            csr_path=ws["csr_path"],
            pwd_path=ws["pwd_path"],
            org_dir=_resolve_org_path(org_dir),
        )
        cert_info["cert_uuid"] = cert_uuid
        cert_id = db.create_certificate_with_extensions(cert_info)

        # Get session identity for audit logging
        user_name = _get_request_user(request)
        try:
            db.log_certificate_operation(cert_id, "created", user_name, json.dumps({"cert_type": "root"}))
        except Exception as e:
            logger.warning(f"Audit log failed (non-fatal): {e}")
        # Ensure a baseline (possibly empty) CRL exists immediately for this CA.
        created_root = db.get_certificate_by_id_for_organization(cert_id, org_id)
        if created_root:
            _trigger_crl_regeneration(org, cert_id, created_root)

        # Auto-revoke previous cert if this is a renewal
        _handle_renewal_revocation(org, org_id, renewal_of_cert_id)

        return RedirectResponse(f"/organizations/{org_id}/manage", status_code=303)

    except subprocess.CalledProcessError as e:
        logger.exception(f"Certificate creation subprocess failed for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Certificate creation process failed. Please contact an administrator.",
                "org_name": org["name"],
            },
        )
    except TimeoutError as e:
        logger.exception(f"Certificate creation subprocess timed out for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Certificate creation process timed out. Please try again.",
                "org_name": org["name"],
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error creating root CA for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "An unexpected error occurred. Please contact an administrator.",
                "org_name": org["name"],
            },
        )


@app.get("/organizations/{org_id}/intermediate-ca", dependencies=[require_roles_config()])
async def intermediate_ca_page(request: Request, org_id: int):
    """Redirect to unified certificate creation page."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    return RedirectResponse(f"/organizations/{org_id}/create-certificate", status_code=302)


@app.post("/organizations/{org_id}/intermediate-ca", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def create_intermediate_ca(
    request: Request,
    org_id: int,
    cert_name: str = Form(...),
    C: str = Form(...),
    ST: str = Form(...),
    L: str = Form(...),
    O: str = Form(...),
    OU: str = Form(...),
    CN: str = Form(...),
    email: str = Form(""),
    subjectAltName: str = Form(""),
    enddate: str = Form(""),
    eccurve: str = Form(""),
    renewal_of_cert_id: str = Form(""),
):
    """Create Intermediate CA for an organization and register it in the database."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    root_ca = get_latest_active_root_ca_name(org_id)

    if not root_ca:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "No Root CA found. Please create a Root CA first.",
                "org_name": org["name"],
            },
        )

    # Validate email format if provided
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(status_code=422, detail="Invalid email format.")

    org_dir = str(_resolve_org_path(org["org_dir"]))
    layout = PkiLayout()
    root_cert = db.get_latest_certificate_by_name_and_type(
        org_id=org_id,
        cert_name=root_ca,
        cert_type="root",
    )
    root_artifact = root_cert["cert_uuid"] if root_cert and root_cert.get("cert_uuid") else root_ca
    issuer_cert_path = _resolve_org_path(org["org_dir"]) / layout.root_dirname / layout.certs_dirname / f"{root_artifact}.pem.enc"
    issuer_subject_fields = _read_cert_subject_fields(issuer_cert_path)
    locked_fields = _policy_locked_fields("root")
    cert_name_clean = _sanitize_cert_name(cert_name)
    cert_uuid = str(uuid.uuid4())

    if not cert_name_clean:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Invalid certificate name.",
                "org_name": org["name"],
            },
        )

    root_policy = _load_role_policy("root")
    subject_values = _apply_match_policy_fields(
        {
            "C": C,
            "ST": ST,
            "L": L,
            "O": O,
            "OU": OU,
            "CN": CN,
            "email": email,
        },
        issuer_subject_fields,
        root_policy,
    )

    params = {
        "org_dir": org_dir,
        "org_id": org_id,
        "cert_name": cert_name_clean,
        "artifact_name": cert_uuid,
        "issuer_name": root_ca,
        "issuer_artifact_name": root_artifact,
        "cert_type": "intermediate",
        "C": subject_values["C"],
        "ST": subject_values["ST"],
        "L": subject_values["L"],
        "O": subject_values["O"],
        "OU": subject_values["OU"],
        "CN": subject_values["CN"],
        "email": subject_values["email"],
        "subjectAltName": subjectAltName,
        "PKI_BASE_URL": os.environ.get("PKI_BASE_URL", "http://localhost:8000"),
    }

    if enddate.strip():
        params["enddate"] = enddate.strip()
    else:
        intermediate_policy = _load_role_policy("intermediate")
        params["enddate"] = compute_enddate(int(intermediate_policy["DEFAULT_DAYS"]))

    if eccurve.strip():
        params["eccurve"] = eccurve.strip()

    try:
        create_output = _run_create_cert_subprocess(params)

        ws = init_intermediate_workspace(_resolve_org_path(org_dir), cert_name_clean, layout, artifact_name=cert_uuid)
        issuer_cert = db.get_latest_certificate_by_name_and_type(
            org_id=org_id,
            cert_name=root_ca,
            cert_type="root",
        )
        issuer_cert_id = issuer_cert["id"] if issuer_cert else None

        cert_info = db.extract_certificate_metadata(
            org_id=org_id,
            cert_name=cert_name_clean,
            cert_type="intermediate",
            cert_path=ws["crt_path"],
            key_path=ws["key_path"],
            csr_path=ws["csr_path"],
            pwd_path=ws["pwd_path"],
            org_dir=_resolve_org_path(org_dir),
            issuer_cert_id=issuer_cert_id,
        )
        cert_info["cert_uuid"] = cert_uuid
        cert_id = db.create_certificate_with_extensions(cert_info)

        # Get session identity for audit logging
        user_name = _get_request_user(request)
        try:
            db.log_certificate_operation(cert_id, "created", user_name, json.dumps({"cert_type": "intermediate"}))
        except Exception as e:
            logger.warning(f"Audit log failed (non-fatal): {e}")
        # Ensure a baseline (possibly empty) CRL exists immediately for this CA.
        created_intermediate = db.get_certificate_by_id_for_organization(cert_id, org_id)
        if created_intermediate:
            _trigger_crl_regeneration(org, cert_id, created_intermediate)

        # Auto-revoke previous cert if this is a renewal
        _handle_renewal_revocation(org, org_id, renewal_of_cert_id)

        return RedirectResponse(f"/organizations/{org_id}/manage", status_code=303)

    except subprocess.CalledProcessError as e:
        logger.exception(f"Certificate creation subprocess failed for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Certificate creation process failed. Please contact an administrator.",
                "org_name": org["name"],
            },
        )
    except TimeoutError as e:
        logger.exception(f"Certificate creation subprocess timed out for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Certificate creation process timed out. Please try again.",
                "org_name": org["name"],
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error creating intermediate CA for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "An unexpected error occurred. Please contact an administrator.",
                "org_name": org["name"],
            },
        )


@app.get("/organizations/{org_id}/end-entity", dependencies=[require_roles_config()])
async def end_entity_page(request: Request, org_id: int):
    """Redirect to unified certificate creation page."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    return RedirectResponse(f"/organizations/{org_id}/create-certificate", status_code=302)


@app.post("/organizations/{org_id}/end-entity", response_class=HTMLResponse, dependencies=[require_roles_config()])
async def create_end_entity(
    request: Request,
    org_id: int,
    cert_name: str = Form(...),
    cert_type: str = Form(...),
    issuer_name: str = Form(...),
    issuer_type: str = Form(...),
    C: str = Form(...),
    ST: str = Form(...),
    L: str = Form(...),
    O: str = Form(...),
    OU: str = Form(...),
    CN: str = Form(...),
    email: str = Form(""),
    subjectAltName: str = Form(""),
    enddate: str = Form(""),
    eccurve: str = Form(""),
    renewal_of_cert_id: str = Form(""),
):
    """Create End-Entity certificate for an organization and register it in the database."""
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    # Validate cert_type
    if cert_type not in ["server", "client", "email", "ocsp"]:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Invalid certificate type: {cert_type}",
                "org_name": org["name"],
            },
        )

    # Validate email format if provided
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(status_code=422, detail="Invalid email format.")

    org_dir = str(_resolve_org_path(org["org_dir"]))
    cert_name_clean = _sanitize_cert_name(cert_name)
    cert_uuid = str(uuid.uuid4())
    issuer_name_clean = _sanitize_cert_name(issuer_name)
    issuer_type_clean = str(issuer_type).strip().lower()

    if not cert_name_clean:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Invalid certificate name.",
                "org_name": org["name"],
            },
        )

    if issuer_type_clean != "intermediate":
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "End-entity certificates must be issued by an Intermediate CA.",
                "org_name": org["name"],
            },
        )

    available_issuers = {issuer["name"] for issuer in list_end_entity_issuers(org["org_dir"])}
    if issuer_name_clean not in available_issuers:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Selected issuer is not available.",
                "org_name": org["name"],
            },
        )

    layout = PkiLayout()
    issuer_cert = db.get_latest_certificate_by_name_and_type(
        org_id=org_id,
        cert_name=issuer_name_clean,
        cert_type="intermediate",
    )
    if not issuer_cert:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Issuer certificate not found.",
                "org_name": org["name"],
            },
        )
    # Intermediate folders use cert_name, files use UUID
    issuer_cert_uuid = issuer_cert.get('cert_uuid') or issuer_name_clean
    issuer_cert_path = (
        _resolve_org_path(org["org_dir"])
        / layout.intermediates_dirname
        / issuer_name_clean
        / layout.certs_dirname
        / f"{issuer_cert_uuid}.pem.enc"
    )
    issuer_subject_fields = _read_cert_subject_fields(issuer_cert_path)
    subject_values = _apply_match_policy_fields(
        {"C": C, "ST": ST, "L": L, "O": O, "OU": OU, "CN": CN, "email": email},
        issuer_subject_fields,
        _load_role_policy("intermediate"),
    )

    params = {
        "org_dir": org_dir,
        "org_id": org_id,
        "cert_name": cert_name_clean,
        "artifact_name": cert_uuid,
        "cert_type": cert_type,
        "issuer_name": issuer_name_clean,
        "issuer_artifact_name": issuer_cert.get("cert_uuid") or issuer_name_clean,
        "issuer_type": issuer_type_clean,
        "C": subject_values["C"],
        "ST": subject_values["ST"],
        "L": subject_values["L"],
        "O": subject_values["O"],
        "OU": subject_values["OU"],
        "CN": subject_values["CN"],
        "email": subject_values["email"],
        "subjectAltName": subjectAltName,
        "PKI_BASE_URL": os.environ.get("PKI_BASE_URL", "http://localhost:8000"),
    }

    if enddate.strip():
        params["enddate"] = enddate.strip()
    else:
        type_to_role = {"server": "end-entity-server", "client": "end-entity-client", "email": "end-entity-email", "ocsp": "end-entity-ocsp"}
        entity_policy = _load_role_policy(type_to_role[cert_type])
        params["enddate"] = compute_enddate(int(entity_policy["DEFAULT_DAYS"]))

    if eccurve.strip():
        params["eccurve"] = eccurve.strip()

    try:
        create_output = _run_create_cert_subprocess(params)

        ws = init_end_entity_workspace(_resolve_org_path(org_dir), cert_type, cert_name_clean, layout, artifact_name=cert_uuid)
        issuer_cert_id = issuer_cert["id"] if issuer_cert else None

        cert_info = db.extract_certificate_metadata(
            org_id=org_id,
            cert_name=cert_name_clean,
            cert_type=cert_type,
            cert_path=ws["crt_path"],
            key_path=ws["key_path"],
            csr_path=ws["csr_path"],
            pwd_path=ws["pwd_path"],
            org_dir=_resolve_org_path(org_dir),
            issuer_cert_id=issuer_cert_id,
        )
        cert_info["cert_uuid"] = cert_uuid
        cert_id = db.create_certificate_with_extensions(cert_info)

        # Get session identity for audit logging
        user_name = _get_request_user(request)
        try:
            db.log_certificate_operation(cert_id, "created", user_name, json.dumps({"cert_type": cert_type}))
        except Exception as e:
            logger.warning(f"Audit log failed (non-fatal): {e}")

        # Auto-revoke previous cert if this is a renewal
        _handle_renewal_revocation(org, org_id, renewal_of_cert_id)

        return RedirectResponse(f"/organizations/{org_id}/manage", status_code=303)

    except subprocess.CalledProcessError as e:
        logger.exception(f"Certificate creation subprocess failed for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Certificate creation process failed. Please contact an administrator.",
                "org_name": org["name"],
            },
        )
    except TimeoutError as e:
        logger.exception(f"Certificate creation subprocess timed out for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "Certificate creation process timed out. Please try again.",
                "org_name": org["name"],
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error creating end-entity certificate for org_id={org_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Certificate Creation Failed",
                "error_message": "An unexpected error occurred. Please contact an administrator.",
                "org_name": org["name"],
            },
        )


@app.post("/organizations/{org_id}/certificates/{cert_id}/revoke", dependencies=[require_roles_config()])
async def revoke_certificate(
    request: Request,
    org_id: int,
    cert_id: int,
    reason: str = Form("unspecified"),
):
    """Revoke a certificate and regenerate CRL."""
    # Validate organization
    org = db.get_organization_by_id(org_id)
    if not org:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Organization ID {org_id} not found.",
                "org_name": None,
            },
        )

    # Get certificate and validate it belongs to this org
    cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
    if not cert:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Certificate not found or does not belong to this organization.",
                "org_name": org["name"],
            },
        )

    # Check if already revoked
    if cert["status"] != "active":
        logger.warning(f"Certificate {cert_id} is already {cert['status']}")
        # Redirect back to dashboard
        root_ca_exists = bool(get_latest_active_root_ca_name(org_id))

        return templates.TemplateResponse(
            "organization_dashboard.html",
            {
                "request": request,
                "organization": org,
                "root_ca_exists": root_ca_exists,
                "stats": db.get_organization_stats(org_id),
                "certificates": db.list_certificates_by_organization(org_id),
                "audit_logs": db.get_recent_audit_logs(org_id, limit=20),
                "hierarchy": db.get_certificate_hierarchy(org_id),
            },
        )

    # SECURITY FIX: Validate revocation reason against RFC 5280
    if reason not in VALID_REVOCATION_REASONS:
        logger.warning(f"Invalid revocation reason '{reason}' for cert_id={cert_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Invalid revocation reason. Valid reasons are: {', '.join(sorted(VALID_REVOCATION_REASONS))}",
                "org_name": org["name"],
            },
        )

    # Get issuer info
    issuer_id = cert["issuer_cert_id"]
    issuer_cert = None
    issuer_type = None

    if issuer_id:
        issuer_cert = db.get_certificate_by_id_for_organization(issuer_id, org_id)
        if issuer_cert:
            issuer_type = issuer_cert["cert_type"]

    if not issuer_cert or issuer_type not in ("root", "intermediate"):
        logger.error(f"Invalid issuer for certificate {cert_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": "Cannot revoke: issuer not found or invalid.",
                "org_name": org["name"],
            },
        )

    # SECURITY FIX: Check if this is a CA cert with active children before revoking
    if cert["cert_type"] in ("root", "intermediate"):
        # Query for active certificates issued by this CA
        children = db.list_certificates_by_organization(org_id)
        active_children = [
            c for c in children
            if c["issuer_cert_id"] == cert_id and c["status"] == "active"
        ]
        if active_children:
            child_names = ", ".join([f"{c['cert_name']} ({c['cert_type']})" for c in active_children])
            logger.warning(f"Attempt to revoke CA {cert_id} with active children: {child_names}")
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error_message": f"Cannot revoke this CA certificate because it has active subordinate certificates: {child_names}. Please revoke child certificates first.",
                    "org_name": org["name"],
                },
            )

    # Mark certificate as revoked
    if not db.revoke_certificate(cert_id, reason):
        logger.error(f"Failed to revoke certificate {cert_id}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": "Failed to revoke certificate in database.",
                "org_name": org["name"],
            },
        )

    # Log revocation with actual session identity
    user_name = _get_request_user(request)
    try:
        db.log_certificate_operation(cert_id, "revoked", user_name, json.dumps({"reason": reason}))
    except Exception as e:
        logger.warning(f"Audit log failed (non-fatal): {e}")

    # Regenerate CRL for the issuer
    _trigger_crl_regeneration(org, issuer_id, issuer_cert)

    # Redirect back to dashboard
    root_ca_exists = bool(get_latest_active_root_ca_name(org_id))

    return templates.TemplateResponse(
        "organization_dashboard.html",
        {
            "request": request,
            "organization": org,
            "root_ca_exists": root_ca_exists,
            "stats": db.get_organization_stats(org_id),
            "certificates": db.list_certificates_by_organization(org_id),
            "audit_logs": db.get_recent_audit_logs(org_id, limit=20),
            "hierarchy": db.get_certificate_hierarchy(org_id),
        },
    )


@app.get("/api/check-consistency", response_class=Response, dependencies=[require_roles_config()])
async def check_consistency():
    """
    Run consistency checks between database and PEM files.
    Returns JSON with results: stats, issues, and overall pass/fail status.
    NOTE: ConsistencyChecker is imported at module level (not inside handler) to avoid sys.path races.
    """
    if ConsistencyChecker is None:
        return Response(
            content=json.dumps({
                "success": False,
                "error": "Consistency check module not available.",
                "stats": {},
                "issues": [{"level": "error", "message": "Consistency check module could not be loaded."}],
            }),
            media_type="application/json",
            status_code=500
        )

    try:
        checker = ConsistencyChecker(strict=False)
        success = checker.run_checks()

        # Build response
        response_data = {
            "success": success,
            "stats": checker.stats,
            "issues": checker.issues,
            "issue_count": len(checker.issues),
        }

        return Response(
            content=json.dumps(response_data),
            media_type="application/json"
        )
    except Exception as e:
        logger.exception("Consistency check failed")
        return Response(
            content=json.dumps({
                "success": False,
                "error": "Consistency check failed. Please contact an administrator.",
                "stats": {},
                "issues": [{"level": "error", "message": "An unexpected error occurred during consistency check."}],
            }),
            media_type="application/json",
            status_code=500
        )


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("PKI_HOST", "0.0.0.0")
    port = int(os.environ.get("PKI_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, reload=False)
