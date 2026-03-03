from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
import os
from typing import Any

import jwt


class AuthConfigError(ValueError):
    pass


class TokenValidationError(ValueError):
    pass


@dataclass(frozen=True)
class AuthSettings:
    api_key_admin: str
    api_key_manager: str
    api_key_user: str
    jwt_secret: str
    session_minutes: int
    cookie_name: str
    cookie_secure: bool
    cookie_samesite: str
    cookie_domain: str | None
    issuer: str = "pki-webapp"


def _parse_bool(value: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_auth_settings() -> AuthSettings:
    api_key_admin = os.environ.get("PKI_API_KEY_ADMIN", "").strip()
    api_key_manager = os.environ.get("PKI_API_KEY_MANAGER", "").strip()
    api_key_user = os.environ.get("PKI_API_KEY_USER", "").strip()
    jwt_secret = os.environ.get("PKI_JWT_SECRET", "").strip()
    if not (api_key_admin and api_key_manager and api_key_user):
        raise AuthConfigError(
            "Missing role API keys. Set PKI_API_KEY_ADMIN, PKI_API_KEY_MANAGER, and PKI_API_KEY_USER in .env."
        )
    if not jwt_secret:
        raise AuthConfigError("Missing PKI_JWT_SECRET. Set it in .env.")

    session_raw = os.environ.get("PKI_SESSION_MINUTES", "15").strip()
    try:
        session_minutes = int(session_raw)
    except ValueError as exc:
        raise AuthConfigError(f"Invalid PKI_SESSION_MINUTES={session_raw!r}. Must be an integer.") from exc
    if session_minutes <= 0:
        raise AuthConfigError("PKI_SESSION_MINUTES must be > 0.")

    cookie_name = os.environ.get("PKI_AUTH_COOKIE_NAME", "pki_session").strip() or "pki_session"
    cookie_secure = _parse_bool(os.environ.get("PKI_COOKIE_SECURE", "true"), default=True)
    cookie_samesite = os.environ.get("PKI_COOKIE_SAMESITE", "lax").strip().lower() or "lax"
    if cookie_samesite not in {"lax", "strict", "none"}:
        raise AuthConfigError("PKI_COOKIE_SAMESITE must be one of: lax, strict, none.")
    cookie_domain = os.environ.get("PKI_COOKIE_DOMAIN", "").strip() or None

    return AuthSettings(
        api_key_admin=api_key_admin,
        api_key_manager=api_key_manager,
        api_key_user=api_key_user,
        jwt_secret=jwt_secret,
        session_minutes=session_minutes,
        cookie_name=cookie_name,
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_samesite,
        cookie_domain=cookie_domain,
    )


def constant_time_api_key_check(provided: str, expected: str) -> bool:
    return bool(provided) and hmac.compare_digest(provided, expected)


def resolve_role(provided: str, settings: AuthSettings) -> str | None:
    """
    Resolve the role from the provided API key.
    Returns 'admin', 'manager', 'user' or None if not found.
    """
    for role, key in (
        ("admin", settings.api_key_admin),
        ("manager", settings.api_key_manager),
        ("user", settings.api_key_user),
    ):
        if key and constant_time_api_key_check(provided, key):
            return role
    return None


def create_session_jwt(
    subject: str, role: str, settings: AuthSettings, now_utc: datetime | None = None
) -> str:
    now = now_utc or datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.session_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": settings.issuer,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def verify_session_jwt(token: str, settings: AuthSettings, *, leeway_seconds: int = 30) -> dict[str, Any]:
    try:
        decoded = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.issuer,
            leeway=leeway_seconds,
        )
    except jwt.PyJWTError as exc:
        raise TokenValidationError(str(exc)) from exc
    return decoded
