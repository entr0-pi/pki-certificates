#!/usr/bin/env python3
"""
Route enforcement smoke test tool.

Tests that every route in rbac.json enforces access control correctly
by making real HTTP requests to a live running PKI app.

Usage:
    python tests/check_routes.py --base-url http://localhost:8000
    python tests/check_routes.py --base-url https://staging.example.com --verbose
    python tests/check_routes.py --filter toolbox --verbose
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import httpx
from dotenv import load_dotenv
import os


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TestCase:
    """A single route test case."""
    method: str
    path_template: str
    path_resolved: str
    allowed_roles: list[str]
    is_public: bool


@dataclass
class TestResult:
    """Result of testing a single route + identity combination."""
    method: str
    path_template: str
    identity: str  # "unauth", "admin", "manager", "user"
    expected_status: int | set[int]
    actual_status: int
    result: str  # "PASS", "FAIL", "WARN"
    note: str = ""


# =============================================================================
# Utility Functions
# =============================================================================

def find_repo_root() -> Path:
    """Find the repository root directory."""
    # First try: look from the script's location
    current = Path(__file__).resolve().parent.parent  # Up from tests/ to repo root
    if (current / "backend" / "app.py").exists():
        return current

    # Second try: walk up from current location
    current = Path.cwd()
    while current != current.parent:
        if (current / "backend" / "app.py").exists():
            return current
        current = current.parent

    raise RuntimeError(f"Could not find repository root. Started from {Path(__file__).resolve().parent.parent}")


def load_rbac_config(rbac_path: Path) -> dict:
    """Load and parse rbac.json, stripping _comment keys."""
    with open(rbac_path) as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def requires_non_html_unauthorized(path: str) -> bool:
    """
    Mirror the logic from app.py _requires_non_html_unauthorized().
    Returns True if the path should return 401 (API/JSON response).
    Returns False if the path should redirect to /auth/login (HTML).
    """
    if path in {"/health", "/organizations"}:
        return True
    if path.startswith("/api/"):
        return True
    if "/crl/" in path:
        return True
    if path.endswith("/download") or path.endswith("/private-key/plain"):
        return True
    return False


# =============================================================================
# HTTP Client and Authentication
# =============================================================================

def authenticate_roles(
    base_url: str,
    admin_key: str,
    manager_key: str,
    user_key: str,
    timeout: int = 10,
) -> dict[str, str]:
    """
    Authenticate as each role via POST /auth/session.
    Returns a dict mapping role name to session cookie value.
    """
    cookies = {}

    with httpx.Client(base_url=base_url, timeout=timeout) as client:
        for role, api_key in [("admin", admin_key), ("manager", manager_key), ("user", user_key)]:
            response = client.post(
                "/auth/session",
                data={"api_key": api_key},
                follow_redirects=False,
            )
            if response.status_code != 302:
                raise RuntimeError(f"Failed to authenticate as {role}: {response.status_code}")

            # Extract session cookie from Set-Cookie header
            set_cookie = response.headers.get("set-cookie", "")
            if not set_cookie:
                raise RuntimeError(f"No Set-Cookie header in {role} auth response")

            # Parse cookie name and value (basic parsing: pki_session=<value>;...)
            cookie_parts = set_cookie.split(";")[0]  # Get "pki_session=<value>"
            if "=" not in cookie_parts:
                raise RuntimeError(f"Could not parse cookie for {role}")

            _, cookie_value = cookie_parts.split("=", 1)
            cookies[role] = cookie_value.strip()

    return cookies


def discover_fixtures(
    base_url: str,
    cookies: dict[str, str],
    timeout: int = 10,
    org_id_override: Optional[int] = None,
    cert_id_override: Optional[int] = None,
    issuer_name_override: Optional[str] = None,
) -> tuple[int, int, str, bool]:
    """
    Discover fixture values from the live app.
    Returns (org_id, cert_id, issuer_name, all_discovered).

    all_discovered: True if all fixtures were auto-discovered from the app.
                    False if any override was used or fallback was applied.
    """
    admin_cookie = cookies["admin"]
    headers = {"cookie": f"pki_session={admin_cookie}"}
    all_discovered = True

    # Discover org_id
    if org_id_override is not None:
        org_id = org_id_override
        all_discovered = False
    else:
        with httpx.Client(base_url=base_url, timeout=timeout) as client:
            response = client.get("/organizations", headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get("organizations"):
                    org_id = data["organizations"][0]["id"]
                else:
                    org_id = 1
                    all_discovered = False
            else:
                org_id = 1
                all_discovered = False

    # Discover issuer_name
    if issuer_name_override is not None:
        issuer_name = issuer_name_override
        all_discovered = False
    else:
        with httpx.Client(base_url=base_url, timeout=timeout) as client:
            response = client.get(f"/api/organizations/{org_id}/crls", headers=headers)
            if response.status_code == 200:
                crls = response.json()
                if crls:
                    issuer_name = crls[0]["issuer_name"]
                else:
                    issuer_name = "test-issuer"
                    all_discovered = False
            else:
                issuer_name = "test-issuer"
                all_discovered = False

    # Discover cert_id (or use override)
    if cert_id_override is not None:
        cert_id = cert_id_override
        all_discovered = False
    else:
        # Default fallback
        cert_id = 1
        all_discovered = False

    return org_id, cert_id, issuer_name, all_discovered


# =============================================================================
# Test Case Generation
# =============================================================================

def resolve_path(path_template: str, org_id: int, cert_id: int, issuer_name: str) -> str:
    """Substitute path template variables with actual values."""
    path = path_template
    path = path.replace("{org_id}", str(org_id))
    path = path.replace("{cert_id}", str(cert_id))
    path = path.replace("{issuer_name}", issuer_name)
    # Handle wildcard in static routes
    path = path.replace("*", "vendor/bundle.css")
    return path


def build_test_cases(rbac_config: dict, org_id: int, cert_id: int, issuer_name: str, filter_pattern: Optional[str] = None) -> list[TestCase]:
    """
    Build test cases from rbac.json.
    Optionally filter by a substring pattern.
    """
    test_cases = []

    for route_key, allowed_roles in rbac_config.items():
        # Parse METHOD and path
        parts = route_key.split(" ", 1)
        if len(parts) != 2:
            continue
        method, path_template = parts

        # Filter if requested
        if filter_pattern and filter_pattern not in route_key:
            continue

        # Resolve path template
        path_resolved = resolve_path(path_template, org_id, cert_id, issuer_name)

        # Determine if public
        is_public = allowed_roles == ["public"]

        # Normalize allowed_roles for public routes
        normalized_roles = [] if is_public else allowed_roles

        test_cases.append(TestCase(
            method=method,
            path_template=route_key,
            path_resolved=path_resolved,
            allowed_roles=normalized_roles,
            is_public=is_public,
        ))

    return test_cases


# =============================================================================
# Test Execution
# =============================================================================

def expected_status_for_identity(
    test_case: TestCase,
    identity: str,  # "unauth", "admin", "manager", "user"
) -> int | set[int]:
    """
    Determine the expected HTTP status code for a given identity on a route.

    Returns:
    - int for a single expected status code
    - set[int] for a range of acceptable status codes
    """
    if test_case.is_public:
        # Public routes: expect NOT 401 or 403 (any other status is OK)
        return set(range(200, 600)) - {401, 403}

    if identity == "unauth":
        # Unauthenticated request to protected route
        if requires_non_html_unauthorized(test_case.path_resolved):
            return 401  # API endpoint
        else:
            return 302  # HTML endpoint (redirect to login)

    # Authenticated request (admin, manager, or user)
    if identity in test_case.allowed_roles:
        # Role is allowed: expect anything but 401/403
        return set(range(200, 600)) - {401, 403}
    else:
        # Role is denied: expect 403
        return 403


def run_tests(
    base_url: str,
    test_cases: list[TestCase],
    cookies: dict[str, str],
    all_discovered: bool,
    timeout: int = 10,
    fail_fast: bool = False,
) -> list[TestResult]:
    """
    Execute all test cases for all identities.
    Returns list of TestResult objects.
    """
    results = []

    with httpx.Client(base_url=base_url, timeout=timeout) as client:
        for test_case in test_cases:
            for identity in ["unauth", "admin", "manager", "user"]:
                # Build request headers
                headers = {}
                if identity != "unauth":
                    headers["cookie"] = f"pki_session={cookies[identity]}"

                # For POST/PUT/DELETE/PATCH, add CSRF header and dummy body
                data = None
                if test_case.method in {"POST", "PUT", "DELETE", "PATCH"}:
                    headers["X-Requested-With"] = "XMLHttpRequest"
                    # Send dummy form data for POST requests
                    if test_case.method == "POST":
                        data = {"__dummy__": "1"}

                # Make request
                try:
                    response = client.request(
                        method=test_case.method,
                        url=test_case.path_resolved,
                        headers=headers,
                        data=data,
                        follow_redirects=False,
                    )
                    actual_status = response.status_code
                except Exception as e:
                    results.append(TestResult(
                        method=test_case.method,
                        path_template=test_case.path_template,
                        identity=identity,
                        expected_status=0,
                        actual_status=0,
                        result="FAIL",
                        note=f"Request error: {str(e)}",
                    ))
                    if fail_fast:
                        return results
                    continue

                # Evaluate pass/fail
                expected = expected_status_for_identity(test_case, identity)

                if isinstance(expected, set):
                    is_pass = actual_status in expected
                else:
                    is_pass = actual_status == expected

                # Mark as WARN if using synthetic fixtures and got 404
                result_str = "PASS" if is_pass else "FAIL"
                note = ""
                if not is_pass and not all_discovered and actual_status == 404:
                    # With synthetic fixtures, 404 is ambiguous (could be auth or not found)
                    if test_case.allowed_roles and identity not in test_case.allowed_roles:
                        result_str = "WARN"
                        note = "404 with synthetic fixtures; could be auth or not found"

                results.append(TestResult(
                    method=test_case.method,
                    path_template=test_case.path_template,
                    identity=identity,
                    expected_status=expected,
                    actual_status=actual_status,
                    result=result_str,
                    note=note,
                ))

                if result_str == "FAIL" and fail_fast:
                    return results

    return results


# =============================================================================
# Output Formatting
# =============================================================================

def print_results_table(
    results: list[TestResult],
    base_url: str,
    org_id: int,
    cert_id: int,
    issuer_name: str,
    all_discovered: bool,
    verbose: bool = False,
) -> int:
    """
    Print results in table format.
    Returns the exit code (0 for all pass, 1 for any fail).
    """
    # Group results by route
    by_route = {}
    for result in results:
        key = result.path_template
        if key not in by_route:
            by_route[key] = {}
        by_route[key][result.identity] = result

    # Header
    print(f"\npki-check-routes  base_url={base_url}")
    fixture_source = "auto-discovered" if all_discovered else "with overrides/fallbacks"
    print(f"Fixtures: org_id={org_id}  cert_id={cert_id}  issuer_name={issuer_name}  ({fixture_source})")
    print(f"Routes: {len(by_route)} routes from rbac.json\n")

    # Column headers
    print(f"{'Route':<50} | {'unauth':<6} | {'admin':<6} | {'manager':<6} | {'user':<6}")
    print("-" * 88)

    # Results rows - always count, only print if verbose or has failures
    passed = 0
    failed = 0
    warned = 0
    total = 0

    for route_key in sorted(by_route.keys()):
        route_results = by_route[route_key]

        # Check for failures
        has_failure = any(r.result == "FAIL" for r in route_results.values())
        has_warning = any(r.result == "WARN" for r in route_results.values())

        # Build cells and count all results
        cells = []
        for identity in ["unauth", "admin", "manager", "user"]:
            result = route_results.get(identity)
            if result:
                cells.append(result.result)
                if result.result == "PASS":
                    passed += 1
                elif result.result == "FAIL":
                    failed += 1
                elif result.result == "WARN":
                    warned += 1
                total += 1
            else:
                cells.append("-")

        # Print if verbose or has failures
        if verbose or has_failure or has_warning:
            print(f"{route_key:<50} | {cells[0]:<6} | {cells[1]:<6} | {cells[2]:<6} | {cells[3]:<6}")

            # Print failure details
            for identity in ["unauth", "admin", "manager", "user"]:
                result = route_results.get(identity)
                if result and result.result == "FAIL":
                    exp = result.expected_status
                    if isinstance(exp, set):
                        exp_str = f"one of {{{', '.join(str(s) for s in sorted(exp))}}}"
                    else:
                        exp_str = str(exp)
                    print(f"  → {identity}: expected={exp_str} actual={result.actual_status}")
                    if result.note:
                        print(f"     {result.note}")

    # Summary
    print("-" * 88)
    print(f"Results: {total} tested  {passed} passed  {failed} failed  {warned} warned")

    return 1 if failed > 0 else 0


def print_results_json(results: list[TestResult]) -> int:
    """Print results in JSON format."""
    data = [
        {
            "method": r.method,
            "path": r.path_template,
            "identity": r.identity,
            "expected": r.expected_status if not isinstance(r.expected_status, set) else list(r.expected_status),
            "actual": r.actual_status,
            "result": r.result,
            "note": r.note,
        }
        for r in results
    ]
    print(json.dumps(data, indent=2))

    failed = sum(1 for r in results if r.result == "FAIL")
    return 1 if failed > 0 else 0


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Test route enforcement on a running PKI app.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/check_routes.py --base-url http://localhost:8000
  python tests/check_routes.py --base-url https://staging.example.com --verbose
  python tests/check_routes.py --filter toolbox --verbose
  python tests/check_routes.py --org-id 1 --cert-id 3 --issuer-name root-ca
        """,
    )

    parser.add_argument("--base-url", default="http://localhost:8000", help="Base URL of the app")
    parser.add_argument("--env-file", default=None, help="Path to .env file (default: .env at repo root)")
    parser.add_argument("--admin-key", default=None, help="Override PKI_API_KEY_ADMIN")
    parser.add_argument("--manager-key", default=None, help="Override PKI_API_KEY_MANAGER")
    parser.add_argument("--user-key", default=None, help="Override PKI_API_KEY_USER")
    parser.add_argument("--org-id", type=int, default=None, help="Override org fixture ID")
    parser.add_argument("--cert-id", type=int, default=None, help="Override cert fixture ID")
    parser.add_argument("--issuer-name", default=None, help="Override issuer name fixture")
    parser.add_argument("--rbac", default="backend/config/rbac.json", help="Path to rbac.json")
    parser.add_argument("--filter", default=None, help="Only test routes matching substring")
    parser.add_argument("--verbose", action="store_true", help="Show all results including passes")
    parser.add_argument("--fail-fast", action="store_true", help="Stop at first failure")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")

    args = parser.parse_args()

    # Find repo root
    repo_root = find_repo_root()

    # Load environment variables
    env_file = Path(args.env_file) if args.env_file else repo_root / ".env"
    if env_file.exists():
        load_dotenv(env_file)

    # Get API keys
    admin_key = args.admin_key or os.getenv("PKI_API_KEY_ADMIN")
    manager_key = args.manager_key or os.getenv("PKI_API_KEY_MANAGER")
    user_key = args.user_key or os.getenv("PKI_API_KEY_USER")

    if not all([admin_key, manager_key, user_key]):
        print("Error: API keys not found. Set PKI_API_KEY_ADMIN, PKI_API_KEY_MANAGER, PKI_API_KEY_USER in .env or via CLI flags.", file=sys.stderr)
        return 1

    # Load rbac.json
    rbac_path = repo_root / args.rbac
    if not rbac_path.exists():
        print(f"Error: rbac.json not found at {rbac_path}", file=sys.stderr)
        print(f"Repo root detected at: {repo_root}", file=sys.stderr)
        return 1
    rbac_config = load_rbac_config(rbac_path)
    if not rbac_config:
        print(f"Error: rbac.json is empty or has no routes at {rbac_path}", file=sys.stderr)
        return 1

    # Authenticate roles
    try:
        cookies = authenticate_roles(args.base_url, admin_key, manager_key, user_key, timeout=args.timeout)
    except Exception as e:
        print(f"Error authenticating: {e}", file=sys.stderr)
        return 1

    # Discover fixtures
    try:
        org_id, cert_id, issuer_name, all_discovered = discover_fixtures(
            args.base_url,
            cookies,
            timeout=args.timeout,
            org_id_override=args.org_id,
            cert_id_override=args.cert_id,
            issuer_name_override=args.issuer_name,
        )
    except Exception as e:
        print(f"Error discovering fixtures: {e}", file=sys.stderr)
        return 1

    # Build and run tests
    test_cases = build_test_cases(rbac_config, org_id, cert_id, issuer_name, filter_pattern=args.filter)
    if not test_cases:
        print(f"Warning: No test cases generated. Loaded {len(rbac_config)} routes from {rbac_path}", file=sys.stderr)
        if args.filter:
            print(f"  (Filter pattern '{args.filter}' may have excluded all routes)", file=sys.stderr)

    results = run_tests(
        args.base_url,
        test_cases,
        cookies,
        all_discovered,
        timeout=args.timeout,
        fail_fast=args.fail_fast,
    )

    # Print results
    if args.format == "json":
        return print_results_json(results)
    else:
        return print_results_table(results, args.base_url, org_id, cert_id, issuer_name, all_discovered, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
