from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers import (
    load_json, require_keys, compute_enddate,
    render_template, strip_empty_assignments,
    posix_path, passfile_arg, openssl
)
from folder import (
    require_project_files, init_root_workspace, ensure_password_file, PkiLayout
)
from root_ca_validate import validate_and_print


def main() -> None:
    # ======================================================================
    # STEP 1  Parse CLI Arguments
    # ----------------------------------------------------------------------
    # Purpose:
    #   Read the command-line input that tells the script where the frontend
    #   parameters JSON is located.
    #
    # Inputs:
    #   --params PATH   (required) path to input-frontend.json
    #
    # Output:
    #   args.params (Path) pointing to the frontend JSON file.
    # ======================================================================
    parser = argparse.ArgumentParser(description="Create Root CA from policy.json + frontend JSON.")
    parser.add_argument("--params", required=True, type=Path, help="Path to the xxx.json")
    args = parser.parse_args()

    # ======================================================================
    # STEP 2  Locate Project Root + Required Project Files
    # ----------------------------------------------------------------------
    # Purpose:
    #   Determine the repository/project root directory (relative to this
    #   script), then ensure mandatory project files exist.
    #
    # Expected project files (typical):
    #   - policy.json
    #   - OpenSSL config template (e.g., root_ca_template.cnf)
    #
    # Output:
    #   policy_path, config_template_path
    # ======================================================================
    project_root = Path(__file__).resolve().parent.parent
    policy_path, config_template_path = require_project_files(project_root)


    # ======================================================================
    # STEP 3  Load Policy and Extract Root CA Defaults
    # ----------------------------------------------------------------------
    # Purpose:
    #   Load the policy.json configuration and extract the defaults for the
    #   "root" CA role. These defaults define crypto parameters, validity
    #   periods, hashing algorithms, and extension policy.
    #
    # Output:
    #   root_defaults: dict of defaults used throughout the process
    # ======================================================================
    policy = load_json(policy_path)
    root_defaults = policy["role_defaults"]["root"]

    # ======================================================================
    # STEP 4  Load Frontend Parameters and Validate Required Subject Fields
    # ----------------------------------------------------------------------
    # Purpose:
    #   Load the frontend JSON (user input/config) and ensure all mandatory
    #   X.509 Subject DN (Distinguished Name) fields are present.
    #
    # Required subject DN keys:
    #   C, ST, L, O, OU, CN
    #
    # Failure mode:
    #   If any required keys are missing, require_keys() raises and stops.
    # ======================================================================
    frontend = load_json(args.params)
    require_keys(frontend, ["C", "ST", "L", "O", "OU", "CN"])

    # ======================================================================
    # STEP 5  Read Optional Frontend Settings (with Defaults)
    # ----------------------------------------------------------------------
    # Purpose:
    #   Extract optional settings for workspace placement and naming.
    #
    # Defaults:
    #   org_dir   -> "orgA"
    #   ca_name -> "rootCA"
    #
    # Also reads:
    #   subjectAltName (SAN) optional; empty string if not provided
    # ======================================================================
    org_dir = Path(frontend.get("org_dir", "orgA"))
    ca_name = str(frontend.get("ca_name", "rootCA"))
    subject_alt_name = frontend.get("subjectAltName", "")

    # ======================================================================
    # STEP 6  Compute Effective Crypto Parameters (Policy vs Frontend Rules)
    # ----------------------------------------------------------------------
    # Rules:
    #   - If frontend eccurve is null/empty -> use policy root default ec_curve
    #   - If frontend enddate is null/empty -> compute enddate from policy
    #     DEFAULT_DAYS (e.g., now + DEFAULT_DAYS).
    #
    # Output:
    #   ec_curve : curve name used for EC key generation
    #   enddate  : OpenSSL -enddate value used when issuing the root cert
    # ======================================================================
    frontend_eccurve = frontend.get("eccurve")
    frontend_enddate = frontend.get("enddate")

    openssl_bin = "openssl"
    ec_curve = str(frontend_eccurve) if frontend_eccurve else str(root_defaults["ec_curve"])
    enddate = str(frontend_enddate) if frontend_enddate else compute_enddate(int(root_defaults["DEFAULT_DAYS"]))

    # ======================================================================
    # STEP 7  Initialize Workspace + Ensure Password File Exists
    # ----------------------------------------------------------------------
    # Purpose:
    #   Create (or reuse) the directory structure and file paths needed for a
    #   root CA creation session, including key/csr/cert/config paths.
    #
    # Also ensures:
    #   A password file exists to support non-interactive key encryption and
    #   OpenSSL operations requiring passphrases.
    #
    # Output:
    #   ws: dict-like structure with paths such as:
    #     ws["dir_root"], ws["cnf_path"], ws["key_path"], ws["csr_path"],
    #     ws["crt_path"], ws["pwd_path"]
    # ======================================================================
    layout = PkiLayout()
    ws = init_root_workspace(org_dir, ca_name, layout)  
    if ws["ca_exists"]:
        sys.exit("\n Root CA certificate already exists ")

    ensure_password_file(ws["pwd_path"])

    # ======================================================================
    # STEP 8  Render OpenSSL Config from Template + Mapping
    # ----------------------------------------------------------------------
    # Purpose:
    #   Read the OpenSSL config template, substitute placeholders using:
    #     - Immutable policy defaults (hashes, extensions, days, policy DN rules)
    #     - Workspace paths
    #     - Subject DN values from frontend JSON
    #     - Optional SAN and EKU fields
    #
    # Post-processing:
    #   strip_empty_assignments removes config lines for optional fields if empty
    #   (e.g. "subjectAltName =" or "extendedKeyUsage =") to avoid OpenSSL issues.
    #
    # Output:
    #   ws["cnf_path"] is written with the final rendered OpenSSL config.
    # ======================================================================
    template = config_template_path.read_text(encoding="utf-8")
    mapping = {
        # Policy (immutable)
        "DEFAULT_DAYS": str(root_defaults["DEFAULT_DAYS"]),
        "DEFAULT_CRL_DAYS": str(root_defaults["DEFAULT_CRL_DAYS"]),
        "DEFAULT_HASH_CA": str(root_defaults["DEFAULT_HASH_CA"]),
        "DEFAULT_HASH_REQ": str(root_defaults["DEFAULT_HASH_REQ"]),
        "DEFAULT_RSA_KEY_BITS": str(root_defaults["DEFAULT_RSA_KEY_BITS"]),
        "KEYUSAGE": str(root_defaults["KEYUSAGE"]),
        "BASICCONSTRAINTS": str(root_defaults["BASICCONSTRAINTS"]),
        "AUTHORITYKEYIDENTIFIER": str(root_defaults["AUTHORITYKEYIDENTIFIER"]),
        "EXTENDEDKEYUSAGE": str(root_defaults["EXTENDEDKEYUSAGE"]),
        "POLICY_C": str(root_defaults["POLICY_C"]),
        "POLICY_ST": str(root_defaults["POLICY_ST"]),
        "POLICY_L": str(root_defaults["POLICY_L"]),
        "POLICY_O": str(root_defaults["POLICY_O"]),
        "POLICY_OU": str(root_defaults["POLICY_OU"]),
        "POLICY_CN": str(root_defaults["POLICY_CN"]),
        "POLICY_EMAIL": str(root_defaults["POLICY_EMAIL"]),

        # Workspace/session
        "dir": posix_path(ws["dir_root"]),
        "countryName": frontend["C"],
        "stateOrProvinceName": frontend["ST"],
        "localityName": frontend["L"],
        "organizationName": frontend["O"],
        "organizationalUnitName": frontend["OU"],
        "commonName": frontend["CN"],
        "emailAddress": frontend["email"],
        "subjectAltName": str(subject_alt_name),
    }

    cnf_text = render_template(template, mapping)
    cnf_text = strip_empty_assignments(cnf_text)
    ws["cnf_path"].write_text(cnf_text, encoding="utf-8")

    # ======================================================================
    # STEP 9  Determine Key Encryption Cipher Flag
    # ----------------------------------------------------------------------
    # Purpose:
    #   Build the OpenSSL flag for encrypting the private key.
    #
    # Example:
    #   policy key_encryption_cipher: "aes256"  -> cipher_flag: "-aes256"
    # ======================================================================
    cipher_flag = "-" + root_defaults["key_encryption_cipher"]

    # ======================================================================
    # STEP 10  OpenSSL #1: Generate Encrypted EC Private Key
    # ----------------------------------------------------------------------
    # Purpose:
    #   Create a new EC private key using the chosen curve and encrypt it with
    #   the configured cipher using a passphrase stored in the password file.
    #
    # Output file:
    #   ws["key_path"]  (encrypted private key)
    # ======================================================================
    openssl(
        openssl_bin, "genpkey",
        "-algorithm", "EC",
        "-pkeyopt", f"ec_paramgen_curve:{ec_curve}",
        cipher_flag,
        "-pass", f"file:{passfile_arg(ws['pwd_path'])}",
        "-out", posix_path(ws["key_path"]),
    )

    # ======================================================================
    # STEP 11  OpenSSL #2: Generate CSR (Certificate Signing Request)
    # ----------------------------------------------------------------------
    # Purpose:
    #   Create a CSR using:
    #     - the generated private key
    #     - the rendered OpenSSL config (subject DN + request extensions)
    #
    # Output file:
    #   ws["csr_path"]  (CSR)
    # ======================================================================
    openssl(
        openssl_bin, "req", "-new",
        "-config", posix_path(ws["cnf_path"]),
        "-passin", f"file:{passfile_arg(ws['pwd_path'])}",
        "-key", posix_path(ws["key_path"]),
        "-out", posix_path(ws["csr_path"]),
    )

    # ======================================================================
    # STEP 12  OpenSSL #3: Self-Sign CSR to Produce Root CA Certificate
    # ----------------------------------------------------------------------
    # Purpose:
    #   Issue a self-signed certificate (Root CA) by signing the CSR with the
    #   same private key. Uses OpenSSL "ca" command to apply CA extensions.
    #
    # Notable flags:
    #   -selfsign      : self-sign root certificate
    #   -extensions    : selects extension block (e.g., "cert_x509") from config
    #   -enddate       : sets explicit validity end date
    #   -batch         : no interactive prompts
    #
    # Output file:
    #   ws["crt_path"]  (root certificate)
    # ======================================================================
    openssl(
        openssl_bin, "ca",
        "-notext", "-selfsign", "-batch",
        "-config", posix_path(ws["cnf_path"]),
        "-extensions", "cert_x509",
        "-keyfile", posix_path(ws["key_path"]),
        "-passin", f"file:{passfile_arg(ws['pwd_path'])}",
        "-in", posix_path(ws["csr_path"]),
        "-enddate", enddate,
        "-out", posix_path(ws["crt_path"]),
    )

    # ======================================================================
    # STEP 13  Validate + Pretty Print Key/CSR/Cert (Optional)
    # ----------------------------------------------------------------------
    # Purpose:
    #   Validate that:
    #     - the private key is readable (with provided passphrase)
    #     - CSR and certificate can be parsed
    #     - key/CSR/cert match expectations (implementation-dependent)
    #
    # Note:
    #   Remove this block to disable validation/pretty-print cleanly.
    # ======================================================================
    print("\nRUN WITH: OPENSSL")
    print("-<>" * 32)
    validate_and_print(
        ws,
        key_path=ws["key_path"],
        cert_path=ws["crt_path"],
        csr_path=ws["csr_path"],
        pwd_path=ws["pwd_path"],
        title=f"Key information for: {ca_name}",
    )
    print("-<>" * 32)

if __name__ == "__main__":
    main()
