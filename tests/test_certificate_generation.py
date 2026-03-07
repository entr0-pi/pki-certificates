"""
Certificate generation tests (test_certificate_generation.md spec).

Tests that certificates are created correctly with proper extensions,
chain relationships, and file structure.

Markers: integration, openssl (for crypto inspection tests)
"""

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import sys

# Add backend to path for imports
BACKEND_PATH = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

import file_crypto


@pytest.mark.integration
def test_root_ca_files_exist(created_root_ca, created_org):
    """
    After root CA creation, verify the three required files exist on disk:
    data/<org>/1_root/certs/<name>.pem
    data/<org>/1_root/private/<name>.key
    data/<org>/1_root/csr/<name>.csr
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    root_dir = org_dir / "1_root"

    cert_file = root_dir / "certs" / f"{created_root_ca['cert_uuid']}.pem.enc"
    key_file = root_dir / "private" / f"{created_root_ca['cert_uuid']}.key.enc"
    csr_file = root_dir / "csr" / f"{created_root_ca['cert_uuid']}.csr.enc"

    assert cert_file.exists(), f"Root cert PEM not found: {cert_file}"
    assert key_file.exists(), f"Root cert key not found: {key_file}"
    assert csr_file.exists(), f"Root cert CSR not found: {csr_file}"


@pytest.mark.integration
@pytest.mark.openssl
def test_root_ca_is_self_signed(created_root_ca, created_org):
    """
    Root CA certificate is self-signed: subject == issuer.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    root_dir = org_dir / "1_root"
    cert_file = root_dir / "certs" / f"{created_root_ca['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    assert cert.subject == cert.issuer, "Root CA is not self-signed"


@pytest.mark.integration
@pytest.mark.openssl
def test_root_ca_basic_constraints(created_root_ca, created_org):
    """
    Root CA has BasicConstraints extension with CA=true and pathlen >= 1.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    root_dir = org_dir / "1_root"
    cert_file = root_dir / "certs" / f"{created_root_ca['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.value.ca is True, "Root CA BasicConstraints.ca is not True"
    assert bc.value.path_length is None or bc.value.path_length >= 1, \
        f"Root CA pathlen is {bc.value.path_length}, expected >=1"


@pytest.mark.integration
@pytest.mark.openssl
def test_root_ca_key_usage(created_root_ca, created_org):
    """
    Root CA has KeyUsage extension with keyCertSign and cRLSign set.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    root_dir = org_dir / "1_root"
    cert_file = root_dir / "certs" / f"{created_root_ca['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    assert ku.value.key_cert_sign is True, "Root CA KeyUsage.key_cert_sign is not True"
    assert ku.value.crl_sign is True, "Root CA KeyUsage.crl_sign is not True"


@pytest.mark.integration
def test_intermediate_ca_files_exist(created_intermediate_ca, created_org):
    """
    After intermediate CA creation, verify files exist:
    data/<org>/2_intermediates/<uuid>/certs/<uuid>.pem
    data/<org>/2_intermediates/<uuid>/private/<uuid>.key
    data/<org>/2_intermediates/<uuid>/csr/<uuid>.csr

    Note: Intermediate folder names now use cert_uuid (not cert_name) for stable identification.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    # Intermediate folder uses cert_name, files use cert_uuid
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]

    cert_file = int_dir / "certs" / f"{created_intermediate_ca['cert_uuid']}.pem.enc"
    key_file = int_dir / "private" / f"{created_intermediate_ca['cert_uuid']}.key.enc"
    csr_file = int_dir / "csr" / f"{created_intermediate_ca['cert_uuid']}.csr.enc"

    assert cert_file.exists(), f"Intermediate cert PEM not found: {cert_file}"
    assert key_file.exists(), f"Intermediate cert key not found: {key_file}"
    assert csr_file.exists(), f"Intermediate cert CSR not found: {csr_file}"


@pytest.mark.integration
@pytest.mark.openssl
def test_intermediate_ca_issuer_is_root(created_intermediate_ca, created_root_ca, created_org):
    """
    Intermediate CA certificate was signed by the root CA: intermediate.issuer == root.subject.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    root_dir = org_dir / "1_root"
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]

    root_cert_file = root_dir / "certs" / f"{created_root_ca['cert_uuid']}.pem.enc"
    int_cert_file = int_dir / "certs" / f"{created_intermediate_ca['cert_uuid']}.pem.enc"

    root_pem = file_crypto.read_encrypted(root_cert_file)
    root_cert = x509.load_pem_x509_certificate(root_pem)

    int_pem = file_crypto.read_encrypted(int_cert_file)
    int_cert = x509.load_pem_x509_certificate(int_pem)

    assert int_cert.issuer == root_cert.subject, \
        f"Intermediate issuer != root subject"


@pytest.mark.integration
@pytest.mark.openssl
def test_intermediate_ca_pathlen_zero(created_intermediate_ca, created_org):
    """
    Intermediate CA has BasicConstraints with pathlen=0 (cannot issue further CAs).
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]
    int_cert_file = int_dir / "certs" / f"{created_intermediate_ca['cert_uuid']}.pem.enc"

    int_pem = file_crypto.read_encrypted(int_cert_file)
    int_cert = x509.load_pem_x509_certificate(int_pem)

    bc = int_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.value.ca is True, "Intermediate BasicConstraints.ca is not True"
    assert bc.value.path_length == 0, \
        f"Intermediate pathlen is {bc.value.path_length}, expected 0"


@pytest.mark.integration
@pytest.mark.openssl
def test_intermediate_ca_chain_verification(created_intermediate_ca, created_root_ca, created_org):
    """
    Intermediate CA certificate signature can be verified with root CA's public key.
    """
    from pathlib import Path
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    root_dir = org_dir / "1_root"
    int_dir = org_dir / "2_intermediates" / created_intermediate_ca["cert_name"]

    root_cert_file = root_dir / "certs" / f"{created_root_ca['cert_uuid']}.pem.enc"
    int_cert_file = int_dir / "certs" / f"{created_intermediate_ca['cert_uuid']}.pem.enc"

    root_pem = file_crypto.read_encrypted(root_cert_file)
    root_cert = x509.load_pem_x509_certificate(root_pem)

    int_pem = file_crypto.read_encrypted(int_cert_file)
    int_cert = x509.load_pem_x509_certificate(int_pem)

    # Verify the intermediate cert signature using root's public key
    root_pub_key = root_cert.public_key()
    try:
        root_pub_key.verify(
            int_cert.signature,
            int_cert.tbs_certificate_bytes,
            ec.ECDSA(int_cert.signature_hash_algorithm),
        )
    except Exception as e:
        pytest.fail(f"Intermediate CA signature verification failed: {e}")


@pytest.mark.integration
@pytest.mark.openssl
def test_server_cert_ca_false(created_server_cert, created_org):
    """
    Server end-entity certificate has CA=false.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "server" / created_server_cert["cert_name"]
    cert_file = ee_dir / "certs" / f"{created_server_cert['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.value.ca is False, "Server cert BasicConstraints.ca is not False"


@pytest.mark.integration
@pytest.mark.openssl
def test_server_cert_eku_server_auth(created_server_cert, created_org):
    """
    Server end-entity certificate has ExtendedKeyUsage with serverAuth.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "server" / created_server_cert["cert_name"]
    cert_file = ee_dir / "certs" / f"{created_server_cert['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = [oid.dotted_string for oid in eku.value]

    # serverAuth OID = 1.3.6.1.5.5.7.3.1
    assert "1.3.6.1.5.5.7.3.1" in eku_oids, "serverAuth not in EKU"


@pytest.mark.integration
@pytest.mark.openssl
def test_client_cert_eku_client_auth(created_client_cert, created_org):
    """
    Client end-entity certificate has ExtendedKeyUsage with clientAuth.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "client" / created_client_cert["cert_name"]
    cert_file = ee_dir / "certs" / f"{created_client_cert['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = [oid.dotted_string for oid in eku.value]

    # clientAuth OID = 1.3.6.1.5.5.7.3.2
    assert "1.3.6.1.5.5.7.3.2" in eku_oids, "clientAuth not in EKU"


@pytest.mark.integration
@pytest.mark.openssl
def test_email_cert_eku_email_protection(created_email_cert, created_org):
    """
    Email end-entity certificate has ExtendedKeyUsage with clientAuth and emailProtection.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "email" / created_email_cert["cert_name"]
    cert_file = ee_dir / "certs" / f"{created_email_cert['cert_uuid']}.pem.enc"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = [oid.dotted_string for oid in eku.value]

    # clientAuth OID = 1.3.6.1.5.5.7.3.2
    # emailProtection OID = 1.3.6.1.5.5.7.3.4
    assert "1.3.6.1.5.5.7.3.2" in eku_oids, "clientAuth not in EKU"
    assert "1.3.6.1.5.5.7.3.4" in eku_oids, "emailProtection not in EKU"


@pytest.mark.integration
@pytest.mark.openssl
def test_email_cert_pkcs12_parseable(created_email_cert, created_org):
    """
    Email end-entity certificate has a parseable PKCS#12 bundle with certificate and key.
    """
    from pathlib import Path
    from cryptography.hazmat.primitives.serialization import pkcs12

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "email" / created_email_cert["cert_name"]

    p12_file = ee_dir / "certs" / f"{created_email_cert['cert_uuid']}.p12.enc"
    pwd_file = ee_dir / "private" / f"{created_email_cert['cert_uuid']}.p12.pwd.enc"

    assert p12_file.exists(), f"PKCS#12 file not found: {p12_file}"
    assert pwd_file.exists(), f"PKCS#12 password file not found: {pwd_file}"

    # Read password and load PKCS#12
    p12_password = file_crypto.read_encrypted(pwd_file).strip()
    p12_data = file_crypto.read_encrypted(p12_file)

    try:
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data,
            p12_password,
        )
    except Exception as e:
        pytest.fail(f"Failed to parse PKCS#12: {e}")

    assert private_key is not None, "PKCS#12 does not contain a private key"
    assert certificate is not None, "PKCS#12 does not contain a certificate"

    # Verify the bundled cert matches the standalone cert
    cert_file = ee_dir / "certs" / f"{created_email_cert['cert_uuid']}.pem.enc"
    cert_pem = file_crypto.read_encrypted(cert_file)
    standalone_cert = x509.load_pem_x509_certificate(cert_pem)

    assert certificate.serial_number == standalone_cert.serial_number, \
        "PKCS#12 cert serial does not match standalone cert"


@pytest.mark.integration
def test_ocsp_cert_has_ocsp_signing_eku(created_ocsp_cert, created_org):
    """
    OCSP responder certificate has OCSPSigning Extended Key Usage (OID 1.3.6.1.5.5.7.3.9),
    not serverAuth.
    """
    from pathlib import Path
    from cryptography import x509

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "ocsp" / created_ocsp_cert["cert_name"]

    cert_file = ee_dir / "certs" / f"{created_ocsp_cert['cert_uuid']}.pem.enc"
    assert cert_file.exists(), f"OCSP cert file not found: {cert_file}"

    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Extract EKU
    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        eku_oids = [str(oid) for oid in eku_ext.value]
    except x509.ExtensionNotFound:
        pytest.fail("OCSP cert does not have ExtendedKeyUsage extension")

    # Verify ocspSigning OID is present
    ocsp_signing_oid = "1.3.6.1.5.5.7.3.9"
    assert ocsp_signing_oid in eku_oids, \
        f"OCSP cert does not have OCSPSigning OID. Found: {eku_oids}"

    # Verify serverAuth is NOT present
    server_auth_oid = "1.3.6.1.5.5.7.3.1"
    assert server_auth_oid not in eku_oids, \
        f"OCSP cert should not have serverAuth OID. Found: {eku_oids}"


@pytest.mark.integration
def test_ocsp_cert_not_ca(created_ocsp_cert, created_org):
    """
    OCSP responder certificate has BasicConstraints CA:FALSE.
    """
    from pathlib import Path
    from cryptography import x509

    project_root = Path(__file__).resolve().parent.parent
    org_dir = project_root / created_org["org_dir"]
    ee_dir = org_dir / "3_end-entities" / "ocsp" / created_ocsp_cert["cert_name"]

    cert_file = ee_dir / "certs" / f"{created_ocsp_cert['cert_uuid']}.pem.enc"
    cert_pem = file_crypto.read_encrypted(cert_file)
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Verify BasicConstraints
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc_ext.value.ca is False, \
            "OCSP cert BasicConstraints.ca should be False"
    except x509.ExtensionNotFound:
        pytest.fail("OCSP cert does not have BasicConstraints extension")


@pytest.mark.unit
def test_ocsp_cert_type_in_db(created_ocsp_cert):
    """
    OCSP certificate is stored in database with cert_type='ocsp'.
    """
    cert = database.get_certificate_by_id(created_ocsp_cert["cert_id"])
    assert cert is not None, f"OCSP cert not found in DB: {created_ocsp_cert['cert_id']}"
    assert cert["cert_type"] == "ocsp", \
        f"OCSP cert type should be 'ocsp', got '{cert['cert_type']}'"
