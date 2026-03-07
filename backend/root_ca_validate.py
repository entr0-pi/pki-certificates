from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID

import file_crypto


def get_tests_banner(is_self_signed: bool, is_ca: bool, check_eku: bool = False) -> str:
    """Generate test banner based on certificate type."""
    banner = (
        "\nTests performed:\n"
        "- Test #1: CSR signature verifies (public key inside CSR)\n"
    )
    if is_self_signed:
        banner += "- Test #2: Root certificate is self-signed (signature verifies with its own public key)\n"
    else:
        banner += "- Test #2: Certificate signature verifies with issuer public key\n"

    banner += "- Test #3: Private key matches certificate public key\n"

    if is_ca:
        banner += "- Test #4: CA extensions are correct (CA:TRUE, keyCertSign, cRLSign)"
    else:
        banner += "- Test #4: End-entity extensions are correct (CA:FALSE"
        if check_eku:
            banner += ", ExtendedKeyUsage)"
        else:
            banner += ")"

    return banner


def load_cert(p: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(file_crypto.read_encrypted(p))


def load_csr(p: Path) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(file_crypto.read_encrypted(p))


def load_private_key(key: Path, pwd: Path):
    pw = file_crypto.read_encrypted(pwd).strip()
    return serialization.load_pem_private_key(file_crypto.read_encrypted(key), password=pw)


def verify_signature(obj, issuer_public_key) -> None:
    sig = obj.signature
    data = obj.tbs_certificate_bytes if isinstance(obj, x509.Certificate) else obj.tbs_certrequest_bytes
    algo = obj.signature_hash_algorithm

    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(sig, data, ec.ECDSA(algo))
        return
    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(sig, data, padding.PKCS1v15(), algo)
        return
    raise RuntimeError(f"Unsupported public key type: {type(issuer_public_key).__name__}")


def cert_validity_utc(cert: x509.Certificate) -> tuple[datetime, datetime]:
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=timezone.utc)
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)

    return nb, na


def fmt_name(name: x509.Name) -> str:
    oids = [
        NameOID.COMMON_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.COUNTRY_NAME,
        NameOID.EMAIL_ADDRESS,
    ]
    labels = ["CN", "OU", "O", "L", "ST", "C", "email"]

    parts = []
    for lab, oid in zip(labels, oids):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            parts.append(f"{lab}={attrs[0].value}")
    return ", ".join(parts) if parts else name.rfc4514_string()


def fmt_dt(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def public_key_info(pub) -> str:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})"
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA ({pub.key_size} bits)"
    return type(pub).__name__


def print_cert_summary(cert: x509.Certificate, title: str) -> None:
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    serial = hex(cert.serial_number).upper()
    nb, na = cert_validity_utc(cert)

    print(f"\n{title}")
    print("-" * 72)

    rows: list[tuple[str, str]] = [
        ("Subject", fmt_name(cert.subject)),
        ("Issuer", fmt_name(cert.issuer)),
        ("Serial", serial),
        ("Valid From", fmt_dt(nb)),
        ("Valid To", fmt_dt(na)),
        ("Public Key", public_key_info(cert.public_key())),
        ("SHA256 FP", fp),
    ]

    def crit_suffix(is_critical: bool) -> str:
        return " (critical)" if is_critical else " (non-critical)"

    try:
        e = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        bc: x509.BasicConstraints = e.value
        pl = f", pathlen={bc.path_length}" if bc.path_length is not None else ""
        rows.append(("BasicConst", f"CA={bc.ca}{pl}{crit_suffix(e.critical)}"))
    except x509.ExtensionNotFound:
        pass

    try:
        e = cert.extensions.get_extension_for_class(x509.KeyUsage)
        ku: x509.KeyUsage = e.value
        flags = []
        if ku.key_cert_sign:
            flags.append("keyCertSign")
        if ku.crl_sign:
            flags.append("cRLSign")
        if ku.digital_signature:
            flags.append("digitalSignature")
        if ku.key_encipherment:
            flags.append("keyEncipherment")
        rows.append(("KeyUsage", f"{', '.join(flags) if flags else '-'}{crit_suffix(e.critical)}"))
    except x509.ExtensionNotFound:
        pass

    try:
        e = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        rows.append(("SKI", f"{e.value.digest.hex().upper()}{crit_suffix(e.critical)}"))
    except x509.ExtensionNotFound:
        pass

    try:
        e = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        aki = e.value.key_identifier.hex().upper() if e.value.key_identifier else "-"
        rows.append(("AKI", f"{aki}{crit_suffix(e.critical)}"))
    except x509.ExtensionNotFound:
        pass

    try:
        e = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(gn.value) for gn in e.value]
        rows.append(("SAN", f"{', '.join(sans) if sans else '-'}{crit_suffix(e.critical)}"))
    except x509.ExtensionNotFound:
        pass

    try:
        e = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        eku: x509.ExtendedKeyUsage = e.value
        eku_names = []
        for oid in eku:
            # Map common OIDs to readable names
            if oid == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                eku_names.append("serverAuth")
            elif oid == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                eku_names.append("clientAuth")
            elif oid == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                eku_names.append("emailProtection")
            elif oid == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                eku_names.append("codeSigning")
            elif oid == x509.oid.ExtendedKeyUsageOID.TIME_STAMPING:
                eku_names.append("timeStamping")
            else:
                eku_names.append(oid.dotted_string)
        rows.append(("ExtKeyUsage", f"{', '.join(eku_names)}{crit_suffix(e.critical)}"))
    except x509.ExtensionNotFound:
        pass

    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k:<{width}} : {v}")

    print("-" * 72)


def validate_and_print(
    ws: dict,
    key_path: Path,
    cert_path: Path,
    csr_path: Path,
    pwd_path: Path,
    title: str,
    issuer_cert: Optional[x509.Certificate] = None,
    is_ca: bool = True,
    expected_eku: Optional[list[str]] = None
) -> None:
    """
    Validate and print certificate information.

    Args:
        ws: Workspace dictionary with paths
        key_path: Path to private key
        cert_path: Path to certificate
        csr_path: Path to CSR
        pwd_path: Path to password file
        title: Title for the certificate summary
        issuer_cert: Optional issuer certificate (if not self-signed)
        is_ca: Whether this is a CA certificate (affects extension validation)
        expected_eku: Optional list of expected ExtendedKeyUsage OIDs (e.g., ['serverAuth', 'clientAuth'])
    """
    cert_key = load_private_key(key_path, pwd_path)
    cert = load_cert(cert_path)
    csr = load_csr(csr_path)

    is_self_signed = issuer_cert is None

    print(get_tests_banner(is_self_signed, is_ca, check_eku=expected_eku is not None))

    # Test #1: Verify CSR signature
    verify_signature(csr, csr.public_key())

    # Test #2: Verify certificate signature (self-signed or issuer-signed)
    if is_self_signed:
        verify_signature(cert, cert.public_key())
    else:
        verify_signature(cert, issuer_cert.public_key())

    # Test #3: Verify private key matches certificate public key
    key_pub = cert_key.public_key()
    cert_pub = cert.public_key()
    if type(key_pub) is not type(cert_pub):
        raise RuntimeError("Key type and certificate public key type do not match.")
    if key_pub.public_numbers() != cert_pub.public_numbers():
        raise RuntimeError("Private key does not match certificate public key.")

    # Test #4: Verify extensions based on certificate type
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if is_ca:
        if not bc.ca:
            raise RuntimeError("basicConstraints is not CA:TRUE")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign or not ku.crl_sign:
            raise RuntimeError("keyUsage missing keyCertSign and/or cRLSign")
    else:
        if bc.ca:
            raise RuntimeError("basicConstraints should be CA:FALSE for end-entity certificates")

    # Validate ExtendedKeyUsage if expected
    if expected_eku:
        try:
            eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            eku: x509.ExtendedKeyUsage = eku_ext.value

            # Map common EKU names to OIDs
            eku_oid_map = {
                "serverAuth": x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                "clientAuth": x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                "emailProtection": x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                "codeSigning": x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                "timeStamping": x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
                "ocspSigning": x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
            }

            # Convert expected EKU names to OIDs
            expected_oids = []
            for eku_name in expected_eku:
                eku_name = eku_name.strip()
                if eku_name in eku_oid_map:
                    expected_oids.append(eku_oid_map[eku_name])
                else:
                    raise RuntimeError(f"Unknown ExtendedKeyUsage name: {eku_name}")

            # Check if all expected EKUs are present
            cert_eku_oids = list(eku)
            for expected_oid in expected_oids:
                if expected_oid not in cert_eku_oids:
                    raise RuntimeError(f"Missing expected ExtendedKeyUsage: {expected_oid._name}")

        except x509.ExtensionNotFound:
            raise RuntimeError(f"ExtendedKeyUsage extension not found, expected: {', '.join(expected_eku)}")

    print("\n Tests passed with cryptography x509")
    print_cert_summary(cert, title=title)
    print("\nInspected files:")
    print(f"Key  : {ws['key_path'].resolve()}")
    print(f"CSR  : {ws['csr_path'].resolve()}")
    print(f"Cert : {ws['crt_path'].resolve()}")
    print(f"Pass : {ws['pwd_path'].resolve()}")
