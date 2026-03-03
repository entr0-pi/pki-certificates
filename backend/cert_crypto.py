from __future__ import annotations

import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import file_crypto


# ---------------------------
# Hash and Curve Mappings
# ---------------------------
_HASH = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}

_CURVE = {
    "prime256v1": ec.SECP256R1(),
    "secp256r1": ec.SECP256R1(),
    "secp256k1": ec.SECP256K1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}

_POLICY_OID_MAP = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "EMAIL": NameOID.EMAIL_ADDRESS,
}


# ---------------------------
# Parsing Functions
# ---------------------------
def parse_hash(name: str) -> hashes.HashAlgorithm:
    """Parse hash algorithm name to cryptography object."""
    n = (name or "").lower().strip()
    # Explicitly reject SHA-1 (RFC 9155, deprecated for certificate issuance)
    if n == "sha1":
        raise ValueError("SHA-1 is not permitted for new certificate issuance (RFC 9155)")
    if n not in _HASH:
        raise ValueError(f"Unsupported hash: {name!r}")
    return _HASH[n]


def parse_curve(name: str) -> ec.EllipticCurve:
    """Parse elliptic curve name to cryptography object."""
    n = (name or "").lower().strip()
    if n not in _CURVE:
        raise ValueError(f"Unsupported curve: {name!r}")
    return _CURVE[n]


def parse_san(value: str) -> Optional[x509.SubjectAlternativeName]:
    """
    Parse SubjectAltName string to extension object.
    Format: "DNS:example.com,IP:1.2.3.4,URI:https://x,EMAIL:a@b.com"
    Also accepts bare items as DNS names.
    """
    v = (value or "").strip()
    if not v:
        return None

    items = [t.strip() for t in v.split(",") if t.strip()]
    names: List[x509.GeneralName] = []

    for item in items:
        if ":" not in item:
            names.append(x509.DNSName(item))
            continue

        typ, val = item.split(":", 1)
        typ = typ.strip().upper()
        val = val.strip()

        if typ == "DNS":
            names.append(x509.DNSName(val))
        elif typ == "URI":
            names.append(x509.UniformResourceIdentifier(val))
        elif typ in ("EMAIL", "RFC822"):
            names.append(x509.RFC822Name(val))
        elif typ == "IP":
            names.append(x509.IPAddress(ipaddress.ip_address(val)))
        else:
            raise ValueError(f"Unsupported SAN entry: {item!r}")

    return x509.SubjectAlternativeName(names)


def parse_subject_dn(dn_fields: dict) -> x509.Name:
    """
    Parse subject DN fields from dictionary to x509.Name object.
    Required fields: C, ST, L, O, OU, CN
    Optional fields: email
    """
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, dn_fields["C"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dn_fields["ST"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, dn_fields["L"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, dn_fields["O"]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dn_fields["OU"]),
        x509.NameAttribute(NameOID.COMMON_NAME, dn_fields["CN"]),
    ]

    if (email := (dn_fields.get("email") or "").strip()):
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

    return x509.Name(attributes)


def get_name_attr(name: x509.Name, field: str) -> str:
    """Return a single DN attribute value by policy field key."""
    oid = _POLICY_OID_MAP[field]
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return ""
    return attrs[0].value.strip()


def enforce_policy_subject(
    subject: x509.Name,
    issuer_subject: x509.Name,
    policy: dict,
) -> None:
    """
    Enforce POLICY_* DN constraints against a subject before issuance.
    Supported rules: match, supplied, optional.
    """
    for field in ("C", "ST", "L", "O", "OU", "CN", "EMAIL"):
        rule = str(policy.get(f"POLICY_{field}", "optional")).strip().lower()
        subj_val = get_name_attr(subject, field)
        issuer_val = get_name_attr(issuer_subject, field)

        if rule == "match":
            if not subj_val:
                raise ValueError(f"POLICY_{field}=match violated: subject field is missing.")
            if subj_val != issuer_val:
                raise ValueError(
                    f"POLICY_{field}=match violated: subject '{subj_val}' != issuer '{issuer_val}'."
                )
        elif rule == "supplied":
            if not subj_val:
                raise ValueError(f"POLICY_{field}=supplied violated: subject field is missing.")
        elif rule == "optional":
            continue
        else:
            raise ValueError(f"Unsupported policy rule for POLICY_{field}: {rule}")


def parse_basic_constraints(bc_string: str) -> Tuple[x509.BasicConstraints, bool]:
    """
    Parse BasicConstraints from policy string.
    Examples:
      "critical, CA:true, pathlen:1" -> (BasicConstraints(ca=True, path_length=1), True)
      "CA:false" -> (BasicConstraints(ca=False, path_length=None), False)
    """
    parts = [p.strip().lower() for p in bc_string.split(",")]
    is_critical = "critical" in parts

    ca = False
    path_length = None

    for part in parts:
        if part.startswith("ca:"):
            ca = part.split(":")[1].strip() == "true"
        elif part.startswith("pathlen:"):
            path_length = int(part.split(":")[1].strip())

    return x509.BasicConstraints(ca=ca, path_length=path_length), is_critical


def parse_key_usage(usage_string: str) -> Tuple[x509.KeyUsage, bool]:
    """
    Parse KeyUsage from policy string.
    Example: "critical, keyCertSign, cRLSign" -> (KeyUsage object, True)
    """
    parts = [p.strip().lower() for p in usage_string.split(",")]
    is_critical = "critical" in parts

    # Map string names to KeyUsage constructor parameters
    usage_flags = {
        "digitalsignature": False,
        "contentcommitment": False,
        "keyencipherment": False,
        "dataencipherment": False,
        "keyagreement": False,
        "keycertsign": False,
        "crlsign": False,
    }

    for part in parts:
        clean = part.replace("_", "").replace("-", "")
        if clean in usage_flags:
            usage_flags[clean] = True

    return x509.KeyUsage(
        digital_signature=usage_flags["digitalsignature"],
        content_commitment=usage_flags["contentcommitment"],
        key_encipherment=usage_flags["keyencipherment"],
        data_encipherment=usage_flags["dataencipherment"],
        key_agreement=usage_flags["keyagreement"],
        key_cert_sign=usage_flags["keycertsign"],
        crl_sign=usage_flags["crlsign"],
        encipher_only=None,
        decipher_only=None,
    ), is_critical


def parse_extended_key_usage(eku_string: str) -> Optional[x509.ExtendedKeyUsage]:
    """
    Parse ExtendedKeyUsage from policy string.
    Example: "serverAuth, clientAuth" -> ExtendedKeyUsage([SERVER_AUTH, CLIENT_AUTH])
    """
    eku_str = (eku_string or "").strip()
    if not eku_str:
        return None

    parts = [p.strip().lower() for p in eku_str.split(",")]

    eku_map = {
        "serverauth": ExtendedKeyUsageOID.SERVER_AUTH,
        "clientauth": ExtendedKeyUsageOID.CLIENT_AUTH,
        "codesigning": ExtendedKeyUsageOID.CODE_SIGNING,
        "emailprotection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "timestamping": ExtendedKeyUsageOID.TIME_STAMPING,
        "ocspsigning": ExtendedKeyUsageOID.OCSP_SIGNING,
    }

    usages = []
    for part in parts:
        if part in eku_map:
            usages.append(eku_map[part])
        else:
            raise ValueError(f"Unsupported ExtendedKeyUsage: {part!r}")

    return x509.ExtendedKeyUsage(usages) if usages else None


def parse_authority_key_identifier(
    aki_string: str,
    issuer_key,
    issuer_cert: Optional[x509.Certificate] = None,
) -> Tuple[Optional[x509.AuthorityKeyIdentifier], bool]:
    """
    Parse AUTHORITYKEYIDENTIFIER policy string.
    Examples:
      "keyid:always" -> AKI with key identifier only
      "keyid:always,issuer" -> AKI with key identifier + issuer name/serial
    """
    parts = [p.strip().lower() for p in (aki_string or "").split(",") if p.strip()]
    if not parts:
        return None, False

    is_critical = "critical" in parts
    include_keyid = any(p.startswith("keyid") for p in parts)
    include_issuer = any(p.startswith("issuer") for p in parts)

    key_identifier = None
    authority_cert_issuer = None
    authority_cert_serial_number = None

    if include_keyid:
        key_identifier = x509.SubjectKeyIdentifier.from_public_key(issuer_key).digest

    if include_issuer:
        if issuer_cert is None:
            raise ValueError(
                "AUTHORITYKEYIDENTIFIER includes issuer, but issuer_cert was not provided."
            )
        authority_cert_issuer = [x509.DirectoryName(issuer_cert.subject)]
        authority_cert_serial_number = issuer_cert.serial_number

    aki = x509.AuthorityKeyIdentifier(
        key_identifier=key_identifier,
        authority_cert_issuer=authority_cert_issuer,
        authority_cert_serial_number=authority_cert_serial_number,
    )
    return aki, is_critical


# ---------------------------
# Key Management
# ---------------------------
def generate_ec_key(curve_name: str) -> ec.EllipticCurvePrivateKey:
    """Generate EC private key with specified curve."""
    curve = parse_curve(curve_name)
    return ec.generate_private_key(curve)


def save_private_key(
    key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    path: Path,
    passphrase: bytes,
    cipher_name: str
) -> None:
    """
    Save private key to file with encryption.
    cipher_name is validated but cryptography uses PBES2 (strong encryption).
    """
    if not passphrase:
        encryption = serialization.NoEncryption()
    else:
        cn = (cipher_name or "").lower().strip()
        if cn and not cn.startswith("aes"):
            raise ValueError(f"Unsupported key_encryption_cipher: {cipher_name!r}")
        encryption = serialization.BestAvailableEncryption(passphrase)

    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )
    file_crypto.write_encrypted(path, key_bytes)


def load_private_key(
    path: Path,
    passphrase: bytes
) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
    """Load encrypted private key from file."""
    key_data = file_crypto.read_encrypted(path)
    return serialization.load_pem_private_key(key_data, password=passphrase)


def load_certificate(path: Path) -> x509.Certificate:
    """Load certificate from PEM file."""
    cert_data = file_crypto.read_encrypted(path)
    return x509.load_pem_x509_certificate(cert_data)


# ---------------------------
# CSR Creation
# ---------------------------
def create_csr(
    key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    subject: x509.Name,
    san: Optional[x509.SubjectAlternativeName],
    hash_algo: hashes.HashAlgorithm
) -> x509.CertificateSigningRequest:
    """Create Certificate Signing Request."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    if san:
        builder = builder.add_extension(san, critical=False)

    return builder.sign(key, hash_algo)


# ---------------------------
# Extension Building
# ---------------------------
def build_extensions(
    role: str,
    policy: dict,
    subject_key,
    issuer_key,
    issuer_cert: Optional[x509.Certificate],
    san: Optional[x509.SubjectAlternativeName],
    crl_url: str = "",
) -> List[Tuple[x509.Extension, bool]]:
    """
    Build certificate extensions based on role and policy.
    Returns list of (extension, is_critical) tuples.
    """
    extensions = []

    # BasicConstraints
    bc, bc_critical = parse_basic_constraints(policy["BASICCONSTRAINTS"])
    extensions.append((bc, bc_critical))

    # KeyUsage
    ku, ku_critical = parse_key_usage(policy["KEYUSAGE"])
    extensions.append((ku, ku_critical))

    # SubjectKeyIdentifier
    ski = x509.SubjectKeyIdentifier.from_public_key(subject_key)
    extensions.append((ski, False))

    # AuthorityKeyIdentifier (policy-driven)
    aki_str = str(policy.get("AUTHORITYKEYIDENTIFIER", "")).strip()
    if aki_str:
        aki, aki_critical = parse_authority_key_identifier(aki_str, issuer_key, issuer_cert)
        if aki:
            extensions.append((aki, aki_critical))

    # ExtendedKeyUsage (optional)
    eku_str = policy.get("EXTENDEDKEYUSAGE", "")
    if eku_str:
        eku = parse_extended_key_usage(eku_str)
        if eku:
            extensions.append((eku, False))

    # SubjectAlternativeName (optional)
    if san:
        extensions.append((san, False))

    # CRL Distribution Points (optional)
    crl_url_clean = (crl_url or "").strip()
    if crl_url_clean:
        cdp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url_clean)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]
        )
        extensions.append((cdp, False))

    return extensions


# ---------------------------
# Certificate Building
# ---------------------------
def build_and_sign_certificate(
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    issuer_key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    extensions: List[Tuple[x509.Extension, bool]],
    hash_algo: hashes.HashAlgorithm
) -> x509.Certificate:
    """
    Build and sign certificate.
    For self-signed: issuer == subject, issuer_key == subject_key
    For CA-signed: issuer != subject, issuer_key is CA's key
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Add all extensions
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)

    # Sign certificate
    return builder.sign(issuer_key, hash_algo)
