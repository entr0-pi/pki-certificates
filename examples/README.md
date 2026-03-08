# Examples Folder

These files are **CLI parameter templates** for:

```bash
python backend/create_cert.py --params <file.json>
```

They are not raw HTTP form payloads from the web UI.  
They represent the JSON consumed by the backend certificate scripts.

## Files

- `root_ca.json.example` — Root CA certificate (trust anchor)
- `intermediate_ca.json.example` — Intermediate CA certificate (issuing authority)
- `end_entity_server.json.example` — Server certificate (TLS for web services)
- `end_entity_client.json.example` — Client certificate (mTLS client authentication)
- `end_entity_email.json.example` — Email certificate (S/MIME signing and encryption)
- `end_entity_ocsp.json.example` — OCSP responder certificate (certificate status checking)

## UUID Fields Required

In UUID-mode storage, artifacts are named with UUIDs, not `cert_name`.

- `artifact_name`: UUID used for generated artifact filenames (`.pem`, `.key`, `.csr`, `.pwd`, `.p12`)
- `issuer_artifact_name`: issuer UUID used to locate issuer cert/key files for signing

## Recommended Issuance Order

1. Create root CA  
   Use `root_ca.json.example` and note its `artifact_name` UUID.
2. Create intermediate CA  
   Set `issuer_name` to root `cert_name`, and `issuer_artifact_name` to root UUID.
3. Create end-entity certs  
   Set `issuer_name` to intermediate `cert_name`, and `issuer_artifact_name` to intermediate UUID.

## End-Entity Certificate Types

| Type | Purpose | Common CN | Key Usage |
|------|---------|-----------|-----------|
| **server** | TLS for web/API services | Domain name (e.g., `api.example.com`) | Digital Signature, Key Encipherment |
| **client** | mTLS client authentication | Application name or service | Digital Signature, Key Agreement |
| **email** | S/MIME signing & encryption | User email address | Digital Signature, Key Encipherment |
| **ocsp** | OCSP responder for status checking | OCSP responder hostname | Digital Signature (OCSP Signing) |

## Notes

- `cert_name` is human-readable identity shown in UI and DB.
- `artifact_name` controls file naming on disk.
- Replace placeholder UUIDs with real `uuid4` values for actual use.
- OCSP responder must be signed by the CA that issues the certificates it checks (typically intermediate CA).
