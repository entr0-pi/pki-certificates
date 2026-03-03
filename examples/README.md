# Examples Folder

These files are **CLI parameter templates** for:

```bash
python backend/create_cert.py --params <file.json>
```

They are not raw HTTP form payloads from the web UI.  
They represent the JSON consumed by the backend certificate scripts.

## Files

- `root_ca.json.example`
- `intermediate_ca.json.example`
- `end_entity_server.json.example`
- `end_entity_client.json.example`
- `end_entity_email.json.example`

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

## Notes

- `cert_name` is human-readable identity shown in UI and DB.
- `artifact_name` controls file naming on disk.
- Replace placeholder UUIDs with real `uuid4` values for actual use.
