"""
PKI Encryption Manager — decrypt or rotate encrypted PKI artifacts.

Encryption scheme (matches backend/file_crypto.py):
  Key derivation : PBKDF2HMAC(SHA-256, 480 000 iterations)
  Input material : PKI_ENCRYPTION_KEY (password) + PKI_ENCRYPTION_SALT (base64 salt)
  File format    : 12-byte nonce || AES-256-GCM ciphertext+tag

SUBCOMMANDS
-----------
decrypt
  Decrypt .enc files to plaintext.

  # Single file to stdout
  python utils/encryption_manager.py decrypt --env .env -i data/org_1/private/key.enc

  # Single file to output file
  python utils/encryption_manager.py decrypt --env .env -i key.enc -o key.pem

  # Directory tree (mirrors structure under --output, strips .enc suffix)
  python utils/encryption_manager.py decrypt --env .env -i data/ -o /tmp/pki_plain/

  # Dry-run: list files without writing
  python utils/encryption_manager.py decrypt --env .env -i data/ --dry-run

rotate
  Re-encrypt all .enc files under a directory with a new key/salt.
  Files are re-encrypted atomically (temp-file + rename per file).

  Before rotating, create .env.new as a copy of .env with fresh encryption values:
    cp .env .env.new
    # replace PKI_ENCRYPTION_KEY and PKI_ENCRYPTION_SALT with new values, e.g.:
    python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

  # Rotate using two .env files (in-place)
  python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/

  # Rotate to a separate output directory (leaves originals untouched)
  python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ -o /tmp/rotated/

  # Backup originals before in-place overwrite
  python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ --backup-dir /tmp/backup/

  # Explicit credentials instead of .env files
  python utils/encryption_manager.py rotate \\
      --old-key OLD_KEY --old-salt OLD_SALT \\
      --new-key NEW_KEY --new-salt NEW_SALT -i data/

  # Dry-run: list files that would be rotated
  python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ --dry-run

prepare
  Copy an existing .env file to a new path and replace PKI_ENCRYPTION_KEY and
  PKI_ENCRYPTION_SALT with freshly generated values. All other variables are preserved.
  Use this to create the .env.new required by the rotate subcommand.

  python utils/encryption_manager.py prepare --env .env --output .env.new
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import shutil
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_ITERATIONS   = 480_000
_NONCE_LENGTH = 12


# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------

def derive_key(password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_ITERATIONS)
    return kdf.derive(password.encode())


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) < _NONCE_LENGTH + 16:
        raise ValueError("File too short to be a valid encrypted artifact.")
    return AESGCM(key).decrypt(data[:_NONCE_LENGTH], data[_NONCE_LENGTH:], None)


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(_NONCE_LENGTH)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


# ---------------------------------------------------------------------------
# .env loader (no external deps)
# ---------------------------------------------------------------------------

def load_dotenv(env_path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        k, _, v = line.partition("=")
        value = v.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[k.strip()] = value
    return result


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------

def resolve_credentials(
    env_file:  str | None,
    key_arg:   str | None,
    salt_arg:  str | None,
    key_flag:  str = "--key",
    env_flag:  str = "--env",
) -> bytes:
    """
    Resolve key/salt from an optional .env file and/or explicit args,
    then derive and return the AES-256 key bytes.
    Explicit args take precedence over .env values.
    """
    password = key_arg
    salt_b64 = salt_arg

    if env_file:
        env_path = Path(env_file)
        if not env_path.exists():
            _die(f".env file not found: {env_path}")
        env = load_dotenv(env_path)
        if not password:
            password = env.get("PKI_ENCRYPTION_KEY", "").strip() or None
        if not salt_b64:
            salt_b64 = env.get("PKI_ENCRYPTION_SALT", "").strip() or None

    if not password:
        _die(f"Encryption key not provided. Use {key_flag} or {env_flag}.")
    if not salt_b64:
        _die(f"Encryption salt not provided. Use {key_flag.replace('key', 'salt')} or {env_flag}.")

    try:
        return derive_key(password, salt_b64)
    except Exception as exc:
        _die(f"Could not derive encryption key: {exc}")


def _die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def collect_enc_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.enc"))


def stripped_path(src: Path, src_root: Path, out_root: Path) -> Path:
    """Mirror src under out_root, stripping the trailing .enc extension."""
    rel        = src.relative_to(src_root)
    plain_name = rel.name[:-4] if rel.name.endswith(".enc") else rel.name
    return out_root / rel.parent / plain_name


# ---------------------------------------------------------------------------
# Subcommand: decrypt
# ---------------------------------------------------------------------------

def run_decrypt(args: argparse.Namespace) -> int:
    key = resolve_credentials(args.env, args.key, args.salt)

    src = Path(args.input).resolve()
    if not src.exists():
        _die(f"Input path does not exist: {src}")

    # ---- single file -------------------------------------------------------
    if src.is_file():
        if args.dry_run:
            dest = args.output or src.name[:-4] if src.name.endswith(".enc") else src.name
            print(f"[dry-run] {src}  ->  {dest if args.output else '<stdout>'}")
            return 0

        try:
            plaintext = decrypt_bytes(src.read_bytes(), key)
        except InvalidTag:
            _die("Decryption failed (InvalidTag). Check --key and --salt match the encryption values.")
        except Exception as exc:
            _die(str(exc))

        if args.output:
            dest = Path(args.output)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(plaintext)
            print(f"Decrypted: {src}  ->  {dest}")
        else:
            if sys.stdout.isatty():
                try:
                    sys.stdout.write(plaintext.decode("utf-8"))
                except UnicodeDecodeError:
                    sys.stdout.buffer.write(plaintext)
            else:
                sys.stdout.buffer.write(plaintext)
        return 0

    # ---- directory ---------------------------------------------------------
    if not src.is_dir():
        _die(f"Input is neither a file nor a directory: {src}")

    enc_files = collect_enc_files(src)
    if not enc_files:
        print(f"No .enc files found under: {src}")
        return 0

    if not args.output:
        _die("--output directory is required when decrypting a directory tree.")

    out_root = Path(args.output).resolve()
    errors   = 0
    done     = 0

    for enc_file in enc_files:
        dest = stripped_path(enc_file, src, out_root)
        if args.dry_run:
            print(f"[dry-run] {enc_file.relative_to(src)}  ->  {dest.relative_to(out_root)}")
            continue
        try:
            plaintext = decrypt_bytes(enc_file.read_bytes(), key)
        except InvalidTag:
            print(f"  SKIP (InvalidTag): {enc_file.relative_to(src)}", file=sys.stderr)
            errors += 1
            continue
        except Exception as exc:
            print(f"  SKIP ({exc}): {enc_file.relative_to(src)}", file=sys.stderr)
            errors += 1
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(plaintext)
        print(f"  OK  {enc_file.relative_to(src)}  ->  {dest.relative_to(out_root)}")
        done += 1

    if not args.dry_run:
        print(f"\nDone: {done} decrypted, {errors} error(s).")

    return 1 if errors else 0


# ---------------------------------------------------------------------------
# Subcommand: rotate
# ---------------------------------------------------------------------------

def run_rotate(args: argparse.Namespace) -> int:
    src = Path(args.input).resolve()
    if not src.is_dir():
        _die(f"--input must be a directory for rotate: {src}")

    enc_files = collect_enc_files(src)
    if not enc_files:
        print(f"No .enc files found under: {src}")
        return 0

    in_place = args.output is None
    out_root = src if in_place else Path(args.output).resolve()

    # ---- dry-run (no credentials needed) -----------------------------------
    if args.dry_run:
        for f in enc_files:
            dest = out_root / f.relative_to(src)
            label = f.relative_to(src)
            if in_place:
                print(f"[dry-run] {label}  (re-encrypt in-place)")
            else:
                print(f"[dry-run] {label}  ->  {dest.relative_to(out_root)}")
        print(f"\n[dry-run] {len(enc_files)} file(s) would be rotated.")
        return 0

    old_key = resolve_credentials(
        args.old_env, args.old_key, args.old_salt,
        key_flag="--old-key", env_flag="--old-env",
    )
    new_key = resolve_credentials(
        args.new_env, args.new_key, args.new_salt,
        key_flag="--new-key", env_flag="--new-env",
    )

    # ---- verify old key against first file ---------------------------------
    print(f"Verifying old key against: {enc_files[0].relative_to(src)} ...", end=" ")
    try:
        decrypt_bytes(enc_files[0].read_bytes(), old_key)
        print("OK")
    except InvalidTag:
        print("FAILED")
        _die("Old key/salt is incorrect (InvalidTag on first file). Aborting — no files modified.")
    except Exception as exc:
        print("FAILED")
        _die(f"Could not verify old key: {exc}")

    # ---- backup originals --------------------------------------------------
    if args.backup_dir:
        backup_root = Path(args.backup_dir).resolve()
        print(f"Backing up {len(enc_files)} file(s) to {backup_root} ...")
        for f in enc_files:
            dest = backup_root / f.relative_to(src)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
        print(f"Backup complete.")

    # ---- rotate ------------------------------------------------------------
    errors = 0
    done   = 0

    for enc_file in enc_files:
        label = enc_file.relative_to(src)
        try:
            plaintext   = decrypt_bytes(enc_file.read_bytes(), old_key)
            ciphertext  = encrypt_bytes(plaintext, new_key)
            # Catch key-derivation or serialization issues before touching disk.
            decrypt_bytes(ciphertext, new_key)
        except InvalidTag:
            print(f"  SKIP (InvalidTag - old key mismatch): {label}", file=sys.stderr)
            errors += 1
            continue
        except Exception as exc:
            print(f"  SKIP ({exc}): {label}", file=sys.stderr)
            errors += 1
            continue

        if in_place:
            # Atomic overwrite via temp file
            tmp = enc_file.with_suffix(".enc.tmp")
            try:
                tmp.write_bytes(ciphertext)
                os.replace(tmp, enc_file)
                decrypt_bytes(enc_file.read_bytes(), new_key)
            except Exception as exc:
                tmp.unlink(missing_ok=True)
                print(f"  SKIP (write error - {exc}): {label}", file=sys.stderr)
                errors += 1
                continue
            print(f"  OK  {label}  (rotated in-place)")
        else:
            dest = out_root / enc_file.relative_to(src)
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(ciphertext)
                decrypt_bytes(dest.read_bytes(), new_key)
            except Exception as exc:
                print(f"  SKIP (write error - {exc}): {label}", file=sys.stderr)
                errors += 1
                continue
            print(f"  OK  {label}  ->  {dest.relative_to(out_root)}")

        done += 1

    print(f"\nDone: {done} rotated, {errors} error(s).")

    # Remove the hash manifest — all hashes are stale after re-encryption.
    # The consistency checker will rebuild it on next run.
    if done > 0:
        hash_manifest = src / ".pki_file_hashes.json"
        if hash_manifest.exists():
            hash_manifest.unlink()
            print(f"Removed stale hash manifest: {hash_manifest.relative_to(src.parent)}")
        if in_place:
            print("Rotation complete. Replace .env with the new credentials file and restart the app before reading .enc files.")

    return 1 if errors else 0


# ---------------------------------------------------------------------------
# Subcommand: prepare
# ---------------------------------------------------------------------------

_ROTATION_KEYS = ("PKI_ENCRYPTION_KEY", "PKI_ENCRYPTION_SALT")


def _generate_secret() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def run_prepare(args: argparse.Namespace) -> int:
    src = Path(args.env)
    if not src.exists():
        _die(f".env file not found: {src}")

    dest = Path(args.output)
    if dest.exists() and not args.force:
        _die(f"Output file already exists: {dest}. Use --force to overwrite.")

    lines     = src.read_text(encoding="utf-8").splitlines(keepends=True)
    new_values: dict[str, str] = {k: _generate_secret() for k in _ROTATION_KEYS}
    out_lines: list[str] = []
    replaced:  set[str]  = set()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            out_lines.append(line)
            continue
        key, _, _ = stripped.partition("=")
        key = key.strip()
        if key in new_values:
            out_lines.append(f"{key}={new_values[key]}\n")
            replaced.add(key)
        else:
            out_lines.append(line)

    # append any rotation keys that were missing from the source file
    for key in _ROTATION_KEYS:
        if key not in replaced:
            out_lines.append(f"{key}={new_values[key]}\n")

    dest.write_text("".join(out_lines), encoding="utf-8")

    print(f"Written: {dest}")
    for key in _ROTATION_KEYS:
        print(f"  {key} = {new_values[key][:6]}***  (newly generated)")
    print(f"\nNext step: python utils/encryption_manager.py rotate --old-env {src} --new-env {dest} -i data/")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _add_credential_args(group: argparse._ArgumentGroup, prefix: str = "") -> None:
    """Add --[prefix-]env, --[prefix-]key, --[prefix-]salt to an argument group."""
    p = f"{prefix}-" if prefix else ""
    group.add_argument(f"--{p}env",  f"-{'e' if not prefix else prefix[0]}",
                       metavar="DOTENV", dest=f"{prefix or 'env'}{'_env' if prefix else ''}",
                       help=f"Load PKI_ENCRYPTION_KEY/SALT from this .env file.")
    group.add_argument(f"--{p}key",  metavar="PASSWORD",
                       dest=f"{prefix}_key" if prefix else "key",
                       help="PKI_ENCRYPTION_KEY value.")
    group.add_argument(f"--{p}salt", metavar="BASE64",
                       dest=f"{prefix}_salt" if prefix else "salt",
                       help="PKI_ENCRYPTION_SALT value (base64-encoded 32-byte salt).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt or rotate AES-256-GCM encrypted PKI artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # ---- decrypt -----------------------------------------------------------
    dec = sub.add_parser("decrypt", help="Decrypt .enc files to plaintext.")
    creds = dec.add_argument_group("credentials (at least one source required)")
    creds.add_argument("--env", "-e", metavar="DOTENV",
                       help="Load PKI_ENCRYPTION_KEY/SALT from this .env file.")
    creds.add_argument("--key", "-k", metavar="PASSWORD",
                       help="PKI_ENCRYPTION_KEY value.")
    creds.add_argument("--salt", "-s", metavar="BASE64",
                       help="PKI_ENCRYPTION_SALT value (base64-encoded 32-byte salt).")
    io = dec.add_argument_group("input / output")
    io.add_argument("--input",  "-i", required=True, metavar="PATH",
                    help="Encrypted file (.enc) or directory to decrypt recursively.")
    io.add_argument("--output", "-o", metavar="PATH",
                    help="Output file or directory. Omit for single-file stdout.")
    dec.add_argument("--dry-run", action="store_true",
                     help="List files that would be decrypted without writing.")

    # ---- rotate ------------------------------------------------------------
    rot = sub.add_parser("rotate", help="Re-encrypt .enc files with a new key/salt.")
    old = rot.add_argument_group("old credentials (current encryption)")
    old.add_argument("--old-env",  metavar="DOTENV",
                     help="Load old PKI_ENCRYPTION_KEY/SALT from this .env file.")
    old.add_argument("--old-key",  metavar="PASSWORD", help="Old PKI_ENCRYPTION_KEY.")
    old.add_argument("--old-salt", metavar="BASE64",   help="Old PKI_ENCRYPTION_SALT.")
    new = rot.add_argument_group("new credentials (replacement encryption)")
    new.add_argument("--new-env",  metavar="DOTENV",
                     help="Load new PKI_ENCRYPTION_KEY/SALT from this .env file.")
    new.add_argument("--new-key",  metavar="PASSWORD", help="New PKI_ENCRYPTION_KEY.")
    new.add_argument("--new-salt", metavar="BASE64",   help="New PKI_ENCRYPTION_SALT.")
    io2 = rot.add_argument_group("input / output")
    io2.add_argument("--input",  "-i", required=True, metavar="DIR",
                     help="Directory containing .enc files to rotate (searched recursively).")
    io2.add_argument("--output", "-o", metavar="DIR",
                     help="Write rotated files here instead of overwriting originals.")
    io2.add_argument("--backup-dir", metavar="DIR",
                     help="Copy originals here before in-place overwrite.")
    rot.add_argument("--dry-run", action="store_true",
                     help="List files that would be rotated without writing.")

    # ---- prepare -----------------------------------------------------------
    prep = sub.add_parser(
        "prepare",
        help="Copy .env to a new file with fresh PKI_ENCRYPTION_KEY and PKI_ENCRYPTION_SALT.",
    )
    prep.add_argument("--env", "-e", required=True, metavar="DOTENV",
                      help="Source .env file to copy.")
    prep.add_argument("--output", "-o", required=True, metavar="PATH",
                      help="Destination path for the new .env file (e.g. .env.new).")
    prep.add_argument("--force", action="store_true",
                      help="Overwrite destination if it already exists.")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.subcommand == "decrypt":
        sys.exit(run_decrypt(args))
    elif args.subcommand == "rotate":
        sys.exit(run_rotate(args))
    elif args.subcommand == "prepare":
        sys.exit(run_prepare(args))


if __name__ == "__main__":
    main()
