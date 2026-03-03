
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from helpers import (
    ensure_dir,
    set_private_perms,
    random_password,
)
import file_crypto
if __package__:
    from .path_config import get_project_root, get_data_dir
else:
    from path_config import get_project_root, get_data_dir

PROJECT_ROOT = get_project_root()
DATA_DIR = get_data_dir()


# =========================
# Parameters (no hard-coded layout at module top)
# =========================

@dataclass(frozen=True, slots=True)
class PkiLayout:
    """
    All folder names + default file contents live here.
    This eliminates hard-coded names scattered through the codebase.
    """
    # Top-level org structure
    root_dirname: str = "1_root"
    intermediates_dirname: str = "2_intermediates"
    end_entities_dirname: str = "3_end-entities"

    # End-entity type subfolders
    end_entity_types: tuple[str, ...] = ("client", "email", "server")

    # CA subdirs
    ca_subdirs: tuple[str, ...] = ("certs", "crl", "csr", "private")

    # Folder names
    private_dirname: str = "private"
    csr_dirname: str = "csr"
    certs_dirname: str = "certs"

    # Organization naming pattern
    org_naming_pattern: str = "org_{id}_{name}"

    # Project required filenames
    policy_filename: str = "config/policy.json"


# =========================
# CA Directory Tree
# =========================


def create_ca_tree(
    base: Path,
    layout: PkiLayout,
    subdirs: Optional[Iterable[str]] = None,
) -> None:
    """Create the standard CA directory tree under `base`."""
    ensure_dir(base)

    subdirs_to_use = tuple(subdirs) if subdirs is not None else layout.ca_subdirs
    for d in subdirs_to_use:
        ensure_dir(base / d)

    set_private_perms(base / layout.private_dirname)


# =========================
# Root CA workspace helpers
# =========================

def init_root_workspace(
    org_dir: Path,
    cert_name: str,
    layout: PkiLayout,
    artifact_name: str | None = None,
) -> dict[str, Path]:
    """
    Creates directory structure for Root CA.

    Args:
        org_dir: Base organization directory
        cert_name: Name of the root CA certificate
        layout: PKI layout configuration

    Returns key paths used by create_root_ca.py.
    """
    dir_root = org_dir / layout.root_dirname

    # Ensure tree
    create_ca_tree(dir_root, layout=layout)

    file_base = artifact_name or cert_name
    pwd_path = dir_root / layout.private_dirname / f"{file_base}.pwd.enc"
    key_path = dir_root / layout.private_dirname / f"{file_base}.key.enc"
    csr_path = dir_root / layout.csr_dirname / f"{file_base}.csr.enc"
    crt_path = dir_root / layout.certs_dirname / f"{file_base}.pem.enc"

    return {
        "dir_root": dir_root,
        "pwd_path": pwd_path,
        "key_path": key_path,
        "csr_path": csr_path,
        "crt_path": crt_path,
        "ca_exists": crt_path.exists() or key_path.exists() or csr_path.exists(),
    }


def init_intermediate_workspace(
    org_dir: Path,
    cert_name: str,
    layout: PkiLayout,
    artifact_name: str,
) -> dict[str, Path]:
    """
    Creates directory structure for Intermediate CA.

    Args:
        org_dir: Base organization directory
        cert_name: Name of the intermediate CA certificate (folder name)
        layout: PKI layout configuration
        artifact_name: UUID for files (REQUIRED, immutable identifier)

    Returns key paths for intermediate CA.

    Note: Folder name uses cert_name (human-readable), while files use artifact_name (UUID).
    This allows safe renaming of intermediates while keeping file references stable.
    """
    inter_base = org_dir / layout.intermediates_dirname / cert_name

    # Use create_ca_tree to avoid redundancy
    create_ca_tree(inter_base, layout=layout)

    file_base = artifact_name
    pwd_path = inter_base / layout.private_dirname / f"{file_base}.pwd.enc"
    key_path = inter_base / layout.private_dirname / f"{file_base}.key.enc"
    csr_path = inter_base / layout.csr_dirname / f"{file_base}.csr.enc"
    crt_path = inter_base / layout.certs_dirname / f"{file_base}.pem.enc"

    return {
        "dir_root": inter_base,
        "pwd_path": pwd_path,
        "key_path": key_path,
        "csr_path": csr_path,
        "crt_path": crt_path,
        "ca_exists": crt_path.exists() or key_path.exists() or csr_path.exists(),
    }


def init_end_entity_workspace(
    org_dir: Path,
    entity_type: str,
    entity_name: str,
    layout: PkiLayout,
    artifact_name: str | None = None,
) -> dict[str, Path]:
    """
    Creates directory structure for end-entity certificate.

    Args:
        org_dir: Base organization directory
        entity_type: Type of entity (server, user, device, client, email)
        entity_name: Name of the entity/certificate
        layout: PKI layout configuration

    Returns key paths for end-entity certificate.
    Note: End-entity certificates don't need database files.
    """
    ee_base = org_dir / layout.end_entities_dirname / entity_type / entity_name
    private = ee_base / "private"
    certs = ee_base / "certs"
    csr = ee_base / "csr"

    for d in (private, certs, csr):
        ensure_dir(d)

    set_private_perms(private)

    file_base = artifact_name or entity_name
    pwd_path = private / f"{file_base}.pwd.enc"
    key_path = private / f"{file_base}.key.enc"
    csr_path = csr / f"{file_base}.csr.enc"
    crt_path = certs / f"{file_base}.pem.enc"
    p12_path = certs / f"{file_base}.p12.enc"
    p12_pwd_path = private / f"{file_base}.p12.pwd.enc"

    return {
        "dir_root": ee_base,
        "pwd_path": pwd_path,
        "key_path": key_path,
        "csr_path": csr_path,
        "crt_path": crt_path,
        "p12_path": p12_path,
        "p12_pwd_path": p12_pwd_path,
        "cert_exists": crt_path.exists() or key_path.exists(),
    }


def ensure_password_file(pwd_path: Path) -> None:
    """
    Ensures password file exists. Creates it if missing.
    Best-effort restrictive permissions on POSIX.
    Files are encrypted at rest via file_crypto.
    """
    if not pwd_path.exists():
        ensure_dir(pwd_path.parent)
        file_crypto.write_encrypted(pwd_path, random_password().encode())

    if os.name == "posix":
        pwd_path.chmod(0o600)


# =========================
# Org initialization + intermediates
# =========================

def init_org(org_dir: Path, layout: PkiLayout) -> None:
    """
    Create initial org structure:
      org_dir/
        <root_dirname>/<ca_subdirs>
        <intermediates_dirname>/
        <end_entities_dirname>/{user,server,device}

    Args:
        org_dir: Base organization directory
        layout: PKI layout configuration
    """
    ensure_dir(org_dir)

    # Root CA tree
    create_ca_tree(org_dir / layout.root_dirname, layout=layout)

    # Intermediates container
    ensure_dir(org_dir / layout.intermediates_dirname)

    # End-entities
    ee_base = org_dir / layout.end_entities_dirname
    ensure_dir(ee_base)
    for t in layout.end_entity_types:
        ensure_dir(ee_base / t)


def add_intermediate(org_dir: Path, layout: PkiLayout, name: Optional[str] = None) -> Path:
    """
    Add an intermediate CA folder under:
      org_dir/<intermediates_dirname>/<name>/

    Args:
        org_dir: Base organization directory
        layout: PKI layout configuration
        name: Optional intermediate name (auto-generated if None)
    """
    inter_base = org_dir / layout.intermediates_dirname
    ensure_dir(inter_base)

    if name is None:
        n = 1
        while (inter_base / f"intermediate{n}").exists():
            n += 1
        name = f"intermediate{n}"

    inter_path = inter_base / name
    create_ca_tree(inter_path, layout=layout)
    return inter_path


def resolve_org_dir(org_dir: Path) -> Path:
    """
    Resolve organization path so relative values live under /data by default.
    """
    org_dir = Path(org_dir)
    if org_dir.is_absolute():
        return org_dir
    if org_dir.parts and org_dir.parts[0] == "data":
        return DATA_DIR.joinpath(*org_dir.parts[1:])
    return DATA_DIR / org_dir


# =========================
# Delete files (merged from delete.py)
# =========================

def is_filesystem_root(p: Path) -> bool:
    """True for / on POSIX and drive roots on Windows."""
    p = p.resolve()
    return p.parent == p


def remove_all_files(root_dir: Path, dry_run: bool = True, follow_symlinks: bool = False) -> int:
    """
    Recursively remove every file under root_dir, preserving folders and subfolders.
    """
    root = Path(root_dir)

    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    count = 0

    for p in root.rglob("*"):
        try:
            if p.is_dir():
                continue

            if p.is_symlink():
                # Safety: delete the link itself, never the target.
                if follow_symlinks:
                    try:
                        _ = p.resolve(strict=True)
                    except FileNotFoundError:
                        pass

                if dry_run:
                    print(f"[DRY RUN] delete symlink: {p}")
                else:
                    p.unlink()
                count += 1
                continue

            if p.is_file():
                if dry_run:
                    print(f"[DRY RUN] delete file: {p}")
                else:
                    p.unlink()
                count += 1

        except Exception as e:
            print(f"Failed to delete {p}: {e}", file=sys.stderr)

    return count


# =========================
# CLI
# =========================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PKI folder helper: init org, add intermediates, and optionally delete files under a folder."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # init
    p_init = sub.add_parser("init", help="Create the initial org folder structure.")
    p_init.add_argument("org_dir", type=Path, help="Base org directory, e.g. orgA")

    # add-intermediate
    p_add = sub.add_parser("add-intermediate", help="Add an intermediate folder.")
    p_add.add_argument("org_dir", type=Path, help="Base org directory, e.g. orgA")
    p_add.add_argument(
        "--name",
        type=str,
        default=None,
        help="Intermediate name (e.g., intermediate2). If omitted, auto-picks next intermediateN.",
    )

    # delete-files
    p_del = sub.add_parser(
        "delete-files",
        help="Recursively remove every file under a folder, preserving folders/subfolders.",
    )
    p_del.add_argument(
        "folder",
        type=Path,
        help="Folder to start from (relative or absolute). Example: ./data/tmp",
    )
    p_del.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be deleted without deleting anything.",
    )
    p_del.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Process symlinks (still deletes only the link, not targets).",
    )
    p_del.add_argument(
        "--refuse-root",
        action="store_true",
        help="Safety: refuse to run if folder is filesystem root (/, C:\\).",
    )

    return parser


def main() -> None:
    layout = PkiLayout()  # single source of truth for folder names and defaults

    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "init":
        target_org_dir = resolve_org_dir(args.org_dir)
        init_org(target_org_dir, layout=layout)
        print(f"Initialized: {target_org_dir.resolve()}")
        return

    if args.cmd == "add-intermediate":
        target_org_dir = resolve_org_dir(args.org_dir)
        created = add_intermediate(target_org_dir, layout=layout, name=args.name)
        print(f"Intermediate ready: {created.resolve()}")
        return

    if args.cmd == "delete-files":
        folder = args.folder

        if args.refuse_root and is_filesystem_root(folder):
            raise RuntimeError(f"Refusing to run on filesystem root: {folder.resolve()}")

        deleted = remove_all_files(
            folder,
            dry_run=args.dry_run,
            follow_symlinks=args.follow_symlinks,
        )

        mode = "would delete" if args.dry_run else "deleted"
        print(f"\nDone: {mode} {deleted} item(s) under {folder}")
        return


if __name__ == "__main__":
    main()
