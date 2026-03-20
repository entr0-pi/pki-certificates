from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from utils import encryption_manager as em


def test_load_dotenv_strips_quotes_and_export(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        'export PKI_ENCRYPTION_KEY="quoted-key"\n'
        "PKI_ENCRYPTION_SALT='quoted-salt'\n",
        encoding="utf-8",
    )

    env = em.load_dotenv(env_file)

    assert env["PKI_ENCRYPTION_KEY"] == "quoted-key"
    assert env["PKI_ENCRYPTION_SALT"] == "quoted-salt"


def test_rotate_in_place_produces_files_readable_with_new_credentials(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    old_env = tmp_path / ".env.old"
    new_env = tmp_path / ".env.new"
    old_env.write_text(
        "PKI_ENCRYPTION_KEY=old-pass\n"
        "PKI_ENCRYPTION_SALT=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\n",
        encoding="utf-8",
    )
    new_env.write_text(
        "PKI_ENCRYPTION_KEY=new-pass\n"
        "PKI_ENCRYPTION_SALT=ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=\n",
        encoding="utf-8",
    )

    old_key = em.resolve_credentials(str(old_env), None, None, "--old-key", "--old-env")
    encrypted = em.encrypt_bytes(b"rotation-check", old_key)
    target = data_dir / "artifact.pem.enc"
    target.write_bytes(encrypted)

    args = Namespace(
        input=str(data_dir),
        output=None,
        dry_run=False,
        old_env=str(old_env),
        new_env=str(new_env),
        old_key=None,
        old_salt=None,
        new_key=None,
        new_salt=None,
        backup_dir=None,
    )

    rc = em.run_rotate(args)

    assert rc == 0
    new_key = em.resolve_credentials(str(new_env), None, None, "--new-key", "--new-env")
    assert em.decrypt_bytes(target.read_bytes(), new_key) == b"rotation-check"
