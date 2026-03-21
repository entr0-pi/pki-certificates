"""
Tests for restore functionality, particularly the pre-flight writability check.
"""

import pytest
import sys
import os
import platform
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_PATH = PROJECT_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

# Import the function to test
from app import _verify_restore_paths_writable


class TestVerifyRestorePathsWritable:
    """Test suite for pre-flight writability checks."""

    def test_both_paths_writable(self):
        """Test when both database and data directories are writable."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            data_dir = tmp_path / "data"

            # Create parent directories
            db_path.parent.mkdir(parents=True, exist_ok=True)
            data_dir.mkdir(parents=True, exist_ok=True)

            is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
            assert is_writable is True
            assert error_msg == ""

    def test_database_directory_does_not_exist(self):
        """Test when database directory doesn't exist."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "nonexistent" / "database" / "pki.db"
            data_dir = tmp_path / "data"
            data_dir.mkdir(parents=True, exist_ok=True)

            is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
            assert is_writable is False
            assert "Database directory does not exist" in error_msg

    @pytest.mark.skipif(platform.system() == "Windows", reason="Permission tests unreliable on Windows")
    def test_database_directory_not_writable(self):
        """Test when database directory exists but is not writable."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            data_dir = tmp_path / "data"
            data_dir.mkdir(parents=True, exist_ok=True)

            # Make database directory read-only
            os.chmod(db_path.parent, 0o444)

            try:
                is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
                assert is_writable is False
                assert "Database directory is not writable" in error_msg
            finally:
                # Restore permissions for cleanup
                os.chmod(db_path.parent, 0o755)

    @pytest.mark.skipif(platform.system() == "Windows", reason="Permission tests unreliable on Windows")
    def test_data_directory_not_writable(self):
        """Test when data directory exists but is not writable."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            data_dir = tmp_path / "data"
            data_dir.mkdir(parents=True, exist_ok=True)

            # Make data directory read-only
            os.chmod(data_dir, 0o444)

            try:
                is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
                assert is_writable is False
                assert "Data directory is not writable" in error_msg
            finally:
                # Restore permissions for cleanup
                os.chmod(data_dir, 0o755)

    def test_data_directory_created_if_missing(self):
        """Test that data directory is created if it doesn't exist."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            data_dir = tmp_path / "data"

            # data_dir doesn't exist yet
            assert not data_dir.exists()

            is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
            assert is_writable is True
            assert error_msg == ""
            assert data_dir.exists()  # Should be created

    @pytest.mark.skipif(platform.system() == "Windows", reason="Permission tests unreliable on Windows")
    def test_data_directory_creation_fails(self):
        """Test when data directory cannot be created due to permissions."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)

            # Create a read-only parent that would prevent creating data_dir
            readonly_parent = tmp_path / "readonly"
            readonly_parent.mkdir(parents=True, exist_ok=True)
            os.chmod(readonly_parent, 0o444)

            data_dir = readonly_parent / "data"

            try:
                is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
                assert is_writable is False
                assert "Cannot create data directory" in error_msg
            finally:
                # Restore permissions for cleanup
                os.chmod(readonly_parent, 0o755)


class TestStartupWritabilityCheck:
    """Test suite for startup-time writability verification."""

    def test_startup_with_writable_paths(self):
        """Test that app startup succeeds when paths are writable."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            data_dir = tmp_path / "data"
            data_dir.mkdir(parents=True, exist_ok=True)

            # Verify check passes during startup scenario
            is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
            assert is_writable is True
            assert error_msg == ""

    def test_startup_fails_with_missing_db_dir(self):
        """Test that startup verification catches missing database directory."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "nonexistent" / "database" / "pki.db"
            data_dir = tmp_path / "data"
            data_dir.mkdir(parents=True, exist_ok=True)

            is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
            assert is_writable is False
            assert "Database directory does not exist" in error_msg

    def test_startup_creates_missing_data_dir(self):
        """Test that startup verification creates data directory if missing."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "database" / "pki.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            data_dir = tmp_path / "data"

            # Verify data_dir doesn't exist initially
            assert not data_dir.exists()

            is_writable, error_msg = _verify_restore_paths_writable(db_path, data_dir)
            assert is_writable is True
            assert error_msg == ""
            # Verify it was created
            assert data_dir.exists()
