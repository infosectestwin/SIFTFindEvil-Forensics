# tests/test_path_validator.py
#
# Project FIND-EVIL — Unit Tests for config/path_validator.py
# ============================================================
# Run with:  python -m pytest tests/ -v

import logging
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from config.path_validator import (
    validate_evidence_path,
    get_tool_path,
    run_forensic_tool,
    PathValidationError,
    ToolNotFoundError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def authorized_path(tmp_path):
    """
    Create a temporary directory that mimics /cases/ and patch AUTHORIZED_ROOTS
    so tests work on any OS without needing a real /cases/ directory.
    """
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    evidence_file = cases_dir / "disk.dd"
    evidence_file.write_bytes(b"\x00" * 512)  # Minimal stub file

    with patch("config.path_validator.AUTHORIZED_ROOTS", [cases_dir]):
        yield evidence_file


@pytest.fixture
def unauthorized_path(tmp_path):
    """A file that exists but is outside any authorized root."""
    evil_file = tmp_path / "evil" / "passwd"
    evil_file.parent.mkdir()
    evil_file.write_text("root:x:0:0:root:/root:/bin/bash")
    return str(evil_file)


# ---------------------------------------------------------------------------
# validate_evidence_path tests
# ---------------------------------------------------------------------------

class TestValidateEvidencePath:

    def test_authorized_path_returns_resolved_path(self, authorized_path):
        """A path inside an authorized root should be returned as a Path object."""
        result = validate_evidence_path(str(authorized_path))
        assert isinstance(result, Path)
        assert result == authorized_path.resolve()

    def test_unauthorized_path_raises(self, unauthorized_path):
        """A path outside all authorized roots must raise PathValidationError."""
        with pytest.raises(PathValidationError, match="not within any authorized"):
            validate_evidence_path(unauthorized_path)

    def test_nonexistent_path_raises(self, tmp_path):
        """A path that does not exist on disk must raise PathValidationError."""
        ghost = str(tmp_path / "cases" / "nonexistent.dd")
        with pytest.raises(PathValidationError, match="does not exist"):
            validate_evidence_path(ghost)

    def test_path_traversal_is_blocked(self, authorized_path):
        """
        A path containing ../ that resolves outside the authorized root
        must be rejected even if the traversal target exists.
        """
        # Construct a traversal: /cases/disk.dd/../../etc/passwd
        traversal = str(authorized_path) + "/../../etc/passwd"
        with pytest.raises(PathValidationError):
            validate_evidence_path(traversal)


# ---------------------------------------------------------------------------
# get_tool_path tests
# ---------------------------------------------------------------------------

class TestGetToolPath:

    def test_registered_tool_returns_path(self, tmp_path):
        """A tool in ALLOWED_BINARIES whose binary exists should return its Path."""
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\necho mmls")

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}):
            result = get_tool_path("mmls")
            assert result == fake_bin

    def test_unregistered_tool_raises(self):
        """A tool name not in ALLOWED_BINARIES must raise ToolNotFoundError."""
        with pytest.raises(ToolNotFoundError, match="not in the authorized binary allowlist"):
            get_tool_path("nc")  # netcat — should never be in the allowlist

    def test_registered_but_missing_binary_raises(self, tmp_path):
        """A tool registered in ALLOWED_BINARIES but absent from disk must raise."""
        missing_bin = tmp_path / "missing_tool"
        with patch("config.path_validator.ALLOWED_BINARIES", {"missing_tool": missing_bin}):
            with pytest.raises(ToolNotFoundError, match="binary was not found"):
                get_tool_path("missing_tool")


# ---------------------------------------------------------------------------
# run_forensic_tool tests
# ---------------------------------------------------------------------------

class TestRunForensicTool:

    def test_successful_execution(self, authorized_path, tmp_path):
        """
        A valid tool + valid path should call subprocess.run with shell=False
        and return a CompletedProcess.
        """
        fake_bin = tmp_path / "sha256sum"
        fake_bin.write_text("#!/bin/sh\necho abc123  $1")

        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout = "abc123  /cases/disk.dd\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("config.path_validator.ALLOWED_BINARIES", {"sha256sum": fake_bin}), \
             patch("config.path_validator.subprocess.run", return_value=mock_result) as mock_run:

            result = run_forensic_tool("sha256sum", str(authorized_path))

            # Verify shell=False was enforced
            _, kwargs = mock_run.call_args
            assert kwargs.get("shell") is False, "shell=False must always be set"
            assert result.returncode == 0

    def test_shell_false_is_always_set(self, authorized_path, tmp_path):
        """
        Regardless of arguments, subprocess.run must NEVER be called with
        shell=True.  This test explicitly asserts the security invariant.
        """
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\necho ok")

        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}), \
             patch("config.path_validator.subprocess.run", return_value=mock_result) as mock_run:

            run_forensic_tool("mmls", str(authorized_path))
            _, kwargs = mock_run.call_args
            assert kwargs["shell"] is False

    def test_invalid_path_raises_before_subprocess(self, unauthorized_path, tmp_path):
        """
        PathValidationError must be raised BEFORE subprocess.run is ever called.
        """
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\necho ok")

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}), \
             patch("config.path_validator.subprocess.run") as mock_run:

            with pytest.raises(PathValidationError):
                run_forensic_tool("mmls", unauthorized_path)

            mock_run.assert_not_called()  # subprocess must never be reached

    def test_timeout_propagates(self, authorized_path, tmp_path):
        """subprocess.TimeoutExpired should propagate to the caller."""
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\nsleep 9999")

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}), \
             patch(
                 "config.path_validator.subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="mmls", timeout=1),
             ):
            with pytest.raises(subprocess.TimeoutExpired):
                run_forensic_tool("mmls", str(authorized_path))


# ---------------------------------------------------------------------------
# Audit log tests
# ---------------------------------------------------------------------------

@pytest.fixture
def audit_log_file(tmp_path):
    """Redirect audit_logger to a temp file; restore original handlers after."""
    from config.path_validator import audit_logger
    log_file = tmp_path / "test_audit.log"
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    original = audit_logger.handlers[:]
    for h in original:
        audit_logger.removeHandler(h)
    audit_logger.addHandler(handler)
    yield log_file
    handler.close()
    audit_logger.removeHandler(handler)
    for h in original:
        audit_logger.addHandler(h)


class TestAuditLog:

    def test_audit_file_is_created_on_success(self, authorized_path, tmp_path, audit_log_file):
        """A successful run must produce a non-empty audit log entry."""
        fake_bin = tmp_path / "sha256sum"
        fake_bin.write_text("#!/bin/sh\necho ok")
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout, mock_result.stderr, mock_result.returncode = "ok\n", "", 0

        with patch("config.path_validator.ALLOWED_BINARIES", {"sha256sum": fake_bin}), \
             patch("config.path_validator.subprocess.run", return_value=mock_result):
            run_forensic_tool("sha256sum", str(authorized_path))

        assert audit_log_file.exists()
        assert audit_log_file.stat().st_size > 0

    def test_audit_entry_format_on_success(self, authorized_path, tmp_path, audit_log_file):
        """Audit entry must contain all required pipe-delimited fields on success."""
        import re
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\necho ok")
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout, mock_result.stderr, mock_result.returncode = "", "", 0

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}), \
             patch("config.path_validator.subprocess.run", return_value=mock_result):
            run_forensic_tool("mmls", str(authorized_path))

        entry = audit_log_file.read_text(encoding="utf-8").strip()
        assert "| AUDIT |" in entry
        assert "tool=mmls" in entry
        assert str(authorized_path.resolve()) in entry
        assert "rc=0" in entry
        assert "status=SUCCESS" in entry
        assert "elapsed=" in entry
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", entry)

    def test_audit_entry_on_nonzero_exit(self, authorized_path, tmp_path, audit_log_file):
        """A non-zero return code must produce status=FAILURE in the audit entry."""
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\nexit 1")
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout, mock_result.stderr, mock_result.returncode = "", "error", 1

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}), \
             patch("config.path_validator.subprocess.run", return_value=mock_result):
            run_forensic_tool("mmls", str(authorized_path))

        entry = audit_log_file.read_text(encoding="utf-8").strip()
        assert "rc=1" in entry
        assert "status=FAILURE" in entry

    def test_multiple_runs_produce_multiple_entries(self, authorized_path, tmp_path, audit_log_file):
        """Each run_forensic_tool call must append exactly one line to the audit log."""
        fake_bin = tmp_path / "mmls"
        fake_bin.write_text("#!/bin/sh\necho ok")
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout, mock_result.stderr, mock_result.returncode = "", "", 0

        with patch("config.path_validator.ALLOWED_BINARIES", {"mmls": fake_bin}), \
             patch("config.path_validator.subprocess.run", return_value=mock_result):
            run_forensic_tool("mmls", str(authorized_path))
            run_forensic_tool("mmls", str(authorized_path))
            run_forensic_tool("mmls", str(authorized_path))

        lines = [l for l in audit_log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) == 3
