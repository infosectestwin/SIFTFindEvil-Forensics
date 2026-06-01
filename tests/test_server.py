# tests/test_server.py
#
# Project FIND-EVIL — Integration Tests for server.py
# ====================================================
# Verifies that the MCP server layer correctly dispatches tool calls through
# the underlying tool modules and all the way down to run_forensic_tool() in
# config/path_validator.py.
#
# Patching strategy: run_forensic_tool is patched at the tool-module level
# (e.g. tools.disk_tools.run_forensic_tool) so the full chain
#   server function → tools/*.py → path_validator.run_forensic_tool
# is exercised with only the final subprocess call mocked out.
#
# Run with:  python -m pytest tests/test_server.py -v

import asyncio
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from config.path_validator import PathValidationError, ToolNotFoundError


def _mock_result(stdout="", stderr="", returncode=0):
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout, m.stderr, m.returncode = stdout, stderr, returncode
    return m


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

class TestToolRegistration:

    def test_all_tools_registered_in_mcp(self):
        """All four implemented tools must be registered on the FastMCP instance."""
        from server import mcp
        tools = asyncio.run(mcp.list_tools())
        names = {t.name for t in tools}
        assert "list_partitions" in names
        assert "list_files" in names
        assert "calculate_hash" in names
        assert "verify_hash" in names

    def test_all_tool_functions_importable(self):
        """Server-level tool functions must be importable and callable."""
        from server import list_partitions, list_files, calculate_hash, verify_hash
        assert all(callable(f) for f in [list_partitions, list_files, calculate_hash, verify_hash])


# ---------------------------------------------------------------------------
# Dispatch chain: server → tools/*.py → run_forensic_tool
# ---------------------------------------------------------------------------

class TestDispatchChain:

    def test_list_partitions_reaches_run_forensic_tool(self):
        """
        Calling server.list_partitions must reach run_forensic_tool with
        tool_name='mmls' and the correct evidence_path.
        """
        from server import list_partitions
        with patch("tools.disk_tools.run_forensic_tool",
                   return_value=_mock_result(stdout="DOS Partition Table")) as mock:
            result = list_partitions("/cases/disk.dd")
            mock.assert_called_once()
            _, kwargs = mock.call_args
            assert kwargs["tool_name"] == "mmls"
            assert kwargs["evidence_path"] == "/cases/disk.dd"
        assert result["stdout"] == "DOS Partition Table"

    def test_list_files_reaches_run_forensic_tool_with_recursive_flag(self):
        """
        Calling server.list_files must reach run_forensic_tool with
        tool_name='fls' and -r in extra_args.
        """
        from server import list_files
        with patch("tools.disk_tools.run_forensic_tool",
                   return_value=_mock_result(stdout="r/r 5-128-1: passwd")) as mock:
            result = list_files("/cases/disk.dd")
            mock.assert_called_once()
            _, kwargs = mock.call_args
            assert kwargs["tool_name"] == "fls"
            assert kwargs["evidence_path"] == "/cases/disk.dd"
            assert "-r" in kwargs.get("extra_args", [])
        assert result["stdout"] == "r/r 5-128-1: passwd"

    def test_list_files_forwards_inode_to_run_forensic_tool(self):
        """When inode is given, it must appear in extra_args after -r."""
        from server import list_files
        with patch("tools.disk_tools.run_forensic_tool",
                   return_value=_mock_result()) as mock:
            list_files("/cases/disk.dd", inode=3)
            _, kwargs = mock.call_args
            extra = kwargs.get("extra_args", [])
            assert "-r" in extra
            assert "3" in extra

    def test_calculate_hash_reaches_run_forensic_tool_with_correct_binary(self):
        """
        Calling server.calculate_hash must reach run_forensic_tool with the
        binary that corresponds to the requested algorithm.
        """
        from server import calculate_hash
        fake_hash = "a" * 64
        with patch("tools.hash_tools.run_forensic_tool",
                   return_value=_mock_result(stdout=f"{fake_hash}  /cases/disk.dd\n")) as mock:
            result = calculate_hash("/cases/disk.dd", algorithm="sha256")
            mock.assert_called_once()
            _, kwargs = mock.call_args
            assert kwargs["tool_name"] == "sha256sum"
            assert kwargs["evidence_path"] == "/cases/disk.dd"
        assert result["hash"] == fake_hash

    @pytest.mark.parametrize("algorithm,binary", [
        ("sha256", "sha256sum"),
        ("sha1",   "sha1sum"),
        ("md5",    "md5sum"),
    ])
    def test_calculate_hash_selects_correct_binary(self, algorithm, binary):
        from server import calculate_hash
        h = "a" * {"sha256": 64, "sha1": 40, "md5": 32}[algorithm]
        with patch("tools.hash_tools.run_forensic_tool",
                   return_value=_mock_result(stdout=f"{h}  /cases/disk.dd\n")) as mock:
            calculate_hash("/cases/disk.dd", algorithm=algorithm)
            _, kwargs = mock.call_args
            assert kwargs["tool_name"] == binary


# ---------------------------------------------------------------------------
# Security error propagation
# ---------------------------------------------------------------------------

class TestSecurityErrorPropagation:

    def test_path_validation_error_propagates_through_server(self):
        """
        PathValidationError raised in path_validator must propagate through
        the server layer unchanged so the MCP host receives a meaningful error.
        """
        from server import list_partitions
        with patch("tools.disk_tools.run_forensic_tool",
                   side_effect=PathValidationError("path outside /cases/")):
            with pytest.raises(PathValidationError, match="path outside /cases/"):
                list_partitions("/etc/passwd")

    def test_tool_not_found_error_propagates_through_server(self):
        """ToolNotFoundError must propagate through the server layer."""
        from server import list_partitions
        with patch("tools.disk_tools.run_forensic_tool",
                   side_effect=ToolNotFoundError("mmls not in allowlist")):
            with pytest.raises(ToolNotFoundError, match="mmls not in allowlist"):
                list_partitions("/cases/disk.dd")

    def test_calculate_hash_rejects_unsupported_algorithm_before_dispatch(self):
        """
        ValueError for an unsupported algorithm must be raised before
        run_forensic_tool is ever called.
        """
        from server import calculate_hash
        with patch("tools.hash_tools.run_forensic_tool") as mock:
            with pytest.raises(ValueError, match="Unsupported algorithm"):
                calculate_hash("/cases/disk.dd", algorithm="crc32")
            mock.assert_not_called()
