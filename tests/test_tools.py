# tests/test_tools.py
#
# Project FIND-EVIL — Smoke Tests for tools/ modules
# ====================================================
# High-level smoke tests that verify each tool module correctly delegates
# to run_forensic_tool() and returns the expected dict structure.
#
# Run with:  python -m pytest tests/ -v

import pytest
from unittest.mock import patch, MagicMock
import subprocess


# ---------------------------------------------------------------------------
# Shared mock factory
# ---------------------------------------------------------------------------

def make_mock_result(stdout="", stderr="", returncode=0):
    """Return a mock subprocess.CompletedProcess."""
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


MOCK_PATH = "config.path_validator.run_forensic_tool"


# ---------------------------------------------------------------------------
# Disk tools
# ---------------------------------------------------------------------------

class TestDiskTools:

    def test_list_partitions_returns_dict(self):
        from tools.disk_tools import list_partitions
        with patch(MOCK_PATH, return_value=make_mock_result(stdout="DOS partition table")) as mock:
            result = list_partitions("/cases/disk.dd")
            assert "stdout" in result
            assert "returncode" in result
            mock.assert_called_once()

    def test_filesystem_stats_returns_dict(self):
        from tools.disk_tools import filesystem_stats
        with patch(MOCK_PATH, return_value=make_mock_result(stdout="FILE SYSTEM INFORMATION")) as mock:
            result = filesystem_stats("/cases/disk.dd")
            assert "stdout" in result
            mock.assert_called_once()

    def test_list_files_recursive_flag(self):
        from tools.disk_tools import list_files
        with patch(MOCK_PATH, return_value=make_mock_result()) as mock:
            list_files("/cases/disk.dd")
            _, kwargs = mock.call_args
            assert "-r" in kwargs.get("extra_args", [])


# ---------------------------------------------------------------------------
# Hash tools
# ---------------------------------------------------------------------------

class TestHashTools:

    def test_hash_evidence_parses_hash(self):
        from tools.hash_tools import calculate_hash
        fake_hash = "a" * 64
        with patch(MOCK_PATH, return_value=make_mock_result(stdout=f"{fake_hash}  /cases/disk.dd\n")):
            result = calculate_hash("/cases/disk.dd", algorithm="sha256")
            assert result["hash"] == fake_hash
            assert result["algorithm"] == "sha256"

    def test_verify_hash_match(self):
        from tools.hash_tools import verify_hash
        fake_hash = "b" * 64
        with patch(MOCK_PATH, return_value=make_mock_result(stdout=f"{fake_hash}  /cases/disk.dd\n")):
            result = verify_hash("/cases/disk.dd", expected_hash=fake_hash)
            assert result["match"] is True

    def test_verify_hash_mismatch(self):
        from tools.hash_tools import verify_hash
        with patch(MOCK_PATH, return_value=make_mock_result(stdout="aaa  /cases/disk.dd\n")):
            result = verify_hash("/cases/disk.dd", expected_hash="bbb")
            assert result["match"] is False

    def test_unsupported_algorithm_raises(self):
        from tools.hash_tools import calculate_hash
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            calculate_hash("/cases/disk.dd", algorithm="crc32")


# ---------------------------------------------------------------------------
# Memory tools
# ---------------------------------------------------------------------------

class TestMemoryTools:

    def test_list_processes_windows(self):
        from tools.memory_tools import list_processes
        with patch(MOCK_PATH, return_value=make_mock_result(stdout="PID  Name")) as mock:
            result = list_processes("/cases/mem.raw", os_profile="windows")
            assert "stdout" in result
            _, kwargs = mock.call_args
            assert "windows.pslist" in kwargs.get("extra_args", [])

    def test_list_processes_linux(self):
        from tools.memory_tools import list_processes
        with patch(MOCK_PATH, return_value=make_mock_result()) as mock:
            list_processes("/cases/mem.raw", os_profile="linux")
            _, kwargs = mock.call_args
            assert "linux.pslist" in kwargs.get("extra_args", [])


# ---------------------------------------------------------------------------
# Network tools
# ---------------------------------------------------------------------------

class TestNetworkTools:

    def test_read_pcap_returns_dict(self):
        from tools.network_tools import read_pcap
        with patch(MOCK_PATH, return_value=make_mock_result(stdout="Frame 1")) as mock:
            result = read_pcap("/cases/capture.pcap")
            assert "stdout" in result
            mock.assert_called_once()

    def test_read_pcap_with_filter(self):
        from tools.network_tools import read_pcap
        with patch(MOCK_PATH, return_value=make_mock_result()) as mock:
            read_pcap("/cases/capture.pcap", display_filter="http")
            _, kwargs = mock.call_args
            assert "-Y" in kwargs.get("extra_args", [])
