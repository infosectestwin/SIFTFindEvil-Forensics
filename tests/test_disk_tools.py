# tests/test_disk_tools.py
#
# Project FIND-EVIL — Tests for tools/disk_tools.py
# ==================================================
# Patches run_forensic_tool at the tools.disk_tools module level so path
# validation is bypassed and only command construction is tested.
#
# Run with:  python -m pytest tests/test_disk_tools.py -v

import subprocess
import pytest
from unittest.mock import patch, MagicMock


PATCH_TARGET = "tools.disk_tools.run_forensic_tool"


def _mock_result(stdout="", stderr="", returncode=0):
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout, m.stderr, m.returncode = stdout, stderr, returncode
    return m


# ---------------------------------------------------------------------------
# list_partitions
# ---------------------------------------------------------------------------

class TestListPartitions:

    def test_calls_mmls(self):
        from tools.disk_tools import list_partitions
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_partitions("/cases/disk.dd")
            args, kwargs = mock.call_args
            assert kwargs.get("tool_name") == "mmls"

    def test_evidence_path_is_forwarded(self):
        from tools.disk_tools import list_partitions
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_partitions("/cases/disk.dd")
            _, kwargs = mock.call_args
            assert kwargs.get("evidence_path") == "/cases/disk.dd"

    def test_partition_type_in_extra_args(self):
        from tools.disk_tools import list_partitions
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_partitions("/cases/disk.dd", partition_type="gpt")
            _, kwargs = mock.call_args
            extra = kwargs.get("extra_args", [])
            assert "-t" in extra
            assert "gpt" in extra

    def test_default_partition_type_is_dos(self):
        from tools.disk_tools import list_partitions
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_partitions("/cases/disk.dd")
            _, kwargs = mock.call_args
            extra = kwargs.get("extra_args", [])
            assert "dos" in extra

    def test_returns_stdout_stderr_returncode(self):
        from tools.disk_tools import list_partitions
        with patch(PATCH_TARGET, return_value=_mock_result(stdout="DOS table", returncode=0)):
            result = list_partitions("/cases/disk.dd")
            assert result == {"stdout": "DOS table", "stderr": "", "returncode": 0}


# ---------------------------------------------------------------------------
# list_files
# ---------------------------------------------------------------------------

class TestListFiles:

    def test_calls_fls(self):
        from tools.disk_tools import list_files
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_files("/cases/disk.dd")
            _, kwargs = mock.call_args
            assert kwargs.get("tool_name") == "fls"

    def test_evidence_path_is_forwarded(self):
        from tools.disk_tools import list_files
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_files("/cases/disk.dd")
            _, kwargs = mock.call_args
            assert kwargs.get("evidence_path") == "/cases/disk.dd"

    def test_recursive_flag_always_present(self):
        from tools.disk_tools import list_files
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_files("/cases/disk.dd")
            _, kwargs = mock.call_args
            assert "-r" in kwargs.get("extra_args", [])

    def test_inode_appended_when_given(self):
        from tools.disk_tools import list_files
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_files("/cases/disk.dd", inode=5)
            _, kwargs = mock.call_args
            extra = kwargs.get("extra_args", [])
            assert "-r" in extra
            assert "5" in extra

    def test_inode_not_present_when_none(self):
        from tools.disk_tools import list_files
        with patch(PATCH_TARGET, return_value=_mock_result()) as mock:
            list_files("/cases/disk.dd", inode=None)
            _, kwargs = mock.call_args
            extra = kwargs.get("extra_args", [])
            assert extra == ["-r"]

    def test_returns_stdout_stderr_returncode(self):
        from tools.disk_tools import list_files
        with patch(PATCH_TARGET, return_value=_mock_result(stdout="r/r 5-128-1: passwd", returncode=0)):
            result = list_files("/cases/disk.dd")
            assert result == {"stdout": "r/r 5-128-1: passwd", "stderr": "", "returncode": 0}
