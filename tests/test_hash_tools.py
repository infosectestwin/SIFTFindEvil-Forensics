# tests/test_hash_tools.py
#
# Project FIND-EVIL — Tests for tools/hash_tools.py
# ==================================================
# Patches run_forensic_tool at the tools.hash_tools module level so path
# validation is bypassed and only command construction / output parsing is
# tested.
#
# Run with:  python -m pytest tests/test_hash_tools.py -v

import subprocess
import pytest
from unittest.mock import patch, MagicMock, call


PATCH_TARGET = "tools.hash_tools.run_forensic_tool"


def _mock_result(stdout="", stderr="", returncode=0):
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout, m.stderr, m.returncode = stdout, stderr, returncode
    return m


def _fake_hash(algorithm: str) -> str:
    lengths = {"sha256": 64, "sha1": 40, "md5": 32}
    return "a" * lengths[algorithm]


# ---------------------------------------------------------------------------
# Binary selection
# ---------------------------------------------------------------------------

class TestBinarySelection:

    @pytest.mark.parametrize("algorithm,expected_binary", [
        ("sha256", "sha256sum"),
        ("sha1",   "sha1sum"),
        ("md5",    "md5sum"),
    ])
    def test_correct_binary_chosen(self, algorithm, expected_binary):
        from tools.hash_tools import calculate_hash
        h = _fake_hash(algorithm)
        with patch(PATCH_TARGET, return_value=_mock_result(stdout=f"{h}  /cases/disk.dd\n")) as mock:
            calculate_hash("/cases/disk.dd", algorithm=algorithm)
            _, kwargs = mock.call_args
            assert kwargs.get("tool_name") == expected_binary

    def test_default_algorithm_is_sha256(self):
        from tools.hash_tools import calculate_hash
        h = _fake_hash("sha256")
        with patch(PATCH_TARGET, return_value=_mock_result(stdout=f"{h}  /cases/disk.dd\n")) as mock:
            calculate_hash("/cases/disk.dd")
            _, kwargs = mock.call_args
            assert kwargs.get("tool_name") == "sha256sum"


# ---------------------------------------------------------------------------
# image_path validation forwarding
# ---------------------------------------------------------------------------

class TestImagePathForwarding:

    def test_image_path_passed_as_evidence_path(self):
        from tools.hash_tools import calculate_hash
        h = _fake_hash("sha256")
        with patch(PATCH_TARGET, return_value=_mock_result(stdout=f"{h}  /cases/img.dd\n")) as mock:
            calculate_hash("/cases/img.dd")
            _, kwargs = mock.call_args
            assert kwargs.get("evidence_path") == "/cases/img.dd"

    def test_image_path_preserved_in_return_dict(self):
        from tools.hash_tools import calculate_hash
        h = _fake_hash("sha256")
        with patch(PATCH_TARGET, return_value=_mock_result(stdout=f"{h}  /cases/img.dd\n")):
            result = calculate_hash("/cases/img.dd")
            assert result["path"] == "/cases/img.dd"


# ---------------------------------------------------------------------------
# Hash parsing
# ---------------------------------------------------------------------------

class TestHashParsing:

    @pytest.mark.parametrize("algorithm", ["sha256", "sha1", "md5"])
    def test_hash_extracted_from_stdout(self, algorithm):
        from tools.hash_tools import calculate_hash
        expected = _fake_hash(algorithm)
        with patch(PATCH_TARGET, return_value=_mock_result(stdout=f"{expected}  /cases/disk.dd\n")):
            result = calculate_hash("/cases/disk.dd", algorithm=algorithm)
            assert result["hash"] == expected
            assert result["algorithm"] == algorithm

    def test_empty_stdout_yields_empty_hash(self):
        from tools.hash_tools import calculate_hash
        with patch(PATCH_TARGET, return_value=_mock_result(stdout="")):
            result = calculate_hash("/cases/disk.dd")
            assert result["hash"] == ""


# ---------------------------------------------------------------------------
# Unsupported algorithm
# ---------------------------------------------------------------------------

class TestUnsupportedAlgorithm:

    @pytest.mark.parametrize("bad_algo", ["crc32", "blake2", "sha512", ""])
    def test_raises_value_error(self, bad_algo):
        from tools.hash_tools import calculate_hash
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            calculate_hash("/cases/disk.dd", algorithm=bad_algo)

    def test_run_forensic_tool_not_called_on_bad_algorithm(self):
        from tools.hash_tools import calculate_hash
        with patch(PATCH_TARGET) as mock:
            with pytest.raises(ValueError):
                calculate_hash("/cases/disk.dd", algorithm="crc32")
            mock.assert_not_called()
