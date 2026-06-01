# tools/hash_tools.py
#
# Project FIND-EVIL — Hashing & Integrity Verification Tools
# ===========================================================
# Wraps sha256sum, sha1sum, and md5sum for evidence integrity verification.
# All subprocess execution is routed through run_forensic_tool() in
# config/path_validator.py, which enforces shell=False and path validation.

from config.path_validator import run_forensic_tool

_ALGORITHM_TO_BINARY: dict[str, str] = {
    "sha256": "sha256sum",
    "sha1":   "sha1sum",
    "md5":    "md5sum",
}


def calculate_hash(image_path: str, algorithm: str = "sha256") -> dict:
    """
    Compute a cryptographic hash of a forensic image or evidence file.

    Parameters
    ----------
    image_path : str
        Absolute path to the file to hash. Must reside within an
        AUTHORIZED_ROOT (e.g. /cases/) — enforced by run_forensic_tool().
    algorithm : str
        Hash algorithm — "sha256" (default), "sha1", or "md5".

    Returns
    -------
    dict
        {"hash": str, "algorithm": str, "path": str,
         "stdout": str, "stderr": str, "returncode": int}

    Raises
    ------
    ValueError
        If algorithm is not one of "sha256", "sha1", "md5".
    """
    if algorithm not in _ALGORITHM_TO_BINARY:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. "
            f"Choose from: {sorted(_ALGORITHM_TO_BINARY)}"
        )

    result = run_forensic_tool(
        tool_name=_ALGORITHM_TO_BINARY[algorithm],
        evidence_path=image_path,
    )

    # sha*sum / md5sum output format: "<hash>  <filename>"
    hash_value = result.stdout.split()[0] if result.stdout.strip() else ""

    return {
        "hash": hash_value,
        "algorithm": algorithm,
        "path": image_path,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def verify_hash(image_path: str, expected_hash: str, algorithm: str = "sha256") -> dict:
    """
    Verify the integrity of an evidence file against a known-good hash.

    Parameters
    ----------
    image_path : str
        Absolute path to the file to verify.
    expected_hash : str
        The known-good hash value to compare against (case-insensitive).
    algorithm : str
        Hash algorithm — "sha256" (default), "sha1", or "md5".

    Returns
    -------
    dict
        {"match": bool, "computed_hash": str, "expected_hash": str,
         "algorithm": str, "path": str}
    """
    result = calculate_hash(image_path, algorithm)
    computed = result["hash"]
    return {
        "match": computed.lower() == expected_hash.lower(),
        "computed_hash": computed,
        "expected_hash": expected_hash,
        "algorithm": algorithm,
        "path": image_path,
    }
