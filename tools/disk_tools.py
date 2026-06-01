# tools/disk_tools.py
#
# Project FIND-EVIL — Disk & Partition Analysis Tools
# =====================================================
# Wraps The Sleuth Kit (TSK) binaries for disk image analysis.
# All subprocess execution is routed through run_forensic_tool() in
# config/path_validator.py, which enforces shell=False and path validation.

from config.path_validator import run_forensic_tool


def list_partitions(image_path: str, partition_type: str = "dos") -> dict:
    """
    List the partition layout of a disk image using mmls.

    Parameters
    ----------
    image_path : str
        Absolute path to the forensic disk image. Must reside within an
        AUTHORIZED_ROOT (e.g. /cases/) — enforced by run_forensic_tool().
    partition_type : str
        Partition table type passed to mmls via -t. Values: "dos" (default),
        "gpt", "mac", "sun".

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    result = run_forensic_tool(
        tool_name="mmls",
        evidence_path=image_path,
        extra_args=["-t", partition_type],
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def list_files(image_path: str, inode: int | None = None) -> dict:
    """
    List files and directories in a disk image using fls -r.

    Always runs recursively. When inode is given, fls lists the contents of
    that specific directory inode instead of starting from the root.

    Parameters
    ----------
    image_path : str
        Absolute path to the forensic disk image. Must reside within an
        AUTHORIZED_ROOT (e.g. /cases/) — enforced by run_forensic_tool().
    inode : int | None
        Optional inode number to list. When None, fls starts from the
        file-system root.

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    extra_args = ["-r"]
    if inode is not None:
        extra_args.append(str(inode))

    result = run_forensic_tool(
        tool_name="fls",
        evidence_path=image_path,
        extra_args=extra_args,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
