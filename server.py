# server.py
#
# Project FIND-EVIL — MCP Server Entry Point
# ===========================================
# Registers all implemented forensic tools via FastMCP and starts the
# stdio transport so an MCP host (e.g., Claude Desktop) can call them.
#
# Architecture
# ------------
#   server.py                 ← you are here (tool registration + startup)
#   tools/disk_tools.py       ← TSK: list_partitions, list_files
#   tools/hash_tools.py       ← sha256/sha1/md5: calculate_hash, verify_hash
#   config/path_validator.py  ← Forensic Execution Wrapper (security core)
#   config/settings.py        ← AUTHORIZED_ROOTS + ALLOWED_BINARIES allowlist
#
# Security note: every tool call flows through run_forensic_tool() in
# config/path_validator.py, which enforces path validation and shell=False.
# image_path / evidence_path arguments MUST reside within /cases/ or another
# root listed in AUTHORIZED_ROOTS — any other path is rejected before any
# subprocess is spawned.
#
# Usage
# -----
#   python server.py

import logging
import sys

from mcp.server.fastmcp import FastMCP

from config.path_validator import PathValidationError, ToolNotFoundError
from tools.disk_tools import list_partitions as _list_partitions, list_files as _list_files
from tools.hash_tools import calculate_hash as _calculate_hash, verify_hash as _verify_hash
from tools.memory_tools import analyze_memory as _analyze_memory

# ---------------------------------------------------------------------------
# Logging — keep on stderr; MCP uses stdout for protocol messages.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("find-evil")

# ---------------------------------------------------------------------------
# FastMCP server instance
# ---------------------------------------------------------------------------
mcp = FastMCP("find-evil")


# ===========================================================================
# Disk tools
# ===========================================================================

@mcp.tool()
def list_partitions(image_path: str, partition_type: str = "dos") -> dict:
    """
    List the partition layout of a forensic disk image using mmls (The Sleuth Kit).

    SECURITY: image_path must be an absolute path within /cases/ or another
    AUTHORIZED_ROOT defined in config/settings.py. Paths outside those roots
    are rejected by config/path_validator.py before any subprocess is run.

    Args:
        image_path: Absolute path to the forensic disk image, e.g. /cases/case01/disk.dd
        partition_type: Partition table type — 'dos' (default), 'gpt', 'mac', or 'sun'
    """
    try:
        return _list_partitions(image_path=image_path, partition_type=partition_type)
    except (PathValidationError, ToolNotFoundError) as exc:
        logger.warning("[server] Security error in list_partitions: %s", exc)
        raise


@mcp.tool()
def list_files(image_path: str, inode: int | None = None) -> dict:
    """
    Recursively list all files and directories in a forensic disk image using fls -r (The Sleuth Kit).

    SECURITY: image_path must be an absolute path within /cases/ or another
    AUTHORIZED_ROOT defined in config/settings.py. Paths outside those roots
    are rejected by config/path_validator.py before any subprocess is run.

    Args:
        image_path: Absolute path to the forensic disk image, e.g. /cases/case01/disk.dd
        inode: Optional inode number to list a specific directory; omit to start from the root
    """
    try:
        return _list_files(image_path=image_path, inode=inode)
    except (PathValidationError, ToolNotFoundError) as exc:
        logger.warning("[server] Security error in list_files: %s", exc)
        raise


# ===========================================================================
# Memory tools
# ===========================================================================

@mcp.tool()
def analyze_memory(
    image_path: str,
    plugin: str,
    plugin_args: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """
    Run a Volatility 3 plugin against a memory image.

    Executes: vol -f <image_path> <plugin> [plugin_args...]

    SECURITY: image_path must be an absolute path within /cases/ or another
    AUTHORIZED_ROOT defined in config/settings.py. Paths outside those roots
    are rejected by config/path_validator.py before any subprocess is run.

    Args:
        image_path:  Absolute path to the memory image, e.g. /cases/memory/rd01-memory.img
        plugin:      Volatility 3 plugin name, e.g. "windows.pstree", "windows.cmdline",
                     "windows.netscan", "windows.malfind", "linux.bash". Single token.
        plugin_args: Optional list of extra plugin arguments, e.g. ["--pid", "1234"].
                     Must be a pre-split list — never a shell-style string.
        timeout:     Subprocess timeout in seconds (default 300). Automatically
                     overridden to 1200 when plugin is "windows.netscan".
    """
    try:
        return _analyze_memory(
            image_path=image_path,
            plugin=plugin,
            plugin_args=plugin_args,
            timeout=timeout,
        )
    except (PathValidationError, ToolNotFoundError) as exc:
        logger.warning("[server] Security error in analyze_memory: %s", exc)
        raise


# ===========================================================================
# Hash tools
# ===========================================================================

@mcp.tool()
def calculate_hash(image_path: str, algorithm: str = "sha256") -> dict:
    """
    Compute a cryptographic hash of a forensic evidence file.

    SECURITY: image_path must be an absolute path within /cases/ or another
    AUTHORIZED_ROOT defined in config/settings.py. Paths outside those roots
    are rejected by config/path_validator.py before any subprocess is run.

    Args:
        image_path: Absolute path to the evidence file, e.g. /cases/case01/disk.dd
        algorithm: Hash algorithm — 'sha256' (default), 'sha1', or 'md5'
    """
    try:
        return _calculate_hash(image_path=image_path, algorithm=algorithm)
    except (PathValidationError, ToolNotFoundError) as exc:
        logger.warning("[server] Security error in calculate_hash: %s", exc)
        raise


@mcp.tool()
def verify_hash(image_path: str, expected_hash: str, algorithm: str = "sha256") -> dict:
    """
    Verify the integrity of a forensic evidence file against a known-good hash.

    SECURITY: image_path must be an absolute path within /cases/ or another
    AUTHORIZED_ROOT defined in config/settings.py. Paths outside those roots
    are rejected by config/path_validator.py before any subprocess is run.

    Args:
        image_path: Absolute path to the evidence file, e.g. /cases/case01/disk.dd
        expected_hash: Known-good hash value to compare against (case-insensitive)
        algorithm: Hash algorithm — 'sha256' (default), 'sha1', or 'md5'
    """
    try:
        return _verify_hash(image_path=image_path, expected_hash=expected_hash, algorithm=algorithm)
    except (PathValidationError, ToolNotFoundError) as exc:
        logger.warning("[server] Security error in verify_hash: %s", exc)
        raise


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    logger.info("Starting Project FIND-EVIL MCP server...")
    mcp.run()
