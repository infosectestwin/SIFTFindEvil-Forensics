# config/path_validator.py
#
# Project FIND-EVIL — Forensic Execution Wrapper
# ================================================
# This module is the security gateway for ALL subprocess execution in the
# project.  Every forensic tool module in tools/ MUST route its subprocess
# calls through run_forensic_tool() defined here.
#
# Security guarantees provided by this module:
#   1. Path traversal prevention  — Path.resolve() canonicalises the input
#      before it is compared against AUTHORIZED_ROOTS.  Sequences like
#      "../../../etc/passwd" are neutralised before any check is performed.
#   2. Authorized-root enforcement — only paths that are descendants of an
#      entry in AUTHORIZED_ROOTS (defined in config/settings.py) are accepted.
#   3. Binary allowlist enforcement — only binaries registered in
#      ALLOWED_BINARIES (defined in config/settings.py) may be executed.
#      See that file for the full list and instructions on adding new tools.
#   4. Shell-injection prevention — subprocess.run() is ALWAYS called with
#      shell=False.  The command is passed as a list[str], never as a string,
#      so the OS kernel receives the arguments directly without shell parsing.
#   5. Timeout enforcement — every child process is subject to
#      SUBPROCESS_TIMEOUT seconds; runaway processes are terminated.
#   6. Output capture — stdout and stderr are always captured so the MCP
#      server can return structured results to the AI agent.
#
# Public API
# ----------
#   validate_evidence_path(raw_path)          -> Path
#   get_tool_path(tool_name)                  -> Path
#   run_forensic_tool(tool_name,
#                     evidence_path,
#                     extra_args)             -> subprocess.CompletedProcess

import datetime
import os
import subprocess
import logging
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Import the two security-critical constants from config/settings.py.
#
# AUTHORIZED_ROOTS  — list of Path objects representing the only directories
#                     where forensic evidence is permitted to reside.
#
# ALLOWED_BINARIES  — dict[str, Path] mapping short tool names to their
#                     absolute binary paths on the SIFT workstation.
#                     *** THE ALLOWED BINARIES LIST IS DEFINED IN
#                         config/settings.py — edit that file to add or
#                         remove tools from the allowlist. ***
#
# SUBPROCESS_TIMEOUT — int, maximum seconds a child process may run.
# ---------------------------------------------------------------------------
from config.settings import AUTHORIZED_ROOTS, ALLOWED_BINARIES, SUBPROCESS_TIMEOUT, AUDIT_LOG_PATH

logger = logging.getLogger(__name__)

# --- Dedicated forensic audit logger (writes to forensic_audit.log) ---
audit_logger = logging.getLogger("find-evil.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False  # CRITICAL: prevents records leaking to stderr / stdio transport
_audit_handler = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_audit_handler)


# ===========================================================================
# Custom exceptions
# ===========================================================================

class PathValidationError(Exception):
    """
    Raised when a caller-supplied path fails one or more authorization checks.

    Possible causes:
      - The path does not exist on disk.
      - The path resolves outside every entry in AUTHORIZED_ROOTS.
      - The path cannot be resolved (e.g., permission denied during stat).
    """


class ToolNotFoundError(Exception):
    """
    Raised when the requested tool name is not present in ALLOWED_BINARIES
    or when the registered binary does not exist at its expected location.

    To fix: add the tool to ALLOWED_BINARIES in config/settings.py.
    """


# ===========================================================================
# validate_evidence_path
# ===========================================================================

def validate_evidence_path(raw_path: str) -> Path:
    """
    Resolve and validate that *raw_path* is within an authorized forensic root.

    This function is the first line of defence against path-traversal attacks.
    It MUST be called before any file-system operation or subprocess invocation
    that uses a caller-supplied path.

    Validation steps
    ----------------
    1. Resolve the path to its absolute, canonical form using Path.resolve().
       ``strict=True`` means the path must already exist; non-existent paths
       are rejected immediately.  This also collapses any ``../`` components,
       symlinks, and redundant separators.
    2. Iterate over AUTHORIZED_ROOTS and check whether the resolved path is a
       descendant of at least one root using Path.relative_to().  If the path
       is not relative to a given root, relative_to() raises ValueError and we
       try the next root.
    3. If no root matches, raise PathValidationError with a descriptive message
       that includes the resolved path and the full list of authorized roots.

    Parameters
    ----------
    raw_path : str
        The raw path string supplied by the MCP tool caller.

    Returns
    -------
    Path
        The resolved, validated Path object — safe to pass to subprocesses.

    Raises
    ------
    PathValidationError
        If the path does not exist, cannot be resolved, or falls outside every
        entry in AUTHORIZED_ROOTS.
    """
    # Step 1 — Canonicalise.  strict=True enforces existence on disk.
    try:
        resolved = Path(raw_path).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise PathValidationError(
            f"Evidence path does not exist or cannot be resolved: {raw_path!r}"
        ) from exc

    # Step 2 — Check against every authorized root.
    for root in AUTHORIZED_ROOTS:
        try:
            # relative_to() raises ValueError if resolved is NOT under root.
            resolved.relative_to(root.resolve())
            logger.info(
                "[path_validator] AUTHORIZED  path=%s  root=%s", resolved, root
            )
            return resolved  # Path is safe — return the canonical form.
        except ValueError:
            continue  # Not under this root; try the next one.

    # Step 3 — No root matched; reject the path.
    authorized_str = [str(r) for r in AUTHORIZED_ROOTS]
    logger.warning(
        "[path_validator] REJECTED  path=%s  authorized_roots=%s",
        resolved, authorized_str
    )
    raise PathValidationError(
        f"Path {str(resolved)!r} is not within any authorized forensic "
        f"directory.\n"
        f"Authorized roots: {authorized_str}\n"
        f"To add a new root, edit AUTHORIZED_ROOTS in config/settings.py."
    )


# ===========================================================================
# get_tool_path
# ===========================================================================

def get_tool_path(tool_name: str) -> Path:
    """
    Look up *tool_name* in the ALLOWED_BINARIES allowlist and return its Path.

    The ALLOWED_BINARIES dict is defined in config/settings.py.  This function
    performs two checks:
      1. The tool name must be a key in ALLOWED_BINARIES.
      2. The registered binary must exist at its declared absolute path.

    Parameters
    ----------
    tool_name : str
        Short name of the forensic tool (e.g., ``"mmls"``, ``"volatility"``).

    Returns
    -------
    Path
        Absolute path to the trusted binary.

    Raises
    ------
    ToolNotFoundError
        If the tool name is not in ALLOWED_BINARIES, or if the binary is
        registered but missing from the file system.
    """
    # Check 1 — Is the tool name in the allowlist?
    # The allowlist itself lives in config/settings.py → ALLOWED_BINARIES.
    if tool_name not in ALLOWED_BINARIES:
        raise ToolNotFoundError(
            f"Tool {tool_name!r} is not in the authorized binary allowlist.\n"
            f"Registered tools: {sorted(ALLOWED_BINARIES.keys())}\n"
            f"To add a new tool, edit ALLOWED_BINARIES in config/settings.py."
        )

    tool_path = ALLOWED_BINARIES[tool_name]

    # Check 2 — Does the binary actually exist on disk?
    if not tool_path.exists():
        raise ToolNotFoundError(
            f"Tool {tool_name!r} is registered in ALLOWED_BINARIES but the "
            f"binary was not found at {str(tool_path)!r}.\n"
            f"Verify the tool is installed on this SIFT workstation."
        )

    logger.info(
        "[path_validator] Tool resolved: name=%s  binary=%s", tool_name, tool_path
    )
    return tool_path


# ===========================================================================
# run_forensic_tool  — The Forensic Execution Wrapper
# ===========================================================================

def run_forensic_tool(
    tool_name: str,
    evidence_path: str,
    extra_args: Optional[list[str]] = None,
    pre_evidence_args: Optional[list[str]] = None,
    timeout: Optional[int] = None,
    extra_env: Optional[dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    """
    The Forensic Execution Wrapper — the ONLY sanctioned way to run a
    forensic binary against evidence in this project.

    This function enforces the full security pipeline:
      validate_evidence_path → get_tool_path → subprocess.run(shell=False)

    Why shell=False?
    ----------------
    When shell=True, the command string is passed to /bin/sh for parsing.
    A malicious path like ``/cases/img.dd; rm -rf /`` would be split by the
    shell into two commands.  With shell=False the OS executes the binary
    directly; the argument list is passed verbatim to execve(), so shell
    metacharacters have no special meaning.

    Command construction
    --------------------
    The command is always built as a list[str]:
        [binary, *pre_evidence_args, evidence_path, *extra_args]

    Default (no pre_evidence_args):
        ["/usr/bin/mmls", "/cases/case01/disk.dd", "-t", "dos"]

    With pre_evidence_args (e.g. Volatility 3 which needs -f before the path):
        ["/usr/local/bin/vol", "-f", "/cases/memory/image.img", "windows.pstree"]

    Parameters
    ----------
    tool_name : str
        Key from ALLOWED_BINARIES in config/settings.py (e.g., ``"mmls"``).
    evidence_path : str
        Raw path to the forensic image or artifact supplied by the caller.
        Will be validated by validate_evidence_path() before use.
    extra_args : list[str] | None
        Additional CLI arguments appended AFTER the evidence path.  Must be
        a pre-split list of strings — do NOT pass a single shell-style string.
        Example: ``["-t", "dos", "-o", "2048"]``
    pre_evidence_args : list[str] | None
        Optional CLI arguments inserted BEFORE the evidence path.  Use for
        tools whose flag syntax requires the image path to appear after a flag
        (e.g. Volatility 3: ``["-f"]`` → ``vol -f <image> <plugin>``).
    timeout : int | None
        Per-call subprocess timeout in seconds.  Overrides SUBPROCESS_TIMEOUT
        from settings.py when provided.  Use for long-running plugins (e.g.
        windows.netscan) that routinely exceed the global default.
    extra_env : dict[str, str] | None
        Additional environment variables merged into the subprocess environment.
        The process inherits the full parent env; only the specified keys are
        added or overridden.  Never used to remove existing variables.

    Returns
    -------
    subprocess.CompletedProcess
        Object with .stdout, .stderr, and .returncode attributes.

    Raises
    ------
    PathValidationError
        If evidence_path is outside every AUTHORIZED_ROOT.
    ToolNotFoundError
        If tool_name is not in ALLOWED_BINARIES or the binary is missing.
    subprocess.TimeoutExpired
        If the child process exceeds SUBPROCESS_TIMEOUT seconds.
    """
    # ------------------------------------------------------------------
    # Stage 1: Validate the evidence path.
    # validate_evidence_path() raises PathValidationError on failure.
    # ------------------------------------------------------------------
    safe_path: Path = validate_evidence_path(evidence_path)

    # ------------------------------------------------------------------
    # Stage 2: Validate and resolve the tool binary.
    # get_tool_path() raises ToolNotFoundError on failure.
    # The ALLOWED_BINARIES allowlist is defined in config/settings.py.
    # ------------------------------------------------------------------
    tool_bin: Path = get_tool_path(tool_name)

    # ------------------------------------------------------------------
    # Stage 3: Build the command as a list — required for shell=False.
    # Never join these into a single string; that would re-introduce the
    # shell-injection risk we are explicitly preventing.
    #
    # Layout: [binary, *pre_evidence_args, evidence_path, *extra_args]
    # ------------------------------------------------------------------
    cmd: list[str] = [str(tool_bin)]
    if pre_evidence_args:
        cmd.extend(pre_evidence_args)
    cmd.append(str(safe_path))
    if extra_args:
        # Extend with caller-supplied arguments.  The caller is responsible
        # for splitting arguments correctly (e.g., ["-t", "dos"] not ["-t dos"]).
        cmd.extend(extra_args)

    logger.info("[path_validator] Executing (shell=False): %s", cmd)
    _t_start = datetime.datetime.now(datetime.timezone.utc)

    # ------------------------------------------------------------------
    # Stage 4: Execute the subprocess.
    #
    #   shell=False      — CRITICAL security control; see docstring above.
    #   capture_output   — captures both stdout and stderr for the caller.
    #   text=True        — decodes output as UTF-8 strings.
    #   timeout          — per-call override; falls back to SUBPROCESS_TIMEOUT.
    #   env              — parent env merged with any caller-supplied extras.
    # ------------------------------------------------------------------
    effective_timeout: int = timeout if timeout is not None else SUBPROCESS_TIMEOUT
    proc_env: dict[str, str] | None = (
        {**os.environ, **extra_env} if extra_env else None
    )
    result: subprocess.CompletedProcess = subprocess.run(
        cmd,
        shell=False,                    # ← NEVER change this to True
        capture_output=True,
        text=True,
        timeout=effective_timeout,
        env=proc_env,
    )

    # Log non-zero exit codes as warnings (not errors — some tools use them
    # to signal informational states, e.g., tsk tools return 1 on warnings).
    if result.returncode != 0:
        logger.warning(
            "[path_validator] Tool %r exited with code %d. stderr: %s",
            tool_name,
            result.returncode,
            result.stderr.strip(),
        )
    else:
        logger.info(
            "[path_validator] Tool %r completed successfully (rc=0).", tool_name
        )

    _elapsed = (datetime.datetime.now(datetime.timezone.utc) - _t_start).total_seconds()
    _status = "SUCCESS" if result.returncode == 0 else "FAILURE"
    audit_logger.info(
        "%s | AUDIT | tool=%s | path=%s | cmd=%s | rc=%d | status=%s | elapsed=%.3fs",
        _t_start.isoformat(),
        tool_name,
        safe_path,
        cmd,
        result.returncode,
        _status,
        _elapsed,
    )

    return result
