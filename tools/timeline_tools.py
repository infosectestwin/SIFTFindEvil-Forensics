# tools/timeline_tools.py
#
# Project FIND-EVIL — Timeline Generation Tools
# ==============================================
# Wraps log2timeline / plaso for super-timeline generation.
# All subprocess execution is routed through run_forensic_tool() in
# config/path_validator.py, which enforces shell=False and path validation.
#
# MCP tools exposed (registered in server.py):
#   - create_timeline  : runs log2timeline to build a plaso storage file
#   - export_timeline  : runs psort to export the timeline to CSV / JSON

from config.path_validator import run_forensic_tool, PathValidationError, ToolNotFoundError


def create_timeline(evidence_path: str, output_file: str) -> dict:
    """
    Generate a super-timeline from a forensic image using log2timeline.

    Parameters
    ----------
    evidence_path : str
        Absolute path to the forensic image or directory to process.
        Must be within an AUTHORIZED_ROOT defined in config/settings.py.
    output_file : str
        Path to the output plaso storage file (.plaso).

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    # TODO: Implement full MCP tool logic, progress reporting, and error handling.
    result = run_forensic_tool(
        tool_name="log2timeline",
        evidence_path=evidence_path,
        extra_args=[output_file, evidence_path],
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def export_timeline(plaso_file: str, output_format: str = "csv", output_file: str = "") -> dict:
    """
    Export a plaso storage file to a human-readable format using psort.

    Parameters
    ----------
    plaso_file : str
        Absolute path to the .plaso storage file (must be within AUTHORIZED_ROOT).
    output_format : str
        Output format — "csv" (default) or "json".
    output_file : str
        Path to write the exported timeline.

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    # TODO: Implement full MCP tool logic and structured output.
    extra = ["-o", output_format]
    if output_file:
        extra += ["-w", output_file]

    result = run_forensic_tool(
        tool_name="psort",
        evidence_path=plaso_file,
        extra_args=extra,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
