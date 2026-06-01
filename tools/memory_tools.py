# tools/memory_tools.py
#
# Project FIND-EVIL — Memory Forensics Tools
# ===========================================
# Wraps Volatility 3 (/usr/local/bin/vol) for memory image analysis.
# All subprocess execution is routed through run_forensic_tool() in
# config/path_validator.py, which enforces shell=False and path validation.
#
# Volatility 3 command layout:
#   vol -f <image_path> <plugin> [plugin_args...]
#
# pre_evidence_args=["-f"] is used so the security gateway inserts the
# validated image path after the -f flag, matching Vol3's expected syntax.
#
# MCP tools exposed (registered in server.py):
#   - analyze_memory   : generic Vol3 plugin runner
#   - list_processes   : windows.pslist / linux.pslist
#   - list_network     : windows.netstat / linux.netstat
#   - dump_process     : windows.dumpfiles

from config.path_validator import run_forensic_tool

_VOLATILITY_ENV = {"VOLATILITY_SYMBOL_CACHE": "/home/sansforensics/.cache/volatility3/symbols"}

# windows.netscan scans the full pool for TCPIP structures and routinely takes
# 15–20 minutes on large images; pin it to 1200 s regardless of the caller default.
_NETSCAN_TIMEOUT = 1200


def analyze_memory(
    image_path: str,
    plugin: str,
    plugin_args: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """
    Run any Volatility 3 plugin against a memory image.

    Parameters
    ----------
    image_path : str
        Absolute path to the memory image. Must reside within an
        AUTHORIZED_ROOT (e.g. /cases/) — enforced by run_forensic_tool().
    plugin : str
        Volatility 3 plugin name, e.g. "windows.pstree", "windows.cmdline",
        "windows.netscan", "linux.bash". Single token — no spaces.
    plugin_args : list[str] | None
        Optional additional arguments for the plugin, e.g. ["--pid", "1234"].
        Must be a pre-split list — never a shell-style string.
    timeout : int
        Subprocess timeout in seconds (default 300). Overridden to 1200 for
        windows.netscan regardless of the value passed by the caller.

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    extra: list[str] = [plugin]
    if plugin_args:
        extra.extend(plugin_args)

    effective_timeout = _NETSCAN_TIMEOUT if plugin == "windows.netscan" else timeout

    result = run_forensic_tool(
        tool_name="volatility",
        evidence_path=image_path,
        pre_evidence_args=["-f"],
        extra_args=extra,
        timeout=effective_timeout,
        extra_env=_VOLATILITY_ENV,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def list_processes(memory_image: str, os_profile: str = "windows") -> dict:
    """
    List running processes from a memory image using Volatility 3.

    Parameters
    ----------
    memory_image : str
        Absolute path to the memory dump (must be within an AUTHORIZED_ROOT).
    os_profile : str
        Target OS — "windows" or "linux" — selects the correct plugin.

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    plugin = "windows.pslist" if os_profile == "windows" else "linux.pslist"
    result = run_forensic_tool(
        tool_name="volatility",
        evidence_path=memory_image,
        pre_evidence_args=["-f"],
        extra_args=[plugin],
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def list_network_connections(memory_image: str, os_profile: str = "windows") -> dict:
    """
    List network connections from a memory image using Volatility 3.

    Parameters
    ----------
    memory_image : str
        Absolute path to the memory dump (must be within an AUTHORIZED_ROOT).
    os_profile : str
        Target OS — "windows" or "linux" — selects the correct plugin.

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    plugin = "windows.netstat" if os_profile == "windows" else "linux.netstat"
    result = run_forensic_tool(
        tool_name="volatility",
        evidence_path=memory_image,
        pre_evidence_args=["-f"],
        extra_args=[plugin],
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def dump_process(memory_image: str, pid: int, output_dir: str) -> dict:
    """
    Dump a specific process from a memory image using Volatility 3.

    Parameters
    ----------
    memory_image : str
        Absolute path to the memory dump (must be within an AUTHORIZED_ROOT).
    pid : int
        Process ID to dump.
    output_dir : str
        Directory to write the dumped process files.

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    result = run_forensic_tool(
        tool_name="volatility",
        evidence_path=memory_image,
        pre_evidence_args=["-f"],
        extra_args=[
            "windows.dumpfiles",
            "--pid", str(pid),
            "--dump-dir", output_dir,
        ],
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
