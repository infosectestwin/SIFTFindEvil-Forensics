# tools/network_tools.py
#
# Project FIND-EVIL — Network / PCAP Analysis Tools
# ==================================================
# Wraps tshark and tcpdump for network artifact analysis.
# All subprocess execution is routed through run_forensic_tool() in
# config/path_validator.py, which enforces shell=False and path validation.
#
# MCP tools exposed (registered in server.py):
#   - read_pcap        : read and summarise packets from a PCAP file
#   - extract_streams  : extract TCP/UDP streams from a PCAP file

from config.path_validator import run_forensic_tool, PathValidationError, ToolNotFoundError


def read_pcap(pcap_path: str, display_filter: str = "") -> dict:
    """
    Read and summarise packets from a PCAP file using tshark.

    Parameters
    ----------
    pcap_path : str
        Absolute path to the PCAP file (must be within an AUTHORIZED_ROOT).
    display_filter : str
        Optional Wireshark display filter (e.g., "http", "dns", "ip.addr==10.0.0.1").

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    # TODO: Implement full MCP tool logic and structured packet parsing.
    extra = ["-r", pcap_path, "-V"]
    if display_filter:
        extra += ["-Y", display_filter]

    result = run_forensic_tool(
        tool_name="tshark",
        evidence_path=pcap_path,
        extra_args=extra,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def extract_streams(pcap_path: str, protocol: str = "tcp") -> dict:
    """
    Extract TCP or UDP streams from a PCAP file using tshark.

    Parameters
    ----------
    pcap_path : str
        Absolute path to the PCAP file.
    protocol : str
        Protocol to extract — "tcp" (default) or "udp".

    Returns
    -------
    dict
        {"stdout": str, "stderr": str, "returncode": int}
    """
    # TODO: Implement full MCP tool logic and stream reassembly.
    follow_filter = f"{protocol}.stream eq 0"
    result = run_forensic_tool(
        tool_name="tshark",
        evidence_path=pcap_path,
        extra_args=[
            "-r", pcap_path,
            "-z", f"follow,{protocol},ascii,0",
            "-q",
        ],
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
