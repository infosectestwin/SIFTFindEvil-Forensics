# config/settings.py
#
# Project FIND-EVIL — Global Configuration
# =========================================
# This file is the single source of truth for:
#   1. AUTHORIZED_ROOTS  — the only directories where evidence may reside.
#   2. ALLOWED_BINARIES  — the explicit allowlist of trusted SIFT forensic
#                          binaries that run_forensic_tool() is permitted to
#                          execute.  If a binary is NOT listed here it will
#                          be rejected before any subprocess is spawned.
#   3. SUBPROCESS_TIMEOUT — hard ceiling (seconds) for any child process.
#
# To add a new tool to the project:
#   1. Add its absolute path to ALLOWED_BINARIES below.
#   2. Create (or update) the corresponding module in tools/.
#   3. Call run_forensic_tool() with the key you defined here.
#
# NOTE: All paths are expressed as POSIX strings because this server is
# designed to run on a SIFT Workstation (Ubuntu/Debian Linux).  If you
# are testing on Windows, adjust the paths accordingly.

from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Authorized evidence roots
#    Only paths that resolve to a child of one of these directories will be
#    accepted by validate_evidence_path().  Any path outside these roots is
#    rejected with a PathValidationError — no exceptions.
# ---------------------------------------------------------------------------
AUTHORIZED_ROOTS: list[Path] = [
    Path("/cases"),           # Primary case evidence directory (SIFT default)
    Path("/mnt/evidence"),    # Mounted forensic images / external media
    Path("/tmp/forensics"),   # Controlled temporary working directory
]

# ---------------------------------------------------------------------------
# 2. Allowed binaries — THE FORENSIC TOOL ALLOWLIST
#    *** THIS IS WHERE THE ALLOWED BINARIES LIST IS DEFINED ***
#
#    Keys   : short, human-readable tool names used as the `tool_name`
#             argument when calling run_forensic_tool().
#    Values : absolute Path to the trusted binary on the SIFT workstation.
#
#    Security note: using absolute paths prevents PATH-hijacking attacks.
#    If a binary is missing from this dict, run_forensic_tool() raises
#    ToolNotFoundError before any subprocess call is made.
# ---------------------------------------------------------------------------
ALLOWED_BINARIES: dict[str, Path] = {
    # --- Disk / partition analysis (The Sleuth Kit) ---
    "mmls":         Path("/usr/bin/mmls"),          # List partition layout
    "fsstat":       Path("/usr/bin/fsstat"),         # File-system statistics
    "fls":          Path("/usr/bin/fls"),            # List files in image
    "icat":         Path("/usr/bin/icat"),           # Extract file by inode
    "blkcat":       Path("/usr/bin/blkcat"),         # Extract data unit
    "tsk_recover":  Path("/usr/bin/tsk_recover"),    # Recover deleted files

    # --- Hashing & integrity ---
    "sha256sum":    Path("/usr/bin/sha256sum"),
    "sha1sum":      Path("/usr/bin/sha1sum"),
    "md5sum":       Path("/usr/bin/md5sum"),

    # --- Memory forensics ---
    "volatility":   Path("/opt/volatility3/bin/vol"),  # Volatility 3 venv binary (direct path)

    # --- Timeline / super-timeline ---
    "log2timeline": Path("/usr/local/bin/log2timeline.py"),
    "psort":        Path("/usr/local/bin/psort.py"),

    # --- Network / PCAP ---
    "tshark":       Path("/usr/bin/tshark"),
    "tcpdump":      Path("/usr/bin/tcpdump"),

    # --- String extraction ---
    "strings":      Path("/usr/bin/strings"),
    "bulk_extractor": Path("/usr/bin/bulk_extractor"),
}

# ---------------------------------------------------------------------------
# 3. Subprocess timeout
#    Any forensic tool that runs longer than this many seconds will be
#    terminated and a subprocess.TimeoutExpired exception will be raised.
# ---------------------------------------------------------------------------
SUBPROCESS_TIMEOUT: int = 300  # 5 minutes

# ---------------------------------------------------------------------------
# 4. Forensic audit log path
#    Every call to run_forensic_tool() appends a structured entry to this
#    file. Path is relative to the server's CWD (project root).
# ---------------------------------------------------------------------------
AUDIT_LOG_PATH: Path = Path("forensic_audit.log")
