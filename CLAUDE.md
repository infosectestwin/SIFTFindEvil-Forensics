# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Project FIND-EVIL: Forensic MCP Server

## What
An MCP-based forensic framework for SIFT workstations, designed for secure, auditable, and automated evidence analysis.

## Structure
- `/server.py`: Entry point for MCP tool registration.
- `/tools/`: Domain-specific forensic modules (disk, memory, hash).
- `/config/`: Security-critical validation logic.

## Conventions (IMPORTANT)
 **Security-First Architecture**: 
   - All forensic operations MUST be routed through `config/path_validator.py`.
   - YOU MUST validate all paths against the `/cases/` directory before access.
   - YOU MUST use `subprocess.run` with `shell=False`.
   - YOU MUST log every tool execution (timestamp, command, status) to `forensic_audit.log`.

## Gotchas
- Never use `shell=True` for any subprocess call; it is a critical security violation.
- If a requested forensic tool is not in the allowlist in `path_validator.py`, pause and ask for confirmation.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the MCP server
python server.py

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_path_validator.py -v

# Run a single test by name
python -m pytest tests/test_path_validator.py::TestRunForensicTool::test_shell_false_is_always_set -v

# Type checking
mypy config/ tools/ server.py
```

## Architecture

This is an **MCP (Model Context Protocol) server** that exposes SIFT Workstation forensic tools to AI agents (e.g., Claude Desktop). The server runs over stdio and wraps binaries like TSK, Volatility 3, tshark, and log2timeline behind a security gateway.

**Data flow:**
```
MCP Host → server.py → tools/*.py → config/path_validator.run_forensic_tool() → subprocess(shell=False)
```

**Key files:**
- `server.py` — MCP tool registration (`list_tools`) and dispatch (`call_tool`). Add new tools here.
- `config/settings.py` — The two security-critical allowlists: `AUTHORIZED_ROOTS` (permitted evidence directories) and `ALLOWED_BINARIES` (permitted binaries with absolute paths). **Edit this file when adding a new tool or evidence path.**
- `config/path_validator.py` — The single security gateway. Every subprocess call must go through `run_forensic_tool()`. Never call `subprocess.run()` directly from a tool module.
- `tools/*.py` — Thin wrappers; each calls `run_forensic_tool()` and returns `{"stdout", "stderr", "returncode"}`.

## Adding a New Forensic Tool

1. Add the binary's absolute path to `ALLOWED_BINARIES` in `config/settings.py`.
2. Add or update a module in `tools/` that calls `run_forensic_tool(tool_name, evidence_path, extra_args)`.
3. Register the tool in `server.py`: add a `Tool` schema to `list_tools()` and a dispatch branch in `call_tool()`.
4. Add tests in `tests/test_tools.py`.

## Security Invariants

- `shell=False` must **never** be changed to `shell=True` in `path_validator.py`.
- All evidence paths must be validated through `validate_evidence_path()` before use — this enforces `AUTHORIZED_ROOTS` and blocks path traversal.
- Only binaries in `ALLOWED_BINARIES` may be executed; absolute paths are used to prevent PATH-hijacking.
- `extra_args` passed to `run_forensic_tool()` must always be a pre-split `list[str]`, never a single shell-style string.

## Forensic Context Switching

Use this table to decide which tool domain to invoke based on evidence type and investigation goal.

| Condition | Use | Tool / MCP call |
|-----------|-----|-----------------|
| Evidence is a raw disk image (`.dd`, `.E01`, `.img` containing a partition table) | **Disk tools (TSK)** | `list_partitions`, `list_files` |
| Evidence is a memory capture (`.raw`, `.mem`, `.img` from a RAM dump) | **Memory tools (Volatility 3)** | `analyze_memory` |
| Need to enumerate partition layout or file-system structure | **Disk tools** | `list_partitions` → `list_files` |
| Need process list, network connections, injected code, command lines | **Memory tools** | `analyze_memory` with appropriate plugin |
| Need to verify or establish chain of custody hash | **Hash tools** | `calculate_hash`, `verify_hash` |
| Both disk and memory images exist | **Both** | Start with `calculate_hash` on both, then pivot by goal |

### Quick plugin reference for `analyze_memory`

| Goal | `plugin` value |
|------|----------------|
| Process tree | `windows.pstree` |
| All processes incl. terminated | `windows.psscan` |
| Command lines | `windows.cmdline` |
| Network connections | `windows.netstat` |
| Injected / suspicious memory | `windows.malfind` |
| Loaded DLLs per process | `windows.dlllist` |
| Registry hives | `windows.registry.hivelist` |
| Linux processes | `linux.pslist` |
| Linux bash history | `linux.bash` |

### Decision rule
- File contains a **partition table** → TSK disk tools.
- File is a **flat RAM dump** (no partition table, high entropy, OS kernel structures) → Volatility 3.
- When in doubt, run `calculate_hash` first to establish integrity, then `mmls` to check for a partition table; if `mmls` fails or returns no partitions, treat the file as a memory image.

## MCP Host Configuration

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "find-evil": {
      "command": "python",
      "args": ["/path/to/SIFTFindEvil/server.py"]
    }
  }
}
```

The server is designed for Ubuntu/Debian SIFT Workstations. Binary paths in `config/settings.py` use POSIX paths (`/usr/bin/...`); adjust for local testing on other OSes.

