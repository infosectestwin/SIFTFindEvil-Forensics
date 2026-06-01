# Project FIND-EVIL 🔍

A purpose-built **Model Context Protocol (MCP) server** for digital forensics on a SIFT Workstation.  
It exposes SIFT forensic tools (The Sleuth Kit, Volatility 3, log2timeline, tshark, and more) as structured MCP tools that an AI agent (e.g., Claude) can call securely.

---

## Project Structure

```
SIFTFindEvil/
│
├── server.py                   # MCP server entry point — registers all tools
│
├── tools/                      # Forensic tool modules (one category per file)
│   ├── __init__.py
│   ├── disk_tools.py           # TSK: mmls, fsstat, fls, tsk_recover
│   ├── memory_tools.py         # Volatility 3: pslist, netstat, dumpfiles
│   ├── hash_tools.py           # sha256sum, sha1sum, md5sum
│   ├── timeline_tools.py       # log2timeline, psort
│   └── network_tools.py        # tshark, tcpdump
│
├── config/                     # Security configuration
│   ├── __init__.py
│   ├── settings.py             # ← AUTHORIZED_ROOTS + ALLOWED_BINARIES (edit here)
│   └── path_validator.py       # Forensic Execution Wrapper (security core)
│
├── tests/                      # Unit tests
│   ├── __init__.py
│   ├── test_path_validator.py  # Tests for the security wrapper
│   └── test_tools.py           # Smoke tests for tool modules
│
├── requirements.txt
├── .env.example
└── README.md
```

---

## Security Architecture

All subprocess execution flows through a single security gateway:

```
MCP Host (Claude)
      │
      ▼
  server.py  ──────────────────────────────────────────────────────────────►  tools/*.py
                                                                                   │
                                                                                   │ calls
                                                                                   ▼
                                                                      config/path_validator.py
                                                                      ┌─────────────────────────┐
                                                                      │ validate_evidence_path() │ ← blocks path traversal
                                                                      │ get_tool_path()          │ ← allowlist check
                                                                      │ run_forensic_tool()      │ ← shell=False exec
                                                                      └─────────────────────────┘
                                                                                   │
                                                                                   ▼
                                                                         subprocess (shell=False)
                                                                         mmls / vol / tshark / …
```

### Security Controls

| Control | Implementation |
|---|---|
| **No shell injection** | `subprocess.run(..., shell=False)` — always |
| **Path traversal prevention** | `Path.resolve(strict=True)` canonicalises before comparison |
| **Authorized-root enforcement** | `AUTHORIZED_ROOTS` in `config/settings.py` |
| **Binary allowlist** | `ALLOWED_BINARIES` in `config/settings.py` |
| **Timeout enforcement** | `SUBPROCESS_TIMEOUT` (default: 300 s) |
| **Output capture** | `capture_output=True` — stdout/stderr always captured |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure authorized paths and tools

Edit **`config/settings.py`** to match your SIFT workstation:

```python
# Authorized evidence directories
AUTHORIZED_ROOTS = [
    Path("/cases"),
    Path("/mnt/evidence"),
]

# Allowed forensic binaries (add new tools here)
ALLOWED_BINARIES = {
    "mmls": Path("/usr/bin/mmls"),
    ...
}
```

### 3. Run the MCP server

```bash
python server.py
```

### 4. Run the tests

```bash
python -m pytest tests/ -v
```

---

## Adding a New Forensic Tool

1. **Add the binary** to `ALLOWED_BINARIES` in `config/settings.py`.
2. **Create or update** a module in `tools/` that calls `run_forensic_tool()`.
3. **Register the tool** in `server.py` — add a `Tool` schema to `list_tools()` and a dispatch branch in `call_tool()`.
4. **Write tests** in `tests/test_tools.py`.

---

## MCP Host Configuration (Claude Desktop)

Add the following to your Claude Desktop `claude_desktop_config.json`:

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

---

## License

For authorized forensic use only.  
Always operate within the scope of your legal authority and case authorization.
