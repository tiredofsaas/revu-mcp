# revu-mcp: Bluebeam Revu MCP server

A Model Context Protocol (MCP) server for Bluebeam Revu 21 on Windows. It lets Claude Desktop, Claude Code, Codex and other MCP hosts read, mark up, stamp, flatten, split, combine, number and secure PDF drawings using the Bluebeam Script engine where your licence allows it, and open-source PDF libraries where it does not. 28 tools over stdio, Python 3.12. Built for engineering and construction work: drawing sets, submittals, field markups, Bates numbering, tool sets and profiles.

Unofficial. Not affiliated with or endorsed by Bluebeam, Inc. See `TRADEMARKS.md`.

Licence: PolyForm Noncommercial 1.0.0. Free for non-commercial use. Commercial use needs separate permission. See `LICENSE` and `NOTICE.md`.

## What it does

Each tool first builds a Bluebeam Script (`.bcs`) for the requested operation and runs it through the locally installed Revu script runner. If your Revu licence tier does not include headless scripting (the runner returns exit code -4), the server performs the equivalent operation itself with open-source PDF libraries (`pypdf`, `reportlab`, `Pillow`) and reports `status: "subscription_fallback"` so you always know which path ran. Nothing here alters or bypasses Bluebeam's licence checks.

Execution modes on every tool: `auto` (default, runner then fallback), `script_only` (generate and validate the script, run nothing), `script_engine_strict` (runner only, error on -4), `native_only` (fallback only).

Custom scripts (`bb_script_generate_and_run`) have no native fallback. They need a Revu licence tier that allows headless scripting.

## Tools

Document and pages: `bb_pdf_info`, `bb_pdf_create_blank`, `bb_pdf_combine`, `bb_pdf_insert_pages`, `bb_pdf_extract_pages`, `bb_pdf_delete_pages`, `bb_pdf_rotate_pages`, `bb_pdf_split`, `bb_pdf_metadata`, `bb_pdf_page_labels`, `bb_pdf_bookmarks`, `bb_pdf_header_footer` (headers, footers, Bates numbering).

Markups, forms, stamps, output: `bb_markup_list`, `bb_markup_add`, `bb_markup_update`, `bb_markup_delete`, `bb_markup_flatten` (flatten and unflatten, recoverable), `bb_markup_export_bax`, `bb_markup_import_bax`, `bb_pdf_stamp`, `bb_form_inspect_and_fill`, `bb_pdf_color_and_optimize` (grayscale, size reduction, security and permissions).

Environment: `bb_env_status`, `bb_profile_inspect`, `bb_toolset_inspect`, `bb_toolset_create_export`, `bb_stamp_library_inspect`, `bb_script_generate_and_run`.

Every response is a JSON envelope with `status`, `data`, `error` (code, message, details), the generated script text and the runner receipt.

## Tested environment

Everything below was exercised on one workstation before release. If your setup differs, you are the first to test it there, and a bug report is welcome.

| Item | Tested with |
|---|---|
| Operating system | Windows 11 Pro, build 10.0.26300, x64 |
| Python | 3.12.10, per-user install |
| Bluebeam Revu | 21.11.0.23287, **Core** licence (subscription) |
| Script engine | present, returns -4 on Core; the native fallback path is what ran |
| mcp SDK | 1.27 and 1.30 (2.x is excluded by the dependency pin) |
| pypdf / reportlab / Pillow / defusedxml | 6.11 and 6.20 / 4.5 / 12.2 and 12.3 / 0.7 |
| MCP hosts | Claude Desktop, Claude Code, Codex CLI, Antigravity, all via stdio |
| Test suite | 221 tests, all passing, in the editable install and in a clean venv |
| Live check | all 28 tools run against a real one-page drawing PDF and a four-page combined set; outputs opened and inspected in Revu |

Not tested, and we would like help with:

- Revu **Complete** (the script-engine path has never executed a script here; every tool generates the script and the runner is invoked, but it exits -4 before running it).
- Revu 20 or earlier, Revu 21 builds other than 21.11, and Windows 10.
- Non-English Revu installs (stamp and profile paths are read from the registry, so they should resolve, but nobody has checked).
- Encrypted drawings with owner passwords other than the ones the suite generates.

## Install

Requirements: Windows, Python 3.12 or newer, Bluebeam Revu 21 installed (the server also works on a machine without Revu, fallback only).

```
git clone <this repository>
cd revu-mcp
python -m pip install .
```

Run the suite if you want to check the install:

```
python -m pip install pytest
python -m pytest -q
```

## Configure your MCP host

Claude Desktop, Claude Code, Codex and similar hosts take a stdio server definition. Use the full path to the Python that has the package installed.

```json
{
  "mcpServers": {
    "revu": {
      "command": "C:\\Path\\To\\Python312\\python.exe",
      "args": ["-m", "bluebeam_mcp"]
    }
  }
}
```

Claude Code: `claude mcp add -s user revu -- C:\Path\To\Python312\python.exe -m bluebeam_mcp`

## Environment variables

| Variable | Purpose |
|---|---|
| `BLUEBEAM_MCP_FORBIDDEN_ROOTS` | Semicolon-separated directories the server must never read, write or delete. Put document vaults and licensed software folders here. User credential directories (`.ssh`, `.aws`, ...) are always protected. |
| `BLUEBEAM_MCP_READ_ROOTS` | Optional allowlist. When set, reads are confined to these roots. |
| `BLUEBEAM_MCP_WRITE_ROOTS` | Optional allowlist. When set, writes are confined to these roots. |
| `BLUEBEAM_MCP_SCRATCH_DIR` | Where generated scripts and temporary files go. |
| `BLUEBEAM_MCP_ALLOW_PRIVILEGED` | Set to `1` only if you want custom scripts to be allowed to use file deletion, email, JavaScript and nested script commands. Off by default. There is deliberately no way for an MCP client to turn this on. |

## Safety model

- Paths are canonicalised and checked against forbidden roots, system folders, an extension allowlist (`.pdf`, `.bcs`, `.btx`, `.bpx`, `.bax`, images, text formats) and a 250 MB size cap.
- Writes are atomic (temp file then replace). In-place output over the input is allowed and safe.
- Script commands are validated against a known-command list with per-argument path checks; privileged commands are rejected unless enabled server-side.
- XML from tool sets, profiles and markup exports is parsed with `defusedxml`; compressed payloads are capped.
- Text that came from a document (authors, comments, metadata) is sanitised before it is returned to the agent.

## Known limits of the fallback path

- Grayscale conversion and flattening re-encode page content losslessly. On image-heavy drawings the output can be larger than the input.
- `reduce_size` never returns a file larger than the input; when it cannot shrink the file it returns an unchanged copy and says so.
- ICCBased, Separation, DeviceN and Pattern colour spaces are not converted by the fallback.
- Form filling ignores field names that do not exist in the document.

## Repository

`src/bluebeam_mcp/` server, security, script builder and tools. `tests/` 221 tests, fixtures generated on the fly under `tests/tmp/` and removed afterwards. `docs/` notes on the Bluebeam Script command surface and the `.btx`, `.bpx` and `.bax` file formats as observed from public documentation and ordinary files.

## Help wanted

This came out of one shop's daily work and it does what that shop needs. It would be better with more hands: people with a Revu Complete licence who can exercise the script-engine path, people on other Revu versions, people who want tools this doesn't have yet.

Open an issue, pick one up, or send a small pull request that says what problem it solves. There is no support commitment. Please keep your own drawings and client documents out of issues.
