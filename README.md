# revu-mcp

A Model Context Protocol (MCP) server that lets an AI agent work with PDF drawings and markups on a Windows machine that has Bluebeam Revu 21 installed. 28 tools over stdio, Python 3.12.

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

## Contributing and support

Issues and pull requests are welcome. There is no support commitment. Please do not open issues that include your own drawings or client documents.
