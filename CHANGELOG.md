# Changelog

## 1.0.0 (2026-10-12)

First public release.

- 28 MCP tools over stdio: document and page management, markups, flatten and unflatten, BAX export and import, stamps, forms, grayscale, size reduction, security and permissions, headers, footers and Bates numbering, environment, profile and tool set inspection, custom Bluebeam Script execution.
- Bluebeam Script generated for every operation; script runner invoked when present; open-source PDF fallback when the installed licence tier does not allow headless scripting.
- Path validation with environment-driven forbidden roots and optional read and write allowlists, atomic writes, extension and size limits, privileged script commands gated server-side only.
- 221 tests. Tested on Windows 11 with Revu 21.11 on a Core licence.
