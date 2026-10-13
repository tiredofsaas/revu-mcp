"""Bluebeam Revu 21 Model Context Protocol (MCP) Server.

Provides a secure, verified interface for Bluebeam Revu 21 headless automation,
PDF manipulation, markups, takeoffs, and tool set operations.

Citations:
    - docs/ARCHITECTURE.md Section 1 (Executive Architectural Vision).
    - docs/TEST_AND_SECURITY_MATRIX.md Section 1 (Testing and Security Matrix Overview).
"""

from typing import Any

from bluebeam_mcp.security import (
    ALLOWED_EXTENSIONS,
    FORBIDDEN_ROOTS,
    MAX_DECOMPRESSED_SIZE,
    MAX_FILE_SIZE,
    READ_ONLY_ROOTS,
    BluebeamMCPError,
    CorruptPDFError,
    CorruptStreamError,
    EmptyFileError,
    EngineExecutionError,
    FileLockedError,
    FileTooLargeError,
    PageRangeError,
    SecurityViolationError,
    SubprocessTimeoutError,
    XMLDefuseError,
    check_pdf_header,
    decompress_btx_raw,
    escape_bcs_string,
    parse_xml_safely,
    validate_path,
)
from bluebeam_mcp.script_builder import (
    ALL_FLATTEN_FLAGS,
    ALL_SECURITY_FLAGS,
    DEFAULT_FLATTEN_FLAGS,
    DEFAULT_SECURITY_FLAGS,
    FLATTEN_FLAGS,
    KNOWN_BCS_COMMANDS,
    SECURITY_FLAGS,
    VALID_MARKUP_KEYS,
    ScriptBuilder,
    build_command,
    calculate_flatten_bitmask,
    calculate_security_bitmask,
    serialize_bcs_dict,
    validate_color,
    validate_insertion_index,
    validate_iso8601_date,
    validate_one_based_page,
    validate_page_range,
)

__version__ = "1.0.0"


def __getattr__(name: str) -> Any:
    """Lazily import create_server and mcp from bluebeam_mcp.server per PEP 562."""
    if name in ("create_server", "mcp"):
        import bluebeam_mcp.server as server_module

        return getattr(server_module, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "__version__",
    "create_server",
    "mcp",
    # Security exceptions
    "BluebeamMCPError",
    "SecurityViolationError",
    "FileTooLargeError",
    "FileLockedError",
    "CorruptPDFError",
    "EmptyFileError",
    "PageRangeError",
    "XMLDefuseError",
    "CorruptStreamError",
    "SubprocessTimeoutError",
    "EngineExecutionError",
    # Security constants
    "FORBIDDEN_ROOTS",
    "READ_ONLY_ROOTS",
    "ALLOWED_EXTENSIONS",
    "MAX_FILE_SIZE",
    "MAX_DECOMPRESSED_SIZE",
    # Security functions
    "validate_path",
    "check_pdf_header",
    "escape_bcs_string",
    "parse_xml_safely",
    "decompress_btx_raw",
    # Script builder constants
    "FLATTEN_FLAGS",
    "DEFAULT_FLATTEN_FLAGS",
    "ALL_FLATTEN_FLAGS",
    "SECURITY_FLAGS",
    "DEFAULT_SECURITY_FLAGS",
    "ALL_SECURITY_FLAGS",
    "VALID_MARKUP_KEYS",
    "KNOWN_BCS_COMMANDS",
    # Script builder functions and class
    "calculate_flatten_bitmask",
    "calculate_security_bitmask",
    "validate_insertion_index",
    "validate_one_based_page",
    "validate_page_range",
    "validate_color",
    "validate_iso8601_date",
    "serialize_bcs_dict",
    "build_command",
    "ScriptBuilder",
]
