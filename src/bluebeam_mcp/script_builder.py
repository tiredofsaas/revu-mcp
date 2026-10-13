"""Bluebeam Script (.bcs/.bci) builder, argument serializer, and bitmask calculator.

Provides type-safe command composition, 0-based vs 1-based page index translation,
markup dictionary serialization, and injection prevention matching Bluebeam Script grammar.

Citations:
    - docs/citations/01_script_reference.md Section 1 (Syntax & Scripting Rules).
    - docs/citations/01_script_reference.md Section 2 (Exhaustive Command Reference).
    - docs/citations/02_binary_and_dotnet_surface.md Section 5 (Script Command Inventory).
    - docs/ARCHITECTURE.md Section 4.2 (Bluebeam Script Injection Defenses).
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.1 (Tier 1: Unit and Schema Validation).
"""

from __future__ import annotations

from datetime import datetime
import math
import os
from pathlib import Path
import re
from typing import Any, Self

from bluebeam_mcp.security import (
    PageRangeError,
    SecurityViolationError,
    escape_bcs_string,
    validate_path,
)

# ============================================================================
# Bitmask Constants and Helpers
# ============================================================================

# Flatten bitmask flags matching Bluebeam Script Reference Version 2.0.11, p. 11-12
# Default: 8191 (sum of flags 1 through 4096). All: 131071 (sum of all 18 flags).
# Citation: docs/ARCHITECTURE.md line 122; docs/TEST_AND_SECURITY_MATRIX.md T1-03.
FLATTEN_FLAGS: dict[str, int] = {
    "image": 1,
    "ellipse": 2,
    "stamp": 4,
    "snapshot": 8,
    "text": 16,
    "callout": 16,
    "text_callout": 16,
    "ink": 32,
    "highlighter": 32,
    "ink_highlighter": 32,
    "line": 64,
    "dimension": 64,
    "line_dimension": 64,
    "measure_area": 128,
    "measure": 128,
    "polyline": 256,
    "polygon": 512,
    "cloud": 512,
    "polygon_cloud": 512,
    "rectangle": 1024,
    "text_markups": 2048,
    "group": 4096,
    "file_attachment": 8192,
    "attachment": 8192,
    "flags": 16384,
    "notes": 32768,
    "form_fields": 65536,
    "forms": 65536,
}

DEFAULT_FLATTEN_FLAGS: int = 8191
ALL_FLATTEN_FLAGS: int = 131071


def calculate_flatten_bitmask(
    flags: int | list[str] | set[str] | tuple[str, ...] | None = None,
) -> int:
    """Calculate the composite integer bitmask for the Flatten command.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 11-12.
        - docs/TEST_AND_SECURITY_MATRIX.md T1-03 (test_flatten_bitmask_flags).
        - docs/REMEDIATION_PLAN.md Finding M-07.
    """
    if flags is None:
        return DEFAULT_FLATTEN_FLAGS

    if isinstance(flags, bool):
        raise TypeError("Flatten bitmask cannot be a boolean")

    if isinstance(flags, int):
        if flags < 0 or flags > ALL_FLATTEN_FLAGS:
            raise ValueError(
                f"Flatten bitmask {flags} is out of permitted range (0 to {ALL_FLATTEN_FLAGS})"
            )
        return flags

    if isinstance(flags, (list, set, tuple)):
        composite = 0
        for flag in flags:
            if isinstance(flag, bool) or not isinstance(flag, str):
                raise TypeError(f"Flag item must be a string: {type(flag)}")
            normalized = flag.strip().lower().replace(" ", "_").replace("-", "_")
            if normalized not in FLATTEN_FLAGS:
                raise ValueError(
                    f"Unknown flatten flag '{flag}'. Supported flags: {sorted(set(FLATTEN_FLAGS.keys()))}"
                )
            composite |= FLATTEN_FLAGS[normalized]
        return composite

    raise TypeError(f"Invalid type for flatten flags: {type(flags)}")


# SetPDFSecurity permission bitmask flags matching Bluebeam Script Reference Version 2.0.11, p. 26
# Default: 193 (Print=1 + CopyContent=64 + Accessibility=128). All: 255.
# Citation: docs/ARCHITECTURE.md line 123; docs/TEST_AND_SECURITY_MATRIX.md T1-04.
SECURITY_FLAGS: dict[str, int] = {
    "print": 1,
    "print_low_only": 2,
    "printlowonly": 2,
    "fill_forms": 4,
    "fillforms": 4,
    "edit_markups": 8,
    "editmarkups": 8,
    "edit_document": 16,
    "editdocument": 16,
    "page_manipulation": 32,
    "pagemanipulation": 32,
    "copy_content": 64,
    "copycontent": 64,
    "accessibility": 128,
}

DEFAULT_SECURITY_FLAGS: int = 193
ALL_SECURITY_FLAGS: int = 255


def calculate_security_bitmask(
    permissions: int | list[str] | set[str] | tuple[str, ...] | None = None,
) -> int:
    """Calculate the composite integer permission bitmask for SetPDFSecurity.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 26.
        - docs/TEST_AND_SECURITY_MATRIX.md T1-04 (test_set_pdf_security_bitmask).
        - docs/REMEDIATION_PLAN.md Finding M-07.
    """
    if permissions is None:
        return DEFAULT_SECURITY_FLAGS

    if isinstance(permissions, bool):
        raise TypeError("Security bitmask cannot be a boolean")

    if isinstance(permissions, int):
        if permissions < 0 or permissions > ALL_SECURITY_FLAGS:
            raise ValueError(
                f"Security bitmask {permissions} is out of permitted range (0 to {ALL_SECURITY_FLAGS})"
            )
        return permissions

    if isinstance(permissions, (list, set, tuple)):
        composite = 0
        for perm in permissions:
            if isinstance(perm, bool) or not isinstance(perm, str):
                raise TypeError(f"Permission item must be a string: {type(perm)}")
            normalized = perm.strip().lower().replace(" ", "_").replace("-", "_")
            if normalized not in SECURITY_FLAGS:
                raise ValueError(
                    f"Unknown security permission '{perm}'. Supported permissions: {sorted(set(SECURITY_FLAGS.keys()))}"
                )
            composite |= SECURITY_FLAGS[normalized]
        return composite

    raise TypeError(f"Invalid type for security permissions: {type(permissions)}")


# ============================================================================
# Markup Properties Dictionary Keys
# ============================================================================

# All 26 documented markup property dictionary keys
# Citation: Bluebeam Script Reference Version 2.0.11, p. 5 (Markups Property Dictionary Keys).
VALID_MARKUP_KEYS: frozenset[str] = frozenset({
    "type",
    "page",
    "author",
    "subject",
    "comment",
    "color",
    "colorfill",
    "colortext",
    "opacity",
    "opacityfill",
    "rotation",
    "parent",
    "grouped",
    "status",
    "checked",
    "locked",
    "datecreated",
    "datemodified",
    "linewidth",
    "linestyle",
    "x",
    "y",
    "width",
    "height",
    "space",
    "layer",
    "captureCount",
})


# ============================================================================
# Known Bluebeam Script Commands and Privilege Separation
# ============================================================================

# All commands documented in Bluebeam Script Reference and reflected in .NET assemblies
# Citation: docs/citations/01_script_reference.md; docs/citations/02_binary_and_dotnet_surface.md.
KNOWN_BCS_COMMANDS: frozenset[str] = frozenset({
    "AddMarkupFromDictionary",
    "AddMarkupResource",
    "BalancePages",
    "Batch",
    "BookmarksExport",
    "BookmarksImport",
    "Close",
    "ColorProcess",
    "ColorProcessAnalyze",
    "ColorProcessModify",
    "ColumnDataGet",
    "ColumnDataGetDict",
    "ColumnDataSet",
    "ColumnsExport",
    "ColumnsImport",
    "Combine",
    "CreatePDFAReport",
    "DeleteFile",
    "Email",
    "EmbedJavaScript",
    "ExecuteJavaScript",
    "Export",
    "FilePropertyGet",
    "FilePropertyList",
    "FilePropertySet",
    "Flatten",
    "FormExport",
    "FormImport",
    "FormMerge",
    "HeaderAndFooter",
    "Import",
    "InsertBlankPages",
    "InsertPages",
    "LinkAdd",
    "LinkDelete",
    "LinkGet",
    "LinkList",
    "LinkSet",
    "LinkSetAction",
    "MarkupAdd",
    "MarkupCaptureExport",
    "MarkupCaptureImport",
    "MarkupCopy",
    "MarkupDelete",
    "MarkupFunction",
    "MarkupGet",
    "MarkupGetEx",
    "MarkupGetExList",
    "MarkupList",
    "MarkupPaste",
    "MarkupSet",
    "MarkupShapeGet",
    "MarkupShapeSet",
    "MarkupStatusGet",
    "MarkupStatusSet",
    "MarkupThumbnail",
    "MergeBot",
    "NamedDestinationDelete",
    "NamedDestinationGet",
    "NamedDestinationList",
    "NamedDestinationSet",
    "New",
    "Open",
    "OpenImage",
    "PageCount",
    "PageDelete",
    "PageExtract",
    "PageLabelGet",
    "PageLabelsSet",
    "PageRotate",
    "PageRotateGet",
    "PageRotation",
    "PageScaleGet",
    "PageScaleSet",
    "PageSize",
    "Print",
    "PrintToFile",
    "Redact",
    "ReduceFileSize",
    "Repair",
    "ReplacePages",
    "ReversePages",
    "Save",
    "SaveAs",
    "SaveAsPDFA",
    "SaveAsText",
    "Script",
    "Search",
    "SearchAndMarkup",
    "SetOpenPassword",
    "SetPDFSecurity",
    "SplitPages",
    "Stamp",
    "StateModelGet",
    "StateModelList",
    "StateModelsExport",
    "StateModelsImport",
    "Thumbnail",
    "Unflatten",
    "UnlockPDFA",
    "UserNameGet",
    "UserNameSet",
    "View",
    "ViewPortAdd",
    "ViewPortDelete",
    "ViewPortGet",
    "ViewPortList",
    "ViewPortSet",
})

# Privileged commands denied in untrusted scripts by default
# Citation: docs/REMEDIATION_PLAN.md Finding C-01.
PRIVILEGED_BCS_COMMANDS: frozenset[str] = frozenset({
    "Batch",
    "DeleteFile",
    "Email",
    "EmbedJavaScript",
    "ExecuteJavaScript",
    "Print",
    "PrintToFile",
    "Redact",
    "SaveAs",
    "Script",
    "SetOpenPassword",
    "SetPDFSecurity",
    "UserNameSet",
    "View",
})

# Safe commands permitted in untrusted scripts
SAFE_BCS_COMMANDS: frozenset[str] = KNOWN_BCS_COMMANDS - PRIVILEGED_BCS_COMMANDS

# Server-side policy flag for privileged script commands (read once at startup; F-01)
ALLOW_PRIVILEGED_COMMANDS: bool = os.environ.get("BLUEBEAM_MCP_ALLOW_PRIVILEGED", "").strip().lower() in (
    "1",
    "true",
    "yes",
)

# Case-insensitive mapping for canonical command resolution
KNOWN_BCS_COMMANDS_MAP: dict[str, str] = {cmd.lower(): cmd for cmd in KNOWN_BCS_COMMANDS}

# Specification of file-bearing commands mapping command name to (arg_index, validation_mode, kind)
PATH_ARG_SPEC: dict[str, list[tuple[int, str, str]]] = {
    "Open": [(0, "read", "file")],
    "Save": [(0, "write", "file")],
    "SaveAs": [(0, "write", "file")],
    "DeleteFile": [(0, "delete", "file")],
    "InsertPages": [(1, "read", "file")],
    "ReplacePages": [(1, "read", "file")],
    "Import": [(0, "read", "file")],
    "Export": [(0, "write", "file")],
    "FormExport": [(0, "write", "file")],
    "FormImport": [(0, "read", "file")],
    "ColumnsExport": [(0, "write", "file")],
    "ColumnsImport": [(0, "read", "file")],
    "StateModelsExport": [(0, "write", "file")],
    "StateModelsImport": [(0, "read", "file")],
    "CreatePDFAReport": [(0, "write", "file")],
    "SaveAsText": [(0, "write", "file")],
    "SaveAsPDFA": [(0, "write", "file")],
    "PageExtract": [(1, "write", "file")],
    "SplitPages": [(0, "write", "any")],
    "BookmarksExport": [(0, "write", "file")],
    "BookmarksImport": [(0, "read", "file")],
    "Script": [(0, "read", "file")],
    "Batch": [(0, "read", "file")],
    "Print": [],
    "PrintToFile": [(0, "write", "file")],
    "Email": [(3, "read", "file")],
    "OpenImage": [(0, "read", "file")],
    "Thumbnail": [(0, "write", "file")],
    "MarkupThumbnail": [(1, "write", "file")],
    "MarkupCaptureExport": [(2, "write", "dir")],
    "MarkupCaptureImport": [(2, "read", "dir")],
}

DISALLOWED_LINE_CHARS: tuple[str, ...] = (
    "\x00",
    "\r",
    "\n",
    "\x85",
    "\u2028",
    "\u2029",
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
)


def _validate_command_paths(
    canonical: str,
    args: tuple[Any, ...] | list[Any],
    allow_privileged: bool = False,
    _depth: int = 0,
) -> None:
    """Validate path arguments for file-bearing Bluebeam Script commands."""
    if _depth > 3:
        raise SecurityViolationError("Maximum nested Script/Batch recursion depth exceeded")

    if canonical in ("Script", "Batch"):
        if len(args) == 0 or not isinstance(args[0], (str, Path)) or not str(args[0]).strip():
            raise SecurityViolationError(f"{canonical} command requires a valid .bcs script path")
        nested_path = validate_path(
            args[0],
            mode="read",
            must_exist=True,
            allowed_extensions={".bcs", ".bci"},
            kind="file",
        )
        nested_text = nested_path.read_text(encoding="utf-8", errors="replace")
        for line in re.split(r"\r\n|\r|\n", nested_text):
            if line.strip():
                parse_and_validate_bcs_line(
                    line,
                    allow_privileged=allow_privileged,
                    _depth=_depth + 1,
                )
        if canonical == "Batch" and len(args) >= 2:
            start_idx = 2 if isinstance(args[1], bool) else 1
            for target in args[start_idx:]:
                if isinstance(target, (str, Path)) and str(target).strip():
                    validate_path(target, mode="read", must_exist=False, kind="any")
        return

    if canonical in PATH_ARG_SPEC:
        for idx, mode, kind in PATH_ARG_SPEC[canonical]:
            if len(args) > idx:
                target = args[idx]
                if isinstance(target, (str, Path)) and str(target).strip():
                    validate_path(target, mode=mode, must_exist=False, kind=kind)
        if canonical == "Email" and len(args) > 4:
            for target in args[4:]:
                if isinstance(target, (str, Path)) and str(target).strip():
                    validate_path(target, mode="read", must_exist=False, kind="file")
    elif canonical == "Combine":
        for target in args:
            if isinstance(target, (str, Path)) and str(target).strip():
                validate_path(target, mode="read", must_exist=False, kind="file")
    elif canonical == "FormMerge":
        if len(args) > 0 and isinstance(args[0], (str, Path)) and str(args[0]).strip():
            validate_path(args[0], mode="write", must_exist=False, kind="file")
        for target in args[2:]:
            if isinstance(target, (str, Path)) and str(target).strip():
                validate_path(target, mode="read", must_exist=False, kind="file")
    elif canonical == "Stamp" and len(args) > 0:
        target = args[0]
        if isinstance(target, (str, Path)):
            raw = str(target).strip()
            if raw.lower().endswith(".pdf") or "\\" in raw or "/" in raw or re.match(r"^[A-Za-z]:", raw):
                validate_path(target, mode="read", must_exist=False, kind="file")


# ============================================================================
# Page Indexing Helpers
# ============================================================================


def validate_insertion_index(index: int, max_pages: int | None = None) -> int:
    """Validate a 0-based page insertion index.

    Insertion commands (InsertPages, InsertBlankPages) use 0-based indexing,
    where index 0 places the new content before the first page.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 14, 15.
        - docs/TEST_AND_SECURITY_MATRIX.md T1-01 (test_page_indexing_conventions).
        - docs/REMEDIATION_PLAN.md Finding M-07.
    """
    if isinstance(index, bool) or not isinstance(index, int):
        raise PageRangeError(f"Insertion index must be an integer: {index}")

    if index < 0:
        raise PageRangeError(
            f"Insertion index must be non-negative (0 places content before first page): {index}"
        )

    if max_pages is not None and index > max_pages:
        raise PageRangeError(
            f"Insertion index {index} exceeds current document page count {max_pages}"
        )

    return index


def validate_one_based_page(page: int, max_pages: int | None = None) -> int:
    """Validate a 1-based page query or markup index.

    Query commands (PageRotateGet, PageSize) and markup queries (MarkupGet, MarkupSet)
    use 1-based indexing where page 1 is the first page of the document.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 16-21.
        - docs/TEST_AND_SECURITY_MATRIX.md T1-01, T3-05, T3-06.
        - docs/REMEDIATION_PLAN.md Finding M-07.
    """
    if isinstance(page, bool) or not isinstance(page, int):
        raise PageRangeError(f"Page number must be an integer: {page}")

    if page < 1:
        raise PageRangeError(
            f"Page index {page} is invalid: Bluebeam page queries require 1-based indexing (page >= 1)"
        )

    if max_pages is not None and page > max_pages:
        raise PageRangeError(
            f"Requested page {page} exceeds document page count of {max_pages}"
        )

    return page


def validate_page_range(page_range: str | int, max_pages: int | None = None) -> str:
    """Validate a 1-based page range string or integer (-1 for all pages).

    Accepts:
        - -1 or "-1" for all pages.
        - Single page numbers as strings ("1") or integers (1).
        - Multi-page and sub-range lists ("1,2,5-10").

    Rejects:
        - Booleans.
        - 0 or negative values other than -1.
        - Non-ASCII digits.
        - Values exceeding 32-bit signed integer limits.
        - Pages out of bounds when max_pages is specified.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 7, 20.
        - docs/TEST_AND_SECURITY_MATRIX.md T1-02 (test_page_range_formatting).
        - docs/REMEDIATION_PLAN.md Finding M-07.
    """
    if isinstance(page_range, bool):
        raise PageRangeError("Page range parameter cannot be a boolean")

    if isinstance(page_range, int):
        if page_range > 2147483647:
            raise PageRangeError(f"Page index exceeds 32-bit signed integer limit: {page_range}")
        if page_range == -1:
            return "-1"
        if page_range < 1:
            raise PageRangeError(
                f"Page index cannot be 0 or negative (use -1 for all pages): {page_range}"
            )
        if max_pages is not None and page_range > max_pages:
            raise PageRangeError(
                f"Page {page_range} exceeds document page count {max_pages}"
            )
        return str(page_range)

    if isinstance(page_range, str):
        cleaned = page_range.strip()
        if not cleaned:
            raise PageRangeError("Page range string cannot be empty")
        if cleaned == "-1":
            return "-1"

        tokens = cleaned.split(",")
        normalized_tokens: list[str] = []
        for token in tokens:
            t = token.strip()
            if not t:
                raise PageRangeError(f"Empty page token in range '{page_range}'")
            if "-" in t:
                parts = t.split("-")
                if len(parts) != 2:
                    raise PageRangeError(f"Invalid page range token format: '{t}'")
                start_str, end_str = parts[0].strip(), parts[1].strip()
                if not (re.fullmatch(r"[0-9]+", start_str, re.ASCII) and re.fullmatch(r"[0-9]+", end_str, re.ASCII)):
                    raise PageRangeError(f"Non-numeric values in page range token: '{t}'")
                start, end = int(start_str), int(end_str)
                if start > 2147483647 or end > 2147483647:
                    raise PageRangeError(f"Page range number exceeds 32-bit limit in token: '{t}'")
                if start < 1 or end < 1:
                    raise PageRangeError(f"Page range numbers must be >= 1: '{t}'")
                if start > end:
                    raise PageRangeError(
                        f"Start page {start} cannot exceed end page {end} in range '{t}'"
                    )
                if max_pages is not None and (start > max_pages or end > max_pages):
                    raise PageRangeError(
                        f"Page range '{t}' exceeds document page count {max_pages}"
                    )
                normalized_tokens.append(f"{start}-{end}")
            else:
                if not re.fullmatch(r"[0-9]+", t, re.ASCII):
                    raise PageRangeError(f"Non-numeric page token: '{t}'")
                val = int(t)
                if val > 2147483647:
                    raise PageRangeError(f"Page number exceeds 32-bit limit: {val}")
                if val < 1:
                    raise PageRangeError(f"Page index cannot be 0 or negative: {val}")
                if max_pages is not None and val > max_pages:
                    raise PageRangeError(
                        f"Page {val} exceeds document page count {max_pages}"
                    )
                normalized_tokens.append(str(val))
        return ",".join(normalized_tokens)

    raise PageRangeError(f"Unsupported page range parameter type: {type(page_range)}")


# ============================================================================
# Serializers
# ============================================================================


def validate_color(color: str | int) -> str:
    """Validate and format a Bluebeam Script color parameter.

    Accepts:
        - Named colors ("Black", "Red", "Blue", etc.).
        - Hex strings ("#FF0000", "#00FF00", "#FFF").
        - Packed RGB integers (0 to 16777215 / 0xFFFFFF).

    Rejects:
        - Booleans.
        - Non-ASCII digits.
        - Out-of-bounds integers.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 4 (Data Types - Color).
        - docs/TEST_AND_SECURITY_MATRIX.md T1-05 (test_color_parameter_formats).
        - docs/REMEDIATION_PLAN.md Finding M-07.
    """
    if isinstance(color, bool):
        raise ValueError("Color parameter cannot be a boolean")

    if isinstance(color, int):
        if color < 0 or color > 0xFFFFFF:
            raise ValueError(
                f"Packed RGB integer {color} is out of valid range (0 to 16777215 / 0xFFFFFF)"
            )
        return str(color)

    if isinstance(color, str):
        cleaned = color.strip()
        if not cleaned:
            raise ValueError("Color string cannot be empty")
        if cleaned.startswith("#"):
            if not re.fullmatch(r"^#[0-9a-fA-F]{6}$", cleaned, re.ASCII) and not re.fullmatch(r"^#[0-9a-fA-F]{3}$", cleaned, re.ASCII):
                raise ValueError(
                    f"Invalid hex color format: '{color}'. Expected '#RRGGBB' or '#RGB'"
                )
            return cleaned
        if re.fullmatch(r"[0-9]+", cleaned, re.ASCII):
            val = int(cleaned)
            if val < 0 or val > 0xFFFFFF:
                raise ValueError(f"Color integer string {cleaned} is out of bounds")
            return str(val)
        known_colors = {
            "black", "white", "red", "green", "blue", "yellow", "cyan", "magenta",
            "gray", "grey", "orange", "purple", "brown", "pink", "lime", "navy",
            "teal", "olive", "maroon", "silver", "gold", "violet", "indigo", "coral",
            "crimson", "darkblue", "darkgreen", "darkred", "darkgray", "darkgrey",
            "lightblue", "lightgreen", "lightgray", "lightgrey", "transparent", "none",
        }
        if cleaned.lower() in known_colors:
            return cleaned

    raise ValueError(f"Unsupported color parameter format: {color}")


def validate_iso8601_date(date_str: str) -> str:
    """Validate a UTC ISO 8601 date string in format YYYY-MM-DDThh:mm:ss.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 4 (Data Types - Date).
        - docs/TEST_AND_SECURITY_MATRIX.md T1-07 (test_iso8601_date_validation).
    """
    if not isinstance(date_str, str):
        raise ValueError(f"ISO 8601 date must be a string: {type(date_str)}")

    cleaned = date_str.strip()
    core = cleaned[:-1] if cleaned.endswith("Z") else cleaned

    try:
        parsed = datetime.strptime(core, "%Y-%m-%dT%H:%M:%S")
        return parsed.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValueError(
            f"Invalid ISO 8601 UTC date: '{date_str}'. Expected format: YYYY-MM-DDThh:mm:ss"
        ) from exc


def serialize_bcs_dict(d: dict[str, Any]) -> str:
    """Serialize a dictionary into Bluebeam Script dictionary format {"Key":"Value"}.

    Enforces proper pipe escaping on quotes and pipes to prevent command breakout.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 4, 5, 8, 17.
        - docs/TEST_AND_SECURITY_MATRIX.md T1-06, T2-04.
    """
    items: list[str] = []
    for k, v in d.items():
        k_str = str(k)
        k_esc = escape_bcs_string(k_str)

        if isinstance(v, bool):
            v_esc = "true" if v else "false"
        elif isinstance(v, (int, float)):
            v_esc = str(v)
        else:
            v_esc = escape_bcs_string(str(v))

        items.append(f'"{k_esc}":"{v_esc}"')

    return "{" + ",".join(items) + "}"


# ============================================================================
# Command Generator and Builder Class
# ============================================================================


def build_command(
    command_name: str,
    *args: Any,
    allow_newlines_in_strings: bool = False,
    allow_privileged: bool = True,
    _depth: int = 0,
) -> str:
    """Format a type-safe Bluebeam Script command matching Command(arg0, arg1, ...).

    Enforces:
        - ASCII command identifier syntax matching ^[A-Za-z][A-Za-z0-9_]*$.
        - Privilege separation (PRIVILEGED_BCS_COMMANDS rejected when allow_privileged=False).
        - Path validation on file-bearing command parameters (PATH_ARG_SPEC).
        - Finite float formatting without scientific notation.
        - Rejection of unsupported complex types (list, tuple, set, bytes).

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 4 (Syntax Format).
        - docs/ARCHITECTURE.md Section 4.2 (Bluebeam Script Injection Defenses).
        - docs/TEST_AND_SECURITY_MATRIX.md T1-01 to T1-07, T2-01 to T2-05; C-01, M-07.
    """
    cmd_clean = command_name.strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", cmd_clean, re.ASCII):
        raise SecurityViolationError(
            f"Invalid Bluebeam Script command identifier format: '{command_name}'",
            details={"command": command_name},
        )

    canonical = KNOWN_BCS_COMMANDS_MAP.get(cmd_clean.lower())
    if canonical is None:
        raise SecurityViolationError(
            f"Unknown or unauthorized Bluebeam Script command: '{command_name}'",
            details={"command": command_name},
        )

    if not allow_privileged and canonical in PRIVILEGED_BCS_COMMANDS:
        raise SecurityViolationError(
            f"Command '{canonical}' is privileged/restricted and not permitted in untrusted scripts",
            details={"command": canonical},
        )

    # Path argument validation for file-bearing commands
    _validate_command_paths(canonical, args, allow_privileged=allow_privileged, _depth=_depth)

    formatted_args: list[str] = []
    for arg in args:
        if isinstance(arg, bool):
            formatted_args.append("true" if arg else "false")
        elif isinstance(arg, int):
            formatted_args.append(str(arg))
        elif isinstance(arg, float):
            if not math.isfinite(arg):
                raise ValueError(f"Float arguments must be finite: {arg}")
            if abs(arg) < 1e-4 or abs(arg) >= 1e6:
                formatted_args.append(f"{arg:.6f}".rstrip("0").rstrip(".") or "0")
            else:
                formatted_args.append(str(arg))
        elif isinstance(arg, Path):
            escaped_path = escape_bcs_string(str(arg), allow_newlines=False)
            formatted_args.append(f'"{escaped_path}"')
        elif isinstance(arg, dict):
            dict_str = serialize_bcs_dict(arg)
            escaped_dict = escape_bcs_string(dict_str, allow_newlines=allow_newlines_in_strings)
            formatted_args.append(f'"{escaped_dict}"')
        elif isinstance(arg, str):
            escaped_str = escape_bcs_string(arg, allow_newlines=allow_newlines_in_strings)
            formatted_args.append(f'"{escaped_str}"')
        elif arg is None:
            formatted_args.append('""')
        elif isinstance(arg, (list, tuple, set, bytes)):
            raise TypeError(f"Unsupported argument type for BCS command: {type(arg).__name__}")
        else:
            raise TypeError(f"Unsupported argument type for BCS command: {type(arg).__name__}")

    return f"{canonical}({', '.join(formatted_args)})"


def _tokenize_bcs_args(args_str: str) -> list[Any]:
    """Tokenize arguments inside a Bluebeam Script Command(...) invocation."""
    tokens: list[Any] = []
    s = args_str.strip()
    if not s:
        return []

    i = 0
    n = len(s)
    while i < n:
        while i < n and s[i] in (" ", "\t"):
            i += 1
        if i >= n:
            break

        c = s[i]
        if c == "%":
            raise SecurityViolationError("Unquoted comment character '%' forbidden in argument list")
        if c in (")", "("):
            raise SecurityViolationError(f"Unexpected '{c}' in argument list")

        if c in ('"', "'"):
            # Quoted string argument (double-quoted or single-quoted per 01_script_reference.md p. 4)
            quote_char = c
            i += 1
            chars: list[str] = []
            while i < n:
                if s[i] == "|":
                    if i + 1 < n and s[i + 1] in ("|", '"', "'"):
                        chars.append(s[i + 1])
                        i += 2
                    else:
                        raise SecurityViolationError("Invalid escape sequence in quoted string")
                elif s[i] == quote_char:
                    i += 1
                    break
                else:
                    chars.append(s[i])
                    i += 1
            else:
                raise SecurityViolationError("Unterminated quoted string in argument list")

            tokens.append("".join(chars))

            # Skip whitespace and require comma or end
            while i < n and s[i] in (" ", "\t"):
                i += 1
            if i < n:
                if s[i] == ",":
                    i += 1
                else:
                    raise SecurityViolationError(f"Expected comma after string argument, found '{s[i]}'")
        else:
            # Bare literal: boolean or number
            start = i
            while i < n and s[i] not in (",", " ", "\t", '"', "'", "(", ")", "%"):
                i += 1
            token_str = s[start:i]
            if not token_str:
                raise SecurityViolationError(f"Unexpected character in argument list: '{s[i]}'")

            if i < n and s[i] == "%":
                raise SecurityViolationError("Unquoted comment character '%' forbidden in argument list")
            if i < n and s[i] in ("(", ")", '"', "'"):
                raise SecurityViolationError(f"Unexpected character '{s[i]}' after token '{token_str}'")

            lower_tok = token_str.lower()
            if lower_tok == "true":
                tokens.append(True)
            elif lower_tok == "false":
                tokens.append(False)
            elif re.fullmatch(r"^-?[0-9]+$", token_str, re.ASCII):
                tokens.append(int(token_str))
            elif re.fullmatch(r"^-?[0-9]+\.[0-9]+$", token_str, re.ASCII):
                tokens.append(float(token_str))
            else:
                raise SecurityViolationError(f"Unquoted string or unrecognized argument token: '{token_str}'")

            while i < n and s[i] in (" ", "\t"):
                i += 1
            if i < n:
                if s[i] == ",":
                    i += 1
                else:
                    raise SecurityViolationError(f"Expected comma after argument, found '{s[i]}'")

    return tokens


def _strip_trailing_bcs_comment(line: str) -> str:
    """Strip an unquoted trailing '% ...' comment after a Command(...) expression."""
    in_quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_quote is not None:
            if ch == "|":
                i += 2
                continue
            if ch == in_quote:
                in_quote = None
            i += 1
        else:
            if ch in ('"', "'"):
                in_quote = ch
                i += 1
            elif ch == "%":
                prefix = line[:i].rstrip()
                if prefix.endswith(")"):
                    return prefix
                break
            else:
                i += 1
    return line


def parse_and_validate_bcs_line(
    raw_line: str,
    allow_privileged: bool = False,
    _depth: int = 0,
) -> str:
    """Parse, tokenize, validate, and rebuild a single Bluebeam Script command line.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 4.
        - docs/ARCHITECTURE.md Section 4.2.
        - docs/REMEDIATION_PLAN.md Finding C-01.
    """
    cleaned = raw_line.strip()
    if not cleaned:
        return ""

    if any(c in cleaned for c in DISALLOWED_LINE_CHARS):
        raise SecurityViolationError("Disallowed control character or line separator in script line")

    # Allow full-line comments
    if cleaned.startswith("%"):
        return cleaned

    # Strip optional unquoted trailing '% ...' comment after closing ')'
    cleaned_cmd = _strip_trailing_bcs_comment(cleaned)

    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*)[ \t]*\((.*)\)", cleaned_cmd, re.ASCII)
    if not match:
        raise SecurityViolationError(f"Malformed command syntax: '{cleaned}'")

    cmd_name = match.group(1)
    args_str = match.group(2)

    tokens = _tokenize_bcs_args(args_str)
    return build_command(cmd_name, *tokens, allow_privileged=allow_privileged, _depth=_depth)


def redact_bcs_secrets(bcs_script: str) -> str:
    """Redact plaintext passwords from Bluebeam Script commands in logs and receipts.

    Citations:
        - docs/ARCHITECTURE.md Section 4.2.
        - docs/REMEDIATION_PLAN.md Finding C-06.
    """
    if not bcs_script:
        return ""

    lines = bcs_script.splitlines(keepends=True)
    redacted_lines: list[str] = []

    for line in lines:
        line_clean = line.strip()

        # Redact SetOpenPassword
        if re.search(r"SetOpenPassword\s*\(", line_clean, re.IGNORECASE):
            redacted = re.sub(
                r'(SetOpenPassword\s*\(\s*)".*?"(\s*\))',
                r'\1"***REDACTED***"\2',
                line,
                flags=re.IGNORECASE,
            )
            redacted_lines.append(redacted)
            continue

        # Redact SetPDFSecurity
        if re.search(r"SetPDFSecurity\s*\(", line_clean, re.IGNORECASE):
            m = re.match(r"^(\s*)SetPDFSecurity\s*\((.*?)\)(\s*[\r\n]*)$", line, re.IGNORECASE | re.DOTALL)
            if m:
                indent = m.group(1)
                inner = m.group(2)
                end = m.group(3)
                try:
                    tokens = _tokenize_bcs_args(inner)
                    if len(tokens) >= 1:
                        tokens[0] = "***REDACTED***"
                    if len(tokens) >= 3 and isinstance(tokens[2], str) and tokens[2]:
                        tokens[2] = "***REDACTED***"
                    args_formatted: list[str] = []
                    for t in tokens:
                        if isinstance(t, str):
                            args_formatted.append(f'"{escape_bcs_string(t)}"')
                        elif isinstance(t, bool):
                            args_formatted.append("true" if t else "false")
                        else:
                            args_formatted.append(str(t))
                    redacted_lines.append(f"{indent}SetPDFSecurity({', '.join(args_formatted)}){end}")
                except Exception:
                    redacted_lines.append(f'{indent}SetPDFSecurity("***REDACTED***"){end}')
                continue

        # Redact 2nd argument of Open("path", "password")
        if re.search(r"Open\s*\(", line_clean, re.IGNORECASE):
            m = re.match(r"^(\s*)Open\s*\((.*?)\)(\s*[\r\n]*)$", line, re.IGNORECASE | re.DOTALL)
            if m:
                indent = m.group(1)
                inner = m.group(2)
                end = m.group(3)
                try:
                    tokens = _tokenize_bcs_args(inner)
                    if len(tokens) == 2 and isinstance(tokens[1], str):
                        tokens[1] = "***REDACTED***"
                        args_formatted = [
                            f'"{escape_bcs_string(str(tokens[0]))}"',
                            f'"{escape_bcs_string(str(tokens[1]))}"',
                        ]
                        redacted_lines.append(f"{indent}Open({', '.join(args_formatted)}){end}")
                        continue
                except Exception:
                    pass

        redacted_lines.append(line)

    return "".join(redacted_lines)


class ScriptBuilder:
    """Fluent builder for composing multi-command Bluebeam Script (.bcs) scripts.

    Citations:
        - docs/ARCHITECTURE.md Section 4.4 (script_builder.py).
        - Bluebeam Script Reference Version 2.0.11.
    """

    def __init__(self) -> None:
        self._commands: list[str] = []

    def add_command(self, command_name: str, *args: Any, allow_privileged: bool = True) -> Self:
        """Add a validated command to the script sequence."""
        cmd_str = build_command(command_name, *args, allow_privileged=allow_privileged)
        self._commands.append(cmd_str)
        return self

    def add_raw_command(self, raw_line: str, allow_privileged: bool = False) -> Self:
        """Add a raw command line, validated via parse_and_validate_bcs_line."""
        validated = parse_and_validate_bcs_line(raw_line, allow_privileged=allow_privileged)
        if validated:
            self._commands.append(validated)
        return self

    def add_comment(self, comment_text: str) -> Self:
        """Add a comment line to the script sequence (prefixed by %)."""
        if "\x00" in comment_text or "\r" in comment_text or "\n" in comment_text:
            raise SecurityViolationError("Comment text cannot contain null bytes or newlines")
        self._commands.append(f"% {comment_text}")
        return self

    # ------------------------------------------------------------------------
    # Convenience Command Builders
    # ------------------------------------------------------------------------

    def open(self, file_path: str | Path, password: str | None = None) -> Self:
        """Open a PDF document, pushing it to the top of the stack."""
        args: list[Any] = [str(file_path)]
        if password is not None:
            args.append(password)
        return self.add_command("Open", *args)

    def save(
        self,
        file_path: str | Path | None = None,
        save_mode: int | None = None,
    ) -> Self:
        """Save the active document over itself or to a new location."""
        args: list[Any] = []
        if file_path is not None:
            args.append(str(file_path))
            if save_mode is not None:
                args.append(save_mode)
        return self.add_command("Save", *args)

    def close(self, save: bool = False, save_mode: int | None = None) -> Self:
        """Close the active document with optional save flag and mode."""
        args: list[Any] = [save]
        if save_mode is not None:
            args.append(save_mode)
        return self.add_command("Close", *args)

    def page_count(self) -> Self:
        """Query page count of active document."""
        return self.add_command("PageCount")

    def page_size(self, page_index: int) -> Self:
        """Query width and height for a 1-based page index."""
        valid_page = validate_one_based_page(page_index)
        return self.add_command("PageSize", valid_page)

    def page_delete(self, page_range: str | int) -> Self:
        """Delete specified 1-based page range."""
        valid_range = validate_page_range(page_range)
        return self.add_command("PageDelete", valid_range)

    def page_rotate(
        self,
        rotations: int,
        portrait: bool = True,
        landscape: bool = True,
        page_range: str | int = -1,
    ) -> Self:
        """Rotate pages by 90-degree increments."""
        if rotations % 90 != 0:
            raise ValueError(f"Rotations must be a multiple of 90: {rotations}")
        valid_range = validate_page_range(page_range)
        return self.add_command("PageRotate", rotations, portrait, landscape, valid_range)

    def page_rotate_get(self, page_index: int) -> Self:
        """Get rotation degrees for a 1-based page index."""
        valid_page = validate_one_based_page(page_index)
        return self.add_command("PageRotateGet", valid_page)

    def insert_pages(
        self,
        insert_index: int,
        source_path: str | Path,
        include_bookmarks: bool = False,
        include_attachments: bool = False,
        include_properties: bool = False,
        include_layers: bool = False,
        include_markups: bool = False,
    ) -> Self:
        """Insert pages from another document using 0-based insertion index per 01_script_reference.md p. 15."""
        valid_idx = validate_insertion_index(insert_index)
        return self.add_command(
            "InsertPages",
            valid_idx,
            str(source_path),
            bool(include_bookmarks),
            bool(include_attachments),
            bool(include_properties),
            bool(include_layers),
            bool(include_markups),
        )

    def insert_blank_pages(
        self,
        insert_index: int,
        width: float = 8.5,
        height: float = 11.0,
        count: int = 1,
        style: int = 0,
    ) -> Self:
        """Insert blank pages using 0-based insertion index per 01_script_reference.md p. 14."""
        valid_idx = validate_insertion_index(insert_index)
        if isinstance(width, bool) or not isinstance(width, (int, float)) or not math.isfinite(width) or width <= 0:
            raise ValueError(f"width must be a finite positive number: {width}")
        if isinstance(height, bool) or not isinstance(height, (int, float)) or not math.isfinite(height) or height <= 0:
            raise ValueError(f"height must be a finite positive number: {height}")
        if type(count) is not int or count < 1:
            raise ValueError(f"count must be an integer >= 1: {count}")
        if type(style) is not int or not (0 <= style <= 8):
            raise ValueError(f"style must be an integer between 0 and 8: {style}")

        return self.add_command(
            "InsertBlankPages",
            valid_idx,
            width,
            height,
            count,
            style,
        )

    def flatten(
        self,
        recoverable: bool = False,
        flags: int | list[str] | set[str] | tuple[str, ...] | None = None,
    ) -> Self:
        """Flatten markups into document content."""
        mask = calculate_flatten_bitmask(flags)
        return self.add_command("Flatten", recoverable, mask)

    def unflatten(self, page_range: str | int = -1) -> Self:
        """Unflatten previously flattened recoverable markups."""
        valid_range = validate_page_range(page_range)
        return self.add_command("Unflatten", valid_range)

    def set_pdf_security(
        self,
        permission_password: str,
        flags: int | list[str] | set[str] | tuple[str, ...] | None = None,
        open_password: str | None = None,
        encryption_level: str | None = None,
    ) -> Self:
        """Apply security permissions to active document per 01_script_reference.md p. 26."""
        if not isinstance(permission_password, str) or not permission_password:
            raise ValueError("permission_password must be a non-empty string")

        norm_level: str | None = None
        if encryption_level is not None:
            if not isinstance(encryption_level, str):
                raise ValueError(f"Invalid encryption_level: {encryption_level}")
            norm_level = encryption_level.strip().upper()
            if norm_level not in {"RC4", "AES128", "AES256"}:
                raise ValueError(
                    f"Unsupported encryption_level '{encryption_level}'. Must be 'RC4', 'AES128', or 'AES256'."
                )

        mask = calculate_security_bitmask(flags)
        args: list[Any] = [permission_password, mask]

        if norm_level is not None:
            args.append(open_password or "")
            args.append(norm_level)
        elif open_password is not None:
            args.append(open_password)

        return self.add_command("SetPDFSecurity", *args)

    # ------------------------------------------------------------------------
    # Builder Output and State Management
    # ------------------------------------------------------------------------

    @property
    def commands(self) -> list[str]:
        """Return a copy of the ordered command list."""
        return list(self._commands)

    def build(self) -> str:
        """Assemble all commands into a complete .bcs script text using CRLF line endings."""
        return "\r\n".join(self._commands)

    def clear(self) -> Self:
        """Reset builder commands."""
        self._commands.clear()
        return self
