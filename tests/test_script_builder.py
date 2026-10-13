"""Unit tests for bluebeam_mcp.script_builder.

Citations:
    - docs/ARCHITECTURE.md Section 4.4 (script_builder.py).
    - docs/citations/01_script_reference.md Section 1 and Section 2.
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.1 (Tier 1: Unit and Schema Validation).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bluebeam_mcp.security import (
    PageRangeError,
    SecurityViolationError,
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


# ============================================================================
# Tier 1: Unit and Schema Validation Tests (T1-01 through T1-07)
# ============================================================================


def test_page_indexing_conventions() -> None:
    """T1-01: Insertion commands accept 0-based index (0 before page 1); queries use 1-based."""
    # 0 is valid for insertion (before page 1)
    assert validate_insertion_index(0, max_pages=10) == 0
    assert validate_insertion_index(5, max_pages=10) == 5
    assert validate_insertion_index(10, max_pages=10) == 10

    # Insertion index < 0 or > max_pages rejected
    with pytest.raises(PageRangeError):
        validate_insertion_index(-1, max_pages=10)
    with pytest.raises(PageRangeError):
        validate_insertion_index(11, max_pages=10)

    # 1-based page queries: 1 is first page; 0 rejected
    assert validate_one_based_page(1, max_pages=10) == 1
    assert validate_one_based_page(10, max_pages=10) == 10

    with pytest.raises(PageRangeError):
        validate_one_based_page(0, max_pages=10)
    with pytest.raises(PageRangeError):
        validate_one_based_page(-1, max_pages=10)
    with pytest.raises(PageRangeError):
        validate_one_based_page(11, max_pages=10)


def test_page_range_formatting() -> None:
    """T1-02: Page ranges formatted as 1-based strings, and all pages denoted as -1."""
    # All pages
    assert validate_page_range(-1) == "-1"
    assert validate_page_range("-1") == "-1"

    # Single pages and sub-ranges
    assert validate_page_range(1) == "1"
    assert validate_page_range("1,2,10-20") == "1,2,10-20"
    assert validate_page_range("1-5,7,9-12", max_pages=20) == "1-5,7,9-12"

    # Rejection of 0 or negative other than -1
    with pytest.raises(PageRangeError):
        validate_page_range(0)
    with pytest.raises(PageRangeError):
        validate_page_range(-2)
    with pytest.raises(PageRangeError):
        validate_page_range("0,1,2")
    with pytest.raises(PageRangeError):
        validate_page_range("1-0")

    # Out of document bounds check
    with pytest.raises(PageRangeError):
        validate_page_range("1-25", max_pages=20)
    with pytest.raises(PageRangeError):
        validate_page_range(25, max_pages=20)


def test_flatten_bitmask_flags() -> None:
    """T1-03: Flatten(pRecoverable, pFlags) bitmask values match documented 18 flags."""
    # Verify bit values per 01_script_reference.md p. 11-12
    assert FLATTEN_FLAGS["image"] == 1
    assert FLATTEN_FLAGS["ellipse"] == 2
    assert FLATTEN_FLAGS["stamp"] == 4
    assert FLATTEN_FLAGS["snapshot"] == 8
    assert FLATTEN_FLAGS["text_callout"] == 16
    assert FLATTEN_FLAGS["ink_highlighter"] == 32
    assert FLATTEN_FLAGS["line_dimension"] == 64
    assert FLATTEN_FLAGS["measure_area"] == 128
    assert FLATTEN_FLAGS["polyline"] == 256
    assert FLATTEN_FLAGS["polygon_cloud"] == 512
    assert FLATTEN_FLAGS["rectangle"] == 1024
    assert FLATTEN_FLAGS["text_markups"] == 2048
    assert FLATTEN_FLAGS["group"] == 4096
    assert FLATTEN_FLAGS["file_attachment"] == 8192
    assert FLATTEN_FLAGS["flags"] == 16384
    assert FLATTEN_FLAGS["notes"] == 32768
    assert FLATTEN_FLAGS["form_fields"] == 65536

    # Verify default flag is 8191 (sum of flags 1 through 4096)
    assert DEFAULT_FLATTEN_FLAGS == 8191
    assert calculate_flatten_bitmask() == 8191
    assert calculate_flatten_bitmask(None) == 8191

    # Verify all flags sum is 131071
    assert ALL_FLATTEN_FLAGS == 131071

    # Verify flag combination helper
    combined = calculate_flatten_bitmask(["image", "stamp", "rectangle"])
    assert combined == (1 | 4 | 1024)

    # Verify invalid flag rejection
    with pytest.raises(ValueError):
        calculate_flatten_bitmask(["invalid_flag_name"])
    with pytest.raises(ValueError):
        calculate_flatten_bitmask(-1)
    with pytest.raises(ValueError):
        calculate_flatten_bitmask(200000)


def test_set_pdf_security_bitmask() -> None:
    """T1-04: SetPDFSecurity permission bitmask matches documented 8 permission flags."""
    # Verify bit values per 01_script_reference.md p. 26
    assert SECURITY_FLAGS["print"] == 1
    assert SECURITY_FLAGS["print_low_only"] == 2
    assert SECURITY_FLAGS["fill_forms"] == 4
    assert SECURITY_FLAGS["edit_markups"] == 8
    assert SECURITY_FLAGS["edit_document"] == 16
    assert SECURITY_FLAGS["page_manipulation"] == 32
    assert SECURITY_FLAGS["copy_content"] == 64
    assert SECURITY_FLAGS["accessibility"] == 128

    # Verify total sum is 255
    assert ALL_SECURITY_FLAGS == 255

    # Verify default is 193 (Print=1 + CopyContent=64 + Accessibility=128)
    assert DEFAULT_SECURITY_FLAGS == 193
    assert calculate_security_bitmask() == 193
    assert calculate_security_bitmask(None) == 193

    # Composite calculation helper
    custom = calculate_security_bitmask(["print", "fill_forms", "accessibility"])
    assert custom == (1 | 4 | 128)

    # Rejection of invalid permission names and values
    with pytest.raises(ValueError):
        calculate_security_bitmask(["unauthorized_permission"])
    with pytest.raises(ValueError):
        calculate_security_bitmask(-1)
    with pytest.raises(ValueError):
        calculate_security_bitmask(256)


def test_color_parameter_formats() -> None:
    """T1-05: Color serializer handles named strings, hex formats, and packed RGB integers."""
    # Named strings
    assert validate_color("Black") == "Black"
    assert validate_color("Red") == "Red"
    assert validate_color("blue") == "blue"

    # Hex strings
    assert validate_color("#FF0000") == "#FF0000"
    assert validate_color("#00ff00") == "#00ff00"
    assert validate_color("#FFF") == "#FFF"

    # Packed RGB integers
    assert validate_color(0) == "0"
    assert validate_color(255) == "255"
    assert validate_color(16777215) == "16777215"

    # Rejection of invalid colors
    with pytest.raises(ValueError):
        validate_color("invalid color with spaces")
    with pytest.raises(ValueError):
        validate_color("#GG0000")
    with pytest.raises(ValueError):
        validate_color(-1)
    with pytest.raises(ValueError):
        validate_color(16777216)


def test_dictionary_serialization() -> None:
    """T1-06: Dictionary serializer emits {"Key":"Value"} with escaped characters."""
    data = {
        "type": "square",
        "author": 'John "Architect" Doe',
        "color": "#FF0000",
        "locked": False,
        "width": 72.0,
    }
    serialized = serialize_bcs_dict(data)
    assert serialized.startswith("{")
    assert serialized.endswith("}")
    assert '"type":"square"' in serialized
    assert r'"author":"John |"Architect|" Doe"' in serialized
    assert '"color":"#FF0000"' in serialized
    assert '"locked":"false"' in serialized
    assert '"width":"72.0"' in serialized


def test_markup_property_dictionary_serialization() -> None:
    """T1-06: Alias satisfying matrix specification for dictionary serialization."""
    test_dictionary_serialization()


def test_iso8601_date_validation() -> None:
    """T1-07: Verifies UTC ISO 8601 date format YYYY-MM-DDThh:mm:ss validation."""
    valid_dates = [
        "2026-10-12T17:00:00",
        "2026-10-12T17:00:00Z",
        "2024-01-01T00:00:00",
    ]
    for vd in valid_dates:
        result = validate_iso8601_date(vd)
        assert result.startswith("202")
        assert "T" in result

    invalid_dates = [
        "10/12/2026 17:00:00",
        "2026-10-12",
        "2026-13-01T00:00:00",
        "not_a_date",
        "",
    ]
    for ivd in invalid_dates:
        with pytest.raises(ValueError):
            validate_iso8601_date(ivd)


# ============================================================================
# Adversarial Dictionary and Page Fault Tests (T2-04, T3-05, T3-06)
# ============================================================================


def test_adversarial_dict_single_quote_breakout() -> None:
    """T2-04: Dictionary serializer escapes single quotes to |' preventing command breakout."""
    malicious_dict = {
        "author": "Admin' : 'Injected' }) DeleteFile(\"important.pdf\") %",
    }
    serialized = serialize_bcs_dict(malicious_dict)
    assert "|'" in serialized

    # Build command wrapping the dict
    cmd = build_command("MarkupSet", 1, serialized)
    assert cmd.startswith("MarkupSet(1, ")
    # The double quotes inside the dictionary argument must be escaped with |"
    assert '|"' in cmd


def test_fault_out_of_bounds_page_index() -> None:
    """T3-05: Requesting page 99 on a 3-page PDF raises PageRangeError."""
    with pytest.raises(PageRangeError) as exc_info:
        validate_one_based_page(99, max_pages=3)
    assert exc_info.value.error_code == "PAGE_OUT_OF_RANGE"

    with pytest.raises(PageRangeError):
        validate_page_range("99", max_pages=3)


def test_fault_page_index_zero_query() -> None:
    """T3-06: Querying page 0 for 1-based operations raises PageRangeError."""
    with pytest.raises(PageRangeError) as exc_info:
        validate_one_based_page(0, max_pages=10)
    assert exc_info.value.error_code == "PAGE_OUT_OF_RANGE"


# ============================================================================
# Schema and Command Inventory Tests
# ============================================================================


def test_valid_markup_keys_inventory() -> None:
    """Verify all 27 documented markup property dictionary keys are present."""
    assert len(VALID_MARKUP_KEYS) == 27
    expected_keys = {
        "type", "page", "author", "subject", "comment", "color", "colorfill",
        "colortext", "opacity", "opacityfill", "rotation", "parent", "grouped",
        "status", "checked", "locked", "datecreated", "datemodified", "linewidth",
        "linestyle", "x", "y", "width", "height", "space", "layer", "captureCount",
    }
    assert VALID_MARKUP_KEYS == expected_keys


def test_known_bcs_commands_inventory() -> None:
    """Verify known Bluebeam Script commands include core documented operations."""
    assert len(KNOWN_BCS_COMMANDS) >= 88
    core_commands = [
        "Open", "Close", "Save", "PageCount", "PageSize", "PageRotate",
        "PageRotateGet", "InsertPages", "InsertBlankPages", "PageDelete",
        "PageExtract", "SplitPages", "Combine", "Flatten", "Unflatten",
        "MarkupAdd", "MarkupGet", "MarkupSet", "MarkupDelete", "MarkupList",
        "SetPDFSecurity", "SetOpenPassword", "Stamp", "Search", "Repair",
        "ReduceFileSize", "HeaderAndFooter", "BookmarksExport", "BookmarksImport",
        "Email", "SaveAs", "MarkupCopy", "MarkupPaste",
    ]
    for cmd in core_commands:
        assert cmd in KNOWN_BCS_COMMANDS


def test_build_command_formatting_and_security() -> None:
    """Verify build_command correctly formats parameters and rejects unknown commands."""
    # 0 args
    assert build_command("PageCount") == "PageCount()"
    assert build_command("pagecount") == "PageCount()"

    # Mixed args: str, int, bool, float
    cmd = build_command("InsertBlankPages", 0, 5, 8.5, 11.0, 0)
    assert cmd == "InsertBlankPages(0, 5, 8.5, 11.0, 0)"

    # String with pipe and quote
    cmd2 = build_command("Open", r'test"|file.pdf')
    assert cmd2 == 'Open("test|"||file.pdf")'

    # Reject unauthorized command
    with pytest.raises(SecurityViolationError):
        build_command("UnauthorizedMaliciousCommand", "arg")


def test_script_builder_fluent_workflow() -> None:
    """Verify ScriptBuilder fluently chains commands and builds valid .bcs output."""
    builder = (
        ScriptBuilder()
        .add_comment("Batch Flatten and Security Pipeline")
        .open(r"C:\docs\input.pdf")
        .page_count()
        .insert_blank_pages(insert_index=0, count=1, width=8.5, height=11.0, style=0)
        .flatten(recoverable=False, flags=["image", "stamp"])
        .set_pdf_security("masterpass", flags=["print", "copy_content"])
        .save(r"C:\docs\output.pdf")
        .close(save=True)
    )

    script_text = builder.build()
    assert "% Batch Flatten and Security Pipeline" in script_text
    assert r'Open("C:\docs\input.pdf")' in script_text
    assert "PageCount()" in script_text
    assert "InsertBlankPages(0, 8.5, 11.0, 1, 0)" in script_text
    assert "Flatten(false, 5)" in script_text
    assert "SetPDFSecurity(" in script_text
    assert r'Save("C:\docs\output.pdf")' in script_text
    assert "Close(true)" in script_text
    assert "\r\n" in script_text
    assert len(builder.commands) == 8

    # Reset
    builder.clear()
    assert len(builder.commands) == 0
    assert builder.build() == ""
