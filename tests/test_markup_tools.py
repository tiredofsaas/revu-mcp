"""Comprehensive four-tier verification suite for markup_tools.py.

Covers all 10 markup, takeoff, stamp, flattening, form, and optimization tools
across Tier 1 (Unit), Tier 2 (Adversarial Security), Tier 3 (Stability & Fault Injection),
and Tier 4 (Live Integration & Dual-Engine Execution).

All temporary files are strictly confined to tests/tmp/.

Primary citations:
- docs/citations/01_script_reference.md p. 5, 8-9, 10, 11-12, 12-13, 14, 15-16, 17-18, 22-23, 26, 27, 29
- docs/citations/02_binary_and_dotnet_surface.md Section 5.2, Section 7.2, Section 7.4
- docs/citations/03_data_formats_and_markups.md Section 4, Section 5
- docs/ARCHITECTURE.md Section 6.2 (Category 2: Markup Tools)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Four-Tier Test Matrix)
"""

from __future__ import annotations

import json
from pathlib import Path
import uuid
import xml.etree.ElementTree as ET

from mcp.server.fastmcp import FastMCP
import pypdf
import pytest

from tests.conftest import requires_revu

from bluebeam_mcp.script_builder import (
    ALL_FLATTEN_FLAGS,
    ALL_SECURITY_FLAGS,
    DEFAULT_FLATTEN_FLAGS,
    DEFAULT_SECURITY_FLAGS,
    FLATTEN_FLAGS,
    SECURITY_FLAGS,
    VALID_MARKUP_KEYS,
    calculate_flatten_bitmask,
    calculate_security_bitmask,
    serialize_bcs_dict,
)
from bluebeam_mcp.security import (
    FORBIDDEN_ROOTS,
    READ_ONLY_ROOTS,
    SecurityViolationError,
)
from bluebeam_mcp.tools.markup_tools import (
    STAMP_BLEND_MODE_MAP,
    STAMP_BLEND_MODE_NAMES,
    STAMP_ORIGIN_MAP,
    STAMP_ORIGIN_NAMES,
    bb_form_inspect_and_fill,
    bb_markup_add,
    bb_markup_delete,
    bb_markup_export_bax,
    bb_markup_flatten,
    bb_markup_import_bax,
    bb_markup_list,
    bb_markup_update,
    bb_pdf_color_and_optimize,
    bb_pdf_stamp,
    register_markup_tools,
    resolve_stamp_blend_mode,
    resolve_stamp_origin,
)

SCRATCH_DIR = Path(__file__).resolve().parent / "tmp"
APPROVED_STAMP_PATH = Path(r"C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\Stamps\Approved.pdf")


# ============================================================================
# TIER 1: UNIT & SCHEMA VALIDATION TESTS
# ============================================================================

def test_tier1_26_key_markup_dictionary_serialization() -> None:
    """T1: Validate all 26 documented markup property keys serialize properly.

    Citation: docs/citations/01_script_reference.md p. 5.
    """
    assert len(VALID_MARKUP_KEYS) >= 26

    # Build dictionary with all 26 keys
    full_dict = {
        "type": "FreeText",
        "page": 1,
        "author": 'Architect "Senior" Lead',
        "subject": "Review Callout",
        "comment": "Verify duct clearance | HVAC",
        "color": "#FF0000",
        "colorfill": "#00FF00",
        "colortext": "#000000",
        "opacity": 0.85,
        "opacityfill": 0.5,
        "rotation": 0,
        "parent": "PARENT-001",
        "grouped": False,
        "status": "Accepted",
        "checked": True,
        "locked": False,
        "datecreated": "2026-10-12T10:00:00",
        "datemodified": "2026-10-12T10:30:00",
        "linewidth": 1.5,
        "linestyle": "solid",
        "x": 100.0,
        "y": 200.0,
        "width": 150.0,
        "height": 50.0,
        "space": "Floor 1",
        "layer": "Mechanical",
        "captureCount": 0,
    }

    serialized = serialize_bcs_dict(full_dict)
    assert serialized.startswith("{")
    assert serialized.endswith("}")

    # Verify escaping of quotes and pipes
    assert r'|"Senior|"' in serialized
    assert r"||" in serialized
    assert '"type":"FreeText"' in serialized
    assert '"locked":"false"' in serialized
    assert '"checked":"true"' in serialized


def test_tier1_flatten_bitmask_flags() -> None:
    """T1: Validate Flatten bitmask calculation for 8191 default and 131071 total.

    Citation: docs/citations/01_script_reference.md p. 11-12.
    """
    assert DEFAULT_FLATTEN_FLAGS == 8191
    assert ALL_FLATTEN_FLAGS == 131071
    assert calculate_flatten_bitmask() == 8191
    assert calculate_flatten_bitmask(None) == 8191
    assert calculate_flatten_bitmask(131071) == 131071

    # Verify individual flags
    assert FLATTEN_FLAGS["image"] == 1
    assert FLATTEN_FLAGS["ellipse"] == 2
    assert FLATTEN_FLAGS["stamp"] == 4
    assert FLATTEN_FLAGS["snapshot"] == 8
    assert FLATTEN_FLAGS["text"] == 16
    assert FLATTEN_FLAGS["form_fields"] == 65536

    combined = calculate_flatten_bitmask(["image", "stamp", "rectangle"])
    assert combined == (1 | 4 | 1024)


def test_tier1_security_bitmask_flags() -> None:
    """T1: Validate SetPDFSecurity bitmask calculation for 193 default and 255 total.

    Citation: docs/citations/01_script_reference.md p. 26.
    """
    assert DEFAULT_SECURITY_FLAGS == 193
    assert ALL_SECURITY_FLAGS == 255
    assert calculate_security_bitmask() == 193
    assert calculate_security_bitmask(None) == 193
    assert calculate_security_bitmask(255) == 255

    # Verify individual permissions
    assert SECURITY_FLAGS["print"] == 1
    assert SECURITY_FLAGS["copy_content"] == 64
    assert SECURITY_FLAGS["accessibility"] == 128
    assert (1 | 64 | 128) == 193

    combined = calculate_security_bitmask(["print", "fill_forms", "accessibility"])
    assert combined == (1 | 4 | 128)


def test_tier1_stamp_origin_enums() -> None:
    """T1: Validate Stamp anchor origin mappings across all 7 supported values.

    Citation: docs/citations/01_script_reference.md p. 27.
    """
    assert len(STAMP_ORIGIN_MAP) == 7
    assert STAMP_ORIGIN_MAP[0] == "center"
    assert STAMP_ORIGIN_MAP[1] == "upperleft"
    assert STAMP_ORIGIN_MAP[2] == "upperright"
    assert STAMP_ORIGIN_MAP[3] == "lowerleft"
    assert STAMP_ORIGIN_MAP[4] == "lowerright"
    assert STAMP_ORIGIN_MAP[5] == "uppercenter"
    assert STAMP_ORIGIN_MAP[6] == "lowercenter"

    for idx, name in STAMP_ORIGIN_MAP.items():
        assert resolve_stamp_origin(idx) == name
        assert resolve_stamp_origin(name) == name
        assert resolve_stamp_origin(name.upper()) == name

    with pytest.raises(ValueError):
        resolve_stamp_origin(99)
    with pytest.raises(ValueError):
        resolve_stamp_origin("invalid_origin")


def test_tier1_stamp_blend_mode_enums() -> None:
    """T1: Validate Stamp blend mode mappings across all 16 supported values.

    Citation: docs/citations/01_script_reference.md p. 27.
    """
    assert len(STAMP_BLEND_MODE_MAP) == 16
    assert STAMP_BLEND_MODE_MAP[0] == "normal"
    assert STAMP_BLEND_MODE_MAP[1] == "multiply"
    assert STAMP_BLEND_MODE_MAP[2] == "screen"
    assert STAMP_BLEND_MODE_MAP[3] == "overlay"
    assert STAMP_BLEND_MODE_MAP[15] == "color"

    for idx, name in STAMP_BLEND_MODE_MAP.items():
        assert resolve_stamp_blend_mode(idx) == name
        assert resolve_stamp_blend_mode(name) == name

    with pytest.raises(ValueError):
        resolve_stamp_blend_mode(99)
    with pytest.raises(ValueError):
        resolve_stamp_blend_mode("invalid_blend")


def test_tier1_script_only_mode_all_10_tools(sample_pdf: Path, sample_bax: Path) -> None:
    """T1: Verify all 10 tools generate valid Bluebeam Script in script_only mode."""
    out_pdf = str(SCRATCH_DIR / "script_only_test.pdf")
    out_bax = str(SCRATCH_DIR / "script_only_test.bax")

    # 1. bb_markup_list
    res1 = bb_markup_list(str(sample_pdf), execution_mode="script_only")
    assert res1["status"] == "success"
    assert "Open(" in res1["bcs_script"]
    assert "MarkupGetExList" in res1["bcs_script"]

    # 2. bb_markup_add
    res2 = bb_markup_add(str(sample_pdf), out_pdf, markup_type="Square", execution_mode="script_only")
    assert res2["status"] == "success"
    assert "AddMarkupFromDictionary" in res2["bcs_script"]

    # 3. bb_markup_update
    res3 = bb_markup_update(str(sample_pdf), out_pdf, page_number=1, markup_id="ID1", updates={"comment": "test"}, execution_mode="script_only")
    assert res3["status"] == "success"
    assert "MarkupSet" in res3["bcs_script"]

    # 4. bb_markup_delete
    res4 = bb_markup_delete(str(sample_pdf), out_pdf, page_number=1, markup_id="ID1", execution_mode="script_only")
    assert res4["status"] == "success"
    assert "MarkupDelete" in res4["bcs_script"]

    # 5. bb_markup_flatten
    res5 = bb_markup_flatten(str(sample_pdf), out_pdf, execution_mode="script_only")
    assert res5["status"] == "success"
    assert "Flatten" in res5["bcs_script"]

    # 6. bb_pdf_stamp
    res6 = bb_pdf_stamp(str(sample_pdf), out_pdf, stamp_path_or_text="APPROVED", execution_mode="script_only")
    assert res6["status"] == "success"
    assert "Stamp" in res6["bcs_script"]

    # 7. bb_markup_export_bax
    res7 = bb_markup_export_bax(str(sample_pdf), out_bax, execution_mode="script_only")
    assert res7["status"] == "success"
    assert "Export" in res7["bcs_script"]

    # 8. bb_markup_import_bax
    res8 = bb_markup_import_bax(str(sample_pdf), str(sample_bax), out_pdf, execution_mode="script_only")
    assert res8["status"] == "success"
    assert "Import" in res8["bcs_script"]

    # 9. bb_form_inspect_and_fill
    res9 = bb_form_inspect_and_fill(str(sample_pdf), action="inspect", execution_mode="script_only")
    assert res9["status"] == "success"
    assert "Open" in res9["bcs_script"]

    # 10. bb_pdf_color_and_optimize
    res10 = bb_pdf_color_and_optimize(str(sample_pdf), out_pdf, operation="reduce_size", execution_mode="script_only")
    assert res10["status"] == "success"
    assert "ReduceFileSize" in res10["bcs_script"]


# ============================================================================
# TIER 2: ADVERSARIAL SECURITY TESTS
# ============================================================================

def test_tier2_adversarial_single_quote_breakout(sample_pdf: Path) -> None:
    """T2-04: Single quote breakout payload in updates is pipe-escaped."""
    out_pdf = str(SCRATCH_DIR / f"sec_quote_{uuid.uuid4().hex}.pdf")
    payload = "Admin' : 'Injected' }) DeleteFile(\"important.pdf\") %"

    res = bb_markup_update(
        str(sample_pdf),
        out_pdf,
        page_number=1,
        markup_id="MK001",
        updates={"author": payload},
        execution_mode="script_only",
    )
    assert res["status"] == "success"
    # Single quote must be pipe-escaped to |'
    assert "|'" in res["bcs_script"]
    assert "DeleteFile" not in res["bcs_script"].split("MarkupSet")[0]


def test_tier2_adversarial_pipe_quote_breakout(sample_pdf: Path) -> None:
    """T2-02: Pipe quote smuggle payload in comment is escaped to |||'."""
    out_pdf = str(SCRATCH_DIR / f"sec_pipe_{uuid.uuid4().hex}.pdf")
    payload = 'test|" DeleteFile("target.pdf")'

    res = bb_markup_add(
        str(sample_pdf),
        out_pdf,
        comment=payload,
        execution_mode="script_only",
    )
    assert res["status"] == "success"
    assert "||" in res["bcs_script"]


def test_tier2_adversarial_xxe_import_bax_blocked(sample_pdf: Path) -> None:
    """T2-12: XXE injection file in bb_markup_import_bax is rejected with XML_PARSE_ERROR."""
    xxe_file = SCRATCH_DIR / f"xxe_{uuid.uuid4().hex}.bax"
    out_pdf = SCRATCH_DIR / f"out_{uuid.uuid4().hex}.pdf"
    xxe_file.write_text(
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        encoding="utf-8",
    )

    res = bb_markup_import_bax(str(sample_pdf), str(xxe_file), str(out_pdf))
    assert res["status"] == "error"
    assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")
    assert res["error"]["category"] == "security"


def test_tier2_adversarial_billion_laughs_import_bax_blocked(sample_pdf: Path) -> None:
    """T2-13: Billion Laughs bomb in bb_markup_import_bax is rejected with XML_PARSE_ERROR."""
    bomb_file = SCRATCH_DIR / f"bomb_{uuid.uuid4().hex}.bax"
    out_pdf = SCRATCH_DIR / f"out_{uuid.uuid4().hex}.pdf"
    bomb_payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<MarkupList><Annotation>&lol3;</Annotation></MarkupList>"""
    bomb_file.write_text(bomb_payload, encoding="utf-8")

    res = bb_markup_import_bax(str(sample_pdf), str(bomb_file), str(out_pdf))
    assert res["status"] == "error"
    assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")


def test_tier2_adversarial_protected_root_denial(sample_pdf: Path) -> None:
    """T2-06: Attempt to target E:\\ProtectedVault is blocked with SECURITY_VIOLATION."""
    forbidden_target = r"E:\ProtectedVault\vault\secret.pdf"
    res1 = bb_markup_list(forbidden_target)
    assert res1["status"] == "error"
    assert res1["error"]["code"] == "SECURITY_VIOLATION"

    res2 = bb_markup_add(str(sample_pdf), forbidden_target)
    assert res2["status"] == "error"
    assert res2["error"]["code"] == "SECURITY_VIOLATION"


def test_tier2_adversarial_solidworks_corp_denial(sample_pdf: Path) -> None:
    """T2-07: Attempt to target C:\\Program Files\\SOLIDWORKS Corp is blocked."""
    forbidden_sw = r"C:\Program Files\SOLIDWORKS Corp\template.pdf"
    res = bb_markup_list(forbidden_sw)
    assert res["status"] == "error"
    assert res["error"]["code"] == "SECURITY_VIOLATION"


def test_tier2_adversarial_write_to_readonly_roots_denial(sample_pdf: Path) -> None:
    """T2-08: Attempt to write to C:\\Windows or C:\\Program Files\\Bluebeam Software is blocked."""
    target_win = r"C:\Windows\System32\injected.pdf"
    res = bb_markup_add(str(sample_pdf), target_win)
    assert res["status"] == "error"
    assert res["error"]["code"] == "SECURITY_VIOLATION"


def test_tier2_adversarial_null_byte_denial(sample_pdf: Path) -> None:
    """T2-05: Null byte in path is immediately rejected."""
    bad_path = str(sample_pdf) + "\x00.exe"
    res = bb_markup_list(bad_path)
    assert res["status"] == "error"
    assert res["error"]["code"] == "SECURITY_VIOLATION"


# ============================================================================
# TIER 3: STABILITY & FAULT INJECTION TESTS
# ============================================================================

def test_tier3_fault_zero_byte_pdf() -> None:
    """T3-01: Zero-byte PDF input returns deterministic error."""
    zero_file = SCRATCH_DIR / f"zero_{uuid.uuid4().hex}.pdf"
    zero_file.write_bytes(b"")

    res = bb_markup_list(str(zero_file))
    assert res["status"] == "error"
    assert res["error"]["code"] in ("INVALID_PDF", "EMPTY_FILE")


def test_tier3_fault_corrupt_pdf_header() -> None:
    """T3-02: Bad PDF header returns INVALID_PDF error envelope."""
    bad_file = SCRATCH_DIR / f"bad_header_{uuid.uuid4().hex}.pdf"
    bad_file.write_bytes(b"NOT_A_PDF_FILE_HEADER_DATA_1234\n")

    res = bb_markup_list(str(bad_file))
    assert res["status"] == "error"
    assert res["error"]["code"] == "INVALID_PDF"


def test_tier3_fault_corrupt_bax_xml(sample_pdf: Path) -> None:
    """T3-09: Corrupt/unclosed XML in bb_markup_import_bax returns XML_PARSE_ERROR."""
    corrupt_bax = SCRATCH_DIR / f"corrupt_{uuid.uuid4().hex}.bax"
    out_pdf = SCRATCH_DIR / f"out_{uuid.uuid4().hex}.pdf"
    corrupt_bax.write_text("<MarkupList><Annotation>Unclosed tag", encoding="utf-8")

    res = bb_markup_import_bax(str(sample_pdf), str(corrupt_bax), str(out_pdf))
    assert res["status"] == "error"
    assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")


def test_tier3_fault_nonexistent_markup_id(annotated_pdf: Path) -> None:
    """T3: Updating or deleting a non-existent markup ID returns INVALID_PARAMETER."""
    out_pdf = str(SCRATCH_DIR / f"out_fault_{uuid.uuid4().hex}.pdf")

    res_up = bb_markup_update(
        str(annotated_pdf),
        out_pdf,
        page_number=1,
        markup_id="DOES_NOT_EXIST_XYZ",
        updates={"comment": "test"},
    )
    assert res_up["status"] == "error"
    assert res_up["error"]["code"] == "INVALID_PARAMETER"

    res_del = bb_markup_delete(
        str(annotated_pdf),
        out_pdf,
        page_number=1,
        markup_id="DOES_NOT_EXIST_XYZ",
    )
    assert res_del["status"] == "error"
    assert res_del["error"]["code"] == "INVALID_PARAMETER"


def test_tier3_fault_out_of_range_page_number(sample_pdf: Path) -> None:
    """T3-05: Page number 99 on a 3-page document returns PAGE_OUT_OF_RANGE."""
    out_pdf = str(SCRATCH_DIR / f"out_fault_{uuid.uuid4().hex}.pdf")

    res = bb_markup_add(
        str(sample_pdf),
        out_pdf,
        page_number=99,
        markup_type="FreeText",
    )
    assert res["status"] == "error"
    assert res["error"]["code"] == "PAGE_OUT_OF_RANGE"

    res_zero = bb_markup_add(
        str(sample_pdf),
        out_pdf,
        page_number=0,
        markup_type="FreeText",
    )
    assert res_zero["status"] == "error"
    assert res_zero["error"]["code"] == "PAGE_OUT_OF_RANGE"


def test_tier3_fault_missing_input_file() -> None:
    """T3-04: Nonexistent input file returns FILE_NOT_FOUND error envelope."""
    missing_path = str(SCRATCH_DIR / f"nonexistent_{uuid.uuid4().hex}.pdf")
    res = bb_markup_list(missing_path)
    assert res["status"] == "error"
    assert res["error"]["code"] == "FILE_NOT_FOUND"


# ============================================================================
# TIER 4: LIVE DUAL-ENGINE EXECUTION TESTS
# ============================================================================

def test_tier4_live_markup_add_and_list(sample_pdf: Path) -> None:
    """T4: Live dual-engine markup creation and round-trip list query."""
    out_pdf = str(SCRATCH_DIR / f"live_add_{uuid.uuid4().hex}.pdf")

    add_res = bb_markup_add(
        pdf_path=str(sample_pdf),
        output_path=out_pdf,
        page_number=1,
        markup_type="FreeText",
        x=100.0,
        y=500.0,
        width=200.0,
        height=40.0,
        subject="Structural Note",
        author="Test Author",
        comment="Live added verification markup",
        color="#0000FF",
    )
    assert add_res["status"] in ("success", "subscription_fallback")
    markup_id = add_res["data"]["markup_id"]
    assert markup_id.startswith("BB-MCP-")

    # Verify markup is listed
    list_res = bb_markup_list(out_pdf, page_range="1")
    assert list_res["status"] in ("success", "subscription_fallback")
    markups = list_res["data"]["markups"]
    assert any(m["id"] == markup_id for m in markups)

    matched = next(m for m in markups if m["id"] == markup_id)
    assert matched["subject"] == "Structural Note"
    assert matched["author"] == "Test Author"
    assert matched["comment"] == "Live added verification markup"
    assert matched["color"] == "#0000FF"


def test_tier4_live_markup_update_and_verify(annotated_pdf: Path) -> None:
    """T4: Live dual-engine markup update of properties and review status."""
    out_pdf = str(SCRATCH_DIR / f"live_upd_{uuid.uuid4().hex}.pdf")

    # Initial markup ID from annotated_pdf
    target_id = "BB-ANNOT-FREETEXT-001"

    upd_res = bb_markup_update(
        pdf_path=str(annotated_pdf),
        output_path=out_pdf,
        page_number=1,
        markup_id=target_id,
        updates={"comment": "Updated comment by engineer", "color": "#00FF00"},
        status="Accepted",
    )
    assert upd_res["status"] in ("success", "subscription_fallback")

    # Verify update via bb_markup_list
    list_res = bb_markup_list(out_pdf)
    markups = list_res["data"]["markups"]
    matched = next(m for m in markups if m["id"] == target_id)
    assert matched["comment"] == "Updated comment by engineer"
    assert matched["color"] == "#00FF00"
    assert matched["status"] == "Accepted"


def test_tier4_live_markup_delete_and_verify(annotated_pdf: Path) -> None:
    """T4: Live dual-engine markup deletion reduces annotation count."""
    out_pdf = str(SCRATCH_DIR / f"live_del_{uuid.uuid4().hex}.pdf")
    target_id = "BB-ANNOT-SQUARE-002"

    del_res = bb_markup_delete(
        pdf_path=str(annotated_pdf),
        output_path=out_pdf,
        page_number=1,
        markup_id=target_id,
    )
    assert del_res["status"] in ("success", "subscription_fallback")
    assert del_res["data"]["deleted"] is True

    # Verify it is gone
    list_res = bb_markup_list(out_pdf)
    markups = list_res["data"]["markups"]
    assert not any(m["id"] == target_id for m in markups)
    assert len(markups) == 1  # 2 originally, 1 remains


def test_tier4_live_markup_flatten_and_unflatten(annotated_pdf: Path) -> None:
    """T4: Live dual-engine markup flattening and recoverable unflattening."""
    flat_pdf = str(SCRATCH_DIR / f"live_flat_{uuid.uuid4().hex}.pdf")
    unflat_pdf = str(SCRATCH_DIR / f"live_unflat_{uuid.uuid4().hex}.pdf")

    # 1. Flatten
    flat_res = bb_markup_flatten(
        pdf_path=str(annotated_pdf),
        output_path=flat_pdf,
        action="flatten",
        recoverable=True,
    )
    assert flat_res["status"] in ("success", "subscription_fallback")
    assert flat_res["data"]["count"] == 2

    # Verify 0 markups remaining in flattened file
    list_flat = bb_markup_list(flat_pdf)
    assert list_flat["data"]["total_markups"] == 0

    # 2. Unflatten
    unflat_res = bb_markup_flatten(
        pdf_path=flat_pdf,
        output_path=unflat_pdf,
        action="unflatten",
    )
    assert unflat_res["status"] in ("success", "subscription_fallback")
    assert unflat_res["data"]["count"] == 2

    # Verify markups restored
    list_unflat = bb_markup_list(unflat_pdf)
    assert list_unflat["data"]["total_markups"] == 2


@requires_revu
def test_tier4_live_stamp_installed_approved(sample_pdf: Path) -> None:
    """T4: Live stamp placement using real Bluebeam Approved.pdf stamp."""
    out_pdf = str(SCRATCH_DIR / f"live_stamp_app_{uuid.uuid4().hex}.pdf")
    stamp_path = str(APPROVED_STAMP_PATH) if APPROVED_STAMP_PATH.exists() else "Approved.pdf"

    res = bb_pdf_stamp(
        pdf_path=str(sample_pdf),
        output_path=out_pdf,
        stamp_path_or_text=stamp_path,
        x=150.0,
        y=400.0,
        width=180.0,
        height=60.0,
        origin=0,
        opacity=0.9,
    )
    assert res["status"] in ("success", "subscription_fallback")

    # Verify stamp markup in output PDF
    list_res = bb_markup_list(out_pdf)
    markups = list_res["data"]["markups"]
    assert any("stamp" in m["type"].lower() or "APPROVED" in m["comment"].upper() for m in markups)


def test_tier4_live_stamp_custom_text(sample_pdf: Path) -> None:
    """T4: Live stamp placement using custom text stamp."""
    out_pdf = str(SCRATCH_DIR / f"live_stamp_text_{uuid.uuid4().hex}.pdf")
    custom_stamp = "CONFIDENTIAL - REVIEW ONLY"

    res = bb_pdf_stamp(
        pdf_path=str(sample_pdf),
        output_path=out_pdf,
        stamp_path_or_text=custom_stamp,
        x=100.0,
        y=350.0,
        width=250.0,
        height=50.0,
        origin=0,
    )
    assert res["status"] in ("success", "subscription_fallback")

    list_res = bb_markup_list(out_pdf)
    markups = list_res["data"]["markups"]
    assert any(custom_stamp in m["comment"] for m in markups)


def test_tier4_live_bax_export_and_reimport(annotated_pdf: Path, sample_pdf: Path) -> None:
    """T4: Live export of markups to .bax XML and re-import onto clean PDF."""
    bax_path = str(SCRATCH_DIR / f"live_exp_{uuid.uuid4().hex}.bax")
    imported_pdf = str(SCRATCH_DIR / f"live_imp_{uuid.uuid4().hex}.pdf")

    # 1. Export
    exp_res = bb_markup_export_bax(
        pdf_path=str(annotated_pdf),
        output_path=bax_path,
        format_type="bax",
    )
    assert exp_res["status"] in ("success", "subscription_fallback")
    assert exp_res["data"]["markup_count"] == 2
    assert Path(bax_path).exists()

    # 2. Re-import onto clean 3-page sample PDF (originally has 0 markups)
    imp_res = bb_markup_import_bax(
        pdf_path=str(sample_pdf),
        import_path=bax_path,
        output_path=imported_pdf,
    )
    assert imp_res["status"] in ("success", "subscription_fallback")
    assert imp_res["data"]["markups_imported"] == 2

    # Verify markups in target
    list_res = bb_markup_list(imported_pdf)
    assert list_res["data"]["total_markups"] == 2


def test_tier4_live_form_inspect_and_fill(form_pdf: Path) -> None:
    """T4: Live AcroForm inspect and fill actions."""
    # 1. Inspect
    insp_res = bb_form_inspect_and_fill(str(form_pdf), action="inspect")
    assert insp_res["status"] in ("success", "subscription_fallback")
    fields = insp_res["data"]["fields"]
    assert "project_name" in fields
    assert "contractor" in fields

    # 2. Fill
    out_form = str(SCRATCH_DIR / f"live_filled_{uuid.uuid4().hex}.pdf")
    fill_res = bb_form_inspect_and_fill(
        str(form_pdf),
        action="fill",
        field_values={"project_name": "Skyline Medical Center Phase II"},
        output_path=out_form,
    )
    assert fill_res["status"] in ("success", "subscription_fallback")

    # Inspect filled result
    insp_filled = bb_form_inspect_and_fill(out_form, action="inspect")
    assert insp_filled["data"]["fields"]["project_name"]["value"] == "Skyline Medical Center Phase II"


def test_tier4_live_color_and_optimize(sample_pdf: Path) -> None:
    """T4: Live optimization and PDF security encryption."""
    opt_out = str(SCRATCH_DIR / f"live_opt_{uuid.uuid4().hex}.pdf")
    sec_out = str(SCRATCH_DIR / f"live_sec_{uuid.uuid4().hex}.pdf")

    # 1. Reduce size
    opt_res = bb_pdf_color_and_optimize(
        pdf_path=str(sample_pdf),
        output_path=opt_out,
        operation="reduce_size",
    )
    assert opt_res["status"] in ("success", "subscription_fallback")
    assert Path(opt_out).exists()

    # 2. Set security
    sec_res = bb_pdf_color_and_optimize(
        pdf_path=str(sample_pdf),
        output_path=sec_out,
        operation="set_security",
        permission_password="MasterPassword99!",
        open_password="UserPassword99!",
        permission_flags=193,
    )
    assert sec_res["status"] in ("success", "subscription_fallback")

    # Verify encryption using pypdf
    sec_reader = pypdf.PdfReader(sec_out)
    assert sec_reader.is_encrypted
    assert sec_reader.decrypt("UserPassword99!") == 1


def test_tier4_fastmcp_registration() -> None:
    """T4: Verify register_markup_tools properly registers all 10 tools on FastMCP."""
    mcp = FastMCP("Bluebeam Revu Test Server")
    register_markup_tools(mcp)

    # FastMCP stores tools in _tool_manager._tools or list_tools()
    tools = mcp._tool_manager.list_tools()
    tool_names = [t.name for t in tools]

    expected_tools = [
        "bb_markup_list",
        "bb_markup_add",
        "bb_markup_update",
        "bb_markup_delete",
        "bb_markup_flatten",
        "bb_pdf_stamp",
        "bb_markup_export_bax",
        "bb_markup_import_bax",
        "bb_form_inspect_and_fill",
        "bb_pdf_color_and_optimize",
    ]
    for exp in expected_tools:
        assert exp in tool_names, f"Tool {exp} missing from FastMCP registration"
