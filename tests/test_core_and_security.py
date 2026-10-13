"""Comprehensive adversarial security, dual-engine regression, and data preservation tests.

Covers:
- C-01: Multi-command line rejection, privileged command restrictions, and forbidden root blocking in bb_script_generate_and_run.
- C-02: Trailing space/dot rejection and extended path normalization in validate_path.
- C-03: Path traversal sanitization in bb_pdf_split prefixes.
- C-04 & H-12: Markup flattening flag bitmask preservation, visual content stream rendering, and recoverable unflatten round-trips.
- C-05: Native color process rewriting content streams and annotation colors to grayscale.
- C-06: Set security permission bitmask /P=2052 enforcement and password secret redaction.
- C-07: Single-document writer preservation of AcroForm, Outlines, PageLabels, OCProperties, and Info metadata.
- C-08: In-place writes succeeding without WinError 32 file-lock sharing violations.
- H-01 & H-02: Dual-engine execution routing: exit_code=0 bypasses native_fn; missing binary falls back to native_fn.
- H-04 & H-18: Subprocess decoding of non-cp1252 bytes and error envelope exception classification mappings.
- H-21: Process tree termination killing grandchildren holding inherited stdio pipes within timeout.

Citations:
- docs/REMEDIATION_PLAN.md Section 2 (Findings C-01 to C-08, H-01 to H-24)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Test Tiers)
- docs/citations/01_script_reference.md
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from unittest import mock

import pypdf
from pypdf.generic import ArrayObject, DecodedStreamObject, DictionaryObject, NameObject
import pytest

from bluebeam_mcp.engine import (
    EngineUnavailableError,
    ScriptEngineReceipt,
    execute_dual_engine,
    format_error_envelope,
    run_subprocess_safely,
)
from bluebeam_mcp.script_builder import parse_and_validate_bcs_line
from bluebeam_mcp.security import (
    CorruptStreamError,
    EmptyFileError,
    EncryptedPDFError,
    SecurityViolationError,
    SubprocessTimeoutError,
    XMLDefuseError,
    validate_path,
)
from bluebeam_mcp.tools.document_tools import (
    bb_pdf_create_blank,
    bb_pdf_delete_pages,
    bb_pdf_extract_pages,
    bb_pdf_header_footer,
    bb_pdf_insert_pages,
    bb_pdf_rotate_pages,
    bb_pdf_split,
)
from bluebeam_mcp.tools.environment_tools import bb_script_generate_and_run
from bluebeam_mcp.tools.markup_tools import (
    bb_form_inspect_and_fill,
    bb_markup_add,
    bb_markup_delete,
    bb_markup_flatten,
    bb_markup_update,
    bb_pdf_color_and_optimize,
)
from tests.fixture_factory import (
    create_annotated_pdf,
    create_form_pdf,
    create_sample_pdf,
)

TEST_TMP_DIR = Path(__file__).resolve().parent / "tmp"


@pytest.fixture(autouse=True)
def ensure_tmp_dir() -> None:
    """Ensure test scratch directory exists in tests/tmp."""
    TEST_TMP_DIR.mkdir(parents=True, exist_ok=True)


def test_c01_script_generate_and_run_restrictions() -> None:
    """C-01: Verify multi-command rejection, privileged command blocking, and forbidden root denial."""
    # 1. Multi-command lines are rejected
    multi_line = 'PageCount() DeleteFile("C:\\Windows\\x.txt")'
    res_multi = bb_script_generate_and_run(script_text=multi_line, execution_mode="script_only")
    assert res_multi["status"] == "error"
    assert res_multi["error"]["code"] == "SECURITY_VIOLATION"

    # 2. Privileged commands are blocked by default server-side policy
    privileged_cmds = [
        "Script",
        "Batch",
        "ExecuteJavaScript",
        "Email",
        "SaveAs",
        "DeleteFile",
    ]
    for p_cmd in privileged_cmds:
        res_cmd = bb_script_generate_and_run(
            commands=[{"name": p_cmd, "args": ["arg1"]}],
            execution_mode="script_only",
        )
        assert res_cmd["status"] == "error", f"Command {p_cmd} should have been blocked"
        assert res_cmd["error"]["code"] == "SECURITY_VIOLATION"

        text_payload = f'{p_cmd}("arg1")'
        res_text = bb_script_generate_and_run(
            script_text=text_payload,
            execution_mode="script_only",
        )
        assert res_text["status"] == "error", f"Script text {text_payload} should have been blocked"
        assert res_text["error"]["code"] == "SECURITY_VIOLATION"

    # 3. Forbidden roots are blocked across path syntax variations
    forbidden_payloads = [
        'Open("E:/ProtectedVault/x.pdf")',
        'Open("E:\\.\\ProtectedVault\\x.pdf")',
        'Open("E:\\DAEDAL~1\\x.pdf")',
    ]
    for f_payload in forbidden_payloads:
        res_forb = bb_script_generate_and_run(
            script_text=f_payload,
            execution_mode="script_only",
        )
        assert res_forb["status"] == "error", f"Forbidden payload {f_payload} should have been blocked"
        assert res_forb["error"]["code"] == "SECURITY_VIOLATION"


def test_c02_trailing_space_dot_and_extended_paths() -> None:
    """C-02: Verify trailing spaces or dots per path segment raise SecurityViolationError."""
    # Trailing space in directory component
    with pytest.raises(SecurityViolationError) as exc_info1:
        validate_path(r"E:\ProtectedVault \new.pdf", mode="write", must_exist=False)
    assert exc_info1.value.error_code == "SECURITY_VIOLATION"

    # Trailing space in Windows system path
    with pytest.raises(SecurityViolationError) as exc_info2:
        validate_path(r"C:\Windows \a.pdf", mode="write", must_exist=False)
    assert exc_info2.value.error_code == "SECURITY_VIOLATION"

    # Trailing dot in directory component
    with pytest.raises(SecurityViolationError) as exc_info3:
        validate_path(r"C:\Windows.\a.pdf", mode="write", must_exist=False)
    assert exc_info3.value.error_code == "SECURITY_VIOLATION"


def test_c03_pdf_split_prefix_traversal_blocked() -> None:
    """C-03: Verify bb_pdf_split sanitizes prefix and blocks directory traversal."""
    src_pdf = TEST_TMP_DIR / "c03_split_src.pdf"
    out_dir = TEST_TMP_DIR / "c03_split_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    create_sample_pdf(src_pdf, num_pages=3)

    try:
        # Relative traversal prefix
        res_rel = bb_pdf_split(
            pdf_path=str(src_pdf),
            output_dir=str(out_dir),
            page_range="1",
            prefix=r"..\ESCAPED_",
            execution_mode="native_only",
        )
        assert res_rel["status"] == "error"
        assert res_rel["error"]["code"] == "SECURITY_VIOLATION"
        assert not (TEST_TMP_DIR / "ESCAPED_1.pdf").exists()

        # Absolute target prefix
        res_abs = bb_pdf_split(
            pdf_path=str(src_pdf),
            output_dir=str(out_dir),
            page_range="1",
            prefix=r"C:\Users\Public\x_",
            execution_mode="native_only",
        )
        assert res_abs["status"] == "error"
        assert res_abs["error"]["code"] == "SECURITY_VIOLATION"
    finally:
        if src_pdf.exists():
            src_pdf.unlink()
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


def test_c04_h12_markup_flatten_flags_and_lossless_recovery() -> None:
    """C-04 and H-12: Verify flags bitmask filtering, visual content rendering, and recovery round-trip."""
    src_pdf = TEST_TMP_DIR / "c04_flatten_src.pdf"
    create_annotated_pdf(src_pdf)

    out_flags = TEST_TMP_DIR / "c04_flatten_flags.pdf"
    out_flat = TEST_TMP_DIR / "c04_flatten_default.pdf"
    out_partial = TEST_TMP_DIR / "c04_unflatten_partial.pdf"
    out_full = TEST_TMP_DIR / "c04_unflatten_full.pdf"

    try:
        # 1. flags=['image'] preserves FreeText and Square annotations
        r_flags = bb_markup_flatten(
            pdf_path=str(src_pdf),
            output_path=str(out_flags),
            flags=["image"],
            recoverable=False,
            execution_mode="native_only",
        )
        assert r_flags["status"] == "success"
        rd_flags = pypdf.PdfReader(str(out_flags))
        annots_flags = sum(len(p.get("/Annots") or []) for p in rd_flags.pages)
        assert annots_flags == 2, "flags=['image'] should preserve FreeText and Square annotations"

        # 2. Default flags flattens markups and renders appearance into /Contents
        r_flat = bb_markup_flatten(
            pdf_path=str(src_pdf),
            output_path=str(out_flat),
            recoverable=True,
            execution_mode="native_only",
        )
        assert r_flat["status"] == "success"
        rd_flat = pypdf.PdfReader(str(out_flat))
        annots_flat = sum(len(p.get("/Annots") or []) for p in rd_flat.pages)
        assert annots_flat == 0, "Default flags should remove markups from /Annots"

        rd_src = pypdf.PdfReader(str(src_pdf))
        src_stream_len = len(rd_src.pages[0].get_contents().get_data())
        flat_stream_len = len(rd_flat.pages[0].get_contents().get_data())
        assert flat_stream_len > src_stream_len, "Flattening must render appearance into page /Contents stream"

        # 3. Partial unflatten on page 1 restores page 1 markups
        r_part = bb_markup_flatten(
            pdf_path=str(out_flat),
            output_path=str(out_partial),
            unflatten=True,
            page_range="1",
            execution_mode="native_only",
        )
        assert r_part["status"] == "success"
        rd_part = pypdf.PdfReader(str(out_partial))
        part_annots = len(rd_part.pages[0].get("/Annots") or [])
        assert part_annots == 2, "Page 1 markups must be restored"

        # 4. Full unflatten restores markups and appearance keys
        r_full = bb_markup_flatten(
            pdf_path=str(out_flat),
            output_path=str(out_full),
            unflatten=True,
            page_range="-1",
            execution_mode="native_only",
        )
        assert r_full["status"] == "success"
        rd_full = pypdf.PdfReader(str(out_full))
        full_annots = len(rd_full.pages[0].get("/Annots") or [])
        assert full_annots == 2
        for annot_ref in rd_full.pages[0]["/Annots"]:
            annot_obj = annot_ref.get_object()
            assert "/Rect" in annot_obj
    finally:
        for f in (src_pdf, out_flags, out_flat, out_partial, out_full):
            if f.exists():
                f.unlink()


def test_c05_color_and_optimize_grayscale() -> None:
    """C-05: Verify color_process modifies /Contents streams and converts annotation colors to grayscale."""
    src_pdf = TEST_TMP_DIR / "c05_color_src.pdf"
    create_annotated_pdf(src_pdf)
    out_pdf = TEST_TMP_DIR / "c05_color_out.pdf"

    try:
        res = bb_pdf_color_and_optimize(
            pdf_path=str(src_pdf),
            output_path=str(out_pdf),
            operation="color_process",
            color_scale="grayscale",
            execution_mode="native_only",
        )
        assert res["status"] == "success"

        rd_src = pypdf.PdfReader(str(src_pdf))
        rd_out = pypdf.PdfReader(str(out_pdf))

        # Verify page content stream is modified
        src_content = rd_src.pages[0].get_contents().get_data()
        out_content = rd_out.pages[0].get_contents().get_data()
        assert src_content != out_content, "Content stream must be modified by color_process"

        # Verify annotation colors converted to grayscale (R == G == B)
        annots = rd_out.pages[0].get("/Annots") or []
        assert len(annots) > 0
        for annot_ref in annots:
            obj = annot_ref.get_object()
            c_val = obj.get("/C")
            if c_val is not None:
                components = [float(v) for v in c_val]
                if len(components) == 3:
                    assert components[0] == pytest.approx(components[1], abs=0.01)
                    assert components[1] == pytest.approx(components[2], abs=0.01)
    finally:
        for f in (src_pdf, out_pdf):
            if f.exists():
                f.unlink()


def test_c06_set_security_permission_mask_and_redaction() -> None:
    """C-06: Verify set_security sets /P permission bitmask (2052) and redacts secrets from envelope."""
    src_pdf = TEST_TMP_DIR / "c06_sec_src.pdf"
    create_sample_pdf(src_pdf, num_pages=2)
    out_pdf = TEST_TMP_DIR / "c06_sec_out.pdf"

    try:
        res = bb_pdf_color_and_optimize(
            pdf_path=str(src_pdf),
            output_path=str(out_pdf),
            operation="set_security",
            permission_password="OwnerSecret123",
            open_password="UserSecret456",
            permission_flags=["print"],
            execution_mode="native_only",
        )
        assert res["status"] == "success"

        # Secret redaction verification
        env_json = json.dumps(res)
        assert "OwnerSecret123" not in env_json, "Owner secret password leaked in returned envelope"
        assert "UserSecret456" not in env_json, "User secret password leaked in returned envelope"

        # Permission bitmask verification (ISO 32000-1 Table 22 reserved bits 7,8,13-32 set + bits 3 & 12)
        rd = pypdf.PdfReader(str(out_pdf))
        rd.decrypt("OwnerSecret123")
        encrypt_dict = rd.trailer["/Encrypt"].get_object()
        p_value = int(encrypt_dict.get("/P", 0))
        assert p_value in (-1852, 4294965444), f"Expected /P=-1852 (unsigned 4294965444) for print permission, got {p_value}"
        assert (p_value & 0xFFFFF0C0) == 0xFFFFF0C0, "ISO 32000-1 reserved bits 7, 8, and 13-32 must be 1"
    finally:
        for f in (src_pdf, out_pdf):
            if f.exists():
                f.unlink()


def test_c07_single_document_writers_preserve_catalog_structures() -> None:
    """C-07: Verify single-document writers preserve AcroForm, Outlines, PageLabels, OCProperties, and Info."""
    src_pdf = TEST_TMP_DIR / "c07_catalog_src.pdf"

    # Construct rich fixture containing all five structures
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({
        "/Title": "Structural Spec",
        "/Author": "Lead Engineer",
        "/Subject": "Foundation Design",
    })
    writer.add_outline_item("Chapter 1", 0)
    writer.set_page_label(0, 1, style="/D", prefix="Sheet-")

    acro = DictionaryObject({NameObject("/Fields"): ArrayObject([])})
    writer._root_object[NameObject("/AcroForm")] = acro

    ocg = DictionaryObject({NameObject("/OCGs"): ArrayObject([])})
    writer._root_object[NameObject("/OCProperties")] = ocg

    with open(src_pdf, "wb") as f:
        writer.write(f)

    def assert_catalog_intact(target_path: Path, op_name: str) -> None:
        reader = pypdf.PdfReader(str(target_path))
        root = reader.trailer["/Root"]
        assert "/AcroForm" in root, f"{op_name} dropped /AcroForm"
        assert "/OCProperties" in root, f"{op_name} dropped /OCProperties"
        assert "/PageLabels" in root, f"{op_name} dropped /PageLabels"
        assert len(reader.outline) > 0, f"{op_name} dropped /Outlines"
        assert reader.metadata is not None
        assert reader.metadata.title == "Structural Spec", f"{op_name} corrupted /Title metadata"
        assert reader.metadata.author == "Lead Engineer", f"{op_name} corrupted /Author metadata"

    rot_out = TEST_TMP_DIR / "c07_rot_out.pdf"
    hf_out = TEST_TMP_DIR / "c07_hf_out.pdf"
    add_out = TEST_TMP_DIR / "c07_add_out.pdf"
    up_out = TEST_TMP_DIR / "c07_up_out.pdf"
    del_out = TEST_TMP_DIR / "c07_del_out.pdf"

    try:
        # 1. bb_pdf_rotate_pages
        r_rot = bb_pdf_rotate_pages(
            pdf_path=str(src_pdf),
            rotation_degrees=90,
            output_path=str(rot_out),
            execution_mode="native_only",
        )
        assert r_rot["status"] == "success"
        assert_catalog_intact(rot_out, "bb_pdf_rotate_pages")

        # 2. bb_pdf_header_footer
        r_hf = bb_pdf_header_footer(
            pdf_path=str(src_pdf),
            output_path=str(hf_out),
            top_left="Header Text",
            execution_mode="native_only",
        )
        assert r_hf["status"] == "success"
        assert_catalog_intact(hf_out, "bb_pdf_header_footer")

        # 3. bb_markup_add
        r_add = bb_markup_add(
            pdf_path=str(src_pdf),
            output_path=str(add_out),
            page_number=1,
            markup_type="Square",
            x=50.0,
            y=50.0,
            width=100.0,
            height=100.0,
            execution_mode="native_only",
        )
        assert r_add["status"] == "success"
        assert_catalog_intact(add_out, "bb_markup_add")

        markup_id = r_add["data"]["markup_id"]

        # 4. bb_markup_update
        r_up = bb_markup_update(
            pdf_path=str(add_out),
            output_path=str(up_out),
            page_number=1,
            markup_id=markup_id,
            updates={"comment": "Verified"},
            execution_mode="native_only",
        )
        assert r_up["status"] == "success"
        assert_catalog_intact(up_out, "bb_markup_update")

        # 5. bb_markup_delete
        r_del = bb_markup_delete(
            pdf_path=str(up_out),
            output_path=str(del_out),
            page_number=1,
            markup_id=markup_id,
            execution_mode="native_only",
        )
        assert r_del["status"] == "success"
        assert_catalog_intact(del_out, "bb_markup_delete")
    finally:
        for f in (src_pdf, rot_out, hf_out, add_out, up_out, del_out):
            if f.exists():
                f.unlink()


def test_c08_in_place_writes_without_winerror_32() -> None:
    """C-08: Verify in-place writes (output_path == pdf_path) succeed without WinError 32."""
    p_rot = TEST_TMP_DIR / "c08_inplace_rot.pdf"
    bb_pdf_create_blank(output_path=str(p_rot), page_count=2, execution_mode="native_only")

    p_mk = TEST_TMP_DIR / "c08_inplace_mk.pdf"
    bb_pdf_create_blank(output_path=str(p_mk), page_count=2, execution_mode="native_only")

    p_form = TEST_TMP_DIR / "c08_inplace_form.pdf"
    create_form_pdf(p_form)

    try:
        # 1. Rotate in place
        r_rot = bb_pdf_rotate_pages(
            pdf_path=str(p_rot),
            rotation_degrees=90,
            output_path=str(p_rot),
            execution_mode="native_only",
        )
        assert r_rot["status"] == "success"
        assert p_rot.exists() and p_rot.stat().st_size > 0

        # 2. Markup add in place
        r_add = bb_markup_add(
            pdf_path=str(p_mk),
            output_path=str(p_mk),
            page_number=1,
            markup_type="Square",
            x=50.0,
            y=50.0,
            width=100.0,
            height=100.0,
            execution_mode="native_only",
        )
        assert r_add["status"] == "success"
        assert p_mk.exists() and p_mk.stat().st_size > 0

        markup_id = r_add["data"]["markup_id"]

        # 3. Markup update in place
        r_up = bb_markup_update(
            pdf_path=str(p_mk),
            output_path=str(p_mk),
            page_number=1,
            markup_id=markup_id,
            updates={"comment": "In-place updated"},
            execution_mode="native_only",
        )
        assert r_up["status"] == "success"
        assert p_mk.exists() and p_mk.stat().st_size > 0

        # 4. Form fill in place
        r_fill = bb_form_inspect_and_fill(
            pdf_path=str(p_form),
            output_path=str(p_form),
            action="fill",
            field_values={"project_name": "Project InPlace"},
            execution_mode="native_only",
        )
        assert r_fill["status"] == "success"
        assert p_form.exists() and p_form.stat().st_size > 0
    finally:
        for f in (p_rot, p_mk, p_form):
            if f.exists():
                f.unlink()


def test_h01_h02_dual_engine_exit_code_zero_and_missing_binary_fallback() -> None:
    """H-01 and H-02: Verify exit_code=0 does not call native_fn, and missing binary falls back to native_fn."""
    # 1. H-01: ScriptEngine exit_code == 0 does NOT execute native_fn
    receipt_success = ScriptEngineReceipt(
        exit_code=0,
        raw_exit_code=0,
        stdout="Success execution",
        stderr="",
        duration_seconds=0.2,
        bcs_script="PageCount()",
        engine_used="script_engine",
        entitlement_restricted=False,
    )
    native_mock = mock.MagicMock(return_value={"status": "success", "native": True})

    with mock.patch("bluebeam_mcp.engine.run_script_engine", return_value=receipt_success):
        res1 = execute_dual_engine(
            bcs_script="PageCount()",
            native_fn=native_mock,
            execution_mode="auto",
            tool_name="bb_pdf_info",
        )
        assert res1["status"] == "success"
        assert res1["execution_engine"] == "script_engine"
        assert not native_mock.called, "native_fn must NOT be called when ScriptEngine exits 0"

    # 2. H-02: Missing ScriptEngine binary in 'auto' mode falls back to native_fn
    native_fallback_mock = mock.MagicMock(return_value={"fallback_executed": True})

    with mock.patch("bluebeam_mcp.engine.run_script_engine", side_effect=FileNotFoundError("Missing binary")):
        res2 = execute_dual_engine(
            bcs_script="PageCount()",
            native_fn=native_fallback_mock,
            execution_mode="auto",
            tool_name="bb_pdf_info",
        )
        assert res2["status"] == "subscription_fallback"
        assert res2["execution_engine"] == "native_fallback"
        assert native_fallback_mock.called, "native_fn must be called when binary is unavailable in auto mode"


def test_h04_h18_subprocess_encoding_and_error_envelopes() -> None:
    """H-04 and H-18: Verify non-cp1252 byte handling and exception error code envelope mappings."""
    # 1. Non-cp1252 bytes (0x81, 0x9d) decoded without crash
    cmd = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(bytes([0x81, 0x9d]))",
    ]
    signed_code, raw_code, stdout, stderr, elapsed = run_subprocess_safely(
        cmd=cmd,
        timeout_seconds=5.0,
        cwd=TEST_TMP_DIR,
    )
    assert signed_code == 0
    assert len(stdout) == 2

    # 2. format_error_envelope exception mappings
    env_xml = format_error_envelope(XMLDefuseError("Entity forbidden"))
    assert env_xml["error"]["code"] == "XML_PARSE_ERROR"

    env_stream = format_error_envelope(CorruptStreamError("Corrupt raw stream"))
    assert env_stream["error"]["code"] == "CORRUPT_RAW_STREAM"

    env_empty = format_error_envelope(EmptyFileError("Empty file"))
    assert env_empty["error"]["code"] == "EMPTY_FILE"

    env_enc = format_error_envelope(EncryptedPDFError("Encrypted PDF requires password"))
    assert env_enc["error"]["code"] == "ENCRYPTED_PDF"


def test_h21_subprocess_grandchild_process_tree_kill() -> None:
    """H-21: Verify process tree termination kills grandchild processes holding stdout/stderr pipes."""
    grandchild_script = TEST_TMP_DIR / "h21_grandchild.py"
    grandchild_code = (
        "import subprocess, sys, time\n"
        "proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "time.sleep(30)\n"
    )
    grandchild_script.write_text(grandchild_code, encoding="utf-8")

    cmd = [sys.executable, str(grandchild_script)]
    t0 = time.time()
    try:
        with pytest.raises(SubprocessTimeoutError):
            run_subprocess_safely(cmd=cmd, timeout_seconds=1.0, cwd=TEST_TMP_DIR)
        elapsed = time.time() - t0
        assert elapsed < 4.0, f"Process termination took {elapsed}s, expected under 4.0s"
    finally:
        if grandchild_script.exists():
            grandchild_script.unlink()


def test_f01_server_side_privilege_gate_and_nested_script_validation() -> None:
    """F-01: Verify allow_privileged is not client-controllable and nested Script/Batch/Email/PrintToFile are validated."""
    with pytest.raises(TypeError):
        bb_script_generate_and_run(script_text="PageCount()", allow_privileged=True)  # type: ignore[call-arg]

    # When server-side allow_privileged=True, PrintToFile, Email, and nested Script are still path-validated
    with pytest.raises(SecurityViolationError):
        parse_and_validate_bcs_line('PrintToFile("C:\\Windows\\System32\\pwn.prn")', allow_privileged=True)

    with pytest.raises(SecurityViolationError):
        parse_and_validate_bcs_line(
            'Email("a@b.com", "sub", "body", "E:\\ProtectedVault\\secret.pdf")',
            allow_privileged=True,
        )

    nested_bcs = TEST_TMP_DIR / "f01_nested_evil.bcs"
    nested_bcs.write_text('DeleteFile("E:\\ProtectedVault\\secret.pdf")\n', encoding="utf-8")
    try:
        with pytest.raises(SecurityViolationError):
            parse_and_validate_bcs_line(f'Script("{nested_bcs}")', allow_privileged=True)
    finally:
        if nested_bcs.exists():
            nested_bcs.unlink()


def _build_four_page_form_pdf(path: Path) -> Path:
    """Build a 4-page PDF with 3 AcroForm fields on page 1, outlines, and PageLabels."""
    base_form = path.parent / f"_base_{path.name}"
    create_form_pdf(base_form)
    try:
        rd = pypdf.PdfReader(str(base_form))
        wr = pypdf.PdfWriter(clone_from=rd)
        for _ in range(3):
            wr.add_blank_page(width=612, height=792)
        wr.add_outline_item("Sec1", 0)
        wr.add_outline_item("Sec2", 1)
        wr.add_outline_item("Sec4", 3)
        wr.set_page_label(0, 1, style="/r")
        wr.set_page_label(2, 3, style="/D", prefix="P-")
        with open(path, "wb") as f:
            wr.write(f)
    finally:
        if base_form.exists():
            base_form.unlink()
    return path


def test_f02_extract_and_split_no_page_tree_bloat() -> None:
    """F-02: Verify bb_pdf_extract_pages and bb_pdf_split do not clone the entire page tree via AcroForm."""
    src_pdf = TEST_TMP_DIR / "f02_form_src.pdf"
    ext_out = TEST_TMP_DIR / "f02_extracted.pdf"
    split_dir = TEST_TMP_DIR / "f02_split"
    _build_four_page_form_pdf(src_pdf)
    try:
        res_ext = bb_pdf_extract_pages(
            pdf_path=str(src_pdf),
            output_path=str(ext_out),
            page_range="1",
            execution_mode="native_only",
        )
        assert res_ext["status"] == "success"
        rd_ext = pypdf.PdfReader(str(ext_out))
        assert len(rd_ext.pages) == 1
        assert len(rd_ext.get_fields() or {}) == 3

        res_split = bb_pdf_split(
            pdf_path=str(src_pdf),
            output_dir=str(split_dir),
            prefix="part_",
            execution_mode="native_only",
        )
        assert res_split["status"] == "success"
        part3_path = Path(res_split["data"]["split_files"][2])
        rd_part = pypdf.PdfReader(str(part3_path))
        assert len(rd_part.pages) == 1
        assert len(rd_part.get_fields() or {}) == 0
        assert "/AcroForm" not in rd_part.trailer["/Root"]
    finally:
        for f in (src_pdf, ext_out):
            if f.exists():
                f.unlink()
        if split_dir.exists():
            shutil.rmtree(split_dir, ignore_errors=True)


def test_f03_color_process_xobject_sc_and_inline_image() -> None:
    """F-03: Verify color_process converts sc/SC and Form XObjects while preserving inline image binary bytes."""
    src_pdf = TEST_TMP_DIR / "f03_color_src.pdf"
    out_pdf = TEST_TMP_DIR / "f03_color_out.pdf"

    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=200, height=200)
    form_xobj = DecodedStreamObject()
    form_xobj.set_data(b"q 1 0 0 rg 0 0 10 10 re f Q")
    form_xobj[NameObject("/Type")] = NameObject("/XObject")
    form_xobj[NameObject("/Subtype")] = NameObject("/Form")
    form_xobj[NameObject("/BBox")] = ArrayObject(
        [pypdf.generic.NumberObject(0), pypdf.generic.NumberObject(0), pypdf.generic.NumberObject(10), pypdf.generic.NumberObject(10)]
    )
    form_ref = writer._add_object(form_xobj)
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/XObject"): DictionaryObject({NameObject("/Fm1"): form_ref})}
    )
    content = DecodedStreamObject()
    content.set_data(
        b"q /DeviceRGB cs 1 0 0 sc 10 10 50 50 re f /Fm1 Do "
        b"BI /W 1 /H 1 /BPC 8 /CS /RGB ID 1 0 0 rg\nEI Q"
    )
    page[NameObject("/Contents")] = writer._add_object(content)
    with open(src_pdf, "wb") as f:
        writer.write(f)

    try:
        res = bb_pdf_color_and_optimize(
            pdf_path=str(src_pdf),
            output_path=str(out_pdf),
            operation="color_process",
            color_scale="grayscale",
            execution_mode="native_only",
        )
        assert res["status"] == "success"
        assert "fidelity_note" in res["data"]

        rd = pypdf.PdfReader(str(out_pdf))
        page_bytes = rd.pages[0].get_contents().get_data()
        assert b"1 0 0 sc" not in page_bytes
        assert b"1 0 0 rg" in page_bytes  # Inside inline image binary data, untouched
        fm_bytes = rd.pages[0]["/Resources"]["/XObject"]["/Fm1"].get_object().get_data()
        assert b"1 0 0 rg" not in fm_bytes
    finally:
        for f in (src_pdf, out_pdf):
            if f.exists():
                f.unlink()


def test_f04_page_labels_and_outlines_reindexed_on_insert_and_delete() -> None:
    """F-04: Verify PageLabels and Outlines are re-indexed on page deletion and insertion."""
    src_pdf = TEST_TMP_DIR / "f04_src.pdf"
    ins_src = TEST_TMP_DIR / "f04_ins_src.pdf"
    del_out = TEST_TMP_DIR / "f04_del_out.pdf"
    ins_out = TEST_TMP_DIR / "f04_ins_out.pdf"
    _build_four_page_form_pdf(src_pdf)
    create_sample_pdf(ins_src, num_pages=3)
    try:
        res_del = bb_pdf_delete_pages(
            pdf_path=str(src_pdf),
            output_path=str(del_out),
            page_range="2",
            execution_mode="native_only",
        )
        assert res_del["status"] == "success"
        rd_del = pypdf.PdfReader(str(del_out))
        assert list(rd_del.page_labels) == ["i", "P-1", "P-2"]
        assert len(rd_del.outline) == 2

        res_ins = bb_pdf_insert_pages(
            target_pdf_path=str(src_pdf),
            output_path=str(ins_out),
            insert_index=0,
            source_pdf_path=str(ins_src),
            execution_mode="native_only",
        )
        assert res_ins["status"] == "success"
        rd_ins = pypdf.PdfReader(str(ins_out))
        assert list(rd_ins.page_labels) == ["1", "2", "3", "i", "ii", "P-1", "P-2"]
    finally:
        for f in (src_pdf, ins_src, del_out, ins_out):
            if f.exists():
                f.unlink()


def test_f05_bcs_tokenizer_whitespace_single_quotes_and_trailing_comments() -> None:
    """F-05: Verify BCS parser accepts whitespace before '(' or ',', single-quoted strings, and trailing % comments."""
    sample_pdf = TEST_TMP_DIR / "f05_sample.pdf"
    create_sample_pdf(sample_pdf, num_pages=1)
    try:
        assert parse_and_validate_bcs_line("PageRotate (1, 90)") == "PageRotate(1, 90)"
        assert parse_and_validate_bcs_line("PageRotate(1 , 90)") == "PageRotate(1, 90)"
        assert parse_and_validate_bcs_line(f"Open('{sample_pdf}')") == f'Open("{sample_pdf.resolve()}")'
        assert parse_and_validate_bcs_line("PageCount() % inline comment") == "PageCount()"
    finally:
        if sample_pdf.exists():
            sample_pdf.unlink()


def test_f06_f08_f09_f10_reserved_bits_path_policy_popups_and_nonform_fill() -> None:
    """F-06, F-08, F-09, F-10: Verify path policy refinements, orphan popup removal on flatten, and non-form fill error."""
    # F-08: New leaf filename containing ~1 in an existing directory is permitted
    allowed_tilde = validate_path(TEST_TMP_DIR / "draft~1.pdf", mode="write", must_exist=False)
    assert allowed_tilde.name == "draft~1.pdf"

    # F-09: Orphan /Popup removed when parent markup is flattened
    annot_pdf = TEST_TMP_DIR / "f09_annot.pdf"
    flat_pdf = TEST_TMP_DIR / "f09_flat.pdf"
    nonform_pdf = TEST_TMP_DIR / "f10_nonform.pdf"
    nonform_out = TEST_TMP_DIR / "f10_nonform_out.pdf"
    create_annotated_pdf(annot_pdf)
    create_sample_pdf(nonform_pdf, num_pages=1)
    try:
        res_flat = bb_markup_flatten(
            pdf_path=str(annot_pdf),
            output_path=str(flat_pdf),
            flags=["text"],
            recoverable=False,
            execution_mode="native_only",
        )
        assert res_flat["status"] == "success"
        rd_flat = pypdf.PdfReader(str(flat_pdf))
        subtypes = [
            str(a.get_object().get("/Subtype"))
            for a in (rd_flat.pages[0].get("/Annots") or [])
        ]
        assert "/Popup" not in subtypes

        # F-10: Filling a PDF without /AcroForm returns INVALID_PARAMETER error
        res_fill = bb_form_inspect_and_fill(
            pdf_path=str(nonform_pdf),
            action="fill",
            output_path=str(nonform_out),
            field_values={"NonExistentField": "val"},
            execution_mode="native_only",
        )
        assert res_fill["status"] == "error"
        assert res_fill["error"]["code"] == "INVALID_PARAMETER"
    finally:
        for f in (annot_pdf, flat_pdf, nonform_pdf, nonform_out):
            if f.exists():
                f.unlink()

