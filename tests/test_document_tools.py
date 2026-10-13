"""Continuous Four-Tier Test Suite for Bluebeam Revu 21 document tools.

Covers all 12 document tools across:
- Tier 1: Unit and Schema Validation (0-based vs 1-based indexing, script_only verification, FastMCP registry)
- Tier 2: Adversarial Security Tests (BCS quote/pipe/newline injection, forbidden roots, UNC, extensions)
- Tier 3: Stability and Fault Injection (0-byte, corrupt header, truncated PDF, missing file, out-of-bounds page, delete all pages)
- Tier 4: Live Dual-Engine Integration (ScriptEngine exit code -4 receipt, native fallback verification, PDF output checks)

Citations:
- docs/citations/01_script_reference.md Section 1, Section 2
- docs/citations/02_binary_and_dotnet_surface.md Section 4.2, Section 5.2, Section 7.2, Section 7.4
- docs/ARCHITECTURE.md Section 3, Section 5, Section 6.1
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Four-Tier Continuous Test Matrix)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import uuid

import pypdf
import pytest

from bluebeam_mcp.security import (
    CorruptPDFError,
    PageRangeError,
    SecurityViolationError,
)
from bluebeam_mcp.tools.document_tools import (
    bb_pdf_bookmarks,
    bb_pdf_combine,
    bb_pdf_create_blank,
    bb_pdf_delete_pages,
    bb_pdf_extract_pages,
    bb_pdf_header_footer,
    bb_pdf_info,
    bb_pdf_insert_pages,
    bb_pdf_metadata,
    bb_pdf_page_labels,
    bb_pdf_rotate_pages,
    bb_pdf_split,
    register_document_tools,
)
from tests.fixture_factory import (
    create_corrupt_header_pdf,
    create_sample_pdf,
    create_truncated_pdf,
    create_zero_byte_pdf,
)


# ============================================================================
# Tier 1: Unit, Page Indexing, and Script-Only Validation Tests
# ============================================================================


class TestTier1DocumentToolsUnit:
    """Tier 1: Unit tests, 0-based vs 1-based indexing conventions, and script-only generation."""

    def test_page_indexing_conventions_in_script_generation(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """T1-01: Insertion uses 0-based indexing (0 is before page 1); extraction/deletion uses 1-based."""
        out_insert = scratch_dir / f"test_insert_{uuid.uuid4().hex}.pdf"
        res_insert = bb_pdf_insert_pages(
            target_pdf_path=str(sample_pdf),
            output_path=str(out_insert),
            insert_index=0,
            blank_page_count=1,
            execution_mode="script_only",
        )
        assert res_insert["status"] == "success"
        assert res_insert["execution_engine"] == "none"
        # 0-based insertion index 0 must be present in script
        assert "InsertBlankPages(0, 8.5, 11.0, 1" in res_insert["bcs_script"]

        out_extract = scratch_dir / f"test_extract_{uuid.uuid4().hex}.pdf"
        res_extract = bb_pdf_extract_pages(
            pdf_path=str(sample_pdf),
            page_range="1-2",
            output_path=str(out_extract),
            execution_mode="script_only",
        )
        assert res_extract["status"] == "success"
        # 1-based page range "1-2" must be present in script
        assert 'PageExtract("1-2"' in res_extract["bcs_script"]

    def test_script_only_mode_across_all_twelve_tools(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """Verify that script_only execution mode emits valid .bcs scripts for all 12 tools without disk writes."""
        uid = uuid.uuid4().hex

        # 1. bb_pdf_info
        r1 = bb_pdf_info(str(sample_pdf), execution_mode="script_only")
        assert r1["status"] == "success"
        assert r1["execution_engine"] == "none"
        assert "PageCount()" in r1["bcs_script"]
        assert "PageSize(1)" in r1["bcs_script"]

        # 2. bb_pdf_create_blank
        out2 = scratch_dir / f"blank_{uid}.pdf"
        r2 = bb_pdf_create_blank(str(out2), width_inches=8.5, height_inches=11.0, page_count=2, style=3, execution_mode="script_only")
        assert r2["status"] == "success"
        assert 'New(8.5, 11' in r2["bcs_script"] and '2, 3)' in r2["bcs_script"]
        assert not out2.exists()

        # 3. bb_pdf_combine
        out3 = scratch_dir / f"combine_{uid}.pdf"
        r3 = bb_pdf_combine([str(sample_pdf), str(sample_pdf)], str(out3), execution_mode="script_only")
        assert r3["status"] == "success"
        assert "Combine(" in r3["bcs_script"]
        assert not out3.exists()

        # 4. bb_pdf_insert_pages
        out4 = scratch_dir / f"insert_{uid}.pdf"
        r4 = bb_pdf_insert_pages(str(sample_pdf), str(out4), insert_index=1, blank_page_count=2, execution_mode="script_only")
        assert r4["status"] == "success"
        assert "InsertBlankPages(1, 8.5, 11.0, 2" in r4["bcs_script"]
        assert not out4.exists()

        # 5. bb_pdf_extract_pages
        out5 = scratch_dir / f"extract_{uid}.pdf"
        r5 = bb_pdf_extract_pages(str(sample_pdf), "1,3", str(out5), execution_mode="script_only")
        assert r5["status"] == "success"
        assert 'PageExtract("1,3"' in r5["bcs_script"]
        assert not out5.exists()

        # 6. bb_pdf_delete_pages
        out6 = scratch_dir / f"delete_{uid}.pdf"
        r6 = bb_pdf_delete_pages(str(sample_pdf), "2", str(out6), execution_mode="script_only")
        assert r6["status"] == "success"
        assert 'PageDelete("2")' in r6["bcs_script"]
        assert not out6.exists()

        # 7. bb_pdf_rotate_pages
        out7 = scratch_dir / f"rotate_{uid}.pdf"
        r7 = bb_pdf_rotate_pages(str(sample_pdf), 90, str(out7), page_range="1", execution_mode="script_only")
        assert r7["status"] == "success"
        assert 'PageRotate(90, true, true, "1")' in r7["bcs_script"]
        assert not out7.exists()

        # 8. bb_pdf_split
        out8_dir = scratch_dir / f"split_{uid}"
        r8 = bb_pdf_split(str(sample_pdf), str(out8_dir), page_range="-1", prefix="page_", execution_mode="script_only")
        assert r8["status"] == "success"
        assert 'SplitPages("-1"' in r8["bcs_script"]
        assert not out8_dir.exists()

        # 9. bb_pdf_metadata (get and set)
        r9_get = bb_pdf_metadata(str(sample_pdf), action="get", execution_mode="script_only")
        assert r9_get["status"] == "success"
        assert "FilePropertyList()" in r9_get["bcs_script"]

        out9 = scratch_dir / f"meta_{uid}.pdf"
        r9_set = bb_pdf_metadata(
            str(sample_pdf),
            action="set",
            properties={"Title": "Structural Review Plan"},
            output_path=str(out9),
            execution_mode="script_only",
        )
        assert r9_set["status"] == "success"
        assert 'FilePropertySet("Title", "Structural Review Plan")' in r9_set["bcs_script"]
        assert not out9.exists()

        # 10. bb_pdf_page_labels
        r10_get = bb_pdf_page_labels(str(sample_pdf), action="get", start_page=1, execution_mode="script_only")
        assert r10_get["status"] == "success"
        assert "PageLabelGet(1)" in r10_get["bcs_script"]

        out10 = scratch_dir / f"labels_{uid}.pdf"
        r10_set = bb_pdf_page_labels(
            str(sample_pdf),
            action="set",
            prefix="SHT-",
            start_page=100,
            output_path=str(out10),
            execution_mode="script_only",
        )
        assert r10_set["status"] == "success"
        assert 'PageLabelsSet("-1", "SHT-", 100)' in r10_set["bcs_script"]
        assert not out10.exists()

        # 11. bb_pdf_bookmarks
        r11_list = bb_pdf_bookmarks(str(sample_pdf), action="list", execution_mode="script_only")
        assert r11_list["status"] == "success"

        out11_exp = scratch_dir / f"bookmarks_{uid}.json"
        r11_exp = bb_pdf_bookmarks(
            str(sample_pdf),
            action="export",
            export_path=str(out11_exp),
            execution_mode="script_only",
        )
        assert r11_exp["status"] == "success"
        assert "BookmarksExport(" in r11_exp["bcs_script"]
        assert not out11_exp.exists()

        # 12. bb_pdf_header_footer
        out12 = scratch_dir / f"hf_{uid}.pdf"
        r12 = bb_pdf_header_footer(
            str(sample_pdf),
            output_path=str(out12),
            top_left="CONFIDENTIAL",
            bottom_center="Page <<1>> of <<n>>",
            execution_mode="script_only",
        )
        assert r12["status"] == "success"
        assert "HeaderAndFooter(" in r12["bcs_script"]
        assert not out12.exists()

    def test_fastmcp_registration_helper(self) -> None:
        """Verify register_document_tools registers all 12 functions on a FastMCP instance."""
        mock_mcp = MagicMock()
        mock_decorator = MagicMock()
        mock_mcp.tool.return_value = mock_decorator

        register_document_tools(mock_mcp)

        assert mock_mcp.tool.call_count == 12
        registered_funcs = [call[0][0].__name__ for call in mock_decorator.call_args_list]
        expected_tools = [
            "bb_pdf_info",
            "bb_pdf_create_blank",
            "bb_pdf_combine",
            "bb_pdf_insert_pages",
            "bb_pdf_extract_pages",
            "bb_pdf_delete_pages",
            "bb_pdf_rotate_pages",
            "bb_pdf_split",
            "bb_pdf_metadata",
            "bb_pdf_page_labels",
            "bb_pdf_bookmarks",
            "bb_pdf_header_footer",
        ]
        for tool in expected_tools:
            assert tool in registered_funcs


# ============================================================================
# Tier 2: Adversarial Security Tests
# ============================================================================


class TestTier2DocumentToolsSecurity:
    """Tier 2: Adversarial security verification against script injection, forbidden roots, and traversal."""

    def test_adversarial_quote_and_pipe_injection(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """T2-01, T2-02: BCS quote and pipe injection payloads are safely sanitized."""
        # Attempt quote breakout in header text
        out_pdf = scratch_dir / f"sec_quote_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_header_footer(
            pdf_path=str(sample_pdf),
            output_path=str(out_pdf),
            top_left='Header") DeleteFile("C:\\important.pdf") %',
            execution_mode="script_only",
        )
        assert res["status"] == "success"
        # Must be escaped with pipe quote |"
        assert '|") DeleteFile(' in res["bcs_script"]
        assert "DeleteFile" not in res["bcs_script"].split("Header")[0]

    def test_adversarial_newline_rejection(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """T2-03: Newlines in file paths are immediately rejected."""
        malicious_path = str(sample_pdf) + "\r\nDeleteFile('C:\\root.pdf')"
        res = bb_pdf_info(pdf_path=malicious_path)
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"

    def test_doc_protected_root_protected_root_denial(
        self,
        scratch_dir: Path,
    ) -> None:
        """T2-06: Operations targeting E:\\ProtectedVault are strictly denied."""
        protected_root_path = r"E:\ProtectedVault\vault\drawing.pdf"
        res = bb_pdf_info(pdf_path=protected_root_path)
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"

        out_pdf = scratch_dir / "out.pdf"
        res_combine = bb_pdf_combine([protected_root_path, str(out_pdf)], str(out_pdf))
        assert res_combine["status"] == "error"
        assert res_combine["error"]["code"] == "SECURITY_VIOLATION"

    def test_doc_protected_root_solidworks_corp_denial(
        self,
    ) -> None:
        """T2-07: Operations targeting C:\\Program Files\\SOLIDWORKS Corp are denied."""
        sw_path = r"C:\Program Files\SOLIDWORKS Corp\template.pdf"
        res = bb_pdf_info(pdf_path=sw_path)
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"

    def test_protected_system_root_write_denial(
        self,
        sample_pdf: Path,
    ) -> None:
        """T2-08: Write operations to C:\\Windows and C:\\Program Files\\Bluebeam Software are denied."""
        windows_out = r"C:\Windows\System32\malicious.pdf"
        res = bb_pdf_create_blank(output_path=windows_out)
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"

        bluebeam_out = r"C:\Program Files\Bluebeam Software\output.pdf"
        res_extract = bb_pdf_extract_pages(str(sample_pdf), page_range="1", output_path=bluebeam_out)
        assert res_extract["status"] == "error"
        assert res_extract["error"]["code"] == "SECURITY_VIOLATION"

    def test_doc_remote_unc_path_rejection(self) -> None:
        """T2-10: UNC network paths are strictly denied."""
        unc_path = r"\\192.168.1.100\share\drawing.pdf"
        res = bb_pdf_info(pdf_path=unc_path)
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"

    def test_doc_disallowed_extension_rejection(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """T2-11: Disallowed file extensions (.exe, .ps1, .bat) are blocked."""
        malicious_out = scratch_dir / "exploit.exe"
        res = bb_pdf_extract_pages(str(sample_pdf), page_range="1", output_path=str(malicious_out))
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"


# ============================================================================
# Tier 3: Stability and Fault Injection Tests
# ============================================================================


class TestTier3DocumentToolsFaultInjection:
    """Tier 3: Stability under malformed, zero-byte, missing, and corrupted files."""

    def test_doc_fault_zero_byte_pdf(
        self,
        scratch_dir: Path,
    ) -> None:
        """T3-01: Zero-byte files return deterministic error envelope."""
        zero_pdf = scratch_dir / f"zero_{uuid.uuid4().hex}.pdf"
        create_zero_byte_pdf(zero_pdf)

        res = bb_pdf_info(str(zero_pdf))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("EMPTY_FILE", "INVALID_PDF")

    def test_doc_fault_corrupt_pdf_header(
        self,
        scratch_dir: Path,
    ) -> None:
        """T3-02: Corrupt PDF header bytes return INVALID_PDF error code."""
        corrupt_pdf = scratch_dir / f"corrupt_hdr_{uuid.uuid4().hex}.pdf"
        create_corrupt_header_pdf(corrupt_pdf)

        res = bb_pdf_info(str(corrupt_pdf))
        assert res["status"] == "error"
        assert res["error"]["code"] == "INVALID_PDF"

    def test_fault_truncated_pdf(
        self,
        scratch_dir: Path,
    ) -> None:
        """T3-03: Truncated PDF with premature EOF returns INVALID_PDF error code."""
        trunc_pdf = scratch_dir / f"truncated_{uuid.uuid4().hex}.pdf"
        create_truncated_pdf(trunc_pdf)

        res = bb_pdf_info(str(trunc_pdf))
        assert res["status"] == "error"
        assert res["error"]["code"] == "INVALID_PDF"

    def test_doc_fault_missing_input_file(
        self,
        scratch_dir: Path,
    ) -> None:
        """T3-04: Non-existent input path returns FILE_NOT_FOUND error code."""
        missing_path = scratch_dir / f"does_not_exist_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_info(str(missing_path))
        assert res["status"] == "error"
        assert res["error"]["code"] == "FILE_NOT_FOUND"

    def test_doc_fault_out_of_bounds_page_index(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """T3-05: Page index 99 on a 3-page PDF returns PAGE_OUT_OF_RANGE error code."""
        out_pdf = scratch_dir / f"oob_{uuid.uuid4().hex}.pdf"

        # Out-of-bounds extract
        res_extract = bb_pdf_extract_pages(str(sample_pdf), page_range="99", output_path=str(out_pdf))
        assert res_extract["status"] == "error"
        assert res_extract["error"]["code"] == "PAGE_OUT_OF_RANGE"

        # Out-of-bounds rotate
        res_rotate = bb_pdf_rotate_pages(str(sample_pdf), rotation_degrees=90, output_path=str(out_pdf), page_range="99")
        assert res_rotate["status"] == "error"
        assert res_rotate["error"]["code"] == "PAGE_OUT_OF_RANGE"

        # Out-of-bounds insertion
        res_insert = bb_pdf_insert_pages(str(sample_pdf), output_path=str(out_pdf), insert_index=99)
        assert res_insert["status"] == "error"
        assert res_insert["error"]["code"] == "PAGE_OUT_OF_RANGE"

    def test_fault_delete_all_pages_blocked(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """T3-06: Attempting to delete all pages from a document returns PAGE_OUT_OF_RANGE error code."""
        out_pdf = scratch_dir / f"del_all_{uuid.uuid4().hex}.pdf"

        # Page range "-1" (all pages)
        res_all = bb_pdf_delete_pages(str(sample_pdf), page_range="-1", output_path=str(out_pdf))
        assert res_all["status"] == "error"
        assert res_all["error"]["code"] == "PAGE_OUT_OF_RANGE"

        # Explicit range "1-3" on 3-page document
        res_explicit = bb_pdf_delete_pages(str(sample_pdf), page_range="1-3", output_path=str(out_pdf))
        assert res_explicit["status"] == "error"
        assert res_explicit["error"]["code"] == "PAGE_OUT_OF_RANGE"

    def test_fault_invalid_parameters_return_error_envelope(
        self,
        sample_pdf: Path,
        scratch_dir: Path,
    ) -> None:
        """Verify invalid parameter values produce structured error envelopes."""
        out_pdf = scratch_dir / f"param_err_{uuid.uuid4().hex}.pdf"

        # Invalid blank page dimensions
        r1 = bb_pdf_create_blank(str(out_pdf), width_inches=-5.0)
        assert r1["status"] == "error"
        assert r1["error"]["code"] == "INVALID_PARAMETER"

        # Invalid rotation angle (not multiple of 90)
        r2 = bb_pdf_rotate_pages(str(sample_pdf), rotation_degrees=45, output_path=str(out_pdf))
        assert r2["status"] == "error"
        assert r2["error"]["code"] == "INVALID_PARAMETER"

        # Invalid metadata action
        r3 = bb_pdf_metadata(str(sample_pdf), action="unsupported_action")
        assert r3["status"] == "error"
        assert r3["error"]["code"] == "INVALID_PARAMETER"


# ============================================================================
# Tier 4: Live Dual-Engine Execution & Artifact Verification
# ============================================================================


class TestTier4DocumentToolsLiveDualEngine:
    """Tier 4: Live execution verifying ScriptEngine.exe exit code -4 receipt and native PDF fallback."""

    def test_live_bb_pdf_info(self, sample_pdf: Path) -> None:
        """Verify live info inspection returns page count and dimensions."""
        res = bb_pdf_info(str(sample_pdf), execution_mode="auto")
        assert res["status"] in ("subscription_fallback", "success")
        assert res["execution_engine"] in ("native_fallback", "script_engine")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert res["data"]["page_count"] == 3
        assert len(res["data"]["pages"]) == 3
        assert res["data"]["pages"][0]["width"] > 0
        assert res["data"]["pages"][0]["height"] > 0

    def test_live_bb_pdf_create_blank(self, scratch_dir: Path) -> None:
        """Verify live create_blank produces valid PDF with requested style and pages."""
        out_pdf = scratch_dir / f"live_blank_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_create_blank(
            output_path=str(out_pdf),
            width_inches=8.5,
            height_inches=11.0,
            page_count=2,
            style=3,  # 1/4" grid
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert len(reader.pages) == 2
        assert abs(float(reader.pages[0].mediabox.width) - 612.0) < 1.0
        assert abs(float(reader.pages[0].mediabox.height) - 792.0) < 1.0

    def test_live_bb_pdf_combine(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live combine merges documents into unified PDF."""
        out_pdf = scratch_dir / f"live_combined_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_combine(
            input_paths=[str(sample_pdf), str(sample_pdf)],
            output_path=str(out_pdf),
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert len(reader.pages) == 6

    def test_live_bb_pdf_insert_pages(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live insert_pages inserts blank pages at 0-based index."""
        out_pdf = scratch_dir / f"live_insert_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_insert_pages(
            target_pdf_path=str(sample_pdf),
            output_path=str(out_pdf),
            insert_index=1,
            blank_page_count=2,
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert len(reader.pages) == 5

    def test_live_bb_pdf_extract_pages(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live extract_pages produces PDF with selected pages."""
        out_pdf = scratch_dir / f"live_extract_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_extract_pages(
            pdf_path=str(sample_pdf),
            page_range="1,3",
            output_path=str(out_pdf),
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert len(reader.pages) == 2

    def test_live_bb_pdf_delete_pages(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live delete_pages deletes target page and preserves others."""
        out_pdf = scratch_dir / f"live_delete_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_delete_pages(
            pdf_path=str(sample_pdf),
            page_range="2",
            output_path=str(out_pdf),
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert len(reader.pages) == 2

    def test_live_bb_pdf_rotate_pages(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live rotate_pages applies rotation to specified page."""
        out_pdf = scratch_dir / f"live_rotate_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_rotate_pages(
            pdf_path=str(sample_pdf),
            rotation_degrees=90,
            output_path=str(out_pdf),
            page_range="1",
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert reader.pages[0].rotation == 90
        assert reader.pages[1].rotation == 0

    def test_live_bb_pdf_split(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live split splits multi-page PDF into single-page documents."""
        split_dir = scratch_dir / f"live_split_{uuid.uuid4().hex}"
        res = bb_pdf_split(
            pdf_path=str(sample_pdf),
            output_dir=str(split_dir),
            page_range="-1",
            prefix="dwg_",
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert split_dir.exists()

        created_files = sorted(split_dir.glob("dwg_*.pdf"))
        assert len(created_files) == 3
        for f in created_files:
            r = pypdf.PdfReader(str(f))
            assert len(r.pages) == 1

    def test_live_bb_pdf_metadata(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live metadata set and get round trip."""
        out_pdf = scratch_dir / f"live_meta_{uuid.uuid4().hex}.pdf"
        res_set = bb_pdf_metadata(
            pdf_path=str(sample_pdf),
            action="set",
            properties={"Title": "Structural Review Plan", "Author": "Test Author"},
            output_path=str(out_pdf),
            execution_mode="auto",
        )
        assert res_set["status"] in ("subscription_fallback", "success")
        assert res_set["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert reader.metadata is not None
        assert reader.metadata.title == "Structural Review Plan"
        assert reader.metadata.author == "Test Author"

        res_get = bb_pdf_metadata(str(out_pdf), action="get", execution_mode="auto")
        assert res_get["data"]["properties"]["Title"] == "Structural Review Plan"

    def test_live_bb_pdf_page_labels(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live page_labels set and get round trip."""
        out_pdf = scratch_dir / f"live_labels_{uuid.uuid4().hex}.pdf"
        res_set = bb_pdf_page_labels(
            pdf_path=str(sample_pdf),
            action="set",
            prefix="SHT-",
            start_page=101,
            output_path=str(out_pdf),
            execution_mode="auto",
        )
        assert res_set["status"] in ("subscription_fallback", "success")
        assert res_set["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert hasattr(reader, "page_labels")
        labels = list(reader.page_labels)
        assert labels == ["SHT-101", "SHT-102", "SHT-103"]

    def test_live_bb_pdf_bookmarks(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live bookmarks import and export round trip."""
        out_pdf = scratch_dir / f"live_bm_{uuid.uuid4().hex}.pdf"
        bms = [
            {"title": "General Notes", "page": 1},
            {"title": "Foundation Plan", "page": 2},
            {"title": "Section Details", "page": 3},
        ]
        res_set = bb_pdf_bookmarks(
            pdf_path=str(sample_pdf),
            action="set",
            bookmarks=bms,
            output_path=str(out_pdf),
            execution_mode="auto",
        )
        assert res_set["status"] in ("subscription_fallback", "success")
        assert res_set["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        # Read back bookmarks
        res_list = bb_pdf_bookmarks(str(out_pdf), action="list", execution_mode="auto")
        assert len(res_list["data"]["bookmarks"]) == 3
        assert res_list["data"]["bookmarks"][0]["title"] == "General Notes"
        assert res_list["data"]["bookmarks"][1]["title"] == "Foundation Plan"

        # Export to JSON
        exp_json = scratch_dir / f"bm_export_{uuid.uuid4().hex}.json"
        res_exp = bb_pdf_bookmarks(str(out_pdf), action="export", export_path=str(exp_json), execution_mode="auto")
        assert res_exp["status"] in ("subscription_fallback", "success")
        assert exp_json.exists()
        loaded = json.loads(exp_json.read_text(encoding="utf-8"))
        assert len(loaded) == 3

    def test_live_bb_pdf_header_footer(self, sample_pdf: Path, scratch_dir: Path) -> None:
        """Verify live header_footer applies substitution codes to document."""
        out_pdf = scratch_dir / f"live_hf_{uuid.uuid4().hex}.pdf"
        res = bb_pdf_header_footer(
            pdf_path=str(sample_pdf),
            output_path=str(out_pdf),
            top_left="CIVIL ENGINEERING WING",
            top_right="Page <<1>> of <<n>>",
            bottom_center="Bates <<1>>",
            bates_digits=5,
            bates_start=1001,
            execution_mode="auto",
        )
        assert res["status"] in ("subscription_fallback", "success")
        assert res["script_engine_receipt"]["exit_code"] in (-4, 0)
        assert out_pdf.exists()

        reader = pypdf.PdfReader(str(out_pdf))
        assert len(reader.pages) == 3
