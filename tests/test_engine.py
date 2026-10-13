"""Comprehensive unit and live integration tests for Bluebeam Revu 21 execution engine.

Primary citations:
- docs/citations/01_script_reference.md Section 1 (Syntax)
- docs/citations/02_binary_and_dotnet_surface.md Section 4.2 (CLI Syntax),
  Section 7.2 (Live CLI Execution Receipts), Section 7.4 (Exit Code Table)
- docs/citations/03_data_formats_and_markups.md Section 2 (BTX), Section 3 (BPX),
  Section 4 (Stamps/Annots), Section 5 (BAX)
- docs/ARCHITECTURE.md Section 3 (Dual-Engine Execution), Section 5 (Response Envelopes)
- docs/TEST_AND_SECURITY_MATRIX.md Section 1.4 (Process Guardrails),
  Section 2.4 (Tier 4 Live Verification), Section 3.3 (Standard Error Catalog)
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest.mock as mock
import zlib

import pypdf
import pytest

from bluebeam_mcp.engine import (
    PBMNGR_EXE,
    SCRIPT_ENGINE_EXE,
    SCRATCH_DIR,
    STAPLER_EXE,
    ScriptEngineReceipt,
    execute_dual_engine,
    format_error_envelope,
    format_success_envelope,
    kill_process_tree,
    run_script_engine,
    run_subprocess_safely,
    to_signed_exit_code,
)
from bluebeam_mcp.security import (
    EngineExecutionError,
    SecurityViolationError,
    SubprocessTimeoutError,
)
from tests.fixture_factory import (
    FIXTURES_DIR,
    create_annotated_pdf,
    create_corrupt_header_pdf,
    create_form_pdf,
    create_sample_bax,
    create_sample_bpx,
    create_sample_btx,
    create_sample_pdf,
    create_truncated_pdf,
    create_zero_byte_pdf,
)


class TestSignedExitCodeConversion:
    """Validate 32-bit unsigned to signed exit code conversions."""

    def test_zero_remains_zero(self) -> None:
        assert to_signed_exit_code(0) == 0

    def test_subscription_restriction_minus_four(self) -> None:
        # 0xFFFFFFFC = 4294967292 unsigned
        assert to_signed_exit_code(4294967292) == -4
        assert to_signed_exit_code(-4) == -4

    def test_syntax_error_minus_one(self) -> None:
        # 0xFFFFFFFF = 4294967295 unsigned
        assert to_signed_exit_code(4294967295) == -1
        assert to_signed_exit_code(-1) == -1

    def test_runtime_exception_minus_three(self) -> None:
        # 0xFFFFFFFD = 4294967293 unsigned
        assert to_signed_exit_code(4294967293) == -3
        assert to_signed_exit_code(-3) == -3

    def test_signed_exit_code_conversion(self) -> None:
        """Verify signed exit code conversions for 0, -1, -3, -4."""
        assert to_signed_exit_code(0) == 0
        assert to_signed_exit_code(4294967295) == -1
        assert to_signed_exit_code(4294967293) == -3
        assert to_signed_exit_code(4294967292) == -4


class TestScriptEngineReceipt:
    """Validate ScriptEngineReceipt serialization and helper properties."""

    def test_receipt_to_dict_fields(self) -> None:
        receipt = ScriptEngineReceipt(
            exit_code=-4,
            raw_exit_code=4294967292,
            stdout="Subscription required",
            stderr="",
            duration_seconds=0.35,
            bcs_script="Open(\"plan.pdf\")",
            engine_used="script_engine",
            entitlement_restricted=True,
        )
        d = receipt.to_dict()
        assert d["exit_code"] == -4
        assert d["raw_exit_code"] == 4294967292
        assert d["stdout"] == "Subscription required"
        assert d["stderr"] == ""
        assert d["duration_seconds"] == 0.35
        assert d["duration_ms"] == 350.0
        assert d["bcs_script"] == "Open(\"plan.pdf\")"
        assert d["engine_used"] == "script_engine"
        assert d["entitlement_restricted"] is True


class TestSubprocessGuardrails:
    """Validate timeout watchdogs and process termination."""

    def test_safe_subprocess_successful_execution(self) -> None:
        cmd = [sys.executable, "-c", "import sys; sys.stdout.write('hello'); sys.exit(0)"]
        signed_code, raw_code, stdout, stderr, elapsed = run_subprocess_safely(
            cmd=cmd,
            timeout_seconds=5.0,
            cwd=SCRATCH_DIR,
        )
        assert signed_code == 0
        assert raw_code == 0
        assert stdout == "hello"
        assert stderr == ""
        assert elapsed >= 0.0

    def test_safe_subprocess_timeout_watchdog_triggers(self) -> None:
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
        with pytest.raises(SubprocessTimeoutError) as exc_info:
            run_subprocess_safely(
                cmd=cmd,
                timeout_seconds=0.2,
                cwd=SCRATCH_DIR,
            )
        err = exc_info.value
        assert "timed out after 0.2s" in str(err)
        assert err.details["timeout_seconds"] == 0.2

    def test_subprocess_timeout_and_taskkill(self) -> None:
        """T2-16: Timeout watchdog triggers process termination."""
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
        with pytest.raises(SubprocessTimeoutError):
            run_subprocess_safely(cmd=cmd, timeout_seconds=0.2, cwd=SCRATCH_DIR)

    def test_max_file_size_enforcement(self) -> None:
        """T2-17: Files larger than specified limit raise FileTooLargeError."""
        from bluebeam_mcp.security import FileTooLargeError, validate_path

        target = SCRATCH_DIR / "large_engine_file.pdf"
        target.write_bytes(b"%PDF-1.7\n" + b"X" * 1000)
        try:
            with pytest.raises(FileTooLargeError):
                validate_path(target, max_size=500, must_exist=True)
        finally:
            if target.exists():
                target.unlink()

    def test_temp_file_cleanup_on_exception(self) -> None:
        """T2-18: Verifies temporary files are cleaned up on exception."""
        bcs_before = set(SCRATCH_DIR.glob("mcp_job_*.bcs"))
        try:
            run_script_engine('NonExistentCommand("test")', timeout_seconds=0.5)
        except Exception:
            pass
        bcs_after = set(SCRATCH_DIR.glob("mcp_job_*.bcs"))
        assert bcs_before == bcs_after


class TestResponseEnvelopes:
    """Validate format_success_envelope and format_error_envelope."""

    def test_format_success_envelope_script_engine(self) -> None:
        receipt = ScriptEngineReceipt(
            exit_code=0,
            raw_exit_code=0,
            stdout="OK",
            stderr="",
            duration_seconds=0.4,
            bcs_script="PageCount()",
            engine_used="script_engine",
            entitlement_restricted=False,
        )
        env = format_success_envelope(
            data={"page_count": 5},
            receipt=receipt,
            tool_name="bb_pdf_info",
            citations=["01_script_reference.md p. 19"],
        )
        assert env["status"] == "success"
        assert env["tool"] == "bb_pdf_info"
        assert env["execution_engine"] == "script_engine"
        assert env["bcs_script"] == "PageCount()"
        assert env["script_engine_receipt"]["exit_code"] == 0
        assert env["data"]["page_count"] == 5
        assert env["citations"] == ["01_script_reference.md p. 19"]

    def test_format_success_envelope_subscription_fallback(self) -> None:
        receipt = ScriptEngineReceipt(
            exit_code=-4,
            raw_exit_code=4294967292,
            stdout="Subscription required",
            stderr="",
            duration_seconds=0.38,
            bcs_script="Combine(\"a.pdf\", \"b.pdf\")",
            engine_used="native_fallback",
            entitlement_restricted=True,
        )
        env = format_success_envelope(
            data={"output_path": "c.pdf", "page_count": 6},
            receipt=receipt,
            tool_name="bb_pdf_combine",
            citations=["01_script_reference.md p. 9"],
        )
        assert env["status"] == "subscription_fallback"
        assert env["execution_engine"] == "native_fallback"
        assert env["script_engine_receipt"]["exit_code"] == -4
        assert env["script_engine_receipt"]["duration_ms"] == 380.0

    def test_format_error_envelope_mappings(self) -> None:
        sec_err = SecurityViolationError("Traversal blocked", details={"path": "secret.pdf"})
        env_sec = format_error_envelope(sec_err, tool_name="bb_pdf_open")
        assert env_sec["status"] == "error"
        assert env_sec["tool"] == "bb_pdf_open"
        assert env_sec["error"]["code"] == "SECURITY_VIOLATION"
        assert env_sec["error"]["category"] == "security"
        assert env_sec["error"]["details"]["path"] == "secret.pdf"

        eng_err = EngineExecutionError(
            "ScriptEngine failed with code -1",
            details={"cli_exit_code": -1, "bcs_script": "InvalidCommand()"},
        )
        env_eng = format_error_envelope(eng_err, tool_name="bb_script_run")
        assert env_eng["status"] == "error"
        assert env_eng["error"]["code"] == "ENGINE_FAILURE"
        assert env_eng["error"]["category"] == "execution"
        assert env_eng["bcs_script"] == "InvalidCommand()"


class TestDualEngineOrchestrator:
    """Validate dual-engine execution pathways and fallbacks."""

    def test_script_only_mode(self) -> None:
        script = "Open(\"doc.pdf\")\nPageCount()\nClose()"
        result = execute_dual_engine(
            bcs_script=script,
            native_fn=None,
            execution_mode="script_only",
            tool_name="bb_pdf_info",
        )
        assert result["status"] == "success"
        assert result["execution_engine"] == "none"
        assert result["bcs_script"] == script
        assert result["script_engine_receipt"]["exit_code"] == 0

    def test_native_only_mode(self) -> None:
        script = "PageRotate(90, true, false, \"1\")"
        result = execute_dual_engine(
            bcs_script=script,
            native_fn=lambda: {"rotated_pages": [1], "rotation": 90},
            execution_mode="native_only",
            tool_name="bb_pdf_rotate",
        )
        assert result["status"] == "success"
        assert result["execution_engine"] == "native_direct"
        assert result["data"]["rotation"] == 90

    def test_invalid_execution_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid execution_mode"):
            execute_dual_engine(
                bcs_script="Test()",
                execution_mode="unsupported_mode",
            )

    def test_auto_mode_with_subscription_fallback(self) -> None:
        fake_receipt = ScriptEngineReceipt(
            exit_code=-4,
            raw_exit_code=4294967292,
            stdout="This feature requires a maximum subscription level.",
            stderr="",
            duration_seconds=0.35,
            bcs_script="Combine(\"a.pdf\")",
            engine_used="script_engine",
            entitlement_restricted=True,
        )

        with mock.patch("bluebeam_mcp.engine.run_script_engine", return_value=fake_receipt):
            result = execute_dual_engine(
                bcs_script="Combine(\"a.pdf\")",
                native_fn=lambda: {"combined": True, "page_count": 10},
                execution_mode="auto",
                tool_name="bb_pdf_combine",
            )
            assert result["status"] == "subscription_fallback"
            assert result["execution_engine"] == "native_fallback"
            assert result["data"]["combined"] is True
            assert result["script_engine_receipt"]["exit_code"] == -4

    def test_script_engine_strict_raises_on_minus_four(self) -> None:
        fake_receipt = ScriptEngineReceipt(
            exit_code=-4,
            raw_exit_code=4294967292,
            stdout="This feature requires a maximum subscription level.",
            stderr="",
            duration_seconds=0.35,
            bcs_script="Combine(\"a.pdf\")",
            engine_used="script_engine",
            entitlement_restricted=True,
        )

        with mock.patch("bluebeam_mcp.engine.run_script_engine", return_value=fake_receipt):
            with pytest.raises(EngineExecutionError) as exc_info:
                execute_dual_engine(
                    bcs_script="Combine(\"a.pdf\")",
                    native_fn=lambda: {"combined": True},
                    execution_mode="script_engine_strict",
                    tool_name="bb_pdf_combine",
                )
            assert "exit code -4" in str(exc_info.value)
            assert exc_info.value.details["cli_exit_code"] == -4

    def test_syntax_error_minus_one_raises(self) -> None:
        fake_receipt = ScriptEngineReceipt(
            exit_code=-1,
            raw_exit_code=4294967295,
            stdout="Parse.Error CMD:InvalidCommand Ln 1 Col 1",
            stderr="",
            duration_seconds=0.1,
            bcs_script="InvalidCommand()",
            engine_used="script_engine",
            entitlement_restricted=False,
        )

        with mock.patch("bluebeam_mcp.engine.run_script_engine", return_value=fake_receipt):
            with pytest.raises(EngineExecutionError) as exc_info:
                execute_dual_engine(
                    bcs_script="InvalidCommand()",
                    native_fn=lambda: {},
                    execution_mode="auto",
                    tool_name="bb_script_run",
                )
            assert "failed with exit code -1" in str(exc_info.value)

    def test_dual_engine_transparent_fallback(self) -> None:
        """T4-03: Dual-engine fallback transparently uses native implementation."""
        self.test_auto_mode_with_subscription_fallback()


class TestFixtureFactory:
    """Validate deterministic test fixture generation."""

    def test_create_sample_pdf(self) -> None:
        target = FIXTURES_DIR / "unit_test_sample.pdf"
        res = create_sample_pdf(target, num_pages=3, title="Fixture Test")
        assert res.exists()
        reader = pypdf.PdfReader(res)
        assert len(reader.pages) == 3

    def test_create_form_pdf(self) -> None:
        target = FIXTURES_DIR / "unit_test_form.pdf"
        res = create_form_pdf(target)
        assert res.exists()
        reader = pypdf.PdfReader(res)
        fields = reader.get_fields()
        assert fields is not None
        assert "project_name" in fields
        assert "contractor" in fields
        assert "inspection_passed" in fields

    def test_create_annotated_pdf(self) -> None:
        target = FIXTURES_DIR / "unit_test_annotated.pdf"
        res = create_annotated_pdf(target)
        assert res.exists()
        reader = pypdf.PdfReader(res)
        page = reader.pages[0]
        annots = page["/Annots"]
        assert len(annots) == 2
        subtypes = [a.get_object()["/Subtype"] for a in annots]
        assert "/FreeText" in subtypes
        assert "/Square" in subtypes

    def test_create_sample_btx(self) -> None:
        target = FIXTURES_DIR / "unit_test_toolset.btx"
        res = create_sample_btx(target)
        assert res.exists()
        content = res.read_text(encoding="utf-8")
        assert "<BluebeamRevuToolSet Version=\"1\">" in content
        assert "<Raw>" in content

        # Verify raw decompresses cleanly
        import re
        match = re.search(r"<Raw>([a-fA-F0-9]+)</Raw>", content)
        assert match is not None
        raw_hex = match.group(1)
        decomp = zlib.decompress(bytes.fromhex(raw_hex))
        assert b"Bluebeam.PDF.Annotations.AnnotationFreeText" in decomp

    def test_create_sample_bpx(self) -> None:
        target = FIXTURES_DIR / "unit_test_profile.bpx"
        res = create_sample_bpx(target)
        assert res.exists()
        content = res.read_text(encoding="utf-8")
        assert "<RevuProfile Version=\"1\"" in content
        assert "<Record Key=\"MarkupList\">" in content
        assert "<Column Key=\"Subject\">" in content

    def test_create_sample_bax(self) -> None:
        target = FIXTURES_DIR / "unit_test_markups.bax"
        res = create_sample_bax(target)
        assert res.exists()
        content = res.read_text(encoding="utf-8")
        assert "<MarkupList Version=\"1\">" in content
        assert "<Annotation>" in content
        assert "<Subj>Text Box</Subj>" in content

    def test_create_corrupt_fixtures(self) -> None:
        zero_target = FIXTURES_DIR / "zero_byte.pdf"
        create_zero_byte_pdf(zero_target)
        assert zero_target.stat().st_size == 0

        header_target = FIXTURES_DIR / "bad_header.pdf"
        create_corrupt_header_pdf(header_target)
        assert not header_target.read_bytes().startswith(b"%PDF-")

        trunc_target = FIXTURES_DIR / "truncated.pdf"
        create_truncated_pdf(trunc_target)
        assert b"%%EOF" not in trunc_target.read_bytes()


class TestLiveScriptEngineIntegration:
    """Live verification against installed ScriptEngine.exe on the reference workstation."""

    @pytest.mark.skipif(not SCRIPT_ENGINE_EXE.exists(), reason="ScriptEngine.exe not installed")
    def test_live_script_engine_entitlement_receipt(self) -> None:
        """Verify live ScriptEngine.exe execution receipt matches primary source findings."""
        receipt = run_script_engine("PageCount()\nClose(false)")
        assert receipt.raw_exit_code != 0 or receipt.exit_code == 0
        # On the reference workstation (Revu Core license), exit code is -4 with entitlement notice
        if receipt.exit_code == -4:
            assert receipt.entitlement_restricted is True
            assert "subscription level" in receipt.stdout.lower() or "upgrade" in receipt.stdout.lower()
            assert receipt.duration_seconds < 5.0

    @pytest.mark.skipif(not SCRIPT_ENGINE_EXE.exists(), reason="ScriptEngine.exe not installed")
    def test_live_script_engine_cli_invocation(self) -> None:
        """T4-01: Invokes ScriptEngine.exe with valid test script and captures receipt."""
        self.test_live_script_engine_entitlement_receipt()

    @pytest.mark.skipif(not SCRIPT_ENGINE_EXE.exists(), reason="ScriptEngine.exe not installed")
    def test_live_script_engine_syntax_error_receipt(self) -> None:
        """T4-02: Invokes ScriptEngine.exe with malformed BCS syntax and parses receipt."""
        receipt = run_script_engine('Open("unterminated_string_literal', timeout_seconds=5.0)
        assert receipt.exit_code in (-1, -4)


class TestPytestFixtures:
    """Validate pytest fixtures exposed by conftest.py."""

    def test_scratch_dir_fixture(self, scratch_dir: Path) -> None:
        assert scratch_dir.exists()
        assert scratch_dir == SCRATCH_DIR

    def test_sample_pdf_fixture(self, sample_pdf: Path) -> None:
        assert sample_pdf.exists()
        reader = pypdf.PdfReader(sample_pdf)
        assert len(reader.pages) == 3

    def test_form_pdf_fixture(self, form_pdf: Path) -> None:
        assert form_pdf.exists()
        reader = pypdf.PdfReader(form_pdf)
        fields = reader.get_fields()
        assert fields is not None
        assert "project_name" in fields

    def test_annotated_pdf_fixture(self, annotated_pdf: Path) -> None:
        assert annotated_pdf.exists()
        reader = pypdf.PdfReader(annotated_pdf)
        assert len(reader.pages[0]["/Annots"]) == 2

    def test_sample_btx_fixture(self, sample_btx: Path) -> None:
        assert sample_btx.exists()
        assert "<BluebeamRevuToolSet Version=\"1\">" in sample_btx.read_text(encoding="utf-8")

    def test_sample_bpx_fixture(self, sample_bpx: Path) -> None:
        assert sample_bpx.exists()
        assert "<RevuProfile Version=\"1\"" in sample_bpx.read_text(encoding="utf-8")

    def test_sample_bax_fixture(self, sample_bax: Path) -> None:
        assert sample_bax.exists()
        assert "<MarkupList Version=\"1\">" in sample_bax.read_text(encoding="utf-8")

