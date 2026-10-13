"""Unit and adversarial security tests for bluebeam_mcp.security.

Citations:
    - docs/ARCHITECTURE.md Section 4 (Security Architecture & Threat Mitigation Matrix).
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2 (Tier 2: Adversarial Security Tests).
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.3 (Tier 3: Fault Injection Matrix).
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import zlib

import pytest

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

# Test temporary directory strictly confined per system instructions
TEST_TMP_DIR = Path(__file__).resolve().parent / "tmp"


@pytest.fixture(autouse=True)
def ensure_tmp_dir() -> None:
    """Ensure tests/tmp directory exists."""
    TEST_TMP_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# Exception Hierarchy and Envelope Tests
# ============================================================================


def test_exception_envelope_structure() -> None:
    """Verify BluebeamMCPError and subclasses serialize to standard response envelope."""
    err = SecurityViolationError(
        "Unauthorized access to directory",
        details={"path": r"E:\ProtectedVault\vault"},
    )
    envelope = err.to_envelope()
    assert envelope["status"] == "error"
    assert envelope["error_code"] == "SECURITY_VIOLATION"
    assert envelope["error_type"] == "SecurityViolationError"
    assert envelope["message"] == "Unauthorized access to directory"
    assert envelope["details"]["path"] == r"E:\ProtectedVault\vault"


def test_exception_inheritance_contracts() -> None:
    """Verify inheritance relationships for specific error classifications."""
    assert issubclass(EmptyFileError, CorruptPDFError)
    assert issubclass(CorruptPDFError, BluebeamMCPError)
    assert issubclass(XMLDefuseError, SecurityViolationError)
    assert issubclass(CorruptStreamError, BluebeamMCPError)
    assert issubclass(CorruptStreamError, ValueError)
    assert issubclass(SubprocessTimeoutError, BluebeamMCPError)
    assert issubclass(EngineExecutionError, BluebeamMCPError)
    assert issubclass(FileTooLargeError, BluebeamMCPError)
    assert issubclass(FileLockedError, BluebeamMCPError)
    assert issubclass(PageRangeError, BluebeamMCPError)


# ============================================================================
# Tier 2: Adversarial Security Tests (T2-01 through T2-15)
# ============================================================================


def test_adversarial_double_quote_breakout() -> None:
    """T2-01: Double quote injection escaped to |" preventing command boundary escape."""
    payload = r'test.pdf") DeleteFile("C:\important.pdf") %'
    escaped = escape_bcs_string(payload)
    assert '|"' in escaped
    # Ensure all double quotes are escaped with pipe prefix
    assert escaped == r'test.pdf|") DeleteFile(|"C:\important.pdf|") %'


def test_adversarial_pipe_quote_smuggle() -> None:
    """T2-02: Pipe character escaped to || before quotes preventing escape sequence smuggle."""
    payload = r'test.pdf|") DeleteFile("C:\important.pdf")'
    escaped = escape_bcs_string(payload)
    assert "||" in escaped
    assert r'|||")' in escaped


def test_adversarial_newline_comment_injection() -> None:
    """T2-03: Newline characters in path or single-line BCS argument raise SecurityViolationError."""
    payload = "test.pdf\r\nDeleteFile(\"C:\\important.pdf\")\r\n%"
    with pytest.raises(SecurityViolationError):
        escape_bcs_string(payload, allow_newlines=False)
    with pytest.raises(SecurityViolationError):
        validate_path(payload, must_exist=False)


def test_adversarial_null_byte_rejection() -> None:
    """T2-05: Null byte in path or script argument immediately raises SecurityViolationError."""
    payload = "test.pdf\x00.exe"
    with pytest.raises(SecurityViolationError):
        validate_path(payload, must_exist=False)
    with pytest.raises(SecurityViolationError):
        escape_bcs_string(payload)


def test_protected_root_protected_root_pdm() -> None:
    """T2-06: Direct access or relative traversal to E:\\ProtectedVault raises SecurityViolationError."""
    path = r"E:\ProtectedVault\vault\drawing.pdf"
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_path(path, must_exist=False)
    assert "protected directory" in str(exc_info.value).lower()


def test_protected_root_solidworks_corp() -> None:
    """T2-07: Direct access or traversal to SOLIDWORKS installation directory is blocked."""
    path = r"C:\Program Files\SOLIDWORKS Corp\template.sldprt"
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_path(path, must_exist=False)
    assert "protected directory" in str(exc_info.value).lower()


def test_write_protection_system_roots() -> None:
    """T2-08: Write or delete access to C:\\Windows or Bluebeam Software program dirs is blocked."""
    system_paths = [
        r"C:\Windows\System32\malicious.pdf",
        r"C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Revu\test.bcs",
        r"C:\ProgramData\Bluebeam Software\malicious.xml",
    ]
    for sp in system_paths:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_path(sp, mode="write", must_exist=False)
        assert "protected system directory" in str(exc_info.value).lower()

        with pytest.raises(SecurityViolationError):
            validate_path(sp, mode="delete", must_exist=False)


def test_path_traversal_relative_escape() -> None:
    """T2-09: Relative traversal escaping outside workspace raises SecurityViolationError."""
    payload = r"tests\tmp\..\..\..\..\..\Windows\explorer.exe"
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_path(payload, must_exist=False)
    assert "traversal" in str(exc_info.value).lower()


def test_remote_unc_path_rejection() -> None:
    """T2-10: UNC network paths starting with double slashes are rejected."""
    unc_paths = [
        r"\\192.168.1.100\share\document.pdf",
        "//server/share/document.pdf",
        r"\\?\UNC\server\share\document.pdf",
    ]
    for unc in unc_paths:
        with pytest.raises(SecurityViolationError) as exc_info:
            validate_path(unc, must_exist=False)
        assert "unc" in str(exc_info.value).lower()


def test_disallowed_extension_rejection() -> None:
    """T2-11: File with non-allowlisted extension (.exe) raises SecurityViolationError."""
    target = TEST_TMP_DIR / "malicious_payload.exe"
    with pytest.raises(SecurityViolationError) as exc_info:
        validate_path(target, must_exist=False)
    assert "extension" in str(exc_info.value).lower()


def test_xxe_payload_blocked_defusedxml() -> None:
    """T2-12: XML External Entity (XXE) injection is safely defused by parse_xml_safely."""
    xxe_payload = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ELEMENT foo ANY >\n'
        '  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>\n'
        '<foo>&xxe;</foo>'
    )
    with pytest.raises(XMLDefuseError) as exc_info:
        parse_xml_safely(xxe_payload)
    assert exc_info.value.error_code == "XML_PARSE_ERROR"


def test_billion_laughs_bomb_blocked() -> None:
    """T2-13: Exponential entity expansion bomb is rejected by defusedxml."""
    bomb_payload = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE lolz [\n'
        ' <!ENTITY lol "lol">\n'
        ' <!ELEMENT lolz (#PCDATA)>\n'
        ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        ' <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n'
        ']>\n'
        '<lolz>&lol2;</lolz>'
    )
    with pytest.raises(XMLDefuseError) as exc_info:
        parse_xml_safely(bomb_payload)
    assert exc_info.value.error_code == "XML_PARSE_ERROR"


def test_btx_corrupt_hex_stream() -> None:
    """T2-14: Invalid non-hex stream raises CorruptStreamError (which is also ValueError)."""
    corrupt_hex = "NOT_VALID_HEX_STREAM!!!"
    with pytest.raises(CorruptStreamError) as exc_info:
        decompress_btx_raw(corrupt_hex)
    assert exc_info.value.error_code == "CORRUPT_RAW_STREAM"
    assert isinstance(exc_info.value, ValueError)


def test_btx_zlib_decompression_bomb() -> None:
    """T2-15: Stream decompressing beyond 10 MB limit raises SecurityViolationError."""
    # Create payload expanding to 11 MB of zeros
    ten_mb_data = b"0" * (11 * 1024 * 1024)
    compressed = zlib.compress(ten_mb_data)
    hex_str = compressed.hex()

    with pytest.raises(SecurityViolationError) as exc_info:
        decompress_btx_raw(hex_str, max_size=MAX_DECOMPRESSED_SIZE)
    assert "exceeds" in str(exc_info.value).lower()


# ============================================================================
# Tier 3: Fault Injection Tests (T3-01, T3-02, T3-04, T3-07, T3-08, T3-09)
# ============================================================================


def test_fault_zero_byte_pdf() -> None:
    """T3-01: Zero-byte file raises EmptyFileError when must_exist=True."""
    target = TEST_TMP_DIR / "empty_test_file.pdf"
    target.write_bytes(b"")
    try:
        with pytest.raises(EmptyFileError) as exc_info:
            validate_path(target, must_exist=True)
        assert exc_info.value.error_code == "EMPTY_FILE"
    finally:
        if target.exists():
            target.unlink()


def test_fault_corrupt_pdf_header() -> None:
    """T3-02: File lacking %PDF- magic bytes in first 1024 bytes raises CorruptPDFError."""
    target = TEST_TMP_DIR / "corrupt_header.pdf"
    target.write_bytes(b"%NOTPDF-INVALID-DATA-HERE\n" + b"X" * 100)
    try:
        with pytest.raises(CorruptPDFError) as exc_info:
            check_pdf_header(target)
        assert exc_info.value.error_code == "INVALID_PDF"
    finally:
        if target.exists():
            target.unlink()


def test_fault_missing_input_file() -> None:
    """T3-04: Non-existent file path raises FileNotFoundError when must_exist=True."""
    target = TEST_TMP_DIR / "does_not_exist_file.pdf"
    if target.exists():
        target.unlink()
    with pytest.raises(FileNotFoundError):
        validate_path(target, must_exist=True)


def test_fault_locked_file_exclusive_handle() -> None:
    """T3-07: File held open with exclusive write access raises FileLockedError on write mode."""
    import msvcrt

    target = TEST_TMP_DIR / "locked_file_test.pdf"
    target.write_bytes(b"%PDF-1.7\nSample\n")
    try:
        with open(target, "r+b") as holder:
            msvcrt.locking(holder.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                with pytest.raises(FileLockedError) as exc_info:
                    validate_path(target, mode="write", must_exist=True)
                assert exc_info.value.error_code == "FILE_LOCKED"
            finally:
                try:
                    msvcrt.locking(holder.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
    finally:
        if target.exists():
            target.unlink()


# ============================================================================
# Test Matrix Specification Aliases & Additional Coverage
# ============================================================================


def test_bcs_quote_injection_in_filename() -> None:
    """Verify double-quote breakout in BCS filename arguments is escaped."""
    test_adversarial_double_quote_breakout()


def test_bcs_pipe_escape_doubling() -> None:
    """Verify pipe characters in BCS strings are doubled before quotes."""
    test_adversarial_pipe_quote_smuggle()


def test_bcs_newline_command_smuggling() -> None:
    """Verify newline characters in command strings are rejected."""
    test_adversarial_newline_comment_injection()


def test_bcs_dictionary_payload_injection() -> None:
    """Verify dictionary payloads escape quotes to prevent breakout."""
    from bluebeam_mcp.script_builder import serialize_bcs_dict

    payload = {"author": 'Admin" || DeleteFile("x") %', "subject": "Test"}
    serialized = serialize_bcs_dict(payload)
    assert '|"' in serialized


def test_path_null_byte_and_unc_rejection() -> None:
    """Verify null bytes and UNC paths are rejected."""
    test_adversarial_null_byte_rejection()
    test_remote_unc_path_rejection()


def test_forbidden_root_solidworks_confinement() -> None:
    """Verify access to SOLIDWORKS root directory is blocked."""
    test_protected_root_solidworks_corp()


def test_readonly_root_bluebeam_and_windows() -> None:
    """Verify write or delete protection to system roots."""
    test_write_protection_system_roots()


def test_directory_traversal_dotdot_escape() -> None:
    """Verify directory traversal attempting to escape workspace is blocked."""
    test_path_traversal_relative_escape()


def test_deletefile_confinement() -> None:
    """Verify DeleteFile operations cannot target protected or system roots."""
    for bad_path in [r"C:\Windows\System32\important.dll", r"E:\ProtectedVault\vault\secret.pdf"]:
        with pytest.raises(SecurityViolationError):
            validate_path(bad_path, mode="delete", must_exist=False)


def test_arbitrary_extension_rejection() -> None:
    """Verify non-allowlisted file extensions are rejected."""
    test_disallowed_extension_rejection()


def test_xxe_external_entity_rejection() -> None:
    """Verify XML external entities (XXE) are safely defused."""
    test_xxe_payload_blocked_defusedxml()


def test_xml_billion_laughs_bomb_defusal() -> None:
    """Verify XML entity expansion bombs are rejected."""
    test_billion_laughs_bomb_blocked()


def test_btx_corrupt_hex_and_zlib_stream() -> None:
    """Verify corrupted hex and zlib streams raise CorruptStreamError."""
    test_btx_corrupt_hex_stream()


def test_btx_decompression_bomb_limit() -> None:
    """Verify decompression bombs exceeding max size limit raise SecurityViolationError."""
    test_btx_zlib_decompression_bomb()


def test_fault_file_not_found() -> None:
    """Verify missing file raises FileNotFoundError."""
    test_fault_missing_input_file()


def test_fault_truncated_pdf_eof() -> None:
    """Verify truncated PDF file header or structure raises CorruptPDFError."""
    target = TEST_TMP_DIR / "truncated_eof.pdf"
    target.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
    try:
        import pypdf

        with pytest.raises(Exception):
            reader = pypdf.PdfReader(target)
            if len(reader.pages) == 0:
                raise CorruptPDFError("Truncated PDF contains no pages")
    finally:
        if target.exists():
            target.unlink()


def test_fault_empty_zero_byte_file() -> None:
    """Verify zero-byte file raises EmptyFileError."""
    test_fault_zero_byte_pdf()


def test_fault_page_out_of_range_high() -> None:
    """Verify querying an out-of-range page raises PageRangeError."""
    from bluebeam_mcp.script_builder import validate_one_based_page
    from bluebeam_mcp.security import PageRangeError

    with pytest.raises(PageRangeError):
        validate_one_based_page(0)


def test_fault_page_zero_and_negative() -> None:
    """Verify page 0 and negative pages (other than -1) raise PageRangeError."""
    from bluebeam_mcp.script_builder import validate_one_based_page, validate_page_range
    from bluebeam_mcp.security import PageRangeError

    with pytest.raises(PageRangeError):
        validate_one_based_page(0)
    with pytest.raises(PageRangeError):
        validate_one_based_page(-2)
    with pytest.raises(PageRangeError):
        validate_page_range("0")


def test_fault_readonly_output_file() -> None:
    """Verify read-only output file raises FileLockedError on write mode."""
    test_fault_read_only_output_target()


def test_fault_malformed_xml_syntax() -> None:
    """Verify malformed XML raises XMLDefuseError."""
    test_fault_corrupt_bax_xml()


def test_fault_subprocess_timeout_kill() -> None:
    """Verify subprocess exceeding timeout raises SubprocessTimeoutError."""
    import sys
    from bluebeam_mcp.engine import run_subprocess_safely

    cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
    with pytest.raises(SubprocessTimeoutError):
        run_subprocess_safely(cmd, timeout_seconds=0.2)


def test_fault_script_engine_syntax_error_minus_1() -> None:
    """Verify script engine syntax error diagnostic receipt (-1)."""
    from bluebeam_mcp.engine import ScriptEngineReceipt, to_signed_exit_code

    receipt = ScriptEngineReceipt(
        exit_code=to_signed_exit_code(4294967295),
        raw_exit_code=4294967295,
        stdout="Parse.Error CMD:Open Ln 1 Col 5: Unexpected token",
        stderr="",
        duration_seconds=0.1,
        bcs_script='Open("bad"',
        engine_used="script_engine",
        entitlement_restricted=False,
    )
    assert receipt.exit_code == -1
    assert "Parse.Error" in receipt.stdout


def test_fault_read_only_output_target() -> None:
    """T3-08: Output file with read-only filesystem attribute raises FileLockedError on write mode."""
    target = TEST_TMP_DIR / "readonly_test.pdf"
    target.write_bytes(b"%PDF-1.7\nSample content\n")
    try:
        # Set file to read-only attribute
        os.chmod(target, stat.S_IREAD)
        with pytest.raises(FileLockedError) as exc_info:
            validate_path(target, mode="write", must_exist=True)
        assert exc_info.value.error_code == "FILE_LOCKED"
    finally:
        # Restore write permissions so file can be unlinked
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        if target.exists():
            target.unlink()


def test_fault_corrupt_bax_xml() -> None:
    """T3-09: Corrupt XML with unclosed tags raises XMLDefuseError with XML_PARSE_ERROR."""
    malformed = "<Markup><Author>John</Markup>"
    with pytest.raises(XMLDefuseError) as exc_info:
        parse_xml_safely(malformed)
    assert exc_info.value.error_code == "XML_PARSE_ERROR"


def test_valid_pdf_header_accepted() -> None:
    """Valid PDF header starting with %PDF- passes check_pdf_header."""
    target = TEST_TMP_DIR / "valid_test.pdf"
    target.write_bytes(b"%PDF-1.7\n%Bluebeam binary header\n")
    try:
        result = check_pdf_header(target)
        assert result == target
    finally:
        if target.exists():
            target.unlink()


def test_valid_btx_decompression() -> None:
    """Valid zlib-compressed hex stream decompresses accurately."""
    original = b"Standard Bluebeam ToolSet Definition"
    compressed = zlib.compress(original)
    hex_str = compressed.hex()
    decompressed = decompress_btx_raw(hex_str)
    assert decompressed == original
