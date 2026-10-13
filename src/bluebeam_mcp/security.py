"""Security architecture, path validation, string sanitization, and XML defusing.

Provides strict containment for Bluebeam Revu 21 automation workflows,
preventing command injection, path traversal, XXE/bomb attacks, and resource exhaustion.

Citations:
    - docs/ARCHITECTURE.md Section 4 (Security Architecture & Threat Mitigation Matrix).
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2 (Tier 2: Adversarial Security Tests).
    - Bluebeam Script Reference Version 2.0.11, p. 4 (Data Types - String escaping).
    - RFC 1950 (ZLIB Compressed Data Format Specification).
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile
from typing import Any
import xml.etree.ElementTree as ET
import zlib

import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

# ============================================================================
# Security Constants
# ============================================================================

_user_home = Path.home()

# Protected roots forbidden from any access (read, write, delete).
# Site-specific roots (a PDM vault view, a licensed CAD install, ...) come from the
# BLUEBEAM_MCP_FORBIDDEN_ROOTS environment variable (semicolon-separated absolute paths);
# user credential directories are always included.
FORBIDDEN_ROOTS: list[str] = [
    *[p.strip() for p in os.environ.get("BLUEBEAM_MCP_FORBIDDEN_ROOTS", "").split(";") if p.strip()],
    str(_user_home / ".ssh"),
    str(_user_home / ".aws"),
    str(_user_home / ".gnupg"),
    str(_user_home / ".azure"),
    str(_user_home / ".config" / "gcloud"),
]

# Protected system roots forbidden from modification (write, delete)
# Citation: docs/ARCHITECTURE.md Section 4.1; docs/TEST_AND_SECURITY_MATRIX.md T2-08; H-09
READ_ONLY_ROOTS: list[str] = [
    r"C:\Program Files\Bluebeam Software",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows",
    r"C:\ProgramData\Bluebeam Software",
    r"C:\ProgramData",
    str(Path(os.environ.get("APPDATA", r"C:\Users\Default\AppData\Roaming")) / "Bluebeam Software"),
]

# Allowlisted file extensions for Bluebeam Revu MCP operations
# Citation: docs/ARCHITECTURE.md Section 4.1; docs/TEST_AND_SECURITY_MATRIX.md T2-11
ALLOWED_EXTENSIONS: set[str] = {
    ".pdf",
    ".bcs",
    ".bci",
    ".bax",
    ".btx",
    ".bpx",
    ".xml",
    ".fdf",
    ".xfdf",
    ".csv",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".tiff",
    ".tif",
    ".joboptions",
    ".json",
}

# Maximum input file size (250 MB)
# Citation: docs/ARCHITECTURE.md Section 4.1; docs/TEST_AND_SECURITY_MATRIX.md S4
MAX_FILE_SIZE: int = 250 * 1024 * 1024

# Maximum decompressed stream size for BTX/BAX raw hex streams (10 MB)
# Citation: docs/ARCHITECTURE.md Section 4.3; docs/TEST_AND_SECURITY_MATRIX.md T2-15
MAX_DECOMPRESSED_SIZE: int = 10 * 1024 * 1024

# Control characters and line separators forbidden in BCS strings
DISALLOWED_BCS_CONTROL_CHARS: tuple[str, ...] = (
    "\x00",
    "\x85",
    "\u2028",
    "\u2029",
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
)


# ============================================================================
# Exception Hierarchy
# ============================================================================


class BluebeamMCPError(Exception):
    """Base exception for all Bluebeam Revu MCP server errors.

    Citations:
        - docs/ARCHITECTURE.md Section 5.1 (Standard Response Envelope Specification).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.3 (Fault Injection Matrix).
    """

    def __init__(
        self,
        message: str,
        error_code: str = "BLUEBEAM_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.error_code: str = error_code
        self.details: dict[str, Any] = details if details is not None else {}

    def get_category(self) -> str:
        """Derive standard error category matching architecture specification."""
        if isinstance(self, SecurityViolationError):
            return "security"
        if isinstance(self, FileTooLargeError):
            return "resource_limit"
        if isinstance(self, FileLockedError):
            return "concurrency"
        if isinstance(self, (CorruptPDFError, CorruptStreamError, PageRangeError)):
            return "data_validation"
        if isinstance(self, (InvalidParameterError, ValueError)):
            return "validation"
        if isinstance(self, SubprocessTimeoutError):
            return "timeout"
        if isinstance(self, EngineExecutionError):
            return "execution"
        return "system"

    def to_envelope(self) -> dict[str, Any]:
        """Serialize exception to uniform MCP error response envelope."""
        category = self.get_category()
        return {
            "status": "error",
            "error": {
                "code": self.error_code,
                "message": self.message,
                "category": category,
                "details": self.details,
            },
            "error_code": self.error_code,
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class SecurityViolationError(BluebeamMCPError):
    """Raised when an operation violates security policy, path boundary, or injection rules."""

    def __init__(
        self,
        message: str,
        error_code: str = "SECURITY_VIOLATION",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class FileTooLargeError(BluebeamMCPError):
    """Raised when a file exceeds the maximum permitted size limit."""

    def __init__(
        self,
        message: str,
        error_code: str = "FILE_TOO_LARGE",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class FileLockedError(BluebeamMCPError):
    """Raised when a target file is locked by another process or marked read-only."""

    def __init__(
        self,
        message: str,
        error_code: str = "FILE_LOCKED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class CorruptPDFError(BluebeamMCPError):
    """Raised when a PDF file is corrupt, truncated, or lacks standard header bytes."""

    def __init__(
        self,
        message: str,
        error_code: str = "INVALID_PDF",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class EmptyFileError(CorruptPDFError):
    """Raised when an input document is zero bytes."""

    def __init__(
        self,
        message: str,
        error_code: str = "EMPTY_FILE",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class EncryptedPDFError(CorruptPDFError):
    """Raised when a PDF file is encrypted and required credentials are not supplied."""

    def __init__(
        self,
        message: str,
        error_code: str = "ENCRYPTED_PDF",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class PageRangeError(BluebeamMCPError):
    """Raised when a page index or page range is invalid or out of document bounds."""

    def __init__(
        self,
        message: str,
        error_code: str = "PAGE_OUT_OF_RANGE",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class XMLDefuseError(SecurityViolationError):
    """Raised when XML parsing encounters a forbidden DTD, entity expansion, or malformed markup."""

    def __init__(
        self,
        message: str,
        error_code: str = "XML_PARSE_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class CorruptStreamError(BluebeamMCPError, ValueError):
    """Raised when a hex or zlib compressed stream cannot be decoded."""

    def __init__(
        self,
        message: str,
        error_code: str = "CORRUPT_RAW_STREAM",
        details: dict[str, Any] | None = None,
    ) -> None:
        BluebeamMCPError.__init__(self, message, error_code=error_code, details=details)
        ValueError.__init__(self, message)


class InvalidParameterError(BluebeamMCPError, ValueError):
    """Raised when tool or command parameter validation fails."""

    def __init__(
        self,
        message: str,
        error_code: str = "INVALID_PARAMETER",
        details: dict[str, Any] | None = None,
    ) -> None:
        BluebeamMCPError.__init__(self, message, error_code=error_code, details=details)
        ValueError.__init__(self, message)


class SubprocessTimeoutError(BluebeamMCPError):
    """Raised when a Bluebeam subprocess exceeds its execution timeout watchdog."""

    def __init__(
        self,
        message: str,
        error_code: str = "SUBPROCESS_TIMEOUT",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class EngineExecutionError(BluebeamMCPError):
    """Raised when ScriptEngine.exe or an auxiliary engine fails during command execution."""

    def __init__(
        self,
        message: str,
        error_code: str = "ENGINE_FAILURE",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


class EngineUnavailableError(EngineExecutionError):
    """Raised when Bluebeam ScriptEngine.exe or required executable is missing or unavailable."""

    def __init__(
        self,
        message: str,
        error_code: str = "ENGINE_FAILURE",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code, details=details)


# ============================================================================
# Path Validation Helpers and Functions
# ============================================================================


def _strip_extended_prefix(p_str: str) -> str:
    """Strip Win32 extended-length prefix (\\\\?\\) if not \\\\?\\UNC."""
    if p_str.startswith(r"\\?\UNC") or p_str.startswith("//?/UNC"):
        return p_str
    if p_str.startswith("\\\\?\\") or p_str.startswith("//?/"):
        return p_str[4:]
    return p_str


def _is_path_under_root(target: Path, root_pattern: str | Path) -> bool:
    """Check if target path is identical to or within the given root pattern."""
    target_stripped = _strip_extended_prefix(str(target.resolve()))
    root_stripped = _strip_extended_prefix(str(Path(os.path.abspath(str(root_pattern))).resolve()))
    t_norm = os.path.normcase(os.path.normpath(target_stripped))
    r_norm = os.path.normcase(os.path.normpath(root_stripped))
    try:
        return os.path.commonpath([t_norm, r_norm]) == r_norm
    except ValueError:
        return False


def validate_path(
    path: str | Path,
    mode: str = "read",
    must_exist: bool = True,
    allowed_extensions: set[str] | None = None,
    max_size: int = MAX_FILE_SIZE,
    kind: str = "file",
) -> Path:
    """Validate and canonicalize a filesystem path against security policies.

    Enforces:
        - Mode strict validation: 'read', 'write', or 'delete'.
        - Kind validation: 'file', 'dir', or 'any'.
        - Non-empty, non-null, and non-control character checks (ord < 32).
        - UNC and Win32 device path rejection.
        - Drive-relative path rejection (e.g. E:foo.pdf).
        - NTFS Alternate Data Stream rejection (: after index 1).
        - Trailing space or dot rejection per path component before resolution.
        - Extended prefix stripping (\\\\?\\) after canonicalization.
        - Forbidden root confinement (BLUEBEAM_MCP_FORBIDDEN_ROOTS plus user credential directories).
        - Read-only system root protection on write or delete modes.
        - Environment root allowlists (BLUEBEAM_MCP_READ_ROOTS, BLUEBEAM_MCP_WRITE_ROOTS).
        - Relative directory traversal containment outside working workspace.
        - Extension allowlist enforcement.
        - File existence, empty-file detection, and size limits when must_exist is True.
        - Read-only attribute and exclusive-lock checks on write or delete mode.

    Citations:
        - docs/ARCHITECTURE.md Section 4.1 (Path Confinement & Protected-Root Enforcement).
        - docs/TEST_AND_SECURITY_MATRIX.md T2-05 to T2-11, T3-01, T3-04, T3-07, T3-08.
    """
    if not isinstance(mode, str) or mode not in ("read", "write", "delete"):
        raise ValueError(f"Invalid path validation mode '{mode}'. Must be 'read', 'write', or 'delete'.")

    if not isinstance(kind, str) or kind not in ("file", "dir", "any"):
        raise ValueError(f"Invalid path validation kind '{kind}'. Must be 'file', 'dir', or 'any'.")

    if path is None:
        raise SecurityViolationError("Path argument cannot be None")

    raw_str = str(path).strip()
    if not raw_str:
        raise SecurityViolationError("Path argument cannot be empty")

    # Reject null bytes immediately
    if "\x00" in raw_str:
        raise SecurityViolationError("Null byte detected in path argument", details={"path": raw_str})

    # Reject newline characters in paths
    if "\r" in raw_str or "\n" in raw_str:
        raise SecurityViolationError("Newline character detected in path argument", details={"path": raw_str})

    # Reject ASCII control characters (ord < 32)
    if any(ord(c) < 32 for c in raw_str):
        raise SecurityViolationError("Control character detected in path argument", details={"path": raw_str})

    # Reject UNC network paths and Win32 device namespaces
    raw_lower = raw_str.lower()
    if (
        raw_str.startswith(("\\", "//"))
        or raw_lower.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./"))
    ):
        raise SecurityViolationError("UNC network or device paths are forbidden", details={"path": raw_str})

    # Reject drive-relative paths (e.g. E:foo.pdf)
    if re.match(r"^[A-Za-z]:(?![\\/])", raw_str):
        raise SecurityViolationError("Drive-relative paths are forbidden", details={"path": raw_str})

    # Reject NTFS Alternate Data Streams (: after drive colon index 1)
    if ":" in raw_str[2:]:
        raise SecurityViolationError("NTFS Alternate Data Streams are forbidden", details={"path": raw_str})

    # Inspect each raw path component before resolution to block Win32 trailing space/dot stripping
    # and unresolved 8.3 short-name aliases (e.g. E:\DAEDAL~1\x.pdf)
    components = re.split(r"[\\/]", raw_str)
    non_empty_indices = [idx for idx, c in enumerate(components) if c and c not in (".", "..")]
    last_comp_idx = non_empty_indices[-1] if non_empty_indices else -1
    for idx, comp in enumerate(components):
        if not comp or comp in (".", ".."):
            continue
        if comp.endswith(" ") or comp.endswith("."):
            raise SecurityViolationError(
                "Path component cannot end with a trailing space or dot",
                details={"path": raw_str, "component": comp},
            )
        if re.search(r"~[0-9]+", comp):
            if comp.upper().startswith(("DAEDAL~", "SOLIDW~", "BLUEBE~", "WINDOW~", "PROGRA~", "SYSTEM~", "SYSWOW~")):
                raise SecurityViolationError(
                    "8.3 short-name path components targeting protected roots are forbidden",
                    details={"path": raw_str, "component": comp},
                )
            is_leaf_file = idx == last_comp_idx and kind != "dir"
            if not is_leaf_file:
                prefix_str = os.sep.join(components[: idx + 1])
                if re.match(r"^[A-Za-z]:$", components[0]):
                    prefix_str = components[0] + os.sep + os.sep.join(components[1 : idx + 1])
                if not Path(os.path.abspath(prefix_str)).exists():
                    raise SecurityViolationError(
                        "8.3 short-name directory components on non-existent paths are forbidden",
                        details={"path": raw_str, "component": comp},
                    )

    # Canonicalize path and strip extended prefix
    resolved_raw = Path(os.path.abspath(raw_str)).resolve()
    resolved = Path(_strip_extended_prefix(str(resolved_raw)))

    # Protected forbidden roots check (read, write, and delete forbidden)
    for forbidden_root in FORBIDDEN_ROOTS:
        if _is_path_under_root(resolved, forbidden_root):
            raise SecurityViolationError(
                f"Access to protected directory is blocked: {resolved}",
                details={"path": raw_str, "forbidden_root": forbidden_root},
            )

    # Protected read-only system roots check (write and delete forbidden)
    if mode in ("write", "delete"):
        for read_only_root in READ_ONLY_ROOTS:
            if _is_path_under_root(resolved, read_only_root):
                raise SecurityViolationError(
                    f"Write or delete access to protected system directory is blocked: {resolved}",
                    details={"path": raw_str, "read_only_root": read_only_root},
                )

    # Optional environment root allowlists
    env_read_roots = [p.strip() for p in os.environ.get("BLUEBEAM_MCP_READ_ROOTS", "").split(";") if p.strip()]
    if env_read_roots and not any(_is_path_under_root(resolved, r) for r in env_read_roots):
        raise SecurityViolationError(
            f"Path is not within permitted read roots: {resolved}",
            details={"path": raw_str, "allowed_read_roots": env_read_roots},
        )

    if mode in ("write", "delete"):
        env_write_roots = [p.strip() for p in os.environ.get("BLUEBEAM_MCP_WRITE_ROOTS", "").split(";") if p.strip()]
        if env_write_roots and not any(_is_path_under_root(resolved, w) for w in env_write_roots):
            raise SecurityViolationError(
                f"Path is not within permitted write roots: {resolved}",
                details={"path": raw_str, "allowed_write_roots": env_write_roots},
            )

    # Relative path traversal check: prevent escaping workspace or top-level anchor via '..'
    if ".." in components:
        working_root = Path(os.getcwd()).resolve()
        if not os.path.isabs(raw_str):
            if not _is_path_under_root(resolved, working_root):
                raise SecurityViolationError(
                    f"Relative path traversal outside workspace is blocked: {path}",
                    details={"path": raw_str, "resolved": str(resolved)},
                )
        else:
            first_dotdot = components.index("..")
            prefix_parts = [c for c in components[:first_dotdot] if c and c != "."]
            if prefix_parts:
                if re.match(r"^[A-Za-z]:$", prefix_parts[0]):
                    prefix_path = Path(prefix_parts[0] + os.sep + os.sep.join(prefix_parts[1:])).resolve()
                    top_anchor = (
                        Path(prefix_parts[0] + os.sep + prefix_parts[1]).resolve()
                        if len(prefix_parts) >= 2
                        else prefix_path
                    )
                else:
                    prefix_path = Path(os.sep.join(prefix_parts)).resolve()
                    top_anchor = prefix_path
                if _is_path_under_root(prefix_path, working_root):
                    if not _is_path_under_root(resolved, working_root):
                        raise SecurityViolationError(
                            f"Path traversal escaping workspace is blocked: {path}",
                            details={"path": raw_str, "resolved": str(resolved)},
                        )
                elif not _is_path_under_root(resolved, top_anchor):
                    raise SecurityViolationError(
                        f"Path traversal escaping directory anchor is blocked: {path}",
                        details={"path": raw_str, "resolved": str(resolved)},
                    )

    # Directory vs file validation
    is_dir_target = (
        kind == "dir"
        or (
            allowed_extensions is not None
            and any(e.upper() == "DIR" for e in allowed_extensions)
            and (resolved.is_dir() or (not resolved.exists() and resolved.suffix == ""))
        )
    )

    if resolved.exists() and resolved.is_file() and kind == "dir":
        raise SecurityViolationError(
            "Expected directory path but found existing file",
            details={"path": raw_str, "resolved": str(resolved)},
        )

    if resolved.exists() and resolved.is_dir() and kind == "file" and not (
        allowed_extensions is not None and any(e.upper() == "DIR" for e in allowed_extensions)
    ):
        raise SecurityViolationError(
            "Expected file path but found existing directory",
            details={"path": raw_str, "resolved": str(resolved)},
        )

    # Extension allowlist check
    effective_allowed = allowed_extensions if allowed_extensions is not None else ALLOWED_EXTENSIONS
    allowed_ext_lower = {e.lower() for e in effective_allowed if e.upper() != "DIR"}

    if not is_dir_target and kind != "any":
        ext = resolved.suffix.lower()
        if ext not in allowed_ext_lower:
            raise SecurityViolationError(
                f"File extension '{ext}' is not permitted for path: {resolved}",
                details={"path": raw_str, "extension": ext, "allowed": sorted(effective_allowed)},
            )
    elif kind == "any" and resolved.exists() and resolved.is_file():
        ext = resolved.suffix.lower()
        if ext not in allowed_ext_lower:
            raise SecurityViolationError(
                f"File extension '{ext}' is not permitted for path: {resolved}",
                details={"path": raw_str, "extension": ext, "allowed": sorted(effective_allowed)},
            )

    # Existence and size checks
    if must_exist:
        if not resolved.exists():
            raise FileNotFoundError(f"File not found: {resolved}")
        if resolved.is_file():
            size = resolved.stat().st_size
            if size == 0:
                raise EmptyFileError(
                    f"File is empty (0 bytes): {resolved}",
                    details={"path": str(resolved), "size": 0},
                )
            if size > max_size:
                raise FileTooLargeError(
                    f"File size {size} bytes exceeds maximum limit of {max_size} bytes: {resolved}",
                    details={"path": str(resolved), "size": size, "max_size": max_size},
                )

    # Write-mode lock and read-only attribute checks
    if mode in ("write", "delete") and resolved.exists():
        if not os.access(resolved, os.W_OK):
            raise FileLockedError(
                f"Target file is marked read-only: {resolved}",
                details={"path": str(resolved)},
            )
        if resolved.is_file():
            try:
                with open(resolved, "r+b") as f:
                    if resolved.stat().st_size > 0:
                        try:
                            import msvcrt

                            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                        except (ImportError, AttributeError):
                            pass
            except (PermissionError, OSError) as exc:
                raise FileLockedError(
                    f"Target file is exclusively locked by another process: {resolved}",
                    details={"path": str(resolved), "error": str(exc)},
                ) from exc

    return resolved


def check_pdf_header(path: Path) -> Path:
    """Validate that the file begins with standard %PDF- magic bytes within the first 1024 bytes.

    Citations:
        - PDF 1.7 Reference (ISO 32000-1:2008), Section 7.5.2 (File Header).
        - docs/TEST_AND_SECURITY_MATRIX.md T3-02 (test_fault_corrupt_pdf_header).
    """
    if not path.is_file():
        raise FileNotFoundError(f"PDF file not found: {path}")

    with open(path, "rb") as f:
        header = f.read(1024)

    if b"%PDF-" not in header:
        raise CorruptPDFError(
            f"Invalid PDF header: %PDF- magic bytes not found in first 1024 bytes of {path}",
            details={"path": str(path)},
        )
    return path


def escape_bcs_string(value: str, allow_newlines: bool = False) -> str:
    """Escape a string argument for inclusion in a Bluebeam Script (.bcs/.bci) command.

    Bluebeam Script uses the pipe character | as its single escape character.
    Literal quotes are escaped as |" and |', and literal pipes are escaped as ||.
    Null bytes, control codes, and unescaped newlines are rejected.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 4 (Data Types - String).
        - docs/ARCHITECTURE.md Section 4.2 (Bluebeam Script Injection Defenses).
        - docs/TEST_AND_SECURITY_MATRIX.md T2-01, T2-02, T2-03, T2-05.
    """
    if any(c in value for c in DISALLOWED_BCS_CONTROL_CHARS):
        raise SecurityViolationError("Disallowed control character or line separator in BCS string argument")

    if not allow_newlines and ("\r" in value or "\n" in value):
        raise SecurityViolationError("Newline characters are forbidden in single-line BCS arguments")

    if allow_newlines:
        value = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")

    # Pipe escaping must execute first to avoid double-escaping quote escape pipes
    escaped = value.replace("|", "||")
    escaped = escaped.replace('"', '|"')
    escaped = escaped.replace("'", "|'")
    return escaped


def parse_xml_safely(
    source: str | bytes | Path,
    max_size: int = MAX_DECOMPRESSED_SIZE,
) -> ET.Element:
    """Safely parse XML using defusedxml, forbidding DTDs, external entities, and expansion bombs.

    Enforces:
        - Path argument validation through validate_path before reading.
        - Strict XML string verification without filesystem sniffing.
        - Strict byte size limit enforcement.
        - Element tree depth cap (<= 64) and element count cap (<= 50000).

    Citations:
        - docs/ARCHITECTURE.md Section 4.3 (XML Security & Defused Parsers).
        - docs/TEST_AND_SECURITY_MATRIX.md T2-12, T2-13, T3-09; Finding H-11.
    """
    if isinstance(source, Path):
        resolved = validate_path(
            source,
            mode="read",
            must_exist=True,
            allowed_extensions={".xml", ".bax", ".btx", ".bpx", ".xfdf", ".fdf"},
            max_size=max_size,
        )
        data = resolved.read_bytes()
    elif isinstance(source, str):
        trimmed = source.lstrip("\ufeff \t\r\n")
        if not trimmed.startswith("<"):
            raise XMLDefuseError("Malformed XML syntax: string is not XML")
        if len(source) > max_size * 2:
            raise FileTooLargeError(
                f"XML string length {len(source)} exceeds maximum permitted size",
                details={"length": len(source), "max_size": max_size * 2},
            )
        data = source.encode("utf-8")
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        raise TypeError(f"Unsupported XML source type: {type(source)}")

    if len(data) > max_size:
        raise FileTooLargeError(
            f"XML data size {len(data)} bytes exceeds maximum permitted size of {max_size} bytes",
            details={"size": len(data), "max_size": max_size},
        )

    try:
        root = DefusedET.fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        raise XMLDefuseError(
            f"XML security policy violation: {exc}",
            details={"error": str(exc)},
        ) from exc
    except ET.ParseError as exc:
        raise XMLDefuseError(
            f"Malformed XML syntax: {exc}",
            details={"error": str(exc)},
        ) from exc
    except RecursionError as exc:
        raise XMLDefuseError(
            f"XML recursion limit exceeded: {exc}",
            details={"error": str(exc)},
        ) from exc

    # Iterative stack traversal to enforce depth and element count limits
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    element_count = 0
    while stack:
        elem, depth = stack.pop()
        element_count += 1
        if depth > 64 or element_count > 50_000:
            raise XMLDefuseError(
                "XML complexity limit exceeded (depth > 64 or elements > 50000)",
                details={"depth": depth, "element_count": element_count},
            )
        for child in elem:
            stack.append((child, depth + 1))

    return root


def decompress_btx_raw(hex_str: str, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """Decompress a zlib-compressed hex stream from a BTX tool set or BAX markup <Raw> tag.

    Enforces:
        - String type check and pre-allocation length guard.
        - ASCII hex validation.
        - Stream completeness check (decompressor.eof must be True).
        - Multi-member or trailing garbage rejection (unused_data must be empty).

    Citations:
        - docs/citations/03_data_formats_and_markups.md Section 2.1 (Tool Set BTX Schema).
        - RFC 1950 (ZLIB Compressed Data Format Specification).
        - docs/TEST_AND_SECURITY_MATRIX.md T2-14, T2-15; Finding H-23.
    """
    if not isinstance(hex_str, str):
        raise CorruptStreamError(
            "Hex stream argument must be a string",
            details={"type": type(hex_str).__name__},
        )

    if len(hex_str) > max_size * 4:
        raise SecurityViolationError(
            f"Hex string length {len(hex_str)} exceeds maximum permitted length of {max_size * 4}",
            details={"length": len(hex_str), "max_allowed": max_size * 4},
        )

    cleaned = "".join(hex_str.split())
    if not cleaned:
        return b""

    if len(cleaned) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned, re.ASCII):
        raise CorruptStreamError(
            "Invalid hex stream encoding in raw XML element",
            details={"length": len(cleaned)},
        )

    try:
        compressed_bytes = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CorruptStreamError(
            f"Hex decoding error: {exc}",
            details={"error": str(exc)},
        ) from exc

    decompressor = zlib.decompressobj()
    try:
        decompressed = decompressor.decompress(compressed_bytes, max_size + 1)
    except zlib.error as exc:
        raise CorruptStreamError(
            f"Corrupt zlib stream: {exc}",
            details={"error": str(exc)},
        ) from exc

    if len(decompressed) > max_size or bool(decompressor.unconsumed_tail):
        raise SecurityViolationError(
            f"Decompressed stream exceeds maximum size limit of {max_size} bytes",
            details={"max_size": max_size},
        )

    if not decompressor.eof or bool(decompressor.unused_data):
        raise CorruptStreamError(
            "Truncated or multi-member zlib stream detected",
            details={"eof": decompressor.eof, "unused_data_len": len(decompressor.unused_data)},
        )

    return decompressed


# ============================================================================
# Shared Security and IO Helpers
# ============================================================================


def atomic_write_pdf(writer: Any, out_file: Path) -> None:
    """Atomically write a PDF writer instance to out_file using a temporary file.

    Citations:
        - docs/ARCHITECTURE.md Section 4.1.
        - docs/REMEDIATION_PLAN.md Finding C-08.
    """
    out_path = Path(out_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(out_path.parent),
            prefix=".bb_tmp_",
            suffix=".pdf",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            writer.write(tmp_file)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, out_path)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def atomic_write_bytes(data: bytes, out_file: Path) -> None:
    """Atomically write binary data to out_file using a temporary file.

    Citations:
        - docs/ARCHITECTURE.md Section 4.1.
        - docs/REMEDIATION_PLAN.md Finding C-08.
    """
    out_path = Path(out_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(out_path.parent),
            prefix=".bb_tmp_",
            suffix=out_path.suffix or ".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, out_path)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def sanitize_untrusted_text(value: Any, max_len: int = 4096) -> str:
    """Sanitize untrusted text from documents by stripping control characters and truncating.

    Citations:
        - docs/ARCHITECTURE.md Section 4.1.
        - docs/REMEDIATION_PLAN.md Finding H-19.
    """
    if value is None:
        return ""
    text = str(value)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)
    if len(cleaned) > max_len:
        return cleaned[:max_len] + " ...[TRUNCATED]"
    return cleaned


def sanitize_csv_cell(value: Any) -> str:
    """Sanitize cell value against CSV formula injection (CWE-1236).

    Citations:
        - docs/ARCHITECTURE.md Section 4.1.
        - docs/REMEDIATION_PLAN.md Finding M-01.
    """
    if value is None:
        return ""
    val = str(value).replace("\x00", "")
    if val.lstrip().startswith(("=", "+", "-", "@")) or val.startswith(("\t", "\r")):
        return "'" + val
    return val


def clean_xml_text(value: Any) -> str:
    """Strip illegal XML 1.0 characters to prevent XML serialization failures.

    Citations:
        - W3C XML 1.0 Fourth Edition Section 2.2.
        - docs/REMEDIATION_PLAN.md Finding M-02.
    """
    if value is None:
        return ""
    text = str(value)
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]", "", text)
