"""Subprocess management, watchdog, and dual-engine orchestrator for Bluebeam Revu 21.

Primary citations:
- docs/citations/01_script_reference.md Section 1 (Syntax and Execution)
- docs/citations/02_binary_and_dotnet_surface.md Section 4.1 (Binary Discovery),
  Section 4.2 (CLI Invocation Syntax), Section 5.2 (Command Surface),
  Section 6 (Stapler and Auxiliary Binaries), Section 7.2 (Live CLI Execution),
  Section 7.4 (Exit Code Summary)
- docs/citations/03_data_formats_and_markups.md Section 6 (PbMngr5 CLI Options)
- docs/ARCHITECTURE.md Section 3 (Compliant Dual-Engine Execution Architecture),
  Section 5 (Standardized Response Envelope Schemas)
- docs/TEST_AND_SECURITY_MATRIX.md Section 1.4 (Resource Exhaustion and Subprocess Guardrails),
  Section 3.3 (Standard Error Code Catalog)
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import functools
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
import uuid

from bluebeam_mcp.security import (
    BluebeamMCPError,
    CorruptPDFError,
    CorruptStreamError,
    EmptyFileError,
    EngineExecutionError,
    EngineUnavailableError,
    FileLockedError,
    FileTooLargeError,
    PageRangeError,
    SecurityViolationError,
    SubprocessTimeoutError,
    XMLDefuseError,
)

try:
    from bluebeam_mcp.security import EncryptedPDFError
except ImportError:
    EncryptedPDFError = None

try:
    from bluebeam_mcp.script_builder import redact_bcs_secrets
except ImportError:
    redact_bcs_secrets = None

BluebeamError = BluebeamMCPError

# Maximum captured stdout and stderr bytes (1 MB) to prevent buffer exhaustion DoS
MAX_STDIO_BYTES: int = 1_048_576


def _redact_script(script: str) -> str:
    """Redact passwords and sensitive parameters from Bluebeam Script text.

    Citations:
        - docs/citations/01_script_reference.md Section 2 (SetPDFSecurity, Open, SetOpenPassword)
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.1
    """
    if not script:
        return ""
    if redact_bcs_secrets is not None:
        try:
            return redact_bcs_secrets(script)
        except Exception:
            pass

    # Regex fallback covering SetPDFSecurity, SetOpenPassword, and 2-arg Open
    redacted = re.sub(
        r'(?i)\bSetOpenPassword\s*\(\s*(?:"[^"]*"|\'[^\']*\'|[^\s,)"]+)\s*\)',
        'SetOpenPassword("***REDACTED***")',
        script,
    )

    def _mask_set_pdf_security(match: re.Match[str]) -> str:
        inner = match.group(1).strip()
        parts = [p.strip() for p in inner.split(",")]
        if len(parts) >= 1:
            parts[0] = '"***REDACTED***"'
        if len(parts) >= 3:
            parts[2] = '"***REDACTED***"'
        return "SetPDFSecurity(" + ", ".join(parts) + ")"

    redacted = re.sub(
        r'(?i)\bSetPDFSecurity\s*\(([^)]*)\)',
        _mask_set_pdf_security,
        redacted,
    )

    def _mask_open_2arg(match: re.Match[str]) -> str:
        path_arg = match.group(1).strip()
        return f'Open({path_arg}, "***REDACTED***")'

    redacted = re.sub(
        r'(?i)\bOpen\s*\(\s*("[^"]*"|\'[^\']*\')\s*,\s*(?:"[^"]*"|\'[^\']*\'|[^\s,)"]+)\s*\)',
        _mask_open_2arg,
        redacted,
    )
    return redacted


def resolve_bluebeam_binary(binary_name: str, default_path: Path) -> Path:
    """Resolve Bluebeam binary from environment, Windows registry, or default path.

    Primary citations:
    - docs/citations/02_binary_and_dotnet_surface.md Section 4.1 (Binary Discovery)
    - docs/ARCHITECTURE.md Section 3.1
    """
    env_dir = os.environ.get("BLUEBEAM_REVU_DIR")
    if env_dir:
        cand = Path(env_dir) / binary_name
        if cand.exists():
            return cand
        cand_revu = Path(env_dir) / "Revu" / binary_name
        if cand_revu.exists():
            return cand_revu
        return cand

    if sys.platform == "win32":
        try:
            import winreg

            subkeys = (
                r"SOFTWARE\Bluebeam Software\21",
                r"SOFTWARE\WOW6432Node\Bluebeam Software\21",
            )
            for subkey in subkeys:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                        for val_name in ("InstallFolder", "RevuLauncherFolder", "InstallPath"):
                            try:
                                val, _ = winreg.QueryValueEx(key, val_name)
                                if val:
                                    cand = Path(val) / binary_name
                                    if cand.exists():
                                        return cand
                                    cand_revu = Path(val) / "Revu" / binary_name
                                    if cand_revu.exists():
                                        return cand_revu
                            except OSError:
                                pass
                except OSError:
                    pass
        except Exception:
            pass

    return default_path


def get_scratch_dir() -> Path:
    """Return the root scratch directory for Bluebeam MCP job isolation.

    Citations:
        - docs/ARCHITECTURE.md Section 3.1
        - docs/TEST_AND_SECURITY_MATRIX.md Section 1.4
    """
    env_path = os.environ.get("BLUEBEAM_MCP_SCRATCH_DIR")
    if env_path:
        scratch = Path(env_path)
    elif "pytest" in sys.modules and (Path(__file__).resolve().parents[2] / "tests" / "tmp").exists():
        scratch = Path(__file__).resolve().parents[2] / "tests" / "tmp"
    else:
        scratch = Path(tempfile.gettempdir()) / "bluebeam_mcp_jobs"
    scratch.mkdir(parents=True, exist_ok=True)
    return scratch


# Verified paths with dynamic registry / env discovery
SCRIPT_ENGINE_EXE: Path = resolve_bluebeam_binary(
    "ScriptEngine.exe",
    Path(r"C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Revu\ScriptEngine.exe"),
)
STAPLER_EXE: Path = resolve_bluebeam_binary(
    "Stapler.exe",
    Path(r"C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Revu\Stapler.exe"),
)
PBMNGR_EXE: Path = resolve_bluebeam_binary(
    "PbMngr5.exe",
    Path(r"C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Pushbutton PDF\PbMngr5.exe"),
)
REVU_EXE: Path = resolve_bluebeam_binary(
    "Revu.exe",
    Path(r"C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Revu\Revu.exe"),
)
_PBMNGR_ALT: Path = Path(r"C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Revu\PbMngr5.exe")
SCRATCH_DIR: Path = get_scratch_dir()


def get_pbmngr_exe() -> Path:
    """Return the verified existing path to PbMngr5.exe."""
    if PBMNGR_EXE.exists():
        return PBMNGR_EXE
    if _PBMNGR_ALT.exists():
        return _PBMNGR_ALT
    return PBMNGR_EXE


# Windows Job Object structures for kernel-level process tree termination
if sys.platform == "win32":
    from ctypes import wintypes

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryLimit", ctypes.c_size_t),
            ("PeakJobMemoryLimit", ctypes.c_size_t),
        ]


def _create_kill_on_close_job() -> int | None:
    """Create a Windows Job Object configured to kill all processes on handle close."""
    if sys.platform != "win32":
        return None
    try:
        job = ctypes.windll.kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        job_limit_kill_on_close = 0x00002000
        extended_limit_info_class = 9
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = job_limit_kill_on_close
        success = ctypes.windll.kernel32.SetInformationJobObject(
            job,
            extended_limit_info_class,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not success:
            ctypes.windll.kernel32.CloseHandle(job)
            return None
        return int(job)
    except Exception:
        return None


def _assign_process_to_job(job_handle: int | None, proc_handle: int) -> None:
    """Assign a Windows process handle to a Job Object."""
    if job_handle is None or sys.platform != "win32":
        return
    try:
        ctypes.windll.kernel32.AssignProcessToJobObject(job_handle, proc_handle)
    except Exception:
        pass


def _close_job_handle(job_handle: int | None) -> None:
    """Safely close a Windows Job Object handle."""
    if job_handle is None or sys.platform != "win32":
        return
    try:
        ctypes.windll.kernel32.CloseHandle(job_handle)
    except Exception:
        pass


@dataclass
class ScriptEngineReceipt:
    """Execution receipt returned by ScriptEngine or native fallback runners.

    Primary citations:
    - docs/citations/02_binary_and_dotnet_surface.md Section 4.2, Section 7.4
    - docs/ARCHITECTURE.md Section 5.1
    """

    exit_code: int
    raw_exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    bcs_script: str
    engine_used: str  # "script_engine", "native_fallback", "native_direct", "script_only"
    entitlement_restricted: bool = False

    def __post_init__(self) -> None:
        self.bcs_script = _redact_script(self.bcs_script)

    def to_dict(self) -> dict[str, Any]:
        """Convert receipt to dictionary matching ARCHITECTURE.md schema."""
        return {
            "exit_code": self.exit_code,
            "raw_exit_code": self.raw_exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": round(self.duration_seconds, 4),
            "duration_ms": round(self.duration_seconds * 1000.0, 2),
            "bcs_script": self.bcs_script,
            "engine_used": self.engine_used,
            "entitlement_restricted": self.entitlement_restricted,
        }


def to_signed_exit_code(code: int) -> int:
    """Convert unsigned 32-bit Windows exit code to signed 32-bit integer.

    Example: converts 4294967292 to -4.
    Primary citation: docs/citations/02_binary_and_dotnet_surface.md Section 7.4
    """
    return ctypes.c_int32(code).value


def kill_process_tree(pid: int) -> None:
    """Forcibly terminate a Windows process and all child processes.

    Prevents zombie processes using taskkill /F /T /PID.
    Primary citations:
    - docs/ARCHITECTURE.md Section 2.3, Section 4.4
    - docs/TEST_AND_SECURITY_MATRIX.md Section 1.4
    """
    if sys.platform != "win32":
        return
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            creationflags=creationflags,
            timeout=10,
        )
    except Exception:
        # Ignore taskkill failures if the process tree already exited
        pass


def run_subprocess_safely(
    cmd: list[str],
    timeout_seconds: float = 30.0,
    stdin_text: str | None = None,
    cwd: Path | None = None,
) -> tuple[int, int, str, str, float]:
    """Execute a subprocess safely with strict timeout watchdog and tree cleanup.

    Returns:
        tuple of (signed_exit_code, raw_exit_code, stdout, stderr, elapsed_seconds)

    Raises:
        SubprocessTimeoutError: If the process exceeds timeout_seconds.
        BluebeamError: On unexpected spawn or execution errors.

    Primary citations:
    - docs/citations/02_binary_and_dotnet_surface.md Section 7.2
    - docs/ARCHITECTURE.md Section 3.1
    - docs/TEST_AND_SECURITY_MATRIX.md Section 1.4
    """
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if sys.platform == "win32" else 0
    start_time = time.perf_counter()
    job_handle = _create_kill_on_close_job()

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL if stdin_text is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
            cwd=str(cwd) if cwd is not None else None,
        )
        if job_handle is not None and hasattr(proc, "_handle") and proc._handle:
            _assign_process_to_job(job_handle, int(proc._handle))
    except FileNotFoundError as err:
        _close_job_handle(job_handle)
        raise EngineUnavailableError(
            f"Executable not found: {cmd[0]}",
            details={"cmd": cmd[0], "error": str(err)},
        ) from err
    except Exception as err:
        _close_job_handle(job_handle)
        raise BluebeamError(
            f"Failed to spawn subprocess: {err}",
            details={"cmd": cmd[0], "error": str(err)},
        ) from err

    try:
        stdout, stderr = proc.communicate(input=stdin_text, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _close_job_handle(job_handle)
        job_handle = None

        if proc.poll() is None:
            kill_process_tree(proc.pid)
            try:
                proc.kill()
            except OSError:
                pass

        for stream in (proc.stdout, proc.stderr, proc.stdin):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

        try:
            proc.communicate(timeout=2.0)
        except Exception:
            pass

        raise SubprocessTimeoutError(
            f"Process timed out after {timeout_seconds}s",
            details={"cmd": cmd[0], "timeout_seconds": timeout_seconds},
        )
    finally:
        _close_job_handle(job_handle)

    elapsed_seconds = time.perf_counter() - start_time
    raw_code = proc.returncode if proc.returncode is not None else -1
    signed_code = to_signed_exit_code(raw_code)

    capped_stdout = (stdout or "")[:MAX_STDIO_BYTES]
    capped_stderr = (stderr or "")[:MAX_STDIO_BYTES]

    return signed_code, raw_code, capped_stdout, capped_stderr, elapsed_seconds


def run_script_engine(
    bcs_script: str,
    timeout_seconds: float = 30.0,
    inline: bool = False,
) -> ScriptEngineReceipt:
    """Execute Bluebeam ScriptEngine.exe with the specified script.

    Creates an isolated per-job temporary directory and .bcs script file.
    Securely zeroes the script before unlinking and removes the temporary directory.
    Returns a ScriptEngineReceipt recording return codes, output, and entitlement state.

    Primary citations:
    - docs/citations/01_script_reference.md Section 1
    - docs/citations/02_binary_and_dotnet_surface.md Section 4.2, Section 7.2, Section 7.4
    - docs/ARCHITECTURE.md Section 3.1
    """
    if not SCRIPT_ENGINE_EXE.exists():
        raise EngineUnavailableError(
            f"ScriptEngine executable not found at {SCRIPT_ENGINE_EXE}",
            details={"path": str(SCRIPT_ENGINE_EXE)},
        )

    scratch_root = get_scratch_dir()
    job_dir = Path(tempfile.mkdtemp(prefix="bb_job_", dir=str(scratch_root)))
    temp_bcs_path = job_dir / "job.bcs"

    try:
        temp_bcs_path.write_text(bcs_script, encoding="utf-8", newline="")
        cmd = [str(SCRIPT_ENGINE_EXE), f'Script("{temp_bcs_path}")']

        signed_code, raw_code, stdout, stderr, elapsed = run_subprocess_safely(
            cmd=cmd,
            timeout_seconds=timeout_seconds,
            cwd=job_dir,
        )

        entitlement_restricted = (signed_code == -4)

        return ScriptEngineReceipt(
            exit_code=signed_code,
            raw_exit_code=raw_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=elapsed,
            bcs_script=_redact_script(bcs_script),
            engine_used="script_engine",
            entitlement_restricted=entitlement_restricted,
        )
    finally:
        try:
            if temp_bcs_path.exists():
                size = temp_bcs_path.stat().st_size
                with open(temp_bcs_path, "wb") as f:
                    f.write(b"\x00" * size)
                temp_bcs_path.unlink(missing_ok=True)
        except Exception:
            pass
        shutil.rmtree(job_dir, ignore_errors=True)


def format_success_envelope(
    data: dict[str, Any],
    receipt: ScriptEngineReceipt | None = None,
    tool_name: str = "",
    citations: list[str] | None = None,
) -> dict[str, Any]:
    """Format a successful MCP response envelope conforming to ARCHITECTURE.md.

    Primary citations:
    - docs/ARCHITECTURE.md Section 5.1, Section 5.2
    """
    if receipt is not None:
        receipt.bcs_script = _redact_script(receipt.bcs_script)
        if receipt.engine_used == "native_fallback" or receipt.exit_code == -4:
            status = "subscription_fallback"
        else:
            status = "success"

        if receipt.engine_used == "script_only":
            execution_engine = "none"
        else:
            execution_engine = receipt.engine_used

        receipt_dict = receipt.to_dict()
        bcs_script = receipt.bcs_script
    else:
        status = "success"
        execution_engine = "none"
        receipt_dict = {
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0.0,
        }
        bcs_script = _redact_script(data.get("bcs_script", ""))

    clean_data = dict(data)
    is_script_only = (receipt is not None and receipt.engine_used == "script_only")
    if is_script_only:
        clean_data["bcs_script"] = bcs_script
    else:
        clean_data.pop("bcs_script", None)

    return {
        "status": status,
        "tool": tool_name,
        "execution_engine": execution_engine,
        "bcs_script": bcs_script,
        "script_engine_receipt": receipt_dict,
        "data": clean_data,
        "citations": citations or [],
    }


def format_error_envelope(err: Exception, tool_name: str = "") -> dict[str, Any]:
    """Format an error MCP response envelope conforming to ARCHITECTURE.md.

    Primary citations:
    - docs/ARCHITECTURE.md Section 5.1
    - docs/TEST_AND_SECURITY_MATRIX.md Section 3.3
    """
    code = "INTERNAL_ERROR"
    category = "unhandled"

    if isinstance(err, XMLDefuseError):
        code = "XML_PARSE_ERROR"
        category = "security"
    elif isinstance(err, CorruptStreamError):
        code = "CORRUPT_RAW_STREAM"
        category = "data_validation"
    elif isinstance(err, EmptyFileError):
        code = "EMPTY_FILE"
        category = "data_validation"
    elif (
        (EncryptedPDFError is not None and isinstance(err, EncryptedPDFError))
        or getattr(err, "error_code", "") == "ENCRYPTED_PDF"
        or err.__class__.__name__ == "EncryptedPDFError"
    ):
        code = "ENCRYPTED_PDF"
        category = "security"
    elif isinstance(err, SecurityViolationError):
        code = "SECURITY_VIOLATION"
        category = "security"
    elif isinstance(err, FileNotFoundError):
        code = "FILE_NOT_FOUND"
        category = "filesystem"
    elif isinstance(err, FileTooLargeError):
        code = "FILE_TOO_LARGE"
        category = "resource_limit"
    elif isinstance(err, FileLockedError):
        code = "FILE_LOCKED"
        category = "concurrency"
    elif isinstance(err, CorruptPDFError):
        code = "INVALID_PDF"
        category = "data_validation"
    elif isinstance(err, PageRangeError):
        code = "PAGE_OUT_OF_RANGE"
        category = "data_validation"
    elif isinstance(err, SubprocessTimeoutError):
        code = "SUBPROCESS_TIMEOUT"
        category = "timeout"
    elif isinstance(err, EngineExecutionError):
        code = getattr(err, "error_code", "ENGINE_FAILURE")
        category = "execution"
    elif isinstance(err, BluebeamMCPError):
        code = getattr(err, "error_code", "BLUEBEAM_ERROR")
        category = "validation" if code == "INVALID_PARAMETER" else "execution"
    elif isinstance(err, ValueError):
        code = "INVALID_PARAMETER"
        category = "validation"

    details: dict[str, Any] = {}
    if hasattr(err, "details") and isinstance(err.details, dict):
        details = dict(err.details)
        details.pop("cmd", None)
        if "bcs_script" in details and isinstance(details["bcs_script"], str):
            details["bcs_script"] = _redact_script(details["bcs_script"])

    bcs_script = ""
    if "bcs_script" in details and isinstance(details["bcs_script"], str):
        bcs_script = details["bcs_script"]

    error_payload: dict[str, Any] = {
        "code": code,
        "message": str(err),
        "category": category,
    }
    if details:
        error_payload["details"] = details

    return {
        "status": "error",
        "tool": tool_name,
        "execution_engine": "none",
        "bcs_script": bcs_script,
        "script_engine_receipt": None,
        "data": {},
        "citations": [],
        "error": error_payload,
    }


def execute_dual_engine(
    bcs_script: str,
    native_fn: Callable[[], dict[str, Any]] | None = None,
    execution_mode: str = "auto",
    timeout_seconds: float = 30.0,
    tool_name: str = "",
    citations: list[str] | None = None,
    on_success_fn: Callable[[ScriptEngineReceipt], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute Bluebeam Script with compliant dual-engine orchestration.

    Modes:
    - "auto" (default): Runs ScriptEngine.exe; falls back transparently to native_fn on -4
      or when ScriptEngine binary is not installed.
    - "script_only": Generates script without executing any subprocess or native action.
    - "script_engine_strict": Runs ScriptEngine.exe; raises error on -4 without fallback.
    - "native_only": Executes native_fn directly without invoking ScriptEngine.exe.

    Primary citations:
    - docs/ARCHITECTURE.md Section 3 (Compliant Dual-Engine Execution Architecture)
    - docs/citations/02_binary_and_dotnet_surface.md Section 7.4 (Exit Code Summary)
    """
    valid_modes = ("auto", "script_only", "script_engine_strict", "native_only")
    if execution_mode not in valid_modes:
        raise ValueError(
            f"Invalid execution_mode '{execution_mode}'. Must be one of: {valid_modes}"
        )

    # 1. Script-only mode: validate and return script artifact
    if execution_mode == "script_only":
        redacted = _redact_script(bcs_script)
        receipt = ScriptEngineReceipt(
            exit_code=0,
            raw_exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            bcs_script=redacted,
            engine_used="script_only",
            entitlement_restricted=False,
        )
        return format_success_envelope(
            data={"bcs_script": redacted},
            receipt=receipt,
            tool_name=tool_name,
            citations=citations,
        )

    # 2. Native-only mode: direct execution
    if execution_mode == "native_only":
        if native_fn is None:
            raise EngineExecutionError(
                "native_only execution mode requested but no native fallback function provided",
                details={"execution_mode": execution_mode, "bcs_script": _redact_script(bcs_script)},
            )
        start_t = time.perf_counter()
        data = native_fn()
        elapsed = time.perf_counter() - start_t
        receipt = ScriptEngineReceipt(
            exit_code=0,
            raw_exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=elapsed,
            bcs_script=_redact_script(bcs_script),
            engine_used="native_direct",
            entitlement_restricted=False,
        )
        return format_success_envelope(
            data=data,
            receipt=receipt,
            tool_name=tool_name,
            citations=citations,
        )

    # 3. Invoke ScriptEngine.exe with graceful fallback when missing
    start_engine_time = time.perf_counter()
    try:
        receipt = run_script_engine(bcs_script, timeout_seconds=timeout_seconds)
    except (EngineUnavailableError, FileNotFoundError) as err:
        elapsed = time.perf_counter() - start_engine_time
        if execution_mode == "auto" and native_fn is not None:
            data = native_fn()
            fallback_receipt = ScriptEngineReceipt(
                exit_code=-4,
                raw_exit_code=-4,
                stdout="",
                stderr="ScriptEngine.exe not found; executed native fallback",
                duration_seconds=elapsed,
                bcs_script=_redact_script(bcs_script),
                engine_used="native_fallback",
                entitlement_restricted=True,
            )
            return format_success_envelope(
                data=data,
                receipt=fallback_receipt,
                tool_name=tool_name,
                citations=citations,
            )
        raise EngineExecutionError(
            f"ScriptEngine.exe is not available: {err}",
            details={"bcs_script": _redact_script(bcs_script), "error": str(err)},
        ) from err

    # On exit code 0: ScriptEngine succeeded. Never call native_fn to avoid overwriting Bluebeam output!
    if receipt.exit_code == 0:
        if on_success_fn is not None:
            data = on_success_fn(receipt)
        else:
            data = {
                "bcs_script": _redact_script(bcs_script),
                "output": (receipt.stdout or "").strip(),
            }
        receipt.engine_used = "script_engine"
        return format_success_envelope(
            data=data,
            receipt=receipt,
            tool_name=tool_name,
            citations=citations,
        )

    # On exit code -4: subscription level restriction
    if receipt.exit_code == -4:
        if execution_mode == "script_engine_strict" or native_fn is None:
            raise EngineExecutionError(
                "ScriptEngine.exe returned exit code -4 (Revu Complete subscription required)",
                details={
                    "cli_exit_code": -4,
                    "cli_stdout": (receipt.stdout or "").strip(),
                    "bcs_script": _redact_script(bcs_script),
                },
            )
        # Transparent native fallback on Revu Core or Basics
        data = native_fn()
        receipt.engine_used = "native_fallback"
        return format_success_envelope(
            data=data,
            receipt=receipt,
            tool_name=tool_name,
            citations=citations,
        )

    # Non-zero exit code: -1 (syntax), -3 (runtime), or other fatal error
    raise EngineExecutionError(
        f"ScriptEngine.exe failed with exit code {receipt.exit_code}",
        details={
            "cli_exit_code": receipt.exit_code,
            "cli_stdout": (receipt.stdout or "").strip(),
            "cli_stderr": (receipt.stderr or "").strip(),
            "bcs_script": _redact_script(bcs_script),
        },
    )


def run_stapler_job(
    job_file: Path | str,
    timeout_seconds: float = 60.0,
) -> ScriptEngineReceipt:
    """Execute Bluebeam Stapler.exe with redline(<path>) headless syntax.

    Primary citations:
    - docs/citations/02_binary_and_dotnet_surface.md Section 6
    - docs/ARCHITECTURE.md Section 3.3
    """
    cmd = [str(STAPLER_EXE), f'redline("{job_file}")']
    signed_code, raw_code, stdout, stderr, elapsed = run_subprocess_safely(
        cmd=cmd,
        timeout_seconds=timeout_seconds,
        cwd=get_scratch_dir(),
    )
    return ScriptEngineReceipt(
        exit_code=signed_code,
        raw_exit_code=raw_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=elapsed,
        bcs_script=f'redline("{job_file}")',
        engine_used="stapler",
        entitlement_restricted=False,
    )


def run_pbmngr(
    args: list[str],
    timeout_seconds: float = 30.0,
) -> tuple[int, int, str, str, float]:
    """Execute Bluebeam Administrator (PbMngr5.exe) with specified flags.

    Primary citations:
    - docs/citations/03_data_formats_and_markups.md Section 6
    - docs/ARCHITECTURE.md Section 3.3
    """
    exe_path = get_pbmngr_exe()
    cmd = [str(exe_path)] + args
    return run_subprocess_safely(
        cmd=cmd,
        timeout_seconds=timeout_seconds,
        cwd=get_scratch_dir(),
    )


__all__ = [
    "SCRIPT_ENGINE_EXE",
    "STAPLER_EXE",
    "PBMNGR_EXE",
    "REVU_EXE",
    "SCRATCH_DIR",
    "MAX_STDIO_BYTES",
    "EngineUnavailableError",
    "ScriptEngineReceipt",
    "to_signed_exit_code",
    "kill_process_tree",
    "run_subprocess_safely",
    "run_script_engine",
    "execute_dual_engine",
    "format_success_envelope",
    "format_error_envelope",
    "run_stapler_job",
    "run_pbmngr",
    "get_pbmngr_exe",
    "get_scratch_dir",
    "resolve_bluebeam_binary",
]
