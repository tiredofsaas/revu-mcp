"""System environment, profiles, toolsets, stamps, and script execution tools for Bluebeam Revu 21.

Provides comprehensive discovery of Bluebeam Revu 21 registry configurations, binary health,
toolset (.btx) decompression and authoring, profile (.bpx) parsing, stamp library inspection,
PbMngr5 administrator CLI generation, and safe custom script execution.

Primary citations:
- docs/ARCHITECTURE.md Section 6.3 (Category 3 Tool Catalog)
- docs/citations/01_script_reference.md Section 1 (Syntax), Section 2 (Exhaustive Command Reference)
- docs/citations/02_binary_and_dotnet_surface.md Section 2 (Binary Inventory), Section 3 (Registry Configuration Surface),
  Section 4.2 (ScriptEngine Execution), Section 5.2 (Command Inventory), Section 6 (Auxiliary Binaries),
  Section 7.2 (Live CLI Execution), Section 7.4 (Exit Code Summary)
- docs/citations/03_data_formats_and_markups.md Section 1 (File Locations), Section 2 (Tool Set BTX Schema),
  Section 3 (Profile BPX Schema), Section 4 (Stamp Dictionary Structure), Section 6 (PbMngr5 CLI Options)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2.1 (T1-08), Section 2.2 (T2-12..T2-15), Section 2.3 (T3-10), Section 2.4 (T4-04..T4-07)
"""

from __future__ import annotations

import io
import math
import os
from pathlib import Path
import re
from typing import Any, Literal
import xml.etree.ElementTree as ET
import zlib

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows fallback

import pypdf
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    TextStringObject,
)
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas

from bluebeam_mcp.engine import (
    REVU_EXE,
    SCRIPT_ENGINE_EXE,
    STAPLER_EXE,
    EngineExecutionError,
    execute_dual_engine,
    format_error_envelope,
    format_success_envelope,
    get_pbmngr_exe,
    run_script_engine,
)
from bluebeam_mcp.script_builder import (
    ALLOW_PRIVILEGED_COMMANDS,
    KNOWN_BCS_COMMANDS_MAP,
    PRIVILEGED_BCS_COMMANDS,
    SAFE_BCS_COMMANDS,
    ScriptBuilder,
    build_command,
    redact_bcs_secrets,
)
from bluebeam_mcp.security import (
    FORBIDDEN_ROOTS,
    READ_ONLY_ROOTS,
    BluebeamMCPError,
    CorruptStreamError,
    FileLockedError,
    InvalidParameterError,
    SecurityViolationError,
    XMLDefuseError,
    atomic_write_bytes,
    atomic_write_pdf,
    clean_xml_text,
    decompress_btx_raw,
    parse_xml_safely,
    sanitize_untrusted_text,
    validate_path,
)

# ============================================================================
# Module-Level Probe Receipt Cache (M-11)
# ============================================================================

_CACHED_PROBE_RECEIPT: dict[str, Any] | None = None

# Unicode line and paragraph separators disallowed in Bluebeam Script text
_DISALLOWED_SCRIPT_SEPARATORS: tuple[str, ...] = (
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
# Administrator CLI (PbMngr5.exe) Plugin Constants
# ============================================================================

# Bitwise plugin flags matching docs/citations/03_data_formats_and_markups.md Section 6
PBMNGR_PLUGIN_FLAGS: dict[str, int] = {
    "office": 1,
    "autocad": 2,
    "autocad_lt": 4,
    "autocadlt": 4,
    "solidworks": 8,
    "revit": 16,
    "ie": 32,
    "internet_explorer": 32,
    "internetexplorer": 32,
    "projectwise": 64,
    "outlook": 128,
    "sketchup": 256,
}
ALL_PBMNGR_PLUGIN_FLAGS: int = 1023


def build_pbmngr_cli_args(
    install_plugins: list[str] | int | None = None,
    default_page_size: str | None = None,
    default_viewer: bool | None = None,
    setup: bool = False,
) -> list[str]:
    """Build command-line arguments for Bluebeam Administrator (PbMngr5.exe).

    Implements exact PbMngr5 switches from primary documentation:
    - /IF:<flags> where Office=1, AutoCAD=2, AutoCAD_LT=4, SolidWorks=8, Revit=16,
      IE=32, ProjectWise=64, Outlook=128, SketchUp=256, all=1023.
    - /DPS:Letter or /DPS:A4 default page size.
    - /DVON or /DVOFF default PDF editor switches.
    - /setup deployment configuration switch.

    Primary citations:
        - docs/citations/03_data_formats_and_markups.md Section 6 (PbMngr5 CLI Options).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.1 (T1-08: test_pbmngr5_cli_flag_builders).

    Args:
        install_plugins: Integer bitmask (0..1023) or list of plugin names to install.
        default_page_size: Default printer page size ("Letter" or "A4").
        default_viewer: If True adds /DVON, if False adds /DVOFF.
        setup: If True adds /setup deployment flag.

    Returns:
        List of formatted CLI switch strings.

    Raises:
        ValueError: On unknown plugin name, out-of-range bitmask, or invalid page size.
    """
    args: list[str] = []

    if install_plugins is not None:
        if isinstance(install_plugins, int):
            if install_plugins < 0 or install_plugins > ALL_PBMNGR_PLUGIN_FLAGS:
                raise ValueError(
                    f"Invalid plugin bitmask {install_plugins}. Permitted range is 0 to {ALL_PBMNGR_PLUGIN_FLAGS}."
                )
            args.append(f"/IF:{install_plugins}")
        elif isinstance(install_plugins, (list, tuple, set)):
            bitmask = 0
            for item in install_plugins:
                norm = str(item).strip().lower().replace("-", "_").replace(" ", "_")
                if norm in ("all", "all_plugins"):
                    bitmask = ALL_PBMNGR_PLUGIN_FLAGS
                    break
                if norm not in PBMNGR_PLUGIN_FLAGS:
                    raise ValueError(
                        f"Unknown plugin name '{item}'. Supported plugins: {sorted(set(PBMNGR_PLUGIN_FLAGS.keys()))}"
                    )
                bitmask |= PBMNGR_PLUGIN_FLAGS[norm]
            args.append(f"/IF:{bitmask}")
        else:
            raise ValueError(f"Invalid type for install_plugins: {type(install_plugins)}")

    if default_page_size is not None:
        norm_size = default_page_size.strip().lower()
        if norm_size == "letter":
            args.append("/DPS:Letter")
        elif norm_size == "a4":
            args.append("/DPS:A4")
        else:
            raise ValueError(
                f"Invalid default page size '{default_page_size}'. Supported page sizes are 'Letter' or 'A4'."
            )

    if default_viewer is not None:
        if default_viewer is True:
            args.append("/DVON")
        elif default_viewer is False:
            args.append("/DVOFF")

    if setup:
        args.append("/setup")

    return args


# ============================================================================
# Tool 1: bb_env_status
# ============================================================================


def _read_registry_key_values(hkey: int, subkey: str) -> dict[str, Any]:
    """Helper to safely read all string and integer values from a Windows Registry key."""
    if winreg is None:
        return {}
    values: dict[str, Any] = {}
    try:
        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
            num_values = winreg.QueryInfoKey(key)[1]
            for i in range(num_values):
                name, val, _ = winreg.EnumValue(key, i)
                values[name] = val
    except (OSError, FileNotFoundError, PermissionError):
        pass
    return values


def bb_env_status(
    probe_script_engine: bool = True,
    force_probe: bool = False,
) -> dict[str, Any]:
    """Query Bluebeam Revu 21 environment status, registry keys, binary health, and entitlement tier.

    Inspects:
    1. HKLM\\SOFTWARE\\Bluebeam Software\\21 (InstallFolder, RevuBuildNo, HelpFolder, CommonFilesFolder).
    2. HKLM\\SOFTWARE\\Bluebeam Software\\21\\Brewery\\V45\\Applications (printer conversion presets).
    3. HKCU\\Software\\Bluebeam Software\\21\\Revu (ProductPackage subscription tier).
    4. Existence, paths, and byte sizes of ScriptEngine.exe, Revu.exe, Stapler.exe, PbMngr5.exe.
    5. Installed toolsets (.btx) and profiles (.bpx) in %APPDATA%\\Bluebeam Software\\Revu\\21.
    6. Installed stamp PDF files in C:\\ProgramData\\Bluebeam Software\\Bluebeam Revu\\21\\Stamps.
    7. Optionally probes live ScriptEngine.exe via PageCount() to report entitlement status,
       caching probe receipts across calls to prevent redundant subprocess spawning.
    8. Diagnostic health audit of required Python dependencies (PIL, pypdf, reportlab, defusedxml, pydantic, mcp).

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Tool 1: bb_env_status).
        - docs/citations/02_binary_and_dotnet_surface.md Section 2, Section 3, Section 7.4.
        - docs/citations/03_data_formats_and_markups.md Section 1 (File Locations).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.4 (T4-07); Findings M-11, M-14.

    Args:
        probe_script_engine: If True, executes or retrieves a cached headless probe to verify entitlement.
        force_probe: If True, bypasses module-level receipt cache and runs a fresh ScriptEngine probe.

    Returns:
        Structured response envelope containing complete environment metrics.
    """
    global _CACHED_PROBE_RECEIPT
    try:
        # 1. Query Registry Keys
        hklm_main = {}
        brewery_apps = {}
        hkcu_revu = {}
        if winreg is not None:
            hklm_main = _read_registry_key_values(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Bluebeam Software\21"
            )
            brewery_apps = _read_registry_key_values(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Bluebeam Software\21\Brewery\V45\Applications"
            )
            hkcu_revu = _read_registry_key_values(
                winreg.HKEY_CURRENT_USER, r"Software\Bluebeam Software\21\Revu"
            )

        # 2. Inspect Executables
        pbmngr_exe = get_pbmngr_exe()
        binaries: dict[str, dict[str, Any]] = {}
        binary_targets = [
            ("script_engine", SCRIPT_ENGINE_EXE),
            ("revu", REVU_EXE),
            ("stapler", STAPLER_EXE),
            ("pbmngr", pbmngr_exe),
        ]
        for name, path_obj in binary_targets:
            exists = path_obj.exists()
            size_bytes = path_obj.stat().st_size if exists else 0
            binaries[name] = {
                "path": str(path_obj),
                "exists": exists,
                "size_bytes": size_bytes,
            }

        # 3. Enumerate Toolsets (.btx) and Profiles (.bpx) in %APPDATA%
        appdata_root = os.environ.get("APPDATA")
        toolsets: list[dict[str, Any]] = []
        profiles: list[dict[str, Any]] = []

        if appdata_root:
            appdata_revu_dir = Path(appdata_root) / "Bluebeam Software" / "Revu" / "21"
            if appdata_revu_dir.is_dir():
                for btx_file in sorted(appdata_revu_dir.glob("*.btx")):
                    toolsets.append({
                        "name": btx_file.name,
                        "path": str(btx_file),
                        "size_bytes": btx_file.stat().st_size,
                    })
                for bpx_file in sorted(appdata_revu_dir.glob("*.bpx")):
                    profiles.append({
                        "name": bpx_file.name,
                        "path": str(bpx_file),
                        "size_bytes": bpx_file.stat().st_size,
                    })

        # 4. Enumerate Stamps in ProgramData
        stamps_dir = Path(r"C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\Stamps")
        stamps: list[dict[str, Any]] = []
        if stamps_dir.is_dir():
            for stamp_pdf in sorted(stamps_dir.glob("*.pdf")):
                stamps.append({
                    "name": stamp_pdf.name,
                    "path": str(stamp_pdf),
                    "size_bytes": stamp_pdf.stat().st_size,
                })

        # 5. Live ScriptEngine probe with module-level caching (M-11)
        probe_receipt_dict: dict[str, Any] | None = None
        entitlement_tier = hkcu_revu.get("ProductPackage", "Unknown")

        if probe_script_engine and SCRIPT_ENGINE_EXE.exists():
            if not force_probe and _CACHED_PROBE_RECEIPT is not None:
                probe_receipt_dict = _CACHED_PROBE_RECEIPT
            else:
                receipt = run_script_engine("PageCount()", timeout_seconds=5.0)
                probe_receipt_dict = receipt.to_dict()
                _CACHED_PROBE_RECEIPT = probe_receipt_dict

            exit_code = probe_receipt_dict.get("exit_code")
            if exit_code == 0:
                entitlement_tier = "Complete"
            elif exit_code == -4:
                entitlement_tier = "Core" if entitlement_tier == "Unknown" else entitlement_tier

        # 6. Python dependency health check (M-14)
        dependencies: dict[str, dict[str, Any]] = {}
        for pkg_name in ("PIL", "pypdf", "reportlab", "defusedxml", "pydantic", "mcp"):
            try:
                mod = __import__(pkg_name)
                ver = getattr(mod, "__version__", "installed")
                dependencies[pkg_name] = {
                    "available": True,
                    "version": str(ver),
                }
            except ImportError as imp_err:
                dependencies[pkg_name] = {
                    "available": False,
                    "error": str(imp_err),
                }

        data: dict[str, Any] = {
            "revu_build_no": hklm_main.get("RevuBuildNo", "Unknown"),
            "install_folder": hklm_main.get("InstallFolder", ""),
            "help_folder": hklm_main.get("HelpFolder", ""),
            "common_files_folder": hklm_main.get("CommonFilesFolder", ""),
            "product_package": hkcu_revu.get("ProductPackage", entitlement_tier),
            "entitlement_tier": entitlement_tier,
            "registry_hklm_main": hklm_main,
            "printer_conversion_presets": brewery_apps,
            "registry_hkcu_revu": hkcu_revu,
            "binaries": binaries,
            "dependencies": dependencies,
            "toolset_count": len(toolsets),
            "toolsets": toolsets,
            "profile_count": len(profiles),
            "profiles": profiles,
            "stamp_count": len(stamps),
            "stamps": stamps,
            "script_engine_probe": probe_receipt_dict,
        }

        citations = [
            "docs/citations/02_binary_and_dotnet_surface.md Section 2 (Binary Inventory)",
            "docs/citations/02_binary_and_dotnet_surface.md Section 3 (Registry Surface)",
            "docs/citations/03_data_formats_and_markups.md Section 1 (File Locations)",
        ]

        return format_success_envelope(data=data, tool_name="bb_env_status", citations=citations)

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name="bb_env_status")


# ============================================================================
# Tool 2: bb_script_generate_and_run
# ============================================================================


def bb_script_generate_and_run(
    commands: list[dict[str, Any]] | None = None,
    script_text: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Compose, validate, and execute custom Bluebeam Script (.bcs) operations.

    Accepts structured command lists or pre-formed script text.
    Validates command names against KNOWN_BCS_COMMANDS and enforces server-side privilege
    boundaries (SAFE_BCS_COMMANDS vs PRIVILEGED_BCS_COMMANDS controlled by
    BLUEBEAM_MCP_ALLOW_PRIVILEGED read once at startup).
    Enforces pipe and quote escaping via build_command and parse_and_validate_bcs_line.
    Strictly denies path references to protected roots (BLUEBEAM_MCP_FORBIDDEN_ROOTS)
    and blocks DeleteFile on system protected directories.
    Handles ScriptEngine -4 exit code with SUBSCRIPTION_REQUIRED error because arbitrary
    custom scripts have no native Python fallback.

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Tool 2: bb_script_generate_and_run).
        - docs/citations/01_script_reference.md Section 1, Section 2.
        - docs/citations/02_binary_and_dotnet_surface.md Section 4.2, Section 5.2, Section 7.4.
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2 (T2-01..T2-08); Findings C-01, H-20, H-22, F-01.

    Args:
        commands: List of command dicts: [{"name": "Open", "args": ["sample.pdf"]}, ...].
        script_text: Raw Bluebeam Script text (mutually exclusive with commands).
        execution_mode: "auto", "script_only", "script_engine_strict", or "native_only".
        timeout_seconds: Subprocess execution watchdog in seconds (0.1 to 300.0).

    Returns:
        Structured response envelope with execution receipt and output.
    """
    try:
        # 1. Validate timeout parameter
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise InvalidParameterError("timeout_seconds must be between 0.1 and 300.0")

        # 2. Validate execution mode
        valid_modes = ("auto", "script_only", "script_engine_strict", "native_only")
        if execution_mode not in valid_modes:
            raise InvalidParameterError(
                f"Invalid execution_mode '{execution_mode}'. Must be one of: {valid_modes}"
            )

        # 3. Native-only mode rejection for arbitrary script execution (H-22)
        if execution_mode == "native_only":
            raise EngineExecutionError(
                "Custom .bcs scripts cannot be executed in native_only mode because arbitrary scripts require ScriptEngine.exe",
                error_code="SUBSCRIPTION_REQUIRED",
            )

        # 4. Validate mutual exclusivity of inputs
        if commands is None and script_text is None:
            raise InvalidParameterError("Either 'commands' or 'script_text' must be provided.")
        if commands is not None and script_text is not None:
            raise InvalidParameterError("Specify either 'commands' or 'script_text', not both.")

        builder = ScriptBuilder()

        # 5. Process structured command dictionaries
        if commands is not None:
            if not isinstance(commands, list):
                raise InvalidParameterError("'commands' parameter must be a list of command dictionaries.")

            for item in commands:
                if not isinstance(item, dict):
                    raise InvalidParameterError("Each command entry in 'commands' must be a dictionary.")
                cmd_name = item.get("name") or item.get("command")
                if not cmd_name or not isinstance(cmd_name, str):
                    raise InvalidParameterError("Command dictionary missing required 'name' or 'command' string key.")

                raw_args = item.get("args", [])
                if not isinstance(raw_args, (list, tuple)):
                    raise InvalidParameterError(f"Command '{cmd_name}' args must be a list or tuple.")

                builder.add_command(cmd_name.strip(), *raw_args, allow_privileged=ALLOW_PRIVILEGED_COMMANDS)

        # 6. Process raw script text
        else:
            assert script_text is not None
            if not isinstance(script_text, str):
                raise InvalidParameterError("'script_text' parameter must be a string.")

            if any(c in script_text for c in _DISALLOWED_SCRIPT_SEPARATORS):
                raise SecurityViolationError(
                    "Disallowed control character, line separator, or null byte detected in script text"
                )

            for forbidden in FORBIDDEN_ROOTS:
                if re.search(rf"(?i){re.escape(forbidden)}(?:[\\/'\"\s]|$)", script_text):
                    raise SecurityViolationError(
                        f"Access to protected directory is blocked in script text: {forbidden}",
                        details={"forbidden_root": forbidden},
                    )

            lines = re.split(r"\r\n|\r|\n", script_text)
            for line in lines:
                cleaned_line = line.strip()
                if not cleaned_line:
                    continue
                builder.add_raw_command(line, allow_privileged=ALLOW_PRIVILEGED_COMMANDS)

            if not builder.commands:
                raise InvalidParameterError("Script text contains no valid commands.")

        final_script = builder.build()

        citations = [
            "docs/citations/01_script_reference.md Section 1 (Syntax and Scripting Rules)",
            "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (Command Inventory)",
        ]

        # 7. Script-only execution mode (H-22)
        if execution_mode == "script_only":
            return execute_dual_engine(
                bcs_script=final_script,
                native_fn=None,
                execution_mode="script_only",
                tool_name="bb_script_generate_and_run",
                citations=citations,
            )

        # 8. Execute via ScriptEngine.exe
        receipt = run_script_engine(final_script, timeout_seconds=timeout_seconds)

        if receipt.exit_code == 0:
            return format_success_envelope(
                data={
                    "output": receipt.stdout.strip(),
                    "bcs_script": redact_bcs_secrets(final_script),
                    "executed": True,
                    "script_executed": True,
                },
                receipt=receipt,
                tool_name="bb_script_generate_and_run",
                citations=citations,
            )

        if receipt.exit_code == -4:
            raise EngineExecutionError(
                "ScriptEngine.exe returned exit code -4 (Revu Complete subscription required; custom scripts have no native fallback)",
                details={
                    "cli_exit_code": -4,
                    "cli_stdout": receipt.stdout.strip(),
                    "bcs_script": redact_bcs_secrets(final_script),
                    "executed": False,
                    "script_executed": False,
                    "entitlement_restricted": True,
                },
                error_code="SUBSCRIPTION_REQUIRED",
            )

        raise EngineExecutionError(
            f"ScriptEngine.exe failed with exit code {receipt.exit_code}",
            details={
                "cli_exit_code": receipt.exit_code,
                "cli_stdout": receipt.stdout.strip(),
                "cli_stderr": receipt.stderr.strip(),
                "bcs_script": redact_bcs_secrets(final_script),
            },
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name="bb_script_generate_and_run")


# ============================================================================
# Tool 3: bb_toolset_inspect
# ============================================================================


def _resolve_toolset_or_profile_path(
    path_str: str | Path,
    file_extension: str,
    mode: str = "read",
) -> Path:
    """Resolve a toolset (.btx) or profile (.bpx) path, checking %APPDATA% before validate_path."""
    if not path_str or not str(path_str).strip():
        raise InvalidParameterError("Path argument cannot be empty")

    raw = str(path_str).strip()

    # Reject null bytes and forbidden roots immediately
    if "\x00" in raw:
        raise SecurityViolationError("Null byte detected in path argument")
    for forbidden in FORBIDDEN_ROOTS:
        if re.search(rf"(?i){re.escape(forbidden)}(?:[\\/'\"\s]|$)", raw):
            raise SecurityViolationError(
                f"Access to protected directory is blocked: {raw}",
                details={"path": raw, "forbidden_root": forbidden},
            )

    # Check %APPDATA% directory for simple filenames
    appdata_root = os.environ.get("APPDATA")
    if appdata_root and not os.path.isabs(raw) and not raw.startswith((".", "..", "/", "\\")):
        candidate = Path(appdata_root) / "Bluebeam Software" / "Revu" / "21" / raw
        if candidate.is_file():
            return validate_path(
                candidate,
                mode=mode,
                must_exist=True,
                allowed_extensions={file_extension, ".xml"},
            )

    # Standard security validation
    return validate_path(
        raw,
        mode=mode,
        must_exist=(mode == "read"),
        allowed_extensions={file_extension, ".xml"},
    )


def bb_toolset_inspect(
    toolset_path: str,
    decompress_raw: bool = True,
) -> dict[str, Any]:
    """Parse and inspect Bluebeam Tool Set (.btx) files and decompress <Raw> markup streams.

    Resolves toolset names from %APPDATA%\\Bluebeam Software\\Revu\\21 or absolute paths.
    Parses <BluebeamRevuToolSet Version="1"> safely using defusedxml.
    Extracts <Title>, <Rollup>, and each <ToolChestItem> (<Name>, <Type>, <X>, <Y>, <Index>, <Child>).
    Sanitizes title, subject, category, and internal names using sanitize_untrusted_text.
    If decompress_raw is True and <Raw> is present, decodes hex and zlib streams with size limits.

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Tool 3: bb_toolset_inspect).
        - docs/citations/03_data_formats_and_markups.md Section 2 (Exact XML Schema of Tool Set Files).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2 (T2-12..T2-15), Section 2.4 (T4-04); Findings H-19, H-23.

    Args:
        toolset_path: Path or filename of .btx file (e.g. "Architect Review.btx").
        decompress_raw: If True, decompresses hex <Raw> elements.

    Returns:
        Structured response envelope with toolset title, metadata, and tool chest items.
    """
    try:
        resolved_path = _resolve_toolset_or_profile_path(
            toolset_path, file_extension=".btx", mode="read"
        )

        root = parse_xml_safely(resolved_path)
        if root.tag != "BluebeamRevuToolSet" and not root.tag.endswith("BluebeamRevuToolSet"):
            raise InvalidParameterError(
                f"Invalid XML root element '{root.tag}'. Expected '<BluebeamRevuToolSet>'."
            )

        version = root.attrib.get("Version", "1")

        # Title extraction (handling zlib-compressed hex titles or plain text)
        title_elem = root.find("Title")
        raw_title = title_elem.text.strip() if title_elem is not None and title_elem.text else ""
        title = raw_title
        if raw_title:
            try:
                decomp_title = decompress_btx_raw(raw_title)
                title = decomp_title.decode("utf-8", errors="replace")
            except Exception:
                title = raw_title

        title = sanitize_untrusted_text(title)
        raw_title = sanitize_untrusted_text(raw_title)

        rollup_elem = root.find("Rollup")
        rollup = (
            sanitize_untrusted_text(rollup_elem.text)
            if rollup_elem is not None and rollup_elem.text
            else None
        )

        tools: list[dict[str, Any]] = []
        for item in root.findall("ToolChestItem"):
            raw_elem = item.find("Raw")
            decomp_bytes = b""
            if raw_elem is not None and raw_elem.text and decompress_raw:
                decomp_bytes = decompress_btx_raw(raw_elem.text)

            item_subject = None
            item_category = None
            item_internal_name = None

            if decomp_bytes:
                try:
                    decomp_str = decomp_bytes.decode("utf-8", errors="replace")
                    for part in decomp_str.split("\x00"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            k_norm = k.strip().lower()
                            if k_norm == "subject" and not item_subject:
                                item_subject = sanitize_untrusted_text(v.strip())
                            elif k_norm == "category" and not item_category:
                                item_category = sanitize_untrusted_text(v.strip())
                            elif k_norm in ("internalname", "internal_name") and not item_internal_name:
                                item_internal_name = sanitize_untrusted_text(v.strip())
                except Exception:
                    pass

            if not item_subject and item.find("Subject") is not None:
                item_subject = sanitize_untrusted_text((item.findtext("Subject") or "").strip())
            if not item_category and item.find("Category") is not None:
                item_category = sanitize_untrusted_text((item.findtext("Category") or "").strip())
            if not item_internal_name and item.find("InternalName") is not None:
                item_internal_name = sanitize_untrusted_text((item.findtext("InternalName") or "").strip())

            item_dict: dict[str, Any] = {
                "version": item.attrib.get("Version", "1"),
                "name": sanitize_untrusted_text((item.findtext("Name") or "").strip()),
                "type": sanitize_untrusted_text((item.findtext("Type") or "").strip()),
                "subject": item_subject,
                "category": item_category,
                "internal_name": item_internal_name,
                "x": float(item.findtext("X") or 0.0) if item.findtext("X") else 0.0,
                "y": float(item.findtext("Y") or 0.0) if item.findtext("Y") else 0.0,
                "index": int(item.findtext("Index") or 0) if (item.findtext("Index") or "").isdigit() else 0,
                "mode": sanitize_untrusted_text((item.findtext("Mode") or "").strip()),
                "child": None,
            }

            if raw_elem is not None and raw_elem.text:
                if decompress_raw:
                    item_dict["raw_length"] = len(decomp_bytes)
                    item_dict["raw_preview"] = sanitize_untrusted_text(
                        decomp_bytes[:200].decode("latin-1", errors="replace")
                    )
                else:
                    item_dict["raw_hex_length"] = len(raw_elem.text.strip())

            # Child tool item
            child_elem = item.find("Child")
            if child_elem is not None:
                child_dict: dict[str, Any] = {
                    "type": sanitize_untrusted_text((child_elem.findtext("Type") or "").strip()),
                    "x": float(child_elem.findtext("X") or 0.0) if child_elem.findtext("X") else 0.0,
                    "y": float(child_elem.findtext("Y") or 0.0) if child_elem.findtext("Y") else 0.0,
                    "index": (
                        int(child_elem.findtext("Index") or 0)
                        if (child_elem.findtext("Index") or "").isdigit()
                        else 0
                    ),
                }
                child_raw = child_elem.find("Raw")
                if child_raw is not None and child_raw.text:
                    if decompress_raw:
                        child_decomp = decompress_btx_raw(child_raw.text)
                        child_dict["raw_length"] = len(child_decomp)
                        child_dict["raw_preview"] = sanitize_untrusted_text(
                            child_decomp[:100].decode("latin-1", errors="replace")
                        )
                    else:
                        child_dict["raw_hex_length"] = len(child_raw.text.strip())
                item_dict["child"] = child_dict

            tools.append(item_dict)

        res_elem = root.find("Resources")
        resource_count = len(res_elem.findall("Resource")) if res_elem is not None else 0

        data: dict[str, Any] = {
            "toolset_path": str(resolved_path),
            "title": title,
            "raw_title": raw_title,
            "version": version,
            "rollup": rollup,
            "tool_count": len(tools),
            "tools": tools,
            "resource_count": resource_count,
        }

        citations = [
            "docs/citations/03_data_formats_and_markups.md Section 2 (Exact XML Schema of Tool Set Files)",
        ]

        return format_success_envelope(data=data, tool_name="bb_toolset_inspect", citations=citations)

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name="bb_toolset_inspect")


# ============================================================================
# Tool 4: bb_toolset_create_export
# ============================================================================


def bb_toolset_create_export(
    name: str,
    tools: list[dict[str, Any]],
    output_path: str,
    overwrite: bool = True,
) -> dict[str, Any]:
    """Create and export a compliant Bluebeam Tool Set (.btx) XML file.

    Encodes <BluebeamRevuToolSet Version="1"> XML with zlib-compressed hex <Raw> elements.
    Ensures safe path containment, write mode permission validation,
    rejects corrupt or unsafe raw streams, strips illegal XML characters,
    and writes output atomically.

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Tool 4: bb_toolset_create_export).
        - docs/citations/03_data_formats_and_markups.md Section 2 (Exact XML Schema of Tool Set Files).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2; Findings H-19, H-23.

    Args:
        name: Human-readable tool set title (e.g. "Structural Review").
        tools: List of tool specifications with type, name, coordinates, and properties.
        output_path: Destination path (.btx or .xml).
        overwrite: If False and destination file already exists, raise FileLockedError.

    Returns:
        Structured response envelope recording exported toolset details.
    """
    try:
        if not name or not str(name).strip():
            raise InvalidParameterError("Tool set 'name' must be a non-empty string.")

        # Validate path before validating tool list so protected directory checks take priority
        resolved_target = validate_path(
            output_path,
            mode="write",
            must_exist=False,
            allowed_extensions={".btx", ".xml"},
        )

        if not overwrite and resolved_target.exists():
            raise FileLockedError(
                f"Output file already exists and overwrite is False: {resolved_target}",
                error_code="FILE_LOCKED",
                details={"path": str(resolved_target)},
            )

        if not isinstance(tools, list) or len(tools) < 1 or len(tools) > 1000:
            raise InvalidParameterError(
                "Parameter 'tools' must be a list containing between 1 and 1000 tool definitions.",
                details={"tool_count": len(tools) if isinstance(tools, list) else 0},
            )

        clean_title = clean_xml_text(sanitize_untrusted_text(str(name).strip()))
        title_hex = zlib.compress(clean_title.encode("utf-8")).hex()

        root = ET.Element("BluebeamRevuToolSet", {"Version": "1"})
        ET.SubElement(root, "Title").text = title_hex

        for idx, t in enumerate(tools):
            if not isinstance(t, dict):
                raise InvalidParameterError(f"Tool specification at index {idx} must be a dictionary.")

            item = ET.SubElement(root, "ToolChestItem", {"Version": "2"})
            t_name = clean_xml_text(sanitize_untrusted_text(str(t.get("name", f"TOOL_{idx}")).strip()))
            t_type = clean_xml_text(str(t.get("type", "Bluebeam.PDF.Annotations.AnnotationFreeText")).strip())
            t_x = str(float(t.get("x", 0.0)))
            t_y = str(float(t.get("y", 0.0)))
            t_idx = str(int(t.get("index", idx)))
            t_mode = clean_xml_text(str(t.get("mode", "properties")).strip())

            ET.SubElement(item, "Name").text = t_name
            ET.SubElement(item, "Type").text = t_type

            # Raw stream encoding and validation (H-23)
            raw_val = t.get("raw_hex") if "raw_hex" in t else t.get("raw")
            if raw_val is not None:
                if not isinstance(raw_val, str):
                    raise CorruptStreamError(
                        f"Raw stream value must be a hex string, got {type(raw_val).__name__}",
                        details={"type": type(raw_val).__name__},
                    )
                decompress_btx_raw(raw_val)
                raw_hex = raw_val.strip()
            else:
                props = t.get("properties", {})
                if not isinstance(props, dict):
                    raise InvalidParameterError("Tool 'properties' must be a dictionary.")
                raw_parts = [f"Type={t_type}", f"Name={t_name}"]
                for pk, pv in props.items():
                    clean_k = clean_xml_text(sanitize_untrusted_text(str(pk)))
                    clean_v = clean_xml_text(sanitize_untrusted_text(str(pv)))
                    raw_parts.append(f"{clean_k}={clean_v}")
                for extra_key in ("subject", "category", "comment"):
                    if extra_key in t and extra_key not in [k.lower() for k in props.keys()]:
                        val_clean = clean_xml_text(sanitize_untrusted_text(str(t[extra_key])))
                        raw_parts.append(f"{extra_key.capitalize()}={val_clean}")
                raw_bytes = "\x00".join(raw_parts).encode("utf-8")
                raw_hex = zlib.compress(raw_bytes).hex()

            ET.SubElement(item, "Raw").text = raw_hex
            ET.SubElement(item, "X").text = t_x
            ET.SubElement(item, "Y").text = t_y
            ET.SubElement(item, "Index").text = t_idx
            ET.SubElement(item, "Mode").text = t_mode

            # Child tool item if present
            child_info = t.get("child")
            if isinstance(child_info, dict):
                child_elem = ET.SubElement(item, "Child")
                c_type = clean_xml_text(
                    str(child_info.get("type", "Bluebeam.PDF.Annotations.AnnotationFreeText")).strip()
                )
                ET.SubElement(child_elem, "Type").text = c_type

                c_raw_val = child_info.get("raw_hex") if "raw_hex" in child_info else child_info.get("raw")
                if c_raw_val is not None:
                    if not isinstance(c_raw_val, str):
                        raise CorruptStreamError(
                            f"Child raw stream value must be a hex string, got {type(c_raw_val).__name__}",
                            details={"type": type(c_raw_val).__name__},
                        )
                    decompress_btx_raw(c_raw_val)
                    c_raw_hex = c_raw_val.strip()
                else:
                    c_raw_hex = zlib.compress(b"ChildAnnotation").hex()

                ET.SubElement(child_elem, "Raw").text = c_raw_hex
                ET.SubElement(child_elem, "X").text = str(float(child_info.get("x", 0.0)))
                ET.SubElement(child_elem, "Y").text = str(float(child_info.get("y", 0.0)))
                ET.SubElement(child_elem, "Index").text = str(int(child_info.get("index", 1)))

        xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        atomic_write_bytes(xml_bytes, resolved_target)

        data = {
            "output_path": str(resolved_target),
            "name": clean_title,
            "tool_count": len(tools),
            "size_bytes": resolved_target.stat().st_size,
        }

        citations = [
            "docs/citations/03_data_formats_and_markups.md Section 2 (Exact XML Schema of Tool Set Files)",
        ]

        return format_success_envelope(data=data, tool_name="bb_toolset_create_export", citations=citations)

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name="bb_toolset_create_export")


# ============================================================================
# Tool 5: bb_profile_inspect
# ============================================================================


def bb_profile_inspect(
    profile_path: str | None = None,
    export_output_path: str | None = None,
) -> dict[str, Any]:
    """Parse and inspect Bluebeam Profile (.bpx) files for Markups List columns and layout states.

    Resolves profile names from %APPDATA%\\Bluebeam Software\\Revu\\21 or absolute paths.
    Falls back to active profile detection from Registry, RevuPreferences.xml, or installed .bpx files
    when profile_path is omitted.
    Parses <RevuProfile Version="1"> safely using defusedxml.
    Extracts:
    1. <Record Key="MarkupList"> column configurations (width, visibility, ordering).
    2. <Record Key="DockContainer"> panel dock root locations.
    3. <Record Key="StateModels"> custom and default review status definitions.
    4. <Record Key="ToolSetManager"> configured toolset chest associations.
    Supports atomic export via export_output_path.

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Tool 5: bb_profile_inspect).
        - docs/citations/03_data_formats_and_markups.md Section 3 (Exact XML Schema of Profile Files).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.4 (T4-06); Findings M-12, H-19.

    Args:
        profile_path: Path or filename of .bpx file (e.g. "Essentials.bpx"), or None for active profile.
        export_output_path: Destination path (.bpx or .xml) to export a copy of the profile.

    Returns:
        Structured response envelope with profile name, columns, toolbars, and status models.
    """
    try:
        # If profile_path is omitted, determine active profile via registry / preferences fallback (M-12)
        target_profile_name = profile_path
        if not target_profile_name or not str(target_profile_name).strip():
            discovered_name: str | None = None
            if winreg is not None:
                hkcu = _read_registry_key_values(
                    winreg.HKEY_CURRENT_USER, r"Software\Bluebeam Software\21\Revu"
                )
                cp = hkcu.get("CurrentProfile")
                if cp and str(cp).strip():
                    discovered_name = str(cp).strip()

            if not discovered_name:
                appdata = os.environ.get("APPDATA")
                if appdata:
                    revu_appdata = Path(appdata) / "Bluebeam Software" / "Revu" / "21"
                    for pref_filename in ("RevuPreferences.xml", "UserPreferences.xml", "ApplicationSettings.xml"):
                        pref_file = revu_appdata / pref_filename
                        if pref_file.is_file():
                            try:
                                pref_root = parse_xml_safely(pref_file)
                                for tag in ("CurrentProfile", "Profile", "ActiveProfile"):
                                    elem = pref_root.find(f".//{tag}")
                                    if elem is not None and elem.text and elem.text.strip():
                                        discovered_name = elem.text.strip()
                                        break
                                if discovered_name:
                                    break
                            except Exception:
                                pass

            if not discovered_name:
                appdata = os.environ.get("APPDATA")
                if appdata:
                    revu_appdata = Path(appdata) / "Bluebeam Software" / "Revu" / "21"
                    bpx_files = sorted(revu_appdata.glob("*.bpx"))
                    if bpx_files:
                        discovered_name = bpx_files[0].stem

            if not discovered_name:
                discovered_name = "Revu Advanced"

            target_profile_name = (
                discovered_name if discovered_name.lower().endswith(".bpx") else f"{discovered_name}.bpx"
            )

        resolved_path = _resolve_toolset_or_profile_path(
            target_profile_name, file_extension=".bpx", mode="read"
        )

        root = parse_xml_safely(resolved_path)
        if root.tag != "RevuProfile" and not root.tag.endswith("RevuProfile"):
            raise InvalidParameterError(
                f"Invalid XML root element '{root.tag}'. Expected '<RevuProfile>'."
            )

        name = sanitize_untrusted_text(root.attrib.get("Name", ""))
        version = root.attrib.get("Version", "1")

        # 1. MarkupList Columns
        columns: list[dict[str, Any]] = []
        active_column = None
        markup_list = root.find('.//Record[@Key="MarkupList"]')
        if markup_list is not None:
            active_col_raw = markup_list.findtext("ActiveColumn")
            active_column = sanitize_untrusted_text(active_col_raw) if active_col_raw else None
            col_elems = markup_list.findall(".//Column")
            for col in col_elems:
                width_text = col.findtext("Width") or "0"
                width_val = int(width_text) if width_text.isdigit() else width_text
                columns.append({
                    "key": sanitize_untrusted_text(col.attrib.get("Key", "")),
                    "width": width_val,
                    "visible": col.findtext("Visible") == "True",
                    "added": col.findtext("Added") == "True",
                })

        # 2. DockContainer Panels
        dock_roots: list[str] = []
        dock_record = root.find('.//Record[@Key="DockContainer"]')
        if dock_record is not None:
            for dr in dock_record.findall("DockRoot"):
                d_name = dr.attrib.get("Name")
                if d_name:
                    dock_roots.append(sanitize_untrusted_text(d_name))

        # 3. StateModels (Review Status definitions)
        state_models: list[dict[str, Any]] = []
        default_state_model = None
        state_record = root.find('.//Record[@Key="StateModels"]')
        if state_record is not None:
            def_model_raw = state_record.findtext("DefaultModel")
            default_state_model = sanitize_untrusted_text(def_model_raw) if def_model_raw else None
            for m in state_record.findall("Model"):
                states = [
                    sanitize_untrusted_text(s.attrib.get("Key", "") or s.text or "")
                    for s in m.findall(".//State")
                    if s.attrib.get("Key") or s.text
                ]
                state_models.append({
                    "key": sanitize_untrusted_text(m.attrib.get("Key", "")),
                    "visible": m.attrib.get("Visible") == "True",
                    "states": states,
                })

        # 4. ToolSetManager references
        toolsets: list[dict[str, Any]] = []
        ts_record = root.find('.//Record[@Key="ToolSetManager"]')
        if ts_record is not None:
            for ts in ts_record.findall("ToolSet"):
                toolsets.append({
                    "index": ts.attrib.get("Index", ""),
                    "name": sanitize_untrusted_text((ts.findtext("Name") or "").strip()),
                    "path": sanitize_untrusted_text((ts.findtext("Path") or "").strip()),
                })

        # 5. Optional atomic export (H-19)
        exported_path: str | None = None
        if export_output_path is not None:
            resolved_export = validate_path(
                export_output_path,
                mode="write",
                must_exist=False,
                allowed_extensions={".bpx", ".xml"},
            )
            profile_bytes = resolved_path.read_bytes()
            atomic_write_bytes(profile_bytes, resolved_export)
            exported_path = str(resolved_export)

        data: dict[str, Any] = {
            "profile_path": str(resolved_path),
            "name": name,
            "version": version,
            "active_column": active_column,
            "column_count": len(columns),
            "columns": columns,
            "dock_roots": dock_roots,
            "default_state_model": default_state_model,
            "state_models": state_models,
            "toolset_associations": toolsets,
        }
        if exported_path is not None:
            data["exported_to"] = exported_path

        citations = [
            "docs/citations/03_data_formats_and_markups.md Section 3 (Exact XML Schema of Profile Files)",
        ]

        return format_success_envelope(data=data, tool_name="bb_profile_inspect", citations=citations)

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name="bb_profile_inspect")


# ============================================================================
# Tool 6: bb_stamp_library_inspect
# ============================================================================


def bb_stamp_library_inspect(
    stamps_dir: str | None = None,
    include_localized: bool = False,
    create_stamp_output_path: str | None = None,
    stamp_text: str | None = None,
    stamp_width_pts: float = 200.0,
    stamp_height_pts: float = 70.0,
    font_name: str = "Helvetica-Bold",
    font_size: float = 24.0,
    color: str = "#FF0000",
) -> dict[str, Any]:
    """Enumerate installed Bluebeam Stamp PDF documents, inspect properties, or author stamps.

    When create_stamp_output_path is provided:
        Generates a custom Stamp PDF with horizontally and vertically centered text using
        reportlab.pdfbase.pdfmetrics.stringWidth, attaches a /Stamp appearance stream (/AP /N),
        and writes atomically.

    When stamps_dir or default library is inspected:
        Inspects:
        1. Stamp metadata (/Info) including /Title, /BlendMode, /Opacity, /Rotation, /ID.
        2. MediaBox page dimensions (width, height in points).
        3. Annotation count on Page 0 (/Annots).
        4. Dynamic evaluation placeholders (&[Date], &[Time], &[User], &[Author], etc.).
        5. JavaScript presence, length, and truncated preview (capped at 200 characters).

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Tool 6: bb_stamp_library_inspect).
        - docs/citations/03_data_formats_and_markups.md Section 1 (File Locations),
          Section 4 (Exact PDF Dictionary Structure of Bluebeam Stamps).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.4 (T4-05); Findings M-13, H-19.

    Args:
        stamps_dir: Directory path containing Stamp PDFs (defaults to standard ProgramData location).
        include_localized: If True, scans localized language subdirectories (da, de, es, fr, etc.).
        create_stamp_output_path: Destination path to author a new Stamp PDF (.pdf).
        stamp_text: Text string to engrave on authored stamp (required when authoring).
        stamp_width_pts: Width of authored stamp page in points (default 200.0).
        stamp_height_pts: Height of authored stamp page in points (default 70.0).
        font_name: PostScript font name for authored stamp text (default "Helvetica-Bold").
        font_size: Font size in points for authored stamp text (default 24.0).
        color: Hex color string for border and text (default "#FF0000").

    Returns:
        Structured response envelope with stamp inventory or authoring details.
    """
    try:
        # Branch 1: Author a custom stamp PDF (M-13)
        if create_stamp_output_path is not None:
            if not stamp_text or not str(stamp_text).strip():
                raise InvalidParameterError("stamp_text must be a non-empty string when creating a stamp PDF.")

            if (
                isinstance(stamp_width_pts, bool)
                or not isinstance(stamp_width_pts, (int, float))
                or not math.isfinite(stamp_width_pts)
                or stamp_width_pts <= 0
                or isinstance(stamp_height_pts, bool)
                or not isinstance(stamp_height_pts, (int, float))
                or not math.isfinite(stamp_height_pts)
                or stamp_height_pts <= 0
            ):
                raise InvalidParameterError("stamp_width_pts and stamp_height_pts must be positive finite numbers.")

            resolved_stamp_path = validate_path(
                create_stamp_output_path,
                mode="write",
                must_exist=False,
                allowed_extensions={".pdf"},
            )

            clean_text = sanitize_untrusted_text(str(stamp_text).strip(), max_len=512)

            # Generate visual page with centered text via ReportLab
            packet = io.BytesIO()
            c = canvas.Canvas(packet, pagesize=(stamp_width_pts, stamp_height_pts))
            c.setFont(font_name, font_size)
            text_w = pdfmetrics.stringWidth(clean_text, font_name, font_size)
            x_pos = (stamp_width_pts - text_w) / 2.0
            y_pos = (stamp_height_pts - font_size) / 2.0

            try:
                c.setStrokeColor(HexColor(color))
                c.setFillColor(HexColor(color))
            except Exception:
                c.setStrokeColorRGB(0.8, 0.1, 0.1)
                c.setFillColorRGB(0.8, 0.1, 0.1)

            c.drawString(x_pos, y_pos, clean_text)
            c.setLineWidth(2.0)
            c.roundRect(2.0, 2.0, stamp_width_pts - 4.0, stamp_height_pts - 4.0, radius=3.0, stroke=1, fill=0)
            c.save()
            packet.seek(0)

            # Add /Stamp appearance stream (/AP /N)
            stamp_reader = pypdf.PdfReader(packet)
            page0 = stamp_reader.pages[0]
            stamp_writer = pypdf.PdfWriter()
            out_page = stamp_writer.add_page(page0)

            ap_stream = DecodedStreamObject()
            ap_stream.set_data(page0.get_contents().get_data())
            ap_stream[NameObject("/Type")] = NameObject("/XObject")
            ap_stream[NameObject("/Subtype")] = NameObject("/Form")
            ap_stream[NameObject("/BBox")] = ArrayObject([
                FloatObject(0),
                FloatObject(0),
                FloatObject(stamp_width_pts),
                FloatObject(stamp_height_pts),
            ])
            if "/Resources" in page0:
                ap_stream[NameObject("/Resources")] = page0["/Resources"]

            stamp_annot = DictionaryObject({
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Stamp"),
                NameObject("/Rect"): ArrayObject([
                    FloatObject(0),
                    FloatObject(0),
                    FloatObject(stamp_width_pts),
                    FloatObject(stamp_height_pts),
                ]),
                NameObject("/Contents"): TextStringObject(clean_text),
                NameObject("/Subj"): TextStringObject("Stamp"),
                NameObject("/AP"): DictionaryObject({NameObject("/N"): ap_stream}),
            })

            if NameObject("/Annots") not in out_page:
                out_page[NameObject("/Annots")] = ArrayObject()
            out_page[NameObject("/Annots")].append(stamp_annot)

            stamp_writer.add_metadata({
                "/Title": clean_text,
                "/BlendMode": "Normal",
                "/Opacity": "1.0",
            })

            atomic_write_pdf(stamp_writer, resolved_stamp_path)

            citations = [
                "docs/citations/03_data_formats_and_markups.md Section 4 (Exact PDF Dictionary Structure of Bluebeam Stamps)",
            ]

            return format_success_envelope(
                data={
                    "output_path": str(resolved_stamp_path),
                    "stamp_text": clean_text,
                    "width_pts": float(stamp_width_pts),
                    "height_pts": float(stamp_height_pts),
                    "font_name": font_name,
                    "font_size": float(font_size),
                    "color": color,
                    "has_appearance_stream": True,
                },
                tool_name="bb_stamp_library_inspect",
                citations=citations,
            )

        # Branch 2: Enumerate stamp library files
        if stamps_dir is None:
            target_dir = Path(r"C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\Stamps")
        else:
            target_dir = validate_path(
                stamps_dir, mode="read", must_exist=True, kind="dir"
            )

        if not target_dir.is_dir():
            raise FileNotFoundError(f"Stamps directory not found: {target_dir}")

        if include_localized:
            pdf_files = sorted(target_dir.rglob("*.pdf"))
        else:
            pdf_files = sorted(target_dir.glob("*.pdf"))

        stamps_data: list[dict[str, Any]] = []

        for stamp_path in pdf_files:
            try:
                reader = pypdf.PdfReader(stamp_path)
                meta = reader.metadata or {}

                # Safely extract Info dictionary items
                info_dict: dict[str, Any] = {}
                for k, v in meta.items():
                    info_dict[str(k)] = str(v)

                title_val = sanitize_untrusted_text(
                    info_dict.get("/Title") or info_dict.get("Title") or stamp_path.stem
                )
                blend_mode = sanitize_untrusted_text(info_dict.get("/BlendMode") or "Normal")

                raw_opacity = info_dict.get("/Opacity", "1.0")
                opacity_val = float(raw_opacity) if raw_opacity.replace(".", "", 1).isdigit() else 1.0

                raw_rotation = info_dict.get("/Rotation", "0.0")
                rotation_val = float(raw_rotation) if raw_rotation.replace(".", "", 1).isdigit() else 0.0

                stamp_id = sanitize_untrusted_text(info_dict.get("/ID", ""))

                # Page dimensions and annotations
                page_size: dict[str, float] = {}
                annot_count = 0
                dynamic_fields: list[str] = []
                has_javascript = False
                js_snippets: list[str] = []
                all_js_codes: list[str] = []

                if len(reader.pages) > 0:
                    page0 = reader.pages[0]
                    mbox = page0.mediabox
                    page_size = {"width": float(mbox.width), "height": float(mbox.height)}

                    annots_raw = page0.get("/Annots")
                    if annots_raw is not None:
                        if hasattr(annots_raw, "get_object"):
                            annots_raw = annots_raw.get_object()
                        if isinstance(annots_raw, (list, pypdf.generic.ArrayObject)):
                            annot_count = len(annots_raw)
                            for a_ref in annots_raw:
                                a_obj = a_ref.get_object() if hasattr(a_ref, "get_object") else a_ref
                                if isinstance(a_obj, dict):
                                    contents = str(a_obj.get("/Contents", ""))
                                    rc_xml = str(a_obj.get("/RC", ""))
                                    corpus = f"{contents} {rc_xml}"

                                    macros = re.findall(r"&\[[A-Za-z0-9_]+\]", corpus)
                                    for m in macros:
                                        if m not in dynamic_fields:
                                            dynamic_fields.append(m)

                                    for act_key in ("/A", "/AA"):
                                        act = a_obj.get(act_key)
                                        if act is not None:
                                            act_obj = act.get_object() if hasattr(act, "get_object") else act
                                            if isinstance(act_obj, dict):
                                                if act_obj.get("/S") == "/JavaScript" or "/JS" in act_obj:
                                                    has_javascript = True
                                                    js_code = str(act_obj.get("/JS", ""))
                                                    if js_code:
                                                        all_js_codes.append(js_code)
                                                        js_snippets.append(js_code[:120])

                # Check catalog / Names / JavaScript or /OpenAction
                try:
                    cat = reader.trailer.get("/Root")
                    if cat is not None:
                        cat_obj = cat.get_object() if hasattr(cat, "get_object") else cat
                        if isinstance(cat_obj, dict):
                            names = cat_obj.get("/Names")
                            if names is not None:
                                names_obj = names.get_object() if hasattr(names, "get_object") else names
                                if isinstance(names_obj, dict) and "/JavaScript" in names_obj:
                                    has_javascript = True
                                    all_js_codes.append(str(names_obj["/JavaScript"]))
                            oa = cat_obj.get("/OpenAction")
                            if oa is not None:
                                oa_obj = oa.get_object() if hasattr(oa, "get_object") else oa
                                if isinstance(oa_obj, dict) and (
                                    oa_obj.get("/S") == "/JavaScript" or "/JS" in oa_obj
                                ):
                                    has_javascript = True
                                    oa_js = str(oa_obj.get("/JS", ""))
                                    if oa_js:
                                        all_js_codes.append(oa_js)
                except Exception:
                    pass

                full_js_str = "\n".join(all_js_codes)
                stamps_data.append({
                    "name": stamp_path.name,
                    "path": str(stamp_path),
                    "size_bytes": stamp_path.stat().st_size,
                    "title": title_val,
                    "blend_mode": blend_mode,
                    "opacity": opacity_val,
                    "rotation": rotation_val,
                    "id": stamp_id,
                    "page_size": page_size,
                    "annotation_count": annot_count,
                    "dynamic_fields": sorted(dynamic_fields),
                    "has_javascript": has_javascript or bool(full_js_str),
                    "javascript_length": len(full_js_str),
                    "javascript_preview": sanitize_untrusted_text(full_js_str, max_len=200) if full_js_str else "",
                    "javascript_snippets": [sanitize_untrusted_text(s, max_len=120) for s in js_snippets],
                })

            except Exception as read_err:
                stamps_data.append({
                    "name": stamp_path.name,
                    "path": str(stamp_path),
                    "error": str(read_err),
                })

        data: dict[str, Any] = {
            "stamps_dir": str(target_dir),
            "include_localized": include_localized,
            "stamp_count": len(stamps_data),
            "stamps": stamps_data,
        }

        citations = [
            "docs/citations/03_data_formats_and_markups.md Section 1 (File Locations)",
            "docs/citations/03_data_formats_and_markups.md Section 4 (Exact PDF Dictionary Structure of Bluebeam Stamps)",
        ]

        return format_success_envelope(data=data, tool_name="bb_stamp_library_inspect", citations=citations)

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name="bb_stamp_library_inspect")


# ============================================================================
# FastMCP Tool Registration Helper
# ============================================================================


def register_environment_tools(mcp: Any) -> None:
    """Register all 6 environment, script, toolset, profile, and stamp tools on a FastMCP instance.

    Primary citations:
        - docs/ARCHITECTURE.md Section 6.3 (Category 3 Tool Catalog).
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.
    """
    mcp.tool(name="bb_env_status")(bb_env_status)
    mcp.tool(name="bb_script_generate_and_run")(bb_script_generate_and_run)
    mcp.tool(name="bb_toolset_inspect")(bb_toolset_inspect)
    mcp.tool(name="bb_toolset_create_export")(bb_toolset_create_export)
    mcp.tool(name="bb_profile_inspect")(bb_profile_inspect)
    mcp.tool(name="bb_stamp_library_inspect")(bb_stamp_library_inspect)


__all__ = [
    "PBMNGR_PLUGIN_FLAGS",
    "ALL_PBMNGR_PLUGIN_FLAGS",
    "build_pbmngr_cli_args",
    "bb_env_status",
    "bb_script_generate_and_run",
    "bb_toolset_inspect",
    "bb_toolset_create_export",
    "bb_profile_inspect",
    "bb_stamp_library_inspect",
    "register_environment_tools",
]
