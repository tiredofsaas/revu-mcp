"""Four-tier test verification suite for Bluebeam Revu 21 environment tools.

Covers Tier 1 (Unit and Schema), Tier 2 (Adversarial Security),
Tier 3 (Stability and Fault Injection), and Tier 4 (Live Integration on the reference workstation).

Primary citations:
- docs/ARCHITECTURE.md Section 6.3 (Category 3 Tool Catalog)
- docs/citations/02_binary_and_dotnet_surface.md Section 2 (Binary Inventory), Section 3 (Registry Surface),
  Section 4.2 (ScriptEngine Execution), Section 7.4 (Exit Code Summary)
- docs/citations/03_data_formats_and_markups.md Section 1 (File Locations), Section 2 (Tool Set BTX Schema),
  Section 3 (Profile BPX Schema), Section 4 (Stamp Dictionary Structure), Section 6 (PbMngr5 CLI Options)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Test Tiers), Section 3 (Error Envelope Catalog)
"""

from __future__ import annotations

import os
from pathlib import Path
import zlib

from mcp.server.fastmcp import FastMCP
import pytest

from tests.conftest import requires_revu

from bluebeam_mcp.tools.environment_tools import (
    ALL_PBMNGR_PLUGIN_FLAGS,
    PBMNGR_PLUGIN_FLAGS,
    bb_env_status,
    bb_profile_inspect,
    bb_script_generate_and_run,
    bb_stamp_library_inspect,
    bb_toolset_create_export,
    bb_toolset_inspect,
    build_pbmngr_cli_args,
    register_environment_tools,
)

TEST_TMP_DIR = Path(__file__).resolve().parent / "tmp"


@pytest.fixture(autouse=True)
def ensure_test_tmp_dir() -> Path:
    """Ensure test scratch directory exists in tests/tmp."""
    TEST_TMP_DIR.mkdir(parents=True, exist_ok=True)
    return TEST_TMP_DIR


# ============================================================================
# Tier 1: Unit and Schema Validation
# ============================================================================


class TestTier1PbMngrAndScriptBuilder:
    """Tier 1: Unit verification of PbMngr5 CLI builders and BCS script generation."""

    def test_pbmngr5_cli_flag_builders_individual_flags(self) -> None:
        """T1-08: Verify individual plugin bitmask flags 1..256 match citations."""
        expected_flags = {
            "office": 1,
            "autocad": 2,
            "autocad_lt": 4,
            "autocadlt": 4,
            "solidworks": 8,
            "revit": 16,
            "ie": 32,
            "projectwise": 64,
            "outlook": 128,
            "sketchup": 256,
        }
        for name, expected_val in expected_flags.items():
            args = build_pbmngr_cli_args(install_plugins=[name])
            assert args == [f"/IF:{expected_val}"]

            # Test integer invocation directly
            args_int = build_pbmngr_cli_args(install_plugins=expected_val)
            assert args_int == [f"/IF:{expected_val}"]

    def test_pbmngr5_cli_flag_builders_composite_and_all(self) -> None:
        """T1-08: Verify composite bitmask summation and 'all' plugin flag (1023)."""
        # Office (1) + AutoCAD (2) + SolidWorks (8) = 11
        args_composite = build_pbmngr_cli_args(
            install_plugins=["office", "autocad", "solidworks"]
        )
        assert args_composite == ["/IF:11"]

        # All plugins keyword
        args_all = build_pbmngr_cli_args(install_plugins=["all"])
        assert args_all == ["/IF:1023"]

        # All plugins integer bitmask
        args_all_int = build_pbmngr_cli_args(install_plugins=ALL_PBMNGR_PLUGIN_FLAGS)
        assert args_all_int == ["/IF:1023"]

    def test_pbmngr5_cli_flag_builders_switches(self) -> None:
        """T1-08: Verify /DPS, /DVON, /DVOFF, and /setup CLI switches."""
        # Page size
        assert build_pbmngr_cli_args(default_page_size="Letter") == ["/DPS:Letter"]
        assert build_pbmngr_cli_args(default_page_size="A4") == ["/DPS:A4"]

        # Viewer default
        assert build_pbmngr_cli_args(default_viewer=True) == ["/DVON"]
        assert build_pbmngr_cli_args(default_viewer=False) == ["/DVOFF"]

        # Setup flag
        assert build_pbmngr_cli_args(setup=True) == ["/setup"]

        # Full combination
        combined = build_pbmngr_cli_args(
            install_plugins=1023,
            default_page_size="Letter",
            default_viewer=True,
            setup=True,
        )
        assert combined == ["/IF:1023", "/DPS:Letter", "/DVON", "/setup"]

    def test_pbmngr5_cli_flag_builders_invalid_inputs(self) -> None:
        """T1-08: Verify validation rejection on invalid plugin or page size."""
        with pytest.raises(ValueError):
            build_pbmngr_cli_args(install_plugins=-1)

        with pytest.raises(ValueError):
            build_pbmngr_cli_args(install_plugins=1024)

        with pytest.raises(ValueError):
            build_pbmngr_cli_args(install_plugins=["nonexistent_cad_system"])

        with pytest.raises(ValueError):
            build_pbmngr_cli_args(default_page_size="Tabloid")

    def test_pbmngr5_cli_flag_builders(self) -> None:
        """T1-08: Verify PbMngr5 CLI flag generation for individual, composite, and switches."""
        self.test_pbmngr5_cli_flag_builders_individual_flags()
        self.test_pbmngr5_cli_flag_builders_composite_and_all()
        self.test_pbmngr5_cli_flag_builders_switches()
        self.test_pbmngr5_cli_flag_builders_invalid_inputs()

    def test_bcs_script_generation_from_commands(self) -> None:
        """T1-01: Verify multi-step BCS script generation in script_only mode."""
        commands = [
            {"name": "Open", "args": ["tests/tmp/drawing.pdf"]},
            {"name": "PageCount", "args": []},
            {"name": "Close", "args": [False]},
        ]
        res = bb_script_generate_and_run(commands=commands, execution_mode="script_only")
        assert res["status"] == "success"
        script = res["data"]["bcs_script"]
        assert 'Open("tests/tmp/drawing.pdf")' in script
        assert "PageCount()" in script
        assert "Close(false)" in script

    def test_bcs_script_generation_from_text(self) -> None:
        """T1-01: Verify pre-formed BCS script text validation in script_only mode."""
        raw_text = 'Open("tests/tmp/plan.pdf")\r\nPageSize(1)\r\nClose(false)'
        res = bb_script_generate_and_run(script_text=raw_text, execution_mode="script_only")
        assert res["status"] == "success"
        assert res["data"]["bcs_script"] == raw_text

    def test_bcs_script_invalid_mode_or_commands_rejected(self) -> None:
        """T1-01: Verify rejection of invalid execution modes and missing inputs."""
        res_no_input = bb_script_generate_and_run()
        assert res_no_input["status"] == "error"
        assert res_no_input["error"]["code"] == "INVALID_PARAMETER"

        res_both = bb_script_generate_and_run(commands=[], script_text="Close()")
        assert res_both["status"] == "error"
        assert res_both["error"]["code"] == "INVALID_PARAMETER"

        res_bad_mode = bb_script_generate_and_run(
            script_text="Close()", execution_mode="unsupported_mode"
        )
        assert res_bad_mode["status"] == "error"
        assert res_bad_mode["error"]["code"] == "INVALID_PARAMETER"


# ============================================================================
# Tier 2: Adversarial Security Tests
# ============================================================================


class TestTier2AdversarialSecurity:
    """Tier 2: Adversarial security verification (XXE, bombs, forbidden roots)."""

    def test_btx_xxe_payload_defused(self) -> None:
        """T2-12: XML External Entity injection in .btx is defused and blocked."""
        xxe_file = TEST_TMP_DIR / "adversarial_xxe.btx"
        xxe_content = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<BluebeamRevuToolSet Version="1">
  <Title>&xxe;</Title>
</BluebeamRevuToolSet>"""
        xxe_file.write_text(xxe_content, encoding="utf-8")

        res = bb_toolset_inspect(str(xxe_file))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")

    def test_bpx_xxe_payload_defused(self) -> None:
        """T2-12: XML External Entity injection in .bpx is defused and blocked."""
        xxe_file = TEST_TMP_DIR / "adversarial_xxe.bpx"
        xxe_content = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<RevuProfile Version="1" Name="XXE_Test">
  <Record Key="MarkupList">&xxe;</Record>
</RevuProfile>"""
        xxe_file.write_text(xxe_content, encoding="utf-8")

        res = bb_profile_inspect(str(xxe_file))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")

    def test_btx_billion_laughs_bomb_blocked(self) -> None:
        """T2-13: Exponential entity expansion bomb in .btx is rejected."""
        bomb_file = TEST_TMP_DIR / "adversarial_bomb.btx"
        bomb_content = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<BluebeamRevuToolSet Version="1">
  <Title>&lol2;</Title>
</BluebeamRevuToolSet>"""
        bomb_file.write_text(bomb_content, encoding="utf-8")

        res = bb_toolset_inspect(str(bomb_file))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")

    def test_bpx_billion_laughs_bomb_blocked(self) -> None:
        """T2-13: Exponential entity expansion bomb in .bpx is rejected."""
        bomb_file = TEST_TMP_DIR / "adversarial_bomb.bpx"
        bomb_content = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<RevuProfile Version="1" Name="BombProfile">
  <Record Key="MarkupList">&lol2;</Record>
</RevuProfile>"""
        bomb_file.write_text(bomb_content, encoding="utf-8")

        res = bb_profile_inspect(str(bomb_file))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")

    def test_btx_corrupt_hex_raw_stream(self) -> None:
        """T2-14: Corrupt non-hex data in <Raw> tag is safely caught and reported."""
        corrupt_file = TEST_TMP_DIR / "corrupt_raw.btx"
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
<BluebeamRevuToolSet Version="1">
  <Title>Corrupt Raw Toolset</Title>
  <ToolChestItem Version="2">
    <Name>TOOL1</Name>
    <Type>Bluebeam.PDF.Annotations.AnnotationFreeText</Type>
    <Raw>ZZZZ_NOT_VALID_HEX_DATA_STREAM</Raw>
  </ToolChestItem>
</BluebeamRevuToolSet>"""
        corrupt_file.write_text(xml_content, encoding="utf-8")

        res = bb_toolset_inspect(str(corrupt_file))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("CORRUPT_RAW_STREAM", "INVALID_PARAMETER")

    def test_btx_decompression_bomb_blocked(self) -> None:
        """T2-15: Zlib payload exceeding 10 MB limit triggers security violation."""
        bomb_file = TEST_TMP_DIR / "zlib_bomb.btx"
        eleven_mb_data = b"X" * (11 * 1024 * 1024)
        compressed_hex = zlib.compress(eleven_mb_data).hex()

        xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<BluebeamRevuToolSet Version="1">
  <Title>Zlib Bomb Toolset</Title>
  <ToolChestItem Version="2">
    <Name>BOMB_TOOL</Name>
    <Type>Bluebeam.PDF.Annotations.AnnotationPolygon</Type>
    <Raw>{compressed_hex}</Raw>
  </ToolChestItem>
</BluebeamRevuToolSet>"""
        bomb_file.write_text(xml_content, encoding="utf-8")

        res = bb_toolset_inspect(str(bomb_file))
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"

    def test_protected_root_protected_root_denial(self) -> None:
        """T2-06: Direct access or traversal resolving to E:\\ProtectedVault is blocked."""
        res_btx = bb_toolset_inspect(r"E:\ProtectedVault\vault\toolset.btx")
        assert res_btx["status"] == "error"
        assert res_btx["error"]["code"] == "SECURITY_VIOLATION"

        res_bpx = bb_profile_inspect(r"E:\ProtectedVault\vault\profile.bpx")
        assert res_bpx["status"] == "error"
        assert res_bpx["error"]["code"] == "SECURITY_VIOLATION"

        res_script = bb_script_generate_and_run(
            commands=[{"name": "DeleteFile", "args": [r"E:\ProtectedVault\secret.pdf"]}],
            execution_mode="script_only",
        )
        assert res_script["status"] == "error"
        assert res_script["error"]["code"] == "SECURITY_VIOLATION"

    def test_protected_root_solidworks_corp_denial(self) -> None:
        """T2-07: Access to SOLIDWORKS installation directory is blocked."""
        res_btx = bb_toolset_inspect(r"C:\Program Files\SOLIDWORKS Corp\tools.btx")
        assert res_btx["status"] == "error"
        assert res_btx["error"]["code"] == "SECURITY_VIOLATION"

        res_bpx = bb_profile_inspect(r"C:\Program Files\SOLIDWORKS Corp\profile.bpx")
        assert res_bpx["status"] == "error"
        assert res_bpx["error"]["code"] == "SECURITY_VIOLATION"

    def test_env_write_protection_system_roots(self) -> None:
        """T2-08: Write or export access to system directories is blocked."""
        forbidden_targets = [
            r"C:\ProgramData\Bluebeam Software\malicious.btx",
            r"C:\Windows\System32\malicious.btx",
            r"C:\Program Files\Bluebeam Software\malicious.btx",
        ]
        for target in forbidden_targets:
            res = bb_toolset_create_export(
                name="Attack Toolset",
                tools=[],
                output_path=target,
            )
            assert res["status"] == "error"
            assert res["error"]["code"] == "SECURITY_VIOLATION"

    def test_script_deletefile_system_roots_denial(self) -> None:
        """T2-08: DeleteFile targeting protected system root is denied."""
        commands = [
            {"name": "DeleteFile", "args": [r"C:\Windows\System32\cmd.exe"]},
        ]
        res = bb_script_generate_and_run(commands=commands, execution_mode="script_only")
        assert res["status"] == "error"
        assert res["error"]["code"] == "SECURITY_VIOLATION"


# ============================================================================
# Tier 3: Stability and Fault Injection
# ============================================================================


class TestTier3FaultInjection:
    """Tier 3: Stability tests under missing, empty, or malformed inputs."""

    def test_fault_missing_btx(self) -> None:
        """T3-10: Inspecting non-existent .btx returns FILE_NOT_FOUND error envelope."""
        res = bb_toolset_inspect(r"tests\tmp\nonexistent_toolset_file.btx")
        assert res["status"] == "error"
        assert res["error"]["code"] == "FILE_NOT_FOUND"

    def test_fault_missing_toolset_btx(self) -> None:
        """T3-10: Alias for test_fault_missing_btx satisfying test matrix specification."""
        self.test_fault_missing_btx()

    def test_fault_missing_bpx(self) -> None:
        """T3-10: Inspecting non-existent .bpx returns FILE_NOT_FOUND error envelope."""
        res = bb_profile_inspect(r"tests\tmp\nonexistent_profile_file.bpx")
        assert res["status"] == "error"
        assert res["error"]["code"] == "FILE_NOT_FOUND"

    def test_fault_empty_btx(self) -> None:
        """T3-01: Zero-byte .btx file returns EMPTY_FILE or XML_PARSE_ERROR envelope."""
        empty_file = TEST_TMP_DIR / "empty_toolset.btx"
        empty_file.write_bytes(b"")

        res = bb_toolset_inspect(str(empty_file))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("EMPTY_FILE", "INVALID_PDF", "XML_PARSE_ERROR")

    def test_fault_malformed_xml_btx(self) -> None:
        """T3-09: Unclosed XML tags in .btx return XML_PARSE_ERROR envelope."""
        malformed = TEST_TMP_DIR / "malformed_toolset.btx"
        malformed.write_text("<BluebeamRevuToolSet><unclosed>", encoding="utf-8")

        res = bb_toolset_inspect(str(malformed))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")

    def test_fault_malformed_xml_bpx(self) -> None:
        """T3-09: Unclosed XML tags in .bpx return XML_PARSE_ERROR envelope."""
        malformed = TEST_TMP_DIR / "malformed_profile.bpx"
        malformed.write_text("<RevuProfile><broken_xml>", encoding="utf-8")

        res = bb_profile_inspect(str(malformed))
        assert res["status"] == "error"
        assert res["error"]["code"] in ("XML_PARSE_ERROR", "SECURITY_VIOLATION")

    def test_fault_invalid_root_tag_btx(self) -> None:
        """T3-09: XML document with incorrect root element returns INVALID_PARAMETER."""
        wrong_root = TEST_TMP_DIR / "wrong_root.btx"
        wrong_root.write_text("<NotAToolSet Version='1'></NotAToolSet>", encoding="utf-8")

        res = bb_toolset_inspect(str(wrong_root))
        assert res["status"] == "error"
        assert res["error"]["code"] == "INVALID_PARAMETER"

    def test_fault_missing_stamps_dir(self) -> None:
        """T3-04: Non-existent stamps directory returns FILE_NOT_FOUND envelope."""
        res = bb_stamp_library_inspect(stamps_dir=r"tests\tmp\nonexistent_stamps_dir")
        assert res["status"] == "error"
        assert res["error"]["code"] == "FILE_NOT_FOUND"


# ============================================================================
# Tier 4: Live Integration on the reference workstation
# ============================================================================


@requires_revu
class TestTier4LiveIntegration:
    """Tier 4: Live integration tests with real installed Bluebeam Revu 21 assets."""

    def test_live_bb_env_status_on_workstation(self) -> None:
        """T4-07: Query live Bluebeam Revu 21 environment on the reference workstation."""
        res = bb_env_status(probe_script_engine=True)
        assert res["status"] in ("success", "subscription_fallback")

        data = res["data"]
        # Verify exact installed version and subscription tier on the reference workstation
        assert data["revu_build_no"] == "21.11.0.23287"
        assert data["product_package"] == "Core"

        # Verify all four binary checks
        binaries = data["binaries"]
        for b_name in ("script_engine", "revu", "stapler", "pbmngr"):
            assert binaries[b_name]["exists"] is True, f"Binary {b_name} must exist on the reference workstation"
            assert binaries[b_name]["size_bytes"] > 0

        # Verify installed toolsets, profiles, and stamps
        assert data["toolset_count"] > 0
        assert data["profile_count"] > 0
        assert data["stamp_count"] > 0

        # Verify live probe receipt matches Revu Core entitlement restriction
        probe = data["script_engine_probe"]
        assert probe is not None
        assert probe["exit_code"] == -4
        assert probe["entitlement_restricted"] is True

    def test_live_bb_toolset_inspect_architect_review(self) -> None:
        """T4-04: Parse live installed 'Architect Review.btx' and decompress items."""
        res = bb_toolset_inspect("Architect Review.btx", decompress_raw=True)
        assert res["status"] == "success"

        data = res["data"]
        assert data["title"] == "Architect Review"
        assert data["tool_count"] == 8
        assert len(data["tools"]) == 8

        # First item is polygon cloud with decompressed properties
        tool0 = data["tools"][0]
        assert tool0["type"] == "Bluebeam.PDF.Annotations.AnnotationPolygon"
        assert "raw_preview" in tool0
        assert len(tool0["raw_preview"]) > 0

    def test_live_bb_profile_inspect_essentials(self) -> None:
        """T4-06: Parse live installed 'Essentials.bpx' and extract column records."""
        res = bb_profile_inspect("Essentials.bpx")
        assert res["status"] == "success"

        data = res["data"]
        assert data["name"] == "Essentials"
        assert data["column_count"] > 0

        column_keys = [c["key"] for c in data["columns"]]
        assert "Subject" in column_keys
        assert "Page" in column_keys
        assert "Comments" in column_keys

    def test_live_bb_stamp_library_inspect_default(self) -> None:
        """T4-05: Enumerate live installed Bluebeam stamp library in ProgramData."""
        res = bb_stamp_library_inspect(include_localized=False)
        assert res["status"] == "success"

        data = res["data"]
        assert data["stamp_count"] >= 10

        stamp_names = [s["name"] for s in data["stamps"]]
        assert "Approved.pdf" in stamp_names
        assert "Date.pdf" in stamp_names
        assert "DateTime.pdf" in stamp_names

        # Find DateTime.pdf and verify dynamic macros
        dt_stamp = next(s for s in data["stamps"] if s["name"] == "DateTime.pdf")
        assert "&[Date]" in dt_stamp["dynamic_fields"]
        assert "&[Time]" in dt_stamp["dynamic_fields"]

    def test_round_trip_toolset_create_export_and_inspect(self) -> None:
        """T4-04: Lossless authoring and inspection round-trip for .btx toolset."""
        out_btx = TEST_TMP_DIR / "roundtrip_test_toolset.btx"
        test_tools = [
            {
                "name": "HVAC Duct Inspection",
                "type": "Bluebeam.PDF.Annotations.AnnotationFreeText",
                "x": 120.5,
                "y": 340.0,
                "index": 0,
                "properties": {
                    "Subject": "HVAC Review",
                    "Author": "Lead Engineer",
                    "Color": "#0000FF",
                },
            },
            {
                "name": "Pipe Penetration Square",
                "type": "Bluebeam.PDF.Annotations.AnnotationSquare",
                "x": 45.0,
                "y": 90.0,
                "index": 1,
                "properties": {
                    "Subject": "Penetration",
                    "Author": "Structural Engineer",
                    "Color": "#FF0000",
                },
            },
        ]

        # 1. Export
        create_res = bb_toolset_create_export(
            name="Mechanical Engineering Review",
            tools=test_tools,
            output_path=str(out_btx),
        )
        assert create_res["status"] == "success"
        assert create_res["data"]["tool_count"] == 2
        assert out_btx.exists()

        # 2. Inspect
        inspect_res = bb_toolset_inspect(str(out_btx), decompress_raw=True)
        assert inspect_res["status"] == "success"

        insp_data = inspect_res["data"]
        assert insp_data["title"] == "Mechanical Engineering Review"
        assert insp_data["tool_count"] == 2

        tool0 = insp_data["tools"][0]
        assert tool0["name"] == "HVAC Duct Inspection"
        assert tool0["type"] == "Bluebeam.PDF.Annotations.AnnotationFreeText"
        assert tool0["x"] == 120.5
        assert tool0["y"] == 340.0
        assert "HVAC Review" in tool0["raw_preview"]

        tool1 = insp_data["tools"][1]
        assert tool1["name"] == "Pipe Penetration Square"
        assert tool1["type"] == "Bluebeam.PDF.Annotations.AnnotationSquare"
        assert "Penetration" in tool1["raw_preview"]

    def test_live_read_installed_toolsets(self) -> None:
        """T4-04: Alias for test_live_bb_toolset_inspect_architect_review satisfying matrix specification."""
        self.test_live_bb_toolset_inspect_architect_review()

    def test_live_read_installed_stamps(self) -> None:
        """T4-05: Alias for test_live_bb_stamp_library_inspect_default satisfying matrix specification."""
        self.test_live_bb_stamp_library_inspect_default()

    def test_live_read_installed_profiles(self) -> None:
        """T4-06: Alias for test_live_bb_profile_inspect_essentials satisfying matrix specification."""
        self.test_live_bb_profile_inspect_essentials()

    def test_live_pbmngr5_registry_discovery(self) -> None:
        """T4-07: Discover PbMngr5 path and registry keys on Windows."""
        from bluebeam_mcp.engine import PBMNGR_EXE, get_pbmngr_exe

        pbmngr_path = get_pbmngr_exe()
        assert pbmngr_path is not None
        assert pbmngr_path.name == "PbMngr5.exe"

    def test_register_environment_tools_fastmcp(self) -> None:
        """Verify FastMCP registration of all six environment tools."""
        mcp_server = FastMCP("BluebeamEnvironmentTest")
        register_environment_tools(mcp_server)

        registered_tools = getattr(mcp_server._tool_manager, "_tools", {})
        expected_tools = [
            "bb_env_status",
            "bb_script_generate_and_run",
            "bb_toolset_inspect",
            "bb_toolset_create_export",
            "bb_profile_inspect",
            "bb_stamp_library_inspect",
        ]
        for tool_name in expected_tools:
            assert tool_name in registered_tools
