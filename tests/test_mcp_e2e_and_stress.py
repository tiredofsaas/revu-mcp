"""End-to-end MCP server, stdio wire protocol, and concurrency stress tests.

Primary citations:
- docs/ARCHITECTURE.md Section 2 (System Context & Package Responsibilities)
- docs/ARCHITECTURE.md Section 4 (Security Architecture & Threat Mitigation Matrix)
- docs/ARCHITECTURE.md Section 6 (Tool Catalog)
- docs/TEST_AND_SECURITY_MATRIX.md Section 1.4 (Zombie Process Prevention)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2.2 (Adversarial Security Tests)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2.4 (Live Integration Tests)
"""

import asyncio
import concurrent.futures
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from bluebeam_mcp.server import create_server
from bluebeam_mcp.tools.document_tools import bb_pdf_create_blank, bb_pdf_info
from bluebeam_mcp.tools.environment_tools import (
    bb_env_status,
    bb_profile_inspect,
    bb_script_generate_and_run,
    bb_stamp_library_inspect,
    bb_toolset_inspect,
)
from bluebeam_mcp.tools.markup_tools import bb_markup_add, bb_markup_list

TEST_TMP_DIR = Path(__file__).resolve().parent / "tmp"

EXPECTED_28_TOOLS = {
    # Document tools (12)
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
    # Markup tools (10)
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
    # Environment tools (6)
    "bb_env_status",
    "bb_script_generate_and_run",
    "bb_toolset_inspect",
    "bb_toolset_create_export",
    "bb_profile_inspect",
    "bb_stamp_library_inspect",
}


def test_server_registers_all_28_tools() -> None:
    """Verify create_server registers the exact 28 expected tools and validates their schemas.

    Citations:
        - docs/ARCHITECTURE.md Section 6 (Tool Catalog)
        - docs/TEST_AND_SECURITY_MATRIX.md Section 1.1
    """
    server = create_server()
    tools = getattr(server._tool_manager, "_tools", {})
    assert len(tools) == 28, f"Expected 28 registered tools, found {len(tools)}"
    assert set(tools.keys()) == EXPECTED_28_TOOLS

    for name, tool in tools.items():
        assert tool.name == name
        assert bool(tool.description and tool.description.strip()), f"Tool {name} must have a non-empty description"
        schema = tool.parameters
        assert isinstance(schema, dict), f"Tool {name} parameters must be a dictionary schema"
        assert schema.get("type") == "object", f"Tool {name} schema type must be object"
        assert "properties" in schema, f"Tool {name} schema must have properties"


def test_mcp_stdio_wire_handshake_and_tools_list() -> None:
    """Verify live stdio connection initializes and retrieves all 28 tools over wire protocol.

    Citations:
        - docs/ARCHITECTURE.md Section 2.1 (FastMCP stdio JSON-RPC)
    """
    async def _runner() -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = "src"
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "bluebeam_mcp"],
            env=env,
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_res = await session.initialize()
                assert init_res.serverInfo.name == "revu-mcp"

                tools_res = await session.list_tools()
                assert len(tools_res.tools) == 28
                tool_names = {t.name for t in tools_res.tools}
                assert tool_names == EXPECTED_28_TOOLS

    asyncio.run(_runner())


def test_mcp_stdio_wire_live_tool_calls() -> None:
    """Execute live call_tool requests over the stdio wire for the 7 specified tools.

    Verifies valid structured JSON responses for:
    - bb_env_status
    - bb_pdf_create_blank
    - bb_pdf_info
    - bb_markup_add
    - bb_markup_list
    - bb_toolset_inspect ("Architect Review.btx")
    - bb_stamp_library_inspect

    Citations:
        - docs/ARCHITECTURE.md Section 6
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.4
    """
    blank_pdf = TEST_TMP_DIR / "mcp_wire_live_blank.pdf"
    marked_pdf = TEST_TMP_DIR / "mcp_wire_live_marked.pdf"

    for p in [blank_pdf, marked_pdf]:
        if p.exists():
            p.unlink()

    async def _runner() -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = "src"
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "bluebeam_mcp"],
            env=env,
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # 1. bb_env_status
                r1 = await session.call_tool("bb_env_status", arguments={"probe_script_engine": False})
                p1 = json.loads(r1.content[0].text)
                assert p1["status"] == "success"
                assert p1["data"]["revu_build_no"] == "21.11.0.23287"
                assert p1["data"]["product_package"] == "Core"

                # 2. bb_pdf_create_blank
                r2 = await session.call_tool(
                    "bb_pdf_create_blank",
                    arguments={"output_path": str(blank_pdf), "page_count": 2},
                )
                p2 = json.loads(r2.content[0].text)
                assert p2["status"] in ("success", "subscription_fallback")
                assert blank_pdf.exists()
                assert p2["data"]["page_count"] == 2

                # 3. bb_pdf_info
                r3 = await session.call_tool("bb_pdf_info", arguments={"pdf_path": str(blank_pdf)})
                p3 = json.loads(r3.content[0].text)
                assert p3["status"] in ("success", "subscription_fallback")
                assert p3["data"]["page_count"] == 2

                # 4. bb_markup_add
                r4 = await session.call_tool(
                    "bb_markup_add",
                    arguments={
                        "pdf_path": str(blank_pdf),
                        "output_path": str(marked_pdf),
                        "page_number": 1,
                        "markup_type": "Square",
                        "x": 72.0,
                        "y": 72.0,
                        "width": 144.0,
                        "height": 144.0,
                        "author": "QA Auditor",
                        "subject": "Inspection",
                    },
                )
                p4 = json.loads(r4.content[0].text)
                assert p4["status"] in ("success", "subscription_fallback")
                assert marked_pdf.exists()
                assert "markup_id" in p4["data"]

                # 5. bb_markup_list
                r5 = await session.call_tool("bb_markup_list", arguments={"pdf_path": str(marked_pdf)})
                p5 = json.loads(r5.content[0].text)
                assert p5["status"] in ("success", "subscription_fallback")
                assert p5["data"]["total_markups"] >= 1
                assert len(p5["data"]["markups"]) >= 1

                # 6. bb_toolset_inspect
                r6 = await session.call_tool(
                    "bb_toolset_inspect",
                    arguments={"toolset_path": "Architect Review.btx", "decompress_raw": True},
                )
                p6 = json.loads(r6.content[0].text)
                assert p6["status"] == "success"
                assert p6["data"]["title"] == "Architect Review"
                assert p6["data"]["tool_count"] > 0

                # 7. bb_stamp_library_inspect
                r7 = await session.call_tool("bb_stamp_library_inspect", arguments={"include_localized": False})
                p7 = json.loads(r7.content[0].text)
                assert p7["status"] == "success"
                assert p7["data"]["stamp_count"] > 0
                assert len(p7["data"]["stamps"]) > 0

    try:
        asyncio.run(_runner())
    finally:
        for p in [blank_pdf, marked_pdf]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass


def test_mcp_stdio_wire_adversarial_security_rejection() -> None:
    """Send live adversarial call_tool requests over stdio wire and verify SECURITY_VIOLATION.

    Verifies deterministic rejection for:
    1. E:\\ProtectedVault\\secret.pdf
    2. C:\\Program Files\\SOLIDWORKS Corp\\part.pdf
    3. .bcs newline and injection payloads
    And verifies the server stays healthy and responsive for subsequent valid requests.

    Citations:
        - docs/ARCHITECTURE.md Section 4 (Security Architecture)
        - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2
    """
    async def _runner() -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = "src"
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "bluebeam_mcp"],
            env=env,
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # 1. E:\ProtectedVault access attempt
                r1 = await session.call_tool("bb_pdf_info", arguments={"pdf_path": r"E:\ProtectedVault\secret.pdf"})
                p1 = json.loads(r1.content[0].text)
                assert p1["status"] == "error"
                assert p1["error"]["code"] == "SECURITY_VIOLATION"

                # 2. C:\Program Files\SOLIDWORKS Corp access attempt
                r2 = await session.call_tool(
                    "bb_pdf_info",
                    arguments={"pdf_path": r"C:\Program Files\SOLIDWORKS Corp\part.pdf"},
                )
                p2 = json.loads(r2.content[0].text)
                assert p2["status"] == "error"
                assert p2["error"]["code"] == "SECURITY_VIOLATION"

                # 3. .bcs injection breakout attempt
                r3 = await session.call_tool(
                    "bb_script_generate_and_run",
                    arguments={
                        "commands": [
                            {"name": "Open", "args": ['legit.pdf\nDeleteFile("C:\\Windows\\System32\\calc.exe")']}
                        ]
                    },
                )
                p3 = json.loads(r3.content[0].text)
                assert p3["status"] == "error"
                assert p3["error"]["code"] == "SECURITY_VIOLATION"

                # 4. Verify server remains healthy and responsive for subsequent requests
                r4 = await session.call_tool("bb_env_status", arguments={"probe_script_engine": False})
                p4 = json.loads(r4.content[0].text)
                assert p4["status"] == "success"
                assert p4["data"]["revu_build_no"] == "21.11.0.23287"

    asyncio.run(_runner())


def test_concurrency_stress_and_zero_zombies_or_temp_leaks() -> None:
    """Execute 8 concurrent tool calls using ThreadPoolExecutor.

    Verifies:
    1. 100% success rate across all 8 concurrent workers.
    2. 0 leftover mcp_job_*.bcs files in tests/tmp/.
    3. 0 lingering ScriptEngine.exe processes in Windows tasklist.

    Citations:
        - docs/ARCHITECTURE.md Section 2.3, Section 4.4
        - docs/TEST_AND_SECURITY_MATRIX.md Section 1.4, Section 2.4
    """
    tmp_files: list[Path] = []
    try:
        def worker(worker_id: int) -> dict[str, Any]:
            if worker_id in (0, 1, 2, 7):
                target_pdf = TEST_TMP_DIR / f"stress_worker_{worker_id}.pdf"
                tmp_files.append(target_pdf)
                res = bb_pdf_create_blank(
                    output_path=str(target_pdf),
                    page_count=worker_id + 1,
                )
                assert target_pdf.exists(), f"Target PDF was not created for worker {worker_id}"
                return res
            elif worker_id == 3:
                return bb_env_status(probe_script_engine=True)
            elif worker_id == 4:
                return bb_toolset_inspect("Architect Review.btx", decompress_raw=True)
            elif worker_id == 5:
                return bb_stamp_library_inspect(include_localized=False)
            else:
                return bb_profile_inspect("Essentials.bpx")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, i) for i in range(8)]
            results = [f.result() for f in futures]

        for idx, res in enumerate(results):
            assert res["status"] in ("success", "subscription_fallback"), f"Worker {idx} returned failure: {res}"
            assert res.get("error") is None, f"Worker {idx} returned error: {res.get('error')}"

        leftover_bcs = list(TEST_TMP_DIR.glob("mcp_job_*.bcs"))
        assert len(leftover_bcs) == 0, f"Detected leftover temporary BCS files: {leftover_bcs}"

        running_count = 0
        for _ in range(15):
            res_ps = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq ScriptEngine.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
            )
            running_count = (
                0
                if "No tasks are running" in res_ps.stdout
                else len([line for line in res_ps.stdout.strip().splitlines() if "ScriptEngine.exe" in line])
            )
            if running_count == 0:
                break
            time.sleep(0.2)
        assert running_count == 0, f"Detected {running_count} lingering ScriptEngine.exe processes"

    finally:
        for f in tmp_files:
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass


def test_mcp_wire_stdio_protocol_handshake() -> None:
    """T4-08: Alias for test_mcp_stdio_wire_handshake_and_tools_list satisfying matrix specification."""
    test_mcp_stdio_wire_handshake_and_tools_list()


def test_mcp_wire_tool_call_round_trip() -> None:
    """T4-09: Alias for test_mcp_stdio_wire_live_tool_calls satisfying matrix specification."""
    test_mcp_stdio_wire_live_tool_calls()


def test_mcp_wire_adversarial_rejection() -> None:
    """T4-10: Alias for test_mcp_stdio_wire_adversarial_security_rejection satisfying matrix specification."""
    test_mcp_stdio_wire_adversarial_security_rejection()


def test_concurrency_and_zero_zombies() -> None:
    """T4-11: Alias for test_concurrency_stress_and_zero_zombies_or_temp_leaks satisfying matrix specification."""
    test_concurrency_stress_and_zero_zombies_or_temp_leaks()
