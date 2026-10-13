"""Bluebeam Revu 21 Model Context Protocol (MCP) Server.

Primary citations:
- docs/citations/01_script_reference.md
- docs/citations/02_binary_and_dotnet_surface.md
- docs/citations/03_data_formats_and_markups.md
- docs/ARCHITECTURE.md Section 2, Section 6
"""

from __future__ import annotations

import functools
import inspect
import logging
import sys
from typing import Any, Callable

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from bluebeam_mcp.tools import register_all_tools

READ_ONLY_TOOLS = {
    "bb_pdf_info",
    "bb_markup_list",
    "bb_env_status",
    "bb_toolset_inspect",
    "bb_profile_inspect",
    "bb_stamp_library_inspect",
}

DESTRUCTIVE_TOOLS = {
    "bb_pdf_delete_pages",
    "bb_markup_delete",
    "bb_markup_flatten",
    "bb_script_generate_and_run",
}


def create_server() -> FastMCP:
    """Create and configure the Bluebeam Revu 21 FastMCP server instance.

    Registers all 28 document, markup, and environment tools with annotations
    and async thread-pool offloading.

    Citations:
        - docs/ARCHITECTURE.md Section 2.3 (server.py)
        - docs/ARCHITECTURE.md Section 6 (Tool Catalog)
        - docs/TEST_AND_SECURITY_MATRIX.md Section 1.4
    """
    server = FastMCP("revu-mcp")
    register_all_tools(server)

    # Attach tool annotations and non-blocking worker thread wrappers
    for tool_name, tool in server._tool_manager._tools.items():
        if tool_name in READ_ONLY_TOOLS:
            tool.annotations = ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
        elif tool_name in DESTRUCTIVE_TOOLS:
            tool.annotations = ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            )
        else:
            tool.annotations = ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )

        orig_fn = tool.fn
        if not inspect.iscoroutinefunction(orig_fn):
            sig = inspect.signature(orig_fn)

            def _create_async_wrapper(fn: Callable[..., Any], fn_sig: inspect.Signature) -> Callable[..., Any]:
                @functools.wraps(fn)
                async def async_tool(*args: Any, **kwargs: Any) -> Any:
                    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))

                async_tool.__signature__ = fn_sig
                return async_tool

            tool.fn = _create_async_wrapper(orig_fn, sig)
            tool.is_async = True

    return server


_server_instance: FastMCP | None = None


def get_server() -> FastMCP:
    """Return singleton FastMCP server instance, creating lazily."""
    global _server_instance
    if _server_instance is None:
        _server_instance = create_server()
    return _server_instance


def __getattr__(name: str) -> Any:
    """Support lazy attribute access for mcp instance per PEP 562."""
    if name == "mcp":
        return get_server()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def main() -> None:
    """Main entrypoint for running the Bluebeam Revu 21 FastMCP server over stdio transport.

    Configures stderr-only logging to protect the stdout JSON-RPC stream.

    Citations:
        - docs/ARCHITECTURE.md Section 2.1 (System Context)
        - docs/TEST_AND_SECURITY_MATRIX.md Section 1.4
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    server = get_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
