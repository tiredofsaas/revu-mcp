"""Bluebeam Revu 21 MCP tools package.

Primary citations:
- docs/citations/01_script_reference.md
- docs/citations/02_binary_and_dotnet_surface.md
- docs/citations/03_data_formats_and_markups.md
- docs/ARCHITECTURE.md Section 6
"""

from typing import Any

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
from bluebeam_mcp.tools.environment_tools import (
    bb_env_status,
    bb_profile_inspect,
    bb_script_generate_and_run,
    bb_stamp_library_inspect,
    bb_toolset_create_export,
    bb_toolset_inspect,
    build_pbmngr_cli_args,
    register_environment_tools,
)
from bluebeam_mcp.tools.markup_tools import (
    STAMP_BLEND_MODE_MAP,
    STAMP_BLEND_MODE_NAMES,
    STAMP_ORIGIN_MAP,
    STAMP_ORIGIN_NAMES,
    bb_form_inspect_and_fill,
    bb_markup_add,
    bb_markup_delete,
    bb_markup_export_bax,
    bb_markup_flatten,
    bb_markup_import_bax,
    bb_markup_list,
    bb_markup_update,
    bb_pdf_color_and_optimize,
    bb_pdf_stamp,
    register_markup_tools,
    resolve_stamp_blend_mode,
    resolve_stamp_origin,
)


def register_all_tools(mcp: Any) -> list[str]:
    """Register all 28 Bluebeam Revu 21 MCP tools across document, markup, and environment modules."""
    register_document_tools(mcp)
    register_markup_tools(mcp)
    register_environment_tools(mcp)
    tool_map = getattr(getattr(mcp, "_tool_manager", None), "_tools", {})
    return list(tool_map.keys())


__all__ = [
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
    "register_document_tools",
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
    "register_markup_tools",
    "STAMP_ORIGIN_MAP",
    "STAMP_ORIGIN_NAMES",
    "STAMP_BLEND_MODE_MAP",
    "STAMP_BLEND_MODE_NAMES",
    "resolve_stamp_origin",
    "resolve_stamp_blend_mode",
    # Environment tools (6)
    "bb_env_status",
    "bb_script_generate_and_run",
    "bb_toolset_inspect",
    "bb_toolset_create_export",
    "bb_profile_inspect",
    "bb_stamp_library_inspect",
    "build_pbmngr_cli_args",
    "register_environment_tools",
    # Unified registrar
    "register_all_tools",
]
