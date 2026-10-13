"""Bluebeam Revu 21 document lifecycle and page manipulation MCP tools.

Provides 12 production-ready document tools:
1. bb_pdf_info: Inspect page count, dimensions, rotation, metadata, annotations, bookmarks, fields.
2. bb_pdf_create_blank: Create new blank or styled grid PDF documents.
3. bb_pdf_combine: Combine multiple PDFs into a single document.
4. bb_pdf_insert_pages: Insert pages from another document or blank pages at 0-based index.
5. bb_pdf_extract_pages: Extract 1-based page range to destination PDF.
6. bb_pdf_delete_pages: Delete specified 1-based page range from document.
7. bb_pdf_rotate_pages: Rotate pages by 90-degree increments with optional filtering.
8. bb_pdf_split: Split document into individual page PDFs in destination folder.
9. bb_pdf_metadata: Get, set, or list document metadata properties.
10. bb_pdf_page_labels: Query or set document page labels.
11. bb_pdf_bookmarks: List, export, or import document bookmark outline trees.
12. bb_pdf_header_footer: Apply dynamic headers, footers, and Bates numbering.

Citations:
- docs/citations/01_script_reference.md Section 1, Section 2
- docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmd* classes)
- docs/ARCHITECTURE.md Section 6.1 (Category 1: Document Lifecycle & Page Tools)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Four-Tier Continuous Test Matrix)
- ISO 32000-1:2008 (PDF 1.7 Specification)
"""

from __future__ import annotations

from datetime import datetime
import io
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Literal
import xml.etree.ElementTree as ET

import pypdf
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from bluebeam_mcp.engine import (
    execute_dual_engine,
    format_error_envelope,
)
from bluebeam_mcp.script_builder import (
    ScriptBuilder,
    validate_insertion_index,
    validate_one_based_page,
    validate_page_range,
)
from bluebeam_mcp.security import (
    CorruptPDFError,
    EncryptedPDFError,
    InvalidParameterError,
    PageRangeError,
    SecurityViolationError,
    atomic_write_pdf,
    check_pdf_header,
    parse_xml_safely,
    sanitize_untrusted_text,
    validate_path,
)

# Document tool citations mapping per ARCHITECTURE.md Section 6.1
CITATIONS_INFO: list[str] = [
    "01_script_reference.md p. 10-11 (FilePropertyList), p. 19-20 (PageCount), p. 21 (PageSize, PageRotateGet)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdPageCount, SCmdPageSize, SCmdPageRotateGet, SCmdFilePropertyList)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 1 (bb_pdf_info)",
]

CITATIONS_CREATE_BLANK: list[str] = [
    "01_script_reference.md p. 18-19 (New, Save, Close)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdNew)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 2 (bb_pdf_create_blank)",
]

CITATIONS_COMBINE: list[str] = [
    "01_script_reference.md p. 9 (Combine, Save, Close)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdCombine), Section 6 (Stapler.exe)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 3 (bb_pdf_combine)",
]

CITATIONS_INSERT_PAGES: list[str] = [
    "01_script_reference.md p. 14 (InsertBlankPages), p. 15 (InsertPages)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdInsertPages, SCmdInsertBlankPages)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 4 (bb_pdf_insert_pages)",
]

CITATIONS_EXTRACT_PAGES: list[str] = [
    "01_script_reference.md p. 20 (PageExtract)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdPageExtract)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 5 (bb_pdf_extract_pages)",
]

CITATIONS_DELETE_PAGES: list[str] = [
    "01_script_reference.md p. 20 (PageDelete)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdPageDelete)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 6 (bb_pdf_delete_pages)",
]

CITATIONS_ROTATE_PAGES: list[str] = [
    "01_script_reference.md p. 20-21 (PageRotate)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdPageRotation)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 7 (bb_pdf_rotate_pages)",
]

CITATIONS_SPLIT: list[str] = [
    "01_script_reference.md p. 26-27 (SplitPages)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdSplitPages)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 8 (bb_pdf_split)",
]

CITATIONS_METADATA: list[str] = [
    "01_script_reference.md p. 10-11 (FilePropertyGet, FilePropertyList, FilePropertySet)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdFilePropertyGet, SCmdFilePropertySet, SCmdFilePropertyList)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 9 (bb_pdf_metadata)",
]

CITATIONS_PAGE_LABELS: list[str] = [
    "01_script_reference.md p. 13, 26 (PageLabelGet, PageLabelsSet)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdPageLabelGet, SCmdPageLabelsSet)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 10 (bb_pdf_page_labels)",
]

CITATIONS_BOOKMARKS: list[str] = [
    "01_script_reference.md p. 15 (BookmarksExport, BookmarksImport)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdBookmarksExport, SCmdBookmarksImport)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 11 (bb_pdf_bookmarks)",
]

CITATIONS_HEADER_FOOTER: list[str] = [
    "01_script_reference.md p. 13-14 (HeaderAndFooter)",
    "02_binary_and_dotnet_surface.md Section 5.2 (SCmdHeaderAndFooter)",
    "docs/ARCHITECTURE.md Section 6.1 Tool 12 (bb_pdf_header_footer)",
]


# ============================================================================
# Helper Functions
# ============================================================================


def _open_pdf_reader(pdf_file: Path, password: str | None = None) -> pypdf.PdfReader:
    """Open and decrypt a PDF file using pypdf.

    Citations:
        - ISO 32000-1:2008 Section 7.5.
        - docs/REMEDIATION_PLAN.md Finding C-07.
    """
    try:
        reader = pypdf.PdfReader(str(pdf_file))
    except Exception as exc:
        raise CorruptPDFError(
            f"Corrupt or unreadable PDF: {exc}",
            details={"path": str(pdf_file), "error": str(exc)},
        ) from exc

    if reader.is_encrypted:
        if password is not None:
            try:
                res = reader.decrypt(password)
            except Exception as exc:
                raise EncryptedPDFError(
                    f"Invalid password for encrypted PDF: {exc}",
                    details={"path": str(pdf_file)},
                ) from exc
            if res == 0:
                raise EncryptedPDFError(
                    "Invalid password for encrypted PDF",
                    details={"path": str(pdf_file)},
                )
        else:
            try:
                res = reader.decrypt("")
                if res == 0:
                    raise EncryptedPDFError(
                        f"PDF file is encrypted and requires a password: {pdf_file}",
                        details={"path": str(pdf_file)},
                    )
            except Exception as exc:
                if isinstance(exc, EncryptedPDFError):
                    raise
                raise EncryptedPDFError(
                    f"PDF file is encrypted and requires a password: {pdf_file}",
                    details={"path": str(pdf_file)},
                ) from exc

    return reader


def _copy_catalog_and_metadata(
    reader: pypdf.PdfReader,
    writer: pypdf.PdfWriter,
    copy_outlines: bool = True,
    copy_labels: bool = True,
    copy_forms: bool = True,
    copy_names: bool = True,
) -> None:
    """Preserve document metadata and root catalog objects onto writer.

    Citations:
        - ISO 32000-1:2008 Section 7.7 (Document Structure).
        - docs/ARCHITECTURE.md Section 4.1.
        - docs/REMEDIATION_PLAN.md Finding C-07, C-08, F-02.
    """
    if reader.metadata:
        writer.add_metadata({
            str(k): str(v)
            for k, v in reader.metadata.items()
            if str(k).startswith("/") and v is not None
        })

    root = None
    try:
        if hasattr(reader, "trailer") and reader.trailer:
            root = reader.trailer.get("/Root")
    except Exception:
        pass

    if root is not None:
        keys_to_copy = ["/OCProperties", "/ViewerPreferences", "/Lang"]
        if copy_names:
            keys_to_copy.append("/Names")
        if copy_labels:
            keys_to_copy.append("/PageLabels")
        if copy_forms:
            keys_to_copy.append("/AcroForm")
        if copy_outlines:
            keys_to_copy.append("/Outlines")

        for k in keys_to_copy:
            name_obj = NameObject(k)
            if k in root and name_obj not in writer._root_object:
                try:
                    v = root[k]
                    writer._root_object[name_obj] = writer._add_object(v.clone(writer))
                except Exception:
                    pass


def _extract_page_label_entries(reader: pypdf.PdfReader) -> list[tuple[int, DictionaryObject]]:
    """Extract sorted (start_page_index, label_dict) pairs from reader /PageLabels /Nums."""
    entries: list[tuple[int, DictionaryObject]] = []
    try:
        root = reader.trailer.get("/Root") if hasattr(reader, "trailer") and reader.trailer else None
        if root is None or "/PageLabels" not in root:
            return entries
        pl = root["/PageLabels"].get_object()
        if not isinstance(pl, DictionaryObject) or "/Nums" not in pl:
            return entries
        nums = pl["/Nums"].get_object()
        for i in range(0, len(nums) - 1, 2):
            idx_val = int(nums[i])
            lbl_obj = nums[i + 1].get_object()
            if isinstance(lbl_obj, DictionaryObject):
                entries.append((idx_val, lbl_obj))
        entries.sort(key=lambda pair: pair[0])
    except Exception:
        pass
    return entries


def _apply_page_labels_for_source_indices(
    reader: pypdf.PdfReader,
    writer: pypdf.PdfWriter,
    source_indices: list[int],
) -> None:
    """Construct /PageLabels on writer for an extracted, split, or deleted subset of source pages."""
    entries = _extract_page_label_entries(reader)
    if not entries or not source_indices:
        return

    nums_array = ArrayObject()
    prev_signature: tuple[str, str, int] | None = None

    for out_idx, src_idx in enumerate(source_indices):
        active_start = 0
        active_dict: DictionaryObject | None = None
        for start_idx, lbl_dict in entries:
            if start_idx <= src_idx:
                active_start = start_idx
                active_dict = lbl_dict
            else:
                break

        if active_dict is None:
            style_str = "/D"
            prefix_str = ""
            st_val = src_idx + 1
        else:
            style_str = str(active_dict.get("/S", ""))
            prefix_str = str(active_dict.get("/P", ""))
            base_st = int(active_dict.get("/St", 1))
            st_val = base_st + (src_idx - active_start) if style_str else 1

        if prev_signature is not None:
            prev_style, prev_prefix, prev_expected_next = prev_signature
            if style_str == prev_style and prefix_str == prev_prefix and (not style_str or st_val == prev_expected_next):
                prev_signature = (style_str, prefix_str, st_val + 1)
                continue

        new_lbl = DictionaryObject()
        if style_str:
            new_lbl[NameObject("/S")] = NameObject(style_str if style_str.startswith("/") else f"/{style_str}")
        if prefix_str:
            new_lbl[NameObject("/P")] = TextStringObject(prefix_str)
        if st_val != 1:
            new_lbl[NameObject("/St")] = NumberObject(st_val)

        nums_array.append(NumberObject(out_idx))
        nums_array.append(writer._add_object(new_lbl))
        prev_signature = (style_str, prefix_str, st_val + 1)

    if len(nums_array) > 0:
        pl_dict = DictionaryObject()
        pl_dict[NameObject("/Nums")] = nums_array
        writer._root_object[NameObject("/PageLabels")] = writer._add_object(pl_dict)


def _shift_page_labels_on_insert(
    reader_target: pypdf.PdfReader,
    writer: pypdf.PdfWriter,
    insert_index: int,
    inserted_count: int,
) -> None:
    """Shift /PageLabels /Nums indices >= insert_index by +inserted_count on page insertion (F-04)."""
    entries = _extract_page_label_entries(reader_target)
    if not entries or inserted_count <= 0:
        return

    nums_array = ArrayObject()
    if insert_index == 0 and entries[0][0] == 0:
        default_lbl = DictionaryObject()
        default_lbl[NameObject("/S")] = NameObject("/D")
        nums_array.append(NumberObject(0))
        nums_array.append(writer._add_object(default_lbl))

    for start_idx, lbl_dict in entries:
        new_idx = start_idx + inserted_count if start_idx >= insert_index else start_idx
        cloned_lbl = DictionaryObject()
        if "/S" in lbl_dict:
            cloned_lbl[NameObject("/S")] = NameObject(str(lbl_dict["/S"]))
        if "/P" in lbl_dict:
            cloned_lbl[NameObject("/P")] = TextStringObject(str(lbl_dict["/P"]))
        if "/St" in lbl_dict:
            cloned_lbl[NameObject("/St")] = NumberObject(int(lbl_dict["/St"]))
        nums_array.append(NumberObject(new_idx))
        nums_array.append(writer._add_object(cloned_lbl))

    pl_dict = DictionaryObject()
    pl_dict[NameObject("/Nums")] = nums_array
    writer._root_object[NameObject("/PageLabels")] = writer._add_object(pl_dict)


def _reconcile_outlines_on_delete(
    reader: pypdf.PdfReader,
    writer: pypdf.PdfWriter,
    indices_to_delete: set[int],
    total_pages: int,
) -> None:
    """Prune outline items targeting deleted pages and rebind surviving items to new page indices (F-04)."""
    try:
        if not reader.outline:
            return
        bookmarks = _extract_bookmarks_list(reader.outline, reader)
    except Exception:
        return

    old_to_new: dict[int, int] = {}
    new_idx = 0
    for old_idx in range(total_pages):
        if old_idx not in indices_to_delete:
            old_to_new[old_idx] = new_idx
            new_idx += 1

    writer._root_object.pop(NameObject("/Outlines"), None)

    def _add_surviving_nodes(nodes: list[dict[str, Any]], parent_ref: Any = None) -> None:
        for node in nodes:
            p_num = node.get("page") if node.get("page") is not None else node.get("page_number")
            old_page_idx = (p_num - 1) if isinstance(p_num, int) and p_num >= 1 else None
            children = node.get("children") or []
            if old_page_idx is not None and old_page_idx in old_to_new:
                added_ref = writer.add_outline_item(
                    str(node.get("title", "Untitled")),
                    old_to_new[old_page_idx],
                    parent=parent_ref,
                )
                if children:
                    _add_surviving_nodes(children, parent_ref=added_ref)
            elif children:
                _add_surviving_nodes(children, parent_ref=parent_ref)

    _add_surviving_nodes(bookmarks, parent_ref=None)


def _parse_page_range_ordered(page_range_str: str, total_pages: int) -> list[int]:
    """Expand a validated 1-based page range into an ordered list of 0-based page indices.

    Preserves explicit user page sequence.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 7, 20.
        - docs/REMEDIATION_PLAN.md Finding L-04.
    """
    if page_range_str == "-1":
        return list(range(total_pages))

    indices: list[int] = []
    tokens = page_range_str.split(",")
    for token in tokens:
        t = token.strip()
        if not t:
            continue
        if "-" in t:
            parts = t.split("-")
            start, end = int(parts[0].strip()), int(parts[1].strip())
            for p in range(start, end + 1):
                idx = p - 1
                if 0 <= idx < total_pages:
                    indices.append(idx)
        else:
            idx = int(t) - 1
            if 0 <= idx < total_pages:
                indices.append(idx)

    return indices


def _parse_page_range_to_indices(page_range_str: str, total_pages: int) -> list[int]:
    """Expand a validated 1-based page range into sorted 0-based indices for set operations."""
    return sorted(set(_parse_page_range_ordered(page_range_str, total_pages)))


def _extract_bookmarks_list(outline_list: Any, reader: pypdf.PdfReader) -> list[dict[str, Any]]:
    """Traverse outlines iteratively with depth and node caps, returning nested bookmark hierarchy.

    Citations:
        - ISO 32000-1:2008 Section 12.3.3 (Document Outline).
        - Bluebeam Script Reference Version 2.0.11, p. 15.
        - docs/REMEDIATION_PLAN.md Finding H-08, M-05.
    """
    if not outline_list or not isinstance(outline_list, list):
        return []

    root_list: list[dict[str, Any]] = []
    stack: list[tuple[list[Any], list[dict[str, Any]], int]] = [(outline_list, root_list, 1)]
    node_count = 0

    while stack:
        items, target_list, depth = stack.pop()
        if depth > 64:
            continue
        for item in items:
            node_count += 1
            if node_count > 10_000:
                break
            if isinstance(item, list):
                if target_list:
                    sub_children = target_list[-1]["children"]
                    stack.append((item, sub_children, depth + 1))
                else:
                    stack.append((item, target_list, depth + 1))
            else:
                title = ""
                if hasattr(item, "title"):
                    title = str(item.title)
                elif isinstance(item, dict) and "/Title" in item:
                    title = str(item["/Title"])
                else:
                    title = str(item)

                page_num: int | None = None
                try:
                    dest_page = reader.get_destination_page_number(item)
                    if dest_page is not None and dest_page >= 0:
                        page_num = dest_page + 1
                except Exception:
                    page_num = None

                node: dict[str, Any] = {
                    "title": sanitize_untrusted_text(title),
                    "page": page_num,
                    "children": [],
                }
                target_list.append(node)
        if node_count > 10_000:
            break

    return root_list


_extract_bookmarks_tree = _extract_bookmarks_list


def _bookmarks_to_xml(bookmarks: list[dict[str, Any]]) -> str:
    """Serialize nested bookmarks hierarchy into XML representation."""
    root = ET.Element("Bookmarks")

    def _add_nodes(parent_elem: ET.Element, items: list[dict[str, Any]]) -> None:
        for item in items:
            b_elem = ET.SubElement(parent_elem, "Bookmark")
            b_elem.set("title", str(item.get("title", "")))
            p_val = item.get("page")
            b_elem.set("page", str(p_val) if p_val is not None else "")
            children = item.get("children", [])
            if children:
                _add_nodes(b_elem, children)

    _add_nodes(root, bookmarks)
    return ET.tostring(root, encoding="utf-8").decode("utf-8")


def _xml_to_bookmarks(root: ET.Element) -> list[dict[str, Any]]:
    """Parse XML representation into nested bookmarks dictionary list."""
    def _parse_elem(elem: ET.Element) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        for child in elem:
            if child.tag == "Bookmark":
                title = child.get("title", "")
                page_raw = child.get("page", "")
                page = int(page_raw) if page_raw.isdigit() else None
                children = _parse_elem(child)
                nodes.append({"title": title, "page": page, "children": children})
        return nodes

    return _parse_elem(root)


def _add_bookmarks_recursive(
    writer: pypdf.PdfWriter,
    items: list[dict[str, Any]],
    total_pages: int,
    parent: Any = None,
    depth: int = 1,
) -> int:
    """Recursively add outline items to writer, validating 1-based page numbers."""
    if depth > 64:
        return 0
    count = 0
    for item in items:
        title = str(item.get("title", "Bookmark"))
        page = item.get("page", 1)
        if isinstance(page, bool) or not isinstance(page, int) or page < 1 or page > total_pages:
            raise PageRangeError(
                f"Bookmark '{title}' target page {page} is out of bounds (1 to {total_pages})"
            )
        page_idx = page - 1
        outline_item = writer.add_outline_item(title, page_idx, parent=parent)
        count += 1
        children = item.get("children", [])
        if children and isinstance(children, list):
            count += _add_bookmarks_recursive(
                writer,
                children,
                total_pages,
                parent=outline_item,
                depth=depth + 1,
            )
    return count


def _expand_hf_macro(
    template: str,
    page_num: int,
    total_pages: int,
    page_idx: int = 0,
    reader: pypdf.PdfReader | None = None,
    resolved_pdf: Path | None = None,
    bates_str: str = "",
    bates_offset: int = 0,
) -> str:
    """Evaluate Bluebeam dynamic substitution codes for headers and footers.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 13.
        - docs/REMEDIATION_PLAN.md Finding H-06, H-07.
    """
    if not template:
        return ""

    text = template
    text = text.replace("<<1 of n>>", f"{page_num} of {total_pages}")
    text = text.replace("<<1/n>>", f"{page_num}/{total_pages}")
    text = text.replace("<<Page 1 of n>>", f"Page {page_num} of {total_pages}")
    text = text.replace("<<Page 1>>", f"Page {page_num}")
    text = text.replace("<<1>>", str(page_num))
    text = text.replace("<<n>>", str(total_pages))

    meta: dict[str, str] = {}
    if reader and reader.metadata:
        for mk, mv in reader.metadata.items():
            clean_k = str(mk).lstrip("/")
            meta[clean_k] = str(mv) if mv is not None else ""

    text = text.replace("<<Title>>", meta.get("Title", ""))
    text = text.replace("<<Author>>", meta.get("Author", ""))
    text = text.replace("<<Subject>>", meta.get("Subject", ""))
    text = text.replace("<<Keywords>>", meta.get("Keywords", ""))

    if resolved_pdf:
        text = text.replace("<<FileName>>", resolved_pdf.name)
        text = text.replace("<<Path>>", str(resolved_pdf))
    else:
        text = text.replace("<<FileName>>", "")
        text = text.replace("<<Path>>", "")

    page_label = ""
    if reader and hasattr(reader, "page_labels") and reader.page_labels:
        labels_list = list(reader.page_labels)
        if 0 <= page_idx < len(labels_list):
            page_label = str(labels_list[page_idx])
    if not page_label:
        page_label = f"Page {page_num}"
    text = text.replace("<<PageLabel>>", page_label)

    now = datetime.now()
    text = text.replace("<<mm/dd/yyyy>>", now.strftime("%m/%d/%Y"))
    text = text.replace("<<MM/dd/yyyy>>", now.strftime("%m/%d/%Y"))
    text = text.replace("<<m/d/yyyy>>", f"{now.month}/{now.day}/{now.year}")
    text = text.replace("<<M/d/yyyy>>", f"{now.month}/{now.day}/{now.year}")
    text = text.replace("<<dd/mm/yyyy>>", now.strftime("%d/%m/%Y"))
    text = text.replace("<<yyyy-mm-dd>>", now.strftime("%Y-%m-%d"))
    text = text.replace("<<mmmm d, yyyy>>", f"{now.strftime('%B')} {now.day}, {now.year}")
    text = text.replace("<<mmm d, yyyy>>", f"{now.strftime('%b')} {now.day}, {now.year}")

    def _replace_embedded_bates(m: re.Match[str]) -> str:
        digits = int(m.group(1))
        start = int(m.group(2))
        prefix = m.group(3)
        suffix = m.group(4)
        val = start + page_idx + bates_offset
        return f"{prefix}{val:0{digits}d}{suffix}"

    text = re.sub(
        r"<<Bates Number#(\d+)#(\d+)#([^#>]*)#([^>]*)>>",
        _replace_embedded_bates,
        text,
    )

    if bates_str:
        text = text.replace("<<Bates>>", bates_str)
        text = text.replace("<<Bates Number>>", bates_str)

    return text


_apply_substitutions = _expand_hf_macro


def _bcs_header_and_footer(
    builder: ScriptBuilder,
    top_left: str,
    top_center: str,
    top_right: str,
    bottom_left: str,
    bottom_center: str,
    bottom_right: str,
    margin_pts: float,
    font_size: float,
    bates_offset: int,
    bates_key: str,
    valid_range: str,
) -> None:
    """Compose BCS HeaderAndFooter command matching 01_script_reference.md p. 13-14."""
    builder.add_command(
        "HeaderAndFooter",
        top_left,
        top_center,
        top_right,
        bottom_left,
        bottom_center,
        bottom_right,
        margin_pts,
        margin_pts,
        margin_pts,
        margin_pts,
        "Helvetica",
        font_size,
        False,
        False,
        False,
        "#000000",
        False,
        bates_offset,
        bates_key,
        valid_range,
    )


def _render_page_grid(c: canvas.Canvas, width_pts: float, height_pts: float, style: int) -> None:
    """Render background grid or notebook lines for blank pages matching Bluebeam styles 0-8.

    Styles:
        0 = Blank
        1 = Notebook
        2 = 1/8 inch Grid (9 points)
        3 = 1/4 inch Grid (18 points)
        4 = Engineering Grid (14.4 points)
        5 = 0.5 cm Grid (14.17 points)
        6 = 1.0 cm Grid (28.35 points)
        7 = 1/2 inch Isometric Grid (36 points)
        8 = 0.5 cm Isometric Grid (14.17 points)

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 6, 19.
        - docs/REMEDIATION_PLAN.md Finding H-20.
    """
    if style == 0:
        return

    c.saveState()

    if style == 1:
        # Notebook style: blue horizontal rules every 24 pts, red margin line at 72 pts
        c.setStrokeColor(HexColor("#C0D0E0"))
        c.setLineWidth(0.5)
        y = 72.0
        while y < height_pts - 36.0:
            c.line(0, y, width_pts, y)
            y += 24.0
        c.setStrokeColor(HexColor("#F0B0B0"))
        c.setLineWidth(1.0)
        c.line(72.0, 0, 72.0, height_pts)

    elif style in (2, 3, 4, 5, 6):
        # Orthogonal grid styles
        spacings = {
            2: 72.0 / 8.0,          # 1/8" = 9.0 pts
            3: 72.0 / 4.0,          # 1/4" = 18.0 pts
            4: 72.0 / 5.0,          # Engineering = 14.4 pts
            5: 0.5 * 72.0 / 2.54,   # 0.5 cm = 14.17 pts
            6: 1.0 * 72.0 / 2.54,   # 1 cm = 28.35 pts
        }
        step = spacings.get(style, 18.0)
        c.setStrokeColor(HexColor("#E0E0E0"))
        c.setLineWidth(0.3)

        # Vertical grid lines
        x = step
        while x < width_pts:
            c.line(x, 0, x, height_pts)
            x += step

        # Horizontal grid lines
        y = step
        while y < height_pts:
            c.line(0, y, width_pts, y)
            y += step

    elif style in (7, 8):
        # Isometric grid styles (isometric angle 30 degrees)
        step = 36.0 if style == 7 else (0.5 * 72.0 / 2.54)
        c.setStrokeColor(HexColor("#E5E5E5"))
        c.setLineWidth(0.3)

        # Horizontal guide lines
        y = step
        while y < height_pts:
            c.line(0, y, width_pts, y)
            y += step

        # Diagonal 30-degree lines (dx = H * sqrt(3))
        dx = height_pts * math.sqrt(3.0)
        diag_x = -height_pts * math.sqrt(3.0)
        while diag_x < width_pts + height_pts * math.sqrt(3.0):
            c.line(diag_x, 0, diag_x + dx, height_pts)
            c.line(diag_x, height_pts, diag_x + dx, 0)
            diag_x += step * 2.0

    c.restoreState()


# ============================================================================
# Tool 1: bb_pdf_info
# ============================================================================


def bb_pdf_info(
    pdf_path: str,
    include_annotations: bool = True,
    include_bookmarks: bool = True,
    include_fields: bool = True,
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Inspect PDF page count, dimensions, rotation, metadata, annotations, bookmarks, and form fields.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 10-11, 19-21.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 1.
    """
    tool_name = "bb_pdf_info"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)

        # Build BCS query sequence
        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        builder.page_count()
        builder.page_size(1)
        builder.page_rotate_get(1)
        builder.add_command("FilePropertyList")
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            reader = _open_pdf_reader(resolved_pdf, password=password)

            page_count = len(reader.pages)
            pages_info: list[dict[str, Any]] = []
            for idx, p in enumerate(reader.pages):
                try:
                    w = float(p.mediabox.width)
                    h = float(p.mediabox.height)
                except Exception:
                    w, h = 0.0, 0.0
                rot = int(p.rotation) if p.rotation else 0
                pages_info.append({
                    "page": idx + 1,
                    "width": round(w, 2),
                    "height": round(h, 2),
                    "rotation": rot,
                })

            meta: dict[str, str] = {}
            if reader.metadata:
                for k, v in reader.metadata.items():
                    clean_k = sanitize_untrusted_text(str(k).lstrip("/"))
                    meta[clean_k] = sanitize_untrusted_text(str(v)) if v is not None else ""

            total_annots = 0
            annots_list: list[dict[str, Any]] = []
            for idx, p in enumerate(reader.pages):
                page_annots = p.get("/Annots")
                if page_annots:
                    try:
                        total_annots += len(page_annots)
                    except Exception:
                        pass
                    if include_annotations:
                        for annot_ref in page_annots:
                            try:
                                annot_obj = (
                                    annot_ref.get_object()
                                    if hasattr(annot_ref, "get_object")
                                    else annot_ref
                                )
                                if isinstance(annot_obj, dict):
                                    subtype = sanitize_untrusted_text(str(annot_obj.get("/Subtype", "")).lstrip("/"))
                                    contents = sanitize_untrusted_text(str(annot_obj.get("/Contents", "")))
                                    subj = sanitize_untrusted_text(str(annot_obj.get("/Subj", "")))
                                    author = sanitize_untrusted_text(str(annot_obj.get("/T", "")))
                                    nm = sanitize_untrusted_text(str(annot_obj.get("/NM", "")))
                                    rect_raw = annot_obj.get("/Rect", [])
                                    rect = [float(x) for x in rect_raw] if rect_raw else []
                                    annots_list.append({
                                        "page": idx + 1,
                                        "subtype": subtype,
                                        "subject": subj,
                                        "author": author,
                                        "contents": contents,
                                        "id": nm,
                                        "rect": rect,
                                    })
                            except Exception:
                                continue

            bookmarks_list = (
                _extract_bookmarks_list(reader.outline, reader)
                if include_bookmarks
                else []
            )

            fields_dict: dict[str, Any] = {}
            if include_fields:
                try:
                    raw_fields = reader.get_fields()
                    if raw_fields:
                        for k, v in raw_fields.items():
                            val = v.get("/V", "") if isinstance(v, dict) else str(v)
                            clean_k = sanitize_untrusted_text(str(k))
                            clean_val = sanitize_untrusted_text(str(val))
                            fields_dict[clean_k] = clean_val
                except Exception:
                    pass

            return {
                "pdf_path": str(resolved_pdf),
                "page_count": page_count,
                "pages": pages_info,
                "metadata": meta,
                "annotations_count": total_annots,
                "annotations": annots_list,
                "bookmarks": bookmarks_list,
                "fields": fields_dict,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_INFO,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 2: bb_pdf_create_blank
# ============================================================================


def bb_pdf_create_blank(
    output_path: str,
    width_inches: float = 8.5,
    height_inches: float = 11.0,
    page_count: int = 1,
    style: int = 0,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Create a new blank or styled grid PDF document with specified dimensions.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 18-19.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 2.
    """
    tool_name = "bb_pdf_create_blank"
    try:
        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        if (
            isinstance(width_inches, bool)
            or not isinstance(width_inches, (int, float))
            or not math.isfinite(width_inches)
            or not (0 < width_inches <= 200)
        ):
            raise InvalidParameterError(f"width_inches must be a finite number between 0 and 200: {width_inches}")
        if (
            isinstance(height_inches, bool)
            or not isinstance(height_inches, (int, float))
            or not math.isfinite(height_inches)
            or not (0 < height_inches <= 200)
        ):
            raise InvalidParameterError(f"height_inches must be a finite number between 0 and 200: {height_inches}")
        if type(page_count) is not int or not (1 <= page_count <= 2000):
            raise InvalidParameterError(f"page_count must be an integer between 1 and 2000: {page_count}")
        if type(style) is not int or not (0 <= style <= 8):
            raise InvalidParameterError(f"style must be an integer between 0 and 8: {style}")

        builder = ScriptBuilder()
        builder.add_command("New", width_inches, height_inches, page_count, style)
        builder.save(resolved_output)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            w_pts = width_inches * 72.0
            h_pts = height_inches * 72.0

            buf = io.BytesIO()
            c = canvas.Canvas(buf, pagesize=(w_pts, h_pts))
            for _ in range(page_count):
                _render_page_grid(c, w_pts, h_pts, style)
                c.showPage()
            c.save()
            buf.seek(0)

            reader = pypdf.PdfReader(buf)
            writer = pypdf.PdfWriter()
            writer.append(reader)
            atomic_write_pdf(writer, resolved_output)

            file_size = resolved_output.stat().st_size
            return {
                "output_path": str(resolved_output),
                "page_count": page_count,
                "width_inches": width_inches,
                "height_inches": height_inches,
                "style": style,
                "bytes": file_size,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_CREATE_BLANK,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 3: bb_pdf_combine
# ============================================================================


def bb_pdf_combine(
    input_paths: list[str],
    output_path: str,
    passwords: list[str | None] | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Combine multiple PDF files into a single document in specified order.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 9.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2, Section 6.
        - docs/ARCHITECTURE.md Section 6.1 Tool 3.
    """
    tool_name = "bb_pdf_combine"
    try:
        if not input_paths or len(input_paths) < 2:
            raise InvalidParameterError("bb_pdf_combine requires at least two input PDF paths to combine")

        resolved_inputs: list[Path] = []
        for p in input_paths:
            v_p = validate_path(p, mode="read", must_exist=True)
            check_pdf_header(v_p)
            resolved_inputs.append(v_p)

        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        builder = ScriptBuilder()
        builder.add_command("Combine", *[str(p) for p in resolved_inputs])
        builder.save(resolved_output)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter()
            for idx, p in enumerate(resolved_inputs):
                pwd = passwords[idx] if passwords and idx < len(passwords) else None
                reader = _open_pdf_reader(p, password=pwd)
                writer.append(reader)

            atomic_write_pdf(writer, resolved_output)

            reader_out = _open_pdf_reader(resolved_output)
            total_pages = len(reader_out.pages)
            return {
                "output_path": str(resolved_output),
                "input_file_count": len(resolved_inputs),
                "page_count": total_pages,
                "bytes": resolved_output.stat().st_size,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_COMBINE,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 4: bb_pdf_insert_pages
# ============================================================================


def bb_pdf_insert_pages(
    target_pdf_path: str,
    output_path: str,
    insert_index: int = 0,
    source_pdf_path: str | None = None,
    blank_page_count: int = 1,
    width_inches: float = 8.5,
    height_inches: float = 11.0,
    style: int = 0,
    include_bookmarks: bool = False,
    include_attachments: bool = False,
    include_properties: bool = False,
    include_layers: bool = False,
    include_markups: bool = False,
    password: str | None = None,
    source_password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Insert pages from another PDF or blank pages at 0-based index.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 14, 15.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 4.
    """
    tool_name = "bb_pdf_insert_pages"
    try:
        resolved_target = validate_path(target_pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_target)

        target_reader = _open_pdf_reader(resolved_target, password=password)
        target_page_count = len(target_reader.pages)

        valid_idx = validate_insertion_index(insert_index, max_pages=target_page_count)
        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        resolved_source: Path | None = None
        if source_pdf_path is not None:
            resolved_source = validate_path(source_pdf_path, mode="read", must_exist=True)
            check_pdf_header(resolved_source)
        else:
            if type(blank_page_count) is not int or not (1 <= blank_page_count <= 2000):
                raise InvalidParameterError(f"blank_page_count must be an integer between 1 and 2000: {blank_page_count}")
            if (
                isinstance(width_inches, bool)
                or not isinstance(width_inches, (int, float))
                or not math.isfinite(width_inches)
                or not (0 < width_inches <= 200)
            ):
                raise InvalidParameterError("width_inches must be a finite number between 0 and 200")
            if (
                isinstance(height_inches, bool)
                or not isinstance(height_inches, (int, float))
                or not math.isfinite(height_inches)
                or not (0 < height_inches <= 200)
            ):
                raise InvalidParameterError("height_inches must be a finite number between 0 and 200")
            if type(style) is not int or not (0 <= style <= 8):
                raise InvalidParameterError(f"style must be an integer between 0 and 8: {style}")

        builder = ScriptBuilder()
        builder.open(resolved_target)
        if resolved_source is not None:
            builder.insert_pages(
                valid_idx,
                resolved_source,
                include_bookmarks=include_bookmarks,
                include_attachments=include_attachments,
                include_properties=include_properties,
                include_layers=include_layers,
                include_markups=include_markups,
            )
        else:
            builder.insert_blank_pages(
                valid_idx,
                width=width_inches,
                height=height_inches,
                count=blank_page_count,
                style=style,
            )
        builder.save(resolved_output)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            reader_target = _open_pdf_reader(resolved_target, password=password)
            writer = pypdf.PdfWriter(clone_from=reader_target)
            _copy_catalog_and_metadata(reader_target, writer)

            inserted_count = 0
            if resolved_source is not None:
                reader_source = _open_pdf_reader(resolved_source, password=source_password)
                for offset, sp in enumerate(reader_source.pages):
                    writer.insert_page(sp, valid_idx + offset)
                inserted_count = len(reader_source.pages)
            else:
                w_pts = width_inches * 72.0
                h_pts = height_inches * 72.0
                buf = io.BytesIO()
                c = canvas.Canvas(buf, pagesize=(w_pts, h_pts))
                for _ in range(blank_page_count):
                    _render_page_grid(c, w_pts, h_pts, style)
                    c.showPage()
                c.save()
                buf.seek(0)
                blank_reader = pypdf.PdfReader(buf)
                for offset, bp in enumerate(blank_reader.pages):
                    writer.insert_page(bp, valid_idx + offset)
                inserted_count = blank_page_count

            _shift_page_labels_on_insert(reader_target, writer, valid_idx, inserted_count)
            atomic_write_pdf(writer, resolved_output)

            return {
                "output_path": str(resolved_output),
                "target_pdf_path": str(resolved_target),
                "insert_index": valid_idx,
                "source_pdf_path": str(resolved_source) if resolved_source else None,
                "pages_inserted": inserted_count,
                "total_pages": len(writer.pages),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_INSERT_PAGES,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 5: bb_pdf_extract_pages
# ============================================================================


def bb_pdf_extract_pages(
    pdf_path: str,
    output_path: str,
    page_range: str | int = "-1",
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Extract a 1-based page range from a PDF to a destination PDF document.

    Preserves explicit user page sequence (e.g. '3,1' extracts page 3 then page 1).

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 20.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 5.
    """
    tool_name = "bb_pdf_extract_pages"
    try:
        # Support legacy positional call order (pdf_path, page_range, output_path)
        if (
            isinstance(page_range, str)
            and (page_range.lower().endswith(".pdf") or "\\" in page_range or "/" in page_range)
            and not str(output_path).lower().endswith(".pdf")
        ):
            output_path, page_range = page_range, output_path

        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)
        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        reader = _open_pdf_reader(resolved_pdf, password=password)
        total_pages = len(reader.pages)

        valid_range = validate_page_range(page_range, max_pages=total_pages)

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        builder.add_command("PageExtract", valid_range, str(resolved_output))
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            indices = _parse_page_range_ordered(valid_range, total_pages)
            writer = pypdf.PdfWriter()
            for idx in indices:
                writer.append(reader, pages=[idx], import_outline=False)

            _copy_catalog_and_metadata(
                reader,
                writer,
                copy_outlines=False,
                copy_labels=False,
                copy_forms=False,
                copy_names=False,
            )
            _apply_page_labels_for_source_indices(reader, writer, indices)
            acro = writer._root_object.get(NameObject("/AcroForm"))
            if acro is not None:
                try:
                    acro_obj = acro.get_object()
                    fields = acro_obj.get("/Fields")
                    if not fields or len(fields.get_object()) == 0:
                        writer._root_object.pop(NameObject("/AcroForm"), None)
                except Exception:
                    pass
            writer.compress_identical_objects(remove_duplicates=True, remove_unreferenced=True)
            atomic_write_pdf(writer, resolved_output)

            return {
                "output_path": str(resolved_output),
                "source_pdf_path": str(resolved_pdf),
                "page_range": valid_range,
                "pages_extracted": len(indices),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_EXTRACT_PAGES,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 6: bb_pdf_delete_pages
# ============================================================================


def bb_pdf_delete_pages(
    pdf_path: str,
    output_path: str,
    page_range: str | int = "1",
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Delete specified 1-based page range from document. Cannot delete all pages.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 20.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 6.
    """
    tool_name = "bb_pdf_delete_pages"
    try:
        # Support legacy positional call order (pdf_path, page_range, output_path)
        if (
            isinstance(page_range, str)
            and (page_range.lower().endswith(".pdf") or "\\" in page_range or "/" in page_range)
            and not str(output_path).lower().endswith(".pdf")
        ):
            output_path, page_range = page_range, output_path

        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)
        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        reader = _open_pdf_reader(resolved_pdf, password=password)
        total_pages = len(reader.pages)

        valid_range = validate_page_range(page_range, max_pages=total_pages)
        if valid_range == "-1":
            raise PageRangeError("Cannot delete all pages from a document (at least one page must remain)")

        indices_to_delete = set(_parse_page_range_ordered(valid_range, total_pages))
        if len(indices_to_delete) >= total_pages:
            raise PageRangeError("Cannot delete all pages from a document (at least one page must remain)")

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        builder.page_delete(valid_range)
        builder.save(resolved_output)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            surviving_indices = [i for i in range(total_pages) if i not in indices_to_delete]
            writer = pypdf.PdfWriter()
            writer.append(reader, pages=surviving_indices, import_outline=False)
            _copy_catalog_and_metadata(
                reader,
                writer,
                copy_outlines=False,
                copy_labels=False,
                copy_forms=False,
                copy_names=False,
            )
            _apply_page_labels_for_source_indices(reader, writer, surviving_indices)
            _reconcile_outlines_on_delete(reader, writer, indices_to_delete, total_pages)
            acro = writer._root_object.get(NameObject("/AcroForm"))
            if acro is not None:
                try:
                    acro_obj = acro.get_object()
                    fields = acro_obj.get("/Fields")
                    if not fields or len(fields.get_object()) == 0:
                        writer._root_object.pop(NameObject("/AcroForm"), None)
                except Exception:
                    pass
            writer.compress_identical_objects(remove_duplicates=True, remove_unreferenced=True)

            atomic_write_pdf(writer, resolved_output)

            return {
                "output_path": str(resolved_output),
                "source_pdf_path": str(resolved_pdf),
                "page_range_deleted": valid_range,
                "pages_deleted_count": len(indices_to_delete),
                "remaining_page_count": len(writer.pages),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_DELETE_PAGES,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 7: bb_pdf_rotate_pages
# ============================================================================


def bb_pdf_rotate_pages(
    pdf_path: str,
    rotation_degrees: int,
    output_path: str,
    page_range: str | int = "-1",
    portrait_only: bool = False,
    landscape_only: bool = False,
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Rotate pages in a PDF by 90-degree increments for a 1-based page range.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 20-21.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 7.
    """
    tool_name = "bb_pdf_rotate_pages"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)
        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        if isinstance(rotation_degrees, bool) or not isinstance(rotation_degrees, int) or (rotation_degrees % 90 != 0):
            raise InvalidParameterError(f"rotation_degrees must be a multiple of 90: {rotation_degrees}")

        norm_rotation = (rotation_degrees % 360 + 360) % 360

        reader = _open_pdf_reader(resolved_pdf, password=password)
        total_pages = len(reader.pages)

        valid_range = validate_page_range(page_range, max_pages=total_pages)

        bcs_portrait = True
        bcs_landscape = True
        if portrait_only and not landscape_only:
            bcs_landscape = False
        elif landscape_only and not portrait_only:
            bcs_portrait = False

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        builder.page_rotate(rotation_degrees, portrait=bcs_portrait, landscape=bcs_landscape, page_range=valid_range)
        builder.save(resolved_output)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            _copy_catalog_and_metadata(reader, writer)
            indices_to_rotate = set(_parse_page_range_ordered(valid_range, total_pages))

            rotated_count = 0
            for i in indices_to_rotate:
                page = writer.pages[i]
                w = float(page.mediabox.width)
                h = float(page.mediabox.height)
                is_portrait = h >= w
                is_landscape = w > h

                if portrait_only and not landscape_only and not is_portrait:
                    continue
                if landscape_only and not portrait_only and not is_landscape:
                    continue

                page.rotate(norm_rotation)
                rotated_count += 1

            atomic_write_pdf(writer, resolved_output)

            return {
                "output_path": str(resolved_output),
                "source_pdf_path": str(resolved_pdf),
                "rotation_degrees": rotation_degrees,
                "page_range": valid_range,
                "pages_rotated_count": rotated_count,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_ROTATE_PAGES,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 8: bb_pdf_split
# ============================================================================


def bb_pdf_split(
    pdf_path: str,
    output_dir: str,
    page_range: str | int = "-1",
    prefix: str = "page_",
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Split pages from a PDF document into individual single-page PDF files.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 26-27.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 8.
    """
    tool_name = "bb_pdf_split"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)
        resolved_dir = validate_path(output_dir, mode="write", must_exist=False, allowed_extensions={"", "DIR"}, kind="dir")

        if (
            not isinstance(prefix, str)
            or not prefix
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", prefix, re.ASCII)
            or ".." in prefix
            or prefix.startswith((".", " "))
            or prefix.endswith((".", " "))
            or any(c in prefix for c in ("/", "\\", ":"))
        ):
            raise SecurityViolationError(f"Invalid split filename prefix: '{prefix}'")

        reader = _open_pdf_reader(resolved_pdf, password=password)
        total_pages = len(reader.pages)

        valid_range = validate_page_range(page_range, max_pages=total_pages)

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        builder.add_command("SplitPages", valid_range, str(resolved_dir), False, prefix)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            resolved_dir.mkdir(parents=True, exist_ok=True)
            indices = _parse_page_range_ordered(valid_range, total_pages)
            created_files: list[str] = []

            for idx in indices:
                writer = pypdf.PdfWriter()
                writer.append(reader, pages=[idx], import_outline=False)
                _copy_catalog_and_metadata(
                    reader,
                    writer,
                    copy_outlines=False,
                    copy_labels=False,
                    copy_forms=False,
                    copy_names=False,
                )
                _apply_page_labels_for_source_indices(reader, writer, [idx])
                acro = writer._root_object.get(NameObject("/AcroForm"))
                if acro is not None:
                    try:
                        acro_obj = acro.get_object()
                        fields = acro_obj.get("/Fields")
                        if not fields or len(fields.get_object()) == 0:
                            writer._root_object.pop(NameObject("/AcroForm"), None)
                    except Exception:
                        pass
                writer.compress_identical_objects(remove_duplicates=True, remove_unreferenced=True)

                target_file = (resolved_dir / f"{prefix}{idx + 1}.pdf").resolve()
                if target_file.parent != resolved_dir.resolve():
                    raise SecurityViolationError(f"Split file path traversal detected: {target_file}")

                validate_path(target_file, mode="write", must_exist=False, allowed_extensions={".pdf"})
                atomic_write_pdf(writer, target_file)
                created_files.append(str(target_file))

            return {
                "output_dir": str(resolved_dir),
                "source_pdf_path": str(resolved_pdf),
                "split_files": created_files,
                "page_count": len(created_files),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_SPLIT,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 9: bb_pdf_metadata
# ============================================================================


def bb_pdf_metadata(
    pdf_path: str,
    action: str = "get",
    properties: dict[str, str | None] | None = None,
    output_path: str | None = None,
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Get, set, or list PDF document metadata properties.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 10-11.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 9.
    """
    tool_name = "bb_pdf_metadata"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)

        clean_action = action.lower().strip()
        if clean_action not in ("get", "set", "list"):
            raise InvalidParameterError(f"Invalid metadata action '{action}'. Must be 'get', 'set', or 'list'")

        resolved_output: Path | None = None
        if clean_action == "set":
            if not properties or not isinstance(properties, dict):
                raise InvalidParameterError("properties dictionary is required when action is 'set'")
            for k, v in properties.items():
                if not isinstance(k, str) or not k.strip():
                    raise InvalidParameterError(f"Metadata property key must be a non-empty string: '{k}'")
                if v is not None and not isinstance(v, str):
                    raise InvalidParameterError(
                        f"Metadata property value for '{k}' must be a string or None, got {type(v).__name__}"
                    )
            dest = output_path if output_path else str(resolved_pdf)
            resolved_output = validate_path(dest, mode="write", must_exist=False)

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        if clean_action == "get":
            if properties:
                for k in properties.keys():
                    builder.add_command("FilePropertyGet", k)
            else:
                builder.add_command("FilePropertyList")
            builder.close(save=False)
        elif clean_action == "list":
            builder.add_command("FilePropertyList")
            builder.close(save=False)
        elif clean_action == "set":
            assert properties is not None
            for k, v in properties.items():
                val_str = str(v) if v is not None else ""
                builder.add_command("FilePropertySet", k, val_str)
            builder.save(resolved_output)
            builder.close(save=False)

        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            reader = _open_pdf_reader(resolved_pdf, password=password)

            meta: dict[str, str] = {}
            if reader.metadata:
                for k, v in reader.metadata.items():
                    if v is not None:
                        meta[str(k).lstrip("/")] = str(v)

            if clean_action == "list":
                return {
                    "action": "list",
                    "pdf_path": str(resolved_pdf),
                    "property_keys": sorted(meta.keys()),
                }

            if clean_action == "get":
                if properties:
                    filtered: dict[str, str] = {}
                    for req_k in properties.keys():
                        matched_val = ""
                        for mk, mv in meta.items():
                            if mk.lower() == req_k.lower():
                                matched_val = mv
                                break
                        filtered[req_k] = matched_val
                    return {
                        "action": "get",
                        "pdf_path": str(resolved_pdf),
                        "properties": filtered,
                    }
                return {
                    "action": "get",
                    "pdf_path": str(resolved_pdf),
                    "properties": meta,
                }

            # set action
            assert resolved_output is not None and properties is not None
            writer = pypdf.PdfWriter(clone_from=reader)
            _copy_catalog_and_metadata(reader, writer)

            meta_to_set: dict[str, str] = {}
            keys_to_delete: set[str] = set()

            for prop_k, prop_v in properties.items():
                norm_key = prop_k if prop_k.startswith("/") else f"/{prop_k}"
                if prop_v is None or prop_v == "":
                    keys_to_delete.add(norm_key.lower())
                else:
                    meta_to_set[norm_key] = str(prop_v)

            # Explicitly delete removed keys from writer._info
            if hasattr(writer, "_info") and writer._info:
                info_obj = writer._info.get_object() if hasattr(writer._info, "get_object") else writer._info
                for k in list(info_obj.keys()):
                    if str(k).lower() in keys_to_delete:
                        del info_obj[k]

            if meta_to_set:
                writer.add_metadata(meta_to_set)
            atomic_write_pdf(writer, resolved_output)

            return {
                "action": "set",
                "pdf_path": str(resolved_pdf),
                "output_path": str(resolved_output),
                "updated_properties": properties,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_METADATA,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 10: bb_pdf_page_labels
# ============================================================================


def bb_pdf_page_labels(
    pdf_path: str,
    action: str = "get",
    prefix: str = "Page ",
    start_page: int = 1,
    style: str = "D",
    page_range: str | int = "-1",
    output_path: str | None = None,
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Query or set document page labels using prefix, numeric style, and start sequence.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 13, 26.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 10.
    """
    tool_name = "bb_pdf_page_labels"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)

        clean_action = action.lower().strip()
        if clean_action not in ("get", "set"):
            raise InvalidParameterError(f"Invalid page labels action '{action}'. Must be 'get' or 'set'")

        if start_page < 1:
            raise PageRangeError(f"start_page must be >= 1: {start_page}")

        reader = _open_pdf_reader(resolved_pdf, password=password)
        total_pages = len(reader.pages)

        valid_range = validate_page_range(page_range, max_pages=total_pages)

        resolved_output: Path | None = None
        if clean_action == "set":
            dest = output_path if output_path else str(resolved_pdf)
            resolved_output = validate_path(dest, mode="write", must_exist=False)

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        if clean_action == "get":
            builder.add_command("PageLabelGet", start_page)
            builder.close(save=False)
        else:
            builder.add_command("PageLabelsSet", valid_range, prefix, start_page)
            builder.save(resolved_output)
            builder.close(save=False)

        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            if clean_action == "get":
                labels = (
                    list(reader.page_labels)
                    if hasattr(reader, "page_labels") and reader.page_labels
                    else [f"Page {i + 1}" for i in range(total_pages)]
                )
                return {
                    "action": "get",
                    "pdf_path": str(resolved_pdf),
                    "page_labels": labels,
                    "page_count": total_pages,
                }

            # set action
            assert resolved_output is not None
            writer = pypdf.PdfWriter(clone_from=reader)
            _copy_catalog_and_metadata(reader, writer)

            clean_style = style if style.startswith("/") else f"/{style}"
            if valid_range == "-1":
                writer.set_page_label(0, total_pages - 1, style=clean_style, prefix=prefix, start=start_page)
            else:
                target_indices = _parse_page_range_ordered(valid_range, total_pages)
                if target_indices:
                    ranges: list[tuple[int, int]] = []
                    start_idx = target_indices[0]
                    prev_idx = target_indices[0]
                    for idx in target_indices[1:]:
                        if idx == prev_idx + 1:
                            prev_idx = idx
                        else:
                            ranges.append((start_idx, prev_idx))
                            start_idx = idx
                            prev_idx = idx
                    ranges.append((start_idx, prev_idx))

                    current_start = start_page
                    for r_start, r_end in ranges:
                        writer.set_page_label(
                            r_start,
                            r_end,
                            style=clean_style,
                            prefix=prefix,
                            start=current_start,
                        )
                        current_start += (r_end - r_start + 1)

            atomic_write_pdf(writer, resolved_output)

            return {
                "action": "set",
                "pdf_path": str(resolved_pdf),
                "output_path": str(resolved_output),
                "prefix": prefix,
                "start_page": start_page,
                "style": style,
                "page_range": valid_range,
                "page_count": total_pages,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_PAGE_LABELS,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 11: bb_pdf_bookmarks
# ============================================================================


def bb_pdf_bookmarks(
    pdf_path: str,
    action: str = "list",
    bookmarks: list[dict[str, Any]] | None = None,
    export_path: str | None = None,
    output_path: str | None = None,
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """List, export, or import PDF bookmark outline trees.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 15.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 11.
    """
    tool_name = "bb_pdf_bookmarks"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)

        clean_action = action.lower().strip()
        if clean_action not in ("list", "export", "import", "set"):
            raise InvalidParameterError(f"Invalid bookmarks action '{action}'. Must be 'list', 'export', 'import', or 'set'")

        resolved_export: Path | None = None
        resolved_output: Path | None = None

        if clean_action == "export":
            if not export_path:
                raise InvalidParameterError("export_path is required when action is 'export'")
            resolved_export = validate_path(
                export_path,
                mode="write",
                must_exist=False,
                allowed_extensions={".json", ".xml"},
            )
            if resolved_export.resolve() == resolved_pdf.resolve():
                raise SecurityViolationError("Bookmark export_path cannot be the same as source pdf_path")

        if clean_action in ("import", "set"):
            if not bookmarks and not export_path:
                raise InvalidParameterError("Either 'bookmarks' or 'export_path' must be provided for action 'set' or 'import'")
            dest = output_path if output_path else str(resolved_pdf)
            resolved_output = validate_path(dest, mode="write", must_exist=False)

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        if clean_action == "export":
            assert resolved_export is not None
            builder.add_command("BookmarksExport", str(resolved_export))
            builder.close(save=False)
        elif clean_action in ("import", "set"):
            if export_path:
                v_imp = validate_path(
                    export_path,
                    mode="read",
                    must_exist=True,
                    allowed_extensions={".json", ".xml"},
                )
                builder.add_command("BookmarksImport", str(v_imp))
            builder.save(resolved_output)
            builder.close(save=False)
        else:
            builder.close(save=False)

        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            reader = _open_pdf_reader(resolved_pdf, password=password)
            extracted = _extract_bookmarks_list(reader.outline, reader)

            if clean_action == "list":
                return {
                    "action": "list",
                    "pdf_path": str(resolved_pdf),
                    "bookmarks": extracted,
                    "count": len(extracted),
                }

            if clean_action == "export":
                assert resolved_export is not None
                resolved_export.parent.mkdir(parents=True, exist_ok=True)
                if resolved_export.suffix.lower() == ".xml":
                    resolved_export.write_text(_bookmarks_to_xml(extracted), encoding="utf-8")
                else:
                    resolved_export.write_text(json.dumps(extracted, indent=2), encoding="utf-8")
                return {
                    "action": "export",
                    "pdf_path": str(resolved_pdf),
                    "export_path": str(resolved_export),
                    "bookmarks_exported": len(extracted),
                }

            # import or set action
            assert resolved_output is not None
            writer = pypdf.PdfWriter(clone_from=reader)
            _copy_catalog_and_metadata(reader, writer, copy_outlines=False)

            # Clear existing outline tree to set fresh bookmarks
            writer._outline = []
            if NameObject("/Outlines") in writer._root_object:
                del writer._root_object[NameObject("/Outlines")]

            items_to_add: list[dict[str, Any]] = []
            if bookmarks:
                items_to_add = bookmarks
            elif export_path:
                v_imp = validate_path(
                    export_path,
                    mode="read",
                    must_exist=True,
                    allowed_extensions={".json", ".xml"},
                )
                if v_imp.suffix.lower() == ".xml":
                    xml_root = parse_xml_safely(v_imp)
                    items_to_add = _xml_to_bookmarks(xml_root)
                else:
                    content = v_imp.read_text(encoding="utf-8")
                    items_to_add = json.loads(content)

            total_pages = len(reader.pages)
            added_count = _add_bookmarks_recursive(writer, items_to_add, total_pages)
            atomic_write_pdf(writer, resolved_output)

            return {
                "action": clean_action,
                "pdf_path": str(resolved_pdf),
                "output_path": str(resolved_output),
                "bookmarks_added": added_count,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_BOOKMARKS,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 12: bb_pdf_header_footer
# ============================================================================


def bb_pdf_header_footer(
    pdf_path: str,
    output_path: str,
    top_left: str = "",
    top_center: str = "",
    top_right: str = "",
    bottom_left: str = "",
    bottom_center: str = "",
    bottom_right: str = "",
    font_size: float = 10.0,
    margin_inches: float = 0.5,
    bates_digits: int = 0,
    bates_start: int = 1,
    bates_offset: int = 0,
    bates_key: str = "",
    page_range: str | int = "-1",
    password: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Apply headers, footers, and Bates numbering to document pages.

    Citations:
        - Bluebeam Script Reference Version 2.0.11, p. 13-14.
        - docs/citations/02_binary_and_dotnet_surface.md Section 5.2.
        - docs/ARCHITECTURE.md Section 6.1 Tool 12.
    """
    tool_name = "bb_pdf_header_footer"
    try:
        resolved_pdf = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(resolved_pdf)
        resolved_output = validate_path(output_path, mode="write", must_exist=False)

        if (
            isinstance(font_size, bool)
            or not isinstance(font_size, (int, float))
            or not math.isfinite(font_size)
            or not (1.0 <= font_size <= 144.0)
        ):
            raise InvalidParameterError(f"font_size must be a finite number between 1.0 and 144.0: {font_size}")
        if (
            isinstance(margin_inches, bool)
            or not isinstance(margin_inches, (int, float))
            or not math.isfinite(margin_inches)
            or not (0.0 <= margin_inches <= 5.0)
        ):
            raise InvalidParameterError(f"margin_inches must be a finite number between 0.0 and 5.0: {margin_inches}")
        if isinstance(bates_digits, bool) or not isinstance(bates_digits, int) or bates_digits < 0:
            raise InvalidParameterError(f"bates_digits cannot be negative: {bates_digits}")
        if isinstance(bates_start, bool) or not isinstance(bates_start, int) or bates_start < 1:
            raise InvalidParameterError(f"bates_start must be >= 1: {bates_start}")
        if isinstance(bates_offset, bool) or not isinstance(bates_offset, int):
            raise InvalidParameterError(f"bates_offset must be an integer: {bates_offset}")
        if not isinstance(bates_key, str):
            raise InvalidParameterError(f"bates_key must be a string: {bates_key}")

        reader = _open_pdf_reader(resolved_pdf, password=password)
        total_pages = len(reader.pages)

        valid_range = validate_page_range(page_range, max_pages=total_pages)
        margin_pts = margin_inches * 72.0

        builder = ScriptBuilder()
        builder.open(resolved_pdf)
        _bcs_header_and_footer(
            builder,
            top_left,
            top_center,
            top_right,
            bottom_left,
            bottom_center,
            bottom_right,
            margin_pts,
            font_size,
            bates_offset,
            bates_key,
            valid_range,
        )
        builder.save(resolved_output)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            target_indices = set(_parse_page_range_ordered(valid_range, total_pages))
            writer = pypdf.PdfWriter(clone_from=reader)
            _copy_catalog_and_metadata(reader, writer)

            bates_counter = bates_start
            for idx in range(total_pages):
                if idx in target_indices:
                    page = writer.pages[idx]
                    box = page.cropbox if hasattr(page, "cropbox") and page.cropbox else page.mediabox
                    box_left = float(box.left)
                    box_bottom = float(box.bottom)
                    box_width = float(box.width)
                    box_height = float(box.height)
                    media_width = float(page.mediabox.width)
                    media_height = float(page.mediabox.height)
                    rot = (page.rotation or 0) % 360

                    bates_str = ""
                    if bates_digits > 0:
                        bates_str = f"{bates_counter:0{bates_digits}d}"
                        bates_counter += 1

                    page_num = idx + 1
                    tl = _expand_hf_macro(top_left, page_num, total_pages, idx, reader, resolved_pdf, bates_str, bates_offset)
                    tc = _expand_hf_macro(top_center, page_num, total_pages, idx, reader, resolved_pdf, bates_str, bates_offset)
                    tr = _expand_hf_macro(top_right, page_num, total_pages, idx, reader, resolved_pdf, bates_str, bates_offset)
                    bl = _expand_hf_macro(bottom_left, page_num, total_pages, idx, reader, resolved_pdf, bates_str, bates_offset)
                    bc = _expand_hf_macro(bottom_center, page_num, total_pages, idx, reader, resolved_pdf, bates_str, bates_offset)
                    br = _expand_hf_macro(bottom_right, page_num, total_pages, idx, reader, resolved_pdf, bates_str, bates_offset)

                    font_name = "Helvetica"
                    all_text_snippets = (tl, tc, tr, bl, bc, br)
                    if any(any(ord(c) > 127 for c in s) for s in all_text_snippets):
                        arial_path = Path(r"C:\Windows\Fonts\arial.ttf")
                        if arial_path.exists():
                            try:
                                if "Arial" not in pdfmetrics.getRegisteredFontNames():
                                    pdfmetrics.registerFont(TTFont("Arial", str(arial_path)))
                                font_name = "Arial"
                            except Exception:
                                font_name = "Helvetica"

                    buf = io.BytesIO()
                    c = canvas.Canvas(buf, pagesize=(media_width, media_height))
                    c.setFont(font_name, font_size)

                    c.saveState()
                    # Apply coordinate translation and rotation compensation
                    if rot == 0:
                        vis_w = box_width
                        vis_h = box_height
                        c.translate(box_left, box_bottom)
                    elif rot == 90:
                        vis_w = box_height
                        vis_h = box_width
                        c.translate(box_left + box_width, box_bottom)
                        c.rotate(90)
                    elif rot == 180:
                        vis_w = box_width
                        vis_h = box_height
                        c.translate(box_left + box_width, box_bottom + box_height)
                        c.rotate(180)
                    elif rot == 270:
                        vis_w = box_height
                        vis_h = box_width
                        c.translate(box_left, box_bottom + box_height)
                        c.rotate(270)
                    else:
                        vis_w = box_width
                        vis_h = box_height
                        c.translate(box_left, box_bottom)

                    top_y = vis_h - margin_pts
                    bot_y = margin_pts
                    left_x = margin_pts
                    mid_x = vis_w / 2.0
                    right_x = vis_w - margin_pts

                    if tl:
                        c.drawString(left_x, top_y, tl)
                    if tc:
                        c.drawCentredString(mid_x, top_y, tc)
                    if tr:
                        c.drawRightString(right_x, top_y, tr)
                    if bl:
                        c.drawString(left_x, bot_y, bl)
                    if bc:
                        c.drawCentredString(mid_x, bot_y, bc)
                    if br:
                        c.drawRightString(right_x, bot_y, br)

                    c.restoreState()
                    c.showPage()
                    c.save()
                    buf.seek(0)

                    overlay_page = pypdf.PdfReader(buf).pages[0]
                    page.merge_page(overlay_page)

            atomic_write_pdf(writer, resolved_output)

            return {
                "output_path": str(resolved_output),
                "source_pdf_path": str(resolved_pdf),
                "page_range": valid_range,
                "pages_processed": len(target_indices),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=CITATIONS_HEADER_FOOTER,
        )

    except Exception as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# FastMCP Tool Registration Helper
# ============================================================================


def register_document_tools(mcp: Any) -> None:
    """Register all 12 document tools on a FastMCP instance.

    Citations:
        - docs/ARCHITECTURE.md Section 6.1
    """
    mcp.tool()(bb_pdf_info)
    mcp.tool()(bb_pdf_create_blank)
    mcp.tool()(bb_pdf_combine)
    mcp.tool()(bb_pdf_insert_pages)
    mcp.tool()(bb_pdf_extract_pages)
    mcp.tool()(bb_pdf_delete_pages)
    mcp.tool()(bb_pdf_rotate_pages)
    mcp.tool()(bb_pdf_split)
    mcp.tool()(bb_pdf_metadata)
    mcp.tool()(bb_pdf_page_labels)
    mcp.tool()(bb_pdf_bookmarks)
    mcp.tool()(bb_pdf_header_footer)


__all__ = [
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
]
