"""Markup, takeoff, stamp, flattening, form, and optimization tools for Bluebeam Revu 21.

Implements all 10 markup-category tools with compliant dual-engine execution,
strict path validation, XML defusing, atomic file operations, and structured response envelopes.

Primary citations:
- docs/citations/01_script_reference.md p. 5, 8-9, 10, 11-12, 12-13, 14, 15-16, 17-18, 22-23, 26, 27, 29
- docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmd Markup, Stamp, Form, Security, Optimize)
- docs/citations/03_data_formats_and_markups.md Section 4 (Page Annotation Dictionary, Stamps), Section 5 (BAX/XFDF)
- docs/ARCHITECTURE.md Section 6.2 (Category 2: Markup, Annotation, Flattening and Forms)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Four-Tier Continuous Test Matrix)
- ISO 32000-1:2008 (PDF 1.7 Specification) Section 12.5 (Annotations), Section 7.6 (Encryption)
"""

from __future__ import annotations

import base64
import copy
import csv
from datetime import datetime
import io
import json
import math
import os
import shutil
from pathlib import Path
import re
from typing import Any, Literal
import uuid
import xml.etree.ElementTree as ET
import xml.sax.saxutils

from PIL import Image
import pypdf
from pypdf.generic import (
    ArrayObject,
    BooleanObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    TextStringObject,
)
from reportlab.pdfgen import canvas

from bluebeam_mcp.engine import (
    execute_dual_engine,
    format_error_envelope,
    format_success_envelope,
)
from bluebeam_mcp.script_builder import (
    ALL_FLATTEN_FLAGS,
    DEFAULT_FLATTEN_FLAGS,
    FLATTEN_FLAGS,
    VALID_MARKUP_KEYS,
    ScriptBuilder,
    calculate_flatten_bitmask,
    calculate_security_bitmask,
    serialize_bcs_dict,
    validate_color,
    validate_one_based_page,
    validate_page_range,
)
from bluebeam_mcp.security import (
    BluebeamMCPError,
    CorruptPDFError,
    EmptyFileError,
    EncryptedPDFError,
    InvalidParameterError,
    PageRangeError,
    SecurityViolationError,
    XMLDefuseError,
    atomic_write_bytes,
    atomic_write_pdf,
    check_pdf_header,
    clean_xml_text,
    parse_xml_safely,
    sanitize_csv_cell,
    sanitize_untrusted_text,
    validate_path,
)

# ============================================================================
# Stamp Origin & Blend Mode Enumerations and Mappings
# Citation: docs/citations/01_script_reference.md p. 27
# ============================================================================

STAMP_ORIGIN_MAP: dict[int, str] = {
    0: "center",
    1: "upperleft",
    2: "upperright",
    3: "lowerleft",
    4: "lowerright",
    5: "uppercenter",
    6: "lowercenter",
}

STAMP_ORIGIN_NAMES: dict[str, int] = {v: k for k, v in STAMP_ORIGIN_MAP.items()}

STAMP_BLEND_MODE_MAP: dict[int, str] = {
    0: "normal",
    1: "multiply",
    2: "screen",
    3: "overlay",
    4: "darken",
    5: "lighten",
    6: "colordodge",
    7: "colorburn",
    8: "hardlight",
    9: "softlight",
    10: "difference",
    11: "exclusion",
    12: "luminosity",
    13: "hue",
    14: "saturation",
    15: "color",
}

STAMP_BLEND_MODE_NAMES: dict[str, int] = {v: k for k, v in STAMP_BLEND_MODE_MAP.items()}


def resolve_stamp_origin(origin: int | str) -> str:
    """Resolve and validate stamp origin parameter from integer or string.

    Citation: docs/citations/01_script_reference.md p. 27.
    """
    if isinstance(origin, int):
        if origin not in STAMP_ORIGIN_MAP:
            raise ValueError(
                f"Invalid stamp origin index {origin}. Must be between 0 and 6 ({list(STAMP_ORIGIN_MAP.values())})"
            )
        return STAMP_ORIGIN_MAP[origin]
    if isinstance(origin, str):
        cleaned = origin.strip().lower()
        if cleaned not in STAMP_ORIGIN_NAMES:
            raise ValueError(
                f"Invalid stamp origin '{origin}'. Supported values: {sorted(STAMP_ORIGIN_NAMES.keys())}"
            )
        return cleaned
    raise ValueError(f"Invalid type for stamp origin: {type(origin)}")


def resolve_stamp_blend_mode(blend_mode: int | str) -> str:
    """Resolve and validate stamp blend mode parameter from integer or string.

    Citation: docs/citations/01_script_reference.md p. 27.
    """
    if isinstance(blend_mode, int):
        if blend_mode not in STAMP_BLEND_MODE_MAP:
            raise ValueError(
                f"Invalid stamp blend mode index {blend_mode}. Must be between 0 and 15 ({list(STAMP_BLEND_MODE_MAP.values())})"
            )
        return STAMP_BLEND_MODE_MAP[blend_mode]
    if isinstance(blend_mode, str):
        cleaned = blend_mode.strip().lower()
        if cleaned not in STAMP_BLEND_MODE_NAMES:
            raise ValueError(
                f"Invalid stamp blend mode '{blend_mode}'. Supported values: {sorted(STAMP_BLEND_MODE_NAMES.keys())}"
            )
        return cleaned
    raise ValueError(f"Invalid type for stamp blend mode: {type(blend_mode)}")


# ============================================================================
# Canonical Markup Subtype Allowlist
# Citation: ISO 32000-1:2008 Section 12.5.6; docs/citations/01_script_reference.md p. 5
# ============================================================================

ALLOWED_MARKUP_SUBTYPES: dict[str, str] = {
    "freetext": "FreeText",
    "square": "Square",
    "circle": "Circle",
    "line": "Line",
    "polyline": "PolyLine",
    "polygon": "Polygon",
    "cloud": "Polygon",
    "highlight": "Highlight",
    "underline": "Underline",
    "strikeout": "StrikeOut",
    "squiggly": "Squiggly",
    "ink": "Ink",
    "text": "Text",
    "stamp": "Stamp",
    "caret": "Caret",
}

FLATTEN_FLAG_SUBTYPES: dict[int, set[str]] = {
    1: {"/Stamp"},
    2: {"/Circle"},
    4: {"/Stamp"},
    8: {"/Stamp"},
    16: {"/FreeText"},
    32: {"/Ink", "/Highlight"},
    64: {"/Line"},
    128: {"/Polygon", "/PolyLine", "/Line"},
    256: {"/PolyLine"},
    512: {"/Polygon"},
    1024: {"/Square"},
    2048: {"/Highlight", "/Underline", "/StrikeOut", "/Squiggly", "/Caret"},
    8192: {"/FileAttachment"},
    32768: {"/Text"},
    65536: {"/Widget"},
}


# ============================================================================
# Color and Annotation Helpers
# ============================================================================

def _color_to_hex(c_val: Any) -> str | None:
    """Convert a PDF annotation color entry to hex string #RRGGBB.

    Supports 1-element (Gray), 3-element (RGB), and 4-element (CMYK) arrays.
    Returns None when c_val is empty, None, or invalid.
    """
    if c_val is None:
        return None
    if isinstance(c_val, str):
        cleaned = c_val.strip()
        if cleaned.startswith("#"):
            return cleaned
        return None
    if isinstance(c_val, (list, tuple, ArrayObject)):
        if len(c_val) == 0:
            return None
        try:
            if len(c_val) == 1:
                g = min(255, max(0, int(float(c_val[0]) * 255.0)))
                return f"#{g:02X}{g:02X}{g:02X}"
            elif len(c_val) == 3:
                r = min(255, max(0, int(float(c_val[0]) * 255.0)))
                g = min(255, max(0, int(float(c_val[1]) * 255.0)))
                b = min(255, max(0, int(float(c_val[2]) * 255.0)))
                return f"#{r:02X}{g:02X}{b:02X}"
            elif len(c_val) == 4:
                c_c = float(c_val[0])
                m_c = float(c_val[1])
                y_c = float(c_val[2])
                k_c = float(c_val[3])
                r_val = (1.0 - min(1.0, c_c * (1.0 - k_c) + k_c)) * 255.0
                g_val = (1.0 - min(1.0, m_c * (1.0 - k_c) + k_c)) * 255.0
                b_val = (1.0 - min(1.0, y_c * (1.0 - k_c) + k_c)) * 255.0
                r = min(255, max(0, int(r_val)))
                g = min(255, max(0, int(g_val)))
                b = min(255, max(0, int(b_val)))
                return f"#{r:02X}{g:02X}{b:02X}"
        except (ValueError, TypeError):
            return None
    return None


def _hex_to_rgb(color_str: str | None) -> list[float]:
    """Convert hex color (#RRGGBB or #RGB) or named color to RGB float list [r, g, b]."""
    if not color_str:
        return [0.0, 0.0, 0.0]
    cleaned = color_str.strip().lstrip("#")
    named = {
        "black": [0.0, 0.0, 0.0],
        "white": [1.0, 1.0, 1.0],
        "red": [1.0, 0.0, 0.0],
        "green": [0.0, 1.0, 0.0],
        "blue": [0.0, 0.0, 1.0],
        "yellow": [1.0, 1.0, 0.0],
        "cyan": [0.0, 1.0, 1.0],
        "magenta": [1.0, 0.0, 1.0],
        "gray": [0.5, 0.5, 0.5],
    }
    if color_str.lower() in named:
        return named[color_str.lower()]

    if len(cleaned) == 6:
        try:
            r = int(cleaned[0:2], 16) / 255.0
            g = int(cleaned[2:4], 16) / 255.0
            b = int(cleaned[4:6], 16) / 255.0
            return [round(r, 4), round(g, 4), round(b, 4)]
        except ValueError:
            pass
    elif len(cleaned) == 3:
        try:
            r = int(cleaned[0] * 2, 16) / 255.0
            g = int(cleaned[1] * 2, 16) / 255.0
            b = int(cleaned[2] * 2, 16) / 255.0
            return [round(r, 4), round(g, 4), round(b, 4)]
        except ValueError:
            pass

    return [1.0, 0.0, 0.0]


def _parse_target_pages(page_range_str: str | int, total_pages: int) -> list[int]:
    """Parse a validated 1-based page range string into a list of 1-based page numbers."""
    valid_range = validate_page_range(page_range_str, max_pages=total_pages)
    if valid_range == "-1":
        return list(range(1, total_pages + 1))

    pages: set[int] = set()
    for token in valid_range.split(","):
        t = token.strip()
        if "-" in t:
            parts = t.split("-")
            start, end = int(parts[0].strip()), int(parts[1].strip())
            for p in range(start, end + 1):
                if 1 <= p <= total_pages:
                    pages.add(p)
        else:
            val = int(t)
            if 1 <= val <= total_pages:
                pages.add(val)
    return sorted(pages)


def _build_appearance_stream(
    width: float,
    height: float,
    line_width: float,
    rgb_stroke: list[float],
    rgb_fill: list[float] | None = None,
    canonical_subtype: str = "FreeText",
) -> DecodedStreamObject:
    """Build a compliant Form XObject appearance stream (/AP /N) for an annotation."""
    ap_stream = DecodedStreamObject()
    ap_stream[NameObject("/Type")] = NameObject("/XObject")
    ap_stream[NameObject("/Subtype")] = NameObject("/Form")
    ap_stream[NameObject("/BBox")] = ArrayObject([
        FloatObject(0.0),
        FloatObject(0.0),
        FloatObject(width),
        FloatObject(height),
    ])

    r_s, g_s, b_s = rgb_stroke[0], rgb_stroke[1], rgb_stroke[2]
    ap_ops: list[str] = [
        f"{r_s:.4f} {g_s:.4f} {b_s:.4f} RG",
        f"{line_width:.2f} w",
    ]
    if rgb_fill is not None:
        r_f, g_f, b_f = rgb_fill[0], rgb_fill[1], rgb_fill[2]
        ap_ops.append(f"{r_f:.4f} {g_f:.4f} {b_f:.4f} rg")
        if canonical_subtype in ("Circle",):
            # Approximate ellipse path
            ap_ops.append(f"0 0 {width:.2f} {height:.2f} re B")
        else:
            ap_ops.append(f"0 0 {width:.2f} {height:.2f} re B")
    else:
        ap_ops.append(f"0 0 {width:.2f} {height:.2f} re S")

    ap_stream.set_data("\n".join(ap_ops).encode("ascii"))
    return ap_stream


def _render_annotation_to_canvas(
    c: canvas.Canvas,
    annot: dict[str, Any] | DictionaryObject,
) -> None:
    """Render an annotation's visual vector path onto a ReportLab canvas for flattening."""
    c.saveState()
    try:
        # Opacity
        if "/CA" in annot:
            try:
                op_val = float(annot["/CA"])
                if 0.0 <= op_val <= 1.0:
                    c.setFillAlpha(op_val)
                    c.setStrokeAlpha(op_val)
            except Exception:
                pass

        # Stroke color
        stroke_rgb = [0.0, 0.0, 0.0]
        if "/C" in annot and annot["/C"]:
            c_val = annot["/C"]
            if isinstance(c_val, (list, tuple, ArrayObject)):
                if len(c_val) == 1:
                    g = float(c_val[0])
                    stroke_rgb = [g, g, g]
                elif len(c_val) >= 3:
                    stroke_rgb = [float(c_val[0]), float(c_val[1]), float(c_val[2])]
        c.setStrokeColorRGB(stroke_rgb[0], stroke_rgb[1], stroke_rgb[2])

        # Fill color
        fill_rgb: list[float] | None = None
        if "/IC" in annot and annot["/IC"]:
            ic_val = annot["/IC"]
            if isinstance(ic_val, (list, tuple, ArrayObject)):
                if len(ic_val) == 1:
                    g = float(ic_val[0])
                    fill_rgb = [g, g, g]
                elif len(ic_val) >= 3:
                    fill_rgb = [float(ic_val[0]), float(ic_val[1]), float(ic_val[2])]

        if fill_rgb is not None:
            c.setFillColorRGB(fill_rgb[0], fill_rgb[1], fill_rgb[2])
        else:
            c.setFillColorRGB(stroke_rgb[0], stroke_rgb[1], stroke_rgb[2])

        # Line width
        line_w = 1.0
        if "/BS" in annot and isinstance(annot["/BS"], (dict, DictionaryObject)):
            try:
                line_w = float(annot["/BS"].get("/W", 1.0))
            except Exception:
                pass
        c.setLineWidth(line_w)

        rect = [float(v) for v in annot.get("/Rect", [0, 0, 0, 0])]
        rx = rect[0] if len(rect) > 0 else 0.0
        ry = rect[1] if len(rect) > 1 else 0.0
        rw = (rect[2] - rect[0]) if len(rect) > 2 else 0.0
        rh = (rect[3] - rect[1]) if len(rect) > 3 else 0.0

        subtype = str(annot.get("/Subtype", "")).lstrip("/")
        contents_text = str(annot.get("/Contents", ""))

        if subtype in ("Square", "Rectangle"):
            c.rect(rx, ry, rw, rh, fill=1 if fill_rgb else 0, stroke=1)
        elif subtype in ("Circle", "Ellipse"):
            c.ellipse(rx, ry, rx + rw, ry + rh, fill=1 if fill_rgb else 0, stroke=1)
        elif subtype == "Line":
            line_pts = annot.get("/L")
            if line_pts and len(line_pts) >= 4:
                lx1, ly1, lx2, ly2 = float(line_pts[0]), float(line_pts[1]), float(line_pts[2]), float(line_pts[3])
                c.line(lx1, ly1, lx2, ly2)
            else:
                c.line(rx, ry, rx + rw, ry + rh)
        elif subtype in ("Polygon", "PolyLine"):
            verts = annot.get("/Vertices")
            if verts and len(verts) >= 4:
                p = c.beginPath()
                p.moveTo(float(verts[0]), float(verts[1]))
                for i in range(2, len(verts) - 1, 2):
                    p.lineTo(float(verts[i]), float(verts[i + 1]))
                if subtype == "Polygon":
                    p.close()
                    c.drawPath(p, fill=1 if fill_rgb else 0, stroke=1)
                else:
                    c.drawPath(p, fill=0, stroke=1)
            else:
                c.rect(rx, ry, rw, rh, fill=1 if fill_rgb else 0, stroke=1)
        elif subtype == "Ink":
            ink_list = annot.get("/InkList")
            if ink_list:
                for stroke in ink_list:
                    if len(stroke) >= 4:
                        p = c.beginPath()
                        p.moveTo(float(stroke[0]), float(stroke[1]))
                        for i in range(2, len(stroke) - 1, 2):
                            p.lineTo(float(stroke[i]), float(stroke[i + 1]))
                        c.drawPath(p, fill=0, stroke=1)
            else:
                c.rect(rx, ry, rw, rh, fill=0, stroke=1)
        elif subtype in ("Highlight", "Underline", "StrikeOut", "Squiggly", "Caret"):
            quads = annot.get("/QuadPoints")
            if quads and len(quads) >= 8:
                for q_idx in range(0, len(quads) - 7, 8):
                    qx = min(float(quads[q_idx]), float(quads[q_idx + 4]))
                    qy = min(float(quads[q_idx + 1]), float(quads[q_idx + 5]))
                    qw = abs(float(quads[q_idx + 2]) - qx)
                    qh = abs(float(quads[q_idx + 3]) - qy)
                    c.rect(qx, qy, qw, qh, fill=1, stroke=0)
            else:
                c.rect(rx, ry, rw, rh, fill=1, stroke=0)
        elif subtype in ("FreeText", "Text", "Stamp"):
            if rw > 0 and rh > 0:
                c.rect(rx, ry, rw, rh, fill=1 if fill_rgb else 0, stroke=1)
            if contents_text:
                c.setFont("Helvetica", 10)
                c.setFillColorRGB(stroke_rgb[0], stroke_rgb[1], stroke_rgb[2])
                c.drawString(rx + 4, ry + (rh / 2) - 4 if rh > 0 else ry, contents_text[:80])
        else:
            if rw > 0 and rh > 0:
                c.rect(rx, ry, rw, rh, fill=1 if fill_rgb else 0, stroke=1)
    finally:
        c.restoreState()


def _serialize_annotation(annot: dict[str, Any] | DictionaryObject, page_num: int) -> dict[str, Any]:
    """Serialize complete annotation dictionary for lossless recoverable flattening."""
    subtype = str(annot.get("/Subtype", "")).lstrip("/")
    data: dict[str, Any] = {
        "page": page_num,
        "subtype": subtype,
        "contents": str(annot.get("/Contents", "")),
        "subj": str(annot.get("/Subj", "")),
        "author": str(annot.get("/T", "")),
        "id": str(annot.get("/NM", "")),
        "rect": [float(v) for v in annot.get("/Rect", [])] if annot.get("/Rect") else [0.0, 0.0, 0.0, 0.0],
    }
    if "/C" in annot and annot["/C"]:
        c_val = annot["/C"]
        data["c"] = [float(v) for v in c_val]
        data["color"] = _color_to_hex(c_val)
    if "/IC" in annot and annot["/IC"]:
        ic_val = annot["/IC"]
        data["ic"] = [float(v) for v in ic_val]
        data["fill_color"] = _color_to_hex(ic_val)
    if "/CA" in annot:
        try:
            data["ca"] = float(annot["/CA"])
        except Exception:
            pass
    if "/BS" in annot and isinstance(annot["/BS"], (dict, DictionaryObject)):
        try:
            data["bs"] = {"/W": float(annot["/BS"].get("/W", 1.0))}
        except Exception:
            pass
    if "/Vertices" in annot:
        data["vertices"] = [float(v) for v in annot["/Vertices"]]
    if "/InkList" in annot:
        data["ink_list"] = [[float(v) for v in stroke] for stroke in annot["/InkList"]]
    if "/QuadPoints" in annot:
        data["quad_points"] = [float(v) for v in annot["/QuadPoints"]]
    if "/L" in annot:
        data["l"] = [float(v) for v in annot["/L"]]
    if "/LE" in annot:
        data["le"] = [str(v) for v in annot["/LE"]]
    if "/Measure" in annot:
        data["measure"] = str(annot["/Measure"])
    if "/RC" in annot:
        data["rc"] = str(annot["/RC"])
    if "/DA" in annot:
        data["da"] = str(annot["/DA"])
    if "/DS" in annot:
        data["ds"] = str(annot["/DS"])
    if "/F" in annot:
        try:
            data["f"] = int(annot["/F"])
        except Exception:
            pass
    if "/M" in annot:
        data["m"] = str(annot["/M"])
    if "/CreationDate" in annot:
        data["creation_date"] = str(annot["/CreationDate"])

    # Appearance stream
    if "/AP" in annot and isinstance(annot["/AP"], (dict, DictionaryObject)):
        ap_dict = annot["/AP"]
        if "/N" in ap_dict:
            ap_n = ap_dict["/N"]
            ap_obj = ap_n.get_object() if hasattr(ap_n, "get_object") else ap_n
            if hasattr(ap_obj, "get_data"):
                try:
                    stream_bytes = ap_obj.get_data()
                    bbox = [float(v) for v in ap_obj.get("/BBox", [])] if "/BBox" in ap_obj else None
                    data["ap_n"] = {
                        "stream_b64": base64.b64encode(stream_bytes).decode("ascii"),
                        "bbox": bbox,
                    }
                except Exception:
                    pass
    return data


def _deserialize_annotation(data: dict[str, Any]) -> DictionaryObject:
    """Reconstruct full PDF annotation dictionary from recoverable metadata."""
    subtype = data.get("subtype", "FreeText")
    rect_coords = data.get("rect", [72.0, 72.0, 144.0, 108.0])
    rect_arr = ArrayObject([FloatObject(float(v)) for v in rect_coords])

    re_annot = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject(f"/{subtype}"),
        NameObject("/Rect"): rect_arr,
        NameObject("/Contents"): TextStringObject(data.get("contents", "")),
        NameObject("/Subj"): TextStringObject(data.get("subj", "")),
        NameObject("/T"): TextStringObject(data.get("author", "")),
        NameObject("/NM"): TextStringObject(data.get("id", f"BB-RESTORE-{uuid.uuid4().hex[:8]}")),
    })

    if "c" in data and data["c"]:
        re_annot[NameObject("/C")] = ArrayObject([FloatObject(float(v)) for v in data["c"]])
    elif "color" in data and data["color"]:
        rgb = _hex_to_rgb(data["color"])
        re_annot[NameObject("/C")] = ArrayObject([FloatObject(v) for v in rgb])

    if "ic" in data and data["ic"]:
        re_annot[NameObject("/IC")] = ArrayObject([FloatObject(float(v)) for v in data["ic"]])
    elif "fill_color" in data and data["fill_color"]:
        rgb = _hex_to_rgb(data["fill_color"])
        re_annot[NameObject("/IC")] = ArrayObject([FloatObject(v) for v in rgb])

    if "ca" in data:
        re_annot[NameObject("/CA")] = FloatObject(float(data["ca"]))
    if "bs" in data and isinstance(data["bs"], dict):
        bs_dict = DictionaryObject()
        if "/W" in data["bs"]:
            bs_dict[NameObject("/W")] = FloatObject(float(data["bs"]["/W"]))
        re_annot[NameObject("/BS")] = bs_dict
    if "vertices" in data:
        re_annot[NameObject("/Vertices")] = ArrayObject([FloatObject(float(v)) for v in data["vertices"]])
    if "ink_list" in data:
        re_annot[NameObject("/InkList")] = ArrayObject([
            ArrayObject([FloatObject(float(v)) for v in stroke]) for stroke in data["ink_list"]
        ])
    if "quad_points" in data:
        re_annot[NameObject("/QuadPoints")] = ArrayObject([FloatObject(float(v)) for v in data["quad_points"]])
    if "l" in data:
        re_annot[NameObject("/L")] = ArrayObject([FloatObject(float(v)) for v in data["l"]])
    if "le" in data:
        re_annot[NameObject("/LE")] = ArrayObject([NameObject(str(v)) for v in data["le"]])
    if "rc" in data:
        re_annot[NameObject("/RC")] = TextStringObject(str(data["rc"]))
    if "da" in data:
        re_annot[NameObject("/DA")] = TextStringObject(str(data["da"]))
    if "ds" in data:
        re_annot[NameObject("/DS")] = TextStringObject(str(data["ds"]))
    if "f" in data:
        re_annot[NameObject("/F")] = NumberObject(int(data["f"]))
    if "m" in data:
        re_annot[NameObject("/M")] = TextStringObject(str(data["m"]))
    if "creation_date" in data:
        re_annot[NameObject("/CreationDate")] = TextStringObject(str(data["creation_date"]))

    if "ap_n" in data and isinstance(data["ap_n"], dict):
        try:
            b64_str = data["ap_n"].get("stream_b64", "")
            raw_bytes = base64.b64decode(b64_str)
            ap_stream = DecodedStreamObject()
            ap_stream[NameObject("/Type")] = NameObject("/XObject")
            ap_stream[NameObject("/Subtype")] = NameObject("/Form")
            if data["ap_n"].get("bbox"):
                ap_stream[NameObject("/BBox")] = ArrayObject([FloatObject(float(v)) for v in data["ap_n"]["bbox"]])
            ap_stream.set_data(raw_bytes)
            re_annot[NameObject("/AP")] = DictionaryObject({NameObject("/N"): ap_stream})
        except Exception:
            pass

    return re_annot


# ============================================================================
# Tool 1: bb_markup_list
# ============================================================================

def bb_markup_list(
    pdf_path: str,
    page_range: str = "-1",
    filter_subject: str | None = None,
    filter_author: str | None = None,
    filter_color: str | None = None,
    include_widgets_and_links: bool = False,
    max_results: int = 1000,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """List markups and annotations on a PDF with full Bluebeam property dictionaries.

    Primary citations:
    - docs/citations/01_script_reference.md p. 5, 16-17 (MarkupList, MarkupGet, MarkupGetExList)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdMarkupList, SCmdMarkupGet)
    - docs/citations/03_data_formats_and_markups.md Section 4 (Page Annotation Dictionary structure)
    """
    tool_name = "bb_markup_list"
    citations = [
        "docs/citations/01_script_reference.md p. 5, 16-17 (MarkupList, MarkupGet, MarkupGetExList)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdMarkupList, SCmdMarkupGet)",
        "docs/citations/03_data_formats_and_markups.md Section 4 (Page Annotation Dictionary structure)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        total_pages = len(reader.pages)
        target_pages = _parse_target_pages(page_range, total_pages)

        # Build BCS Script
        builder = ScriptBuilder()
        builder.open(pdf_file)
        if page_range == "-1":
            builder.add_command("MarkupGetExList", 1)
        else:
            for p in target_pages:
                builder.add_command("MarkupList", p)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            markups: list[dict[str, Any]] = []

            for p_num in target_pages:
                if len(markups) >= max_results:
                    break
                page_obj = reader.pages[p_num - 1]
                annots_entry = page_obj.get("/Annots")
                if not annots_entry:
                    continue

                annots_list = annots_entry.get_object() if hasattr(annots_entry, "get_object") else annots_entry
                if not isinstance(annots_list, (list, ArrayObject)):
                    continue

                for annot_ref in annots_list:
                    if len(markups) >= max_results:
                        break
                    try:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        if not isinstance(annot, (dict, DictionaryObject)):
                            continue

                        subtype_raw = str(annot.get("/Subtype", "")).lstrip("/")
                        if not include_widgets_and_links and subtype_raw in ("Widget", "Link", "Popup"):
                            continue

                        subj = sanitize_untrusted_text(annot.get("/Subj", ""))
                        author = sanitize_untrusted_text(annot.get("/T", ""))
                        comment = sanitize_untrusted_text(annot.get("/Contents", ""))
                        nm_id = str(annot.get("/NM", ""))

                        # Filters
                        if filter_subject is not None and filter_subject.lower() not in subj.lower():
                            continue
                        if filter_author is not None and filter_author.lower() not in author.lower():
                            continue

                        color_hex = _color_to_hex(annot.get("/C"))
                        if filter_color is not None:
                            target_filter = validate_color(filter_color)
                            if color_hex is None or color_hex.upper() != target_filter.upper():
                                continue

                        rect_raw = annot.get("/Rect", [])
                        rect_coords = [float(val) for val in rect_raw] if rect_raw else []

                        fill_hex = _color_to_hex(annot.get("/IC")) if annot.get("/IC") else ""
                        opacity_val = float(annot.get("/CA", 1.0))

                        bs_dict = annot.get("/BS")
                        line_w = 1.0
                        if isinstance(bs_dict, (dict, DictionaryObject)):
                            line_w = float(bs_dict.get("/W", 1.0))

                        status_val = str(annot.get("/ReviewStatus", annot.get("/State", "")))
                        date_mod = str(annot.get("/M", ""))
                        date_create = str(annot.get("/CreationDate", ""))

                        markup_dict: dict[str, Any] = {
                            "id": nm_id,
                            "page": p_num,
                            "type": subtype_raw,
                            "subject": subj,
                            "author": author,
                            "comment": comment,
                            "color": color_hex if color_hex is not None else "#000000",
                            "fill_color": fill_hex or "",
                            "opacity": opacity_val,
                            "line_width": line_w,
                            "rect": rect_coords,
                            "status": status_val,
                            "date_modified": date_mod,
                            "date_created": date_create,
                        }
                        markups.append(markup_dict)
                    except Exception:
                        continue

            return {
                "pdf_path": str(pdf_file),
                "total_markups": len(markups),
                "markups": markups,
                "page_count": total_pages,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 2: bb_markup_add
# ============================================================================

def bb_markup_add(
    pdf_path: str,
    output_path: str,
    page_number: int = 1,
    markup_type: str = "FreeText",
    x: float = 72.0,
    y: float = 72.0,
    width: float = 144.0,
    height: float = 36.0,
    subject: str = "Note",
    author: str = "Bluebeam MCP",
    comment: str = "",
    color: str = "#FF0000",
    fill_color: str | None = None,
    opacity: float = 1.0,
    line_width: float = 1.0,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Add a markup annotation to a PDF page with Bluebeam property dictionary.

    Primary citations:
    - docs/citations/01_script_reference.md p. 5, 17 (AddMarkupFromDictionary, MarkupAdd)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdAddMarkupFromDictionary)
    - docs/citations/03_data_formats_and_markups.md Section 4 (Page Annotation Dictionary)
    """
    tool_name = "bb_markup_add"
    citations = [
        "docs/citations/01_script_reference.md p. 5, 17 (AddMarkupFromDictionary, MarkupAdd)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdAddMarkupFromDictionary)",
        "docs/citations/03_data_formats_and_markups.md Section 4 (Annotation Dictionaries)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        out_file = validate_path(output_path, mode="write", must_exist=False)

        validate_one_based_page(page_number)
        valid_color = validate_color(color)
        valid_fill = validate_color(fill_color) if fill_color else None

        # Validate markup_type against allowlist
        clean_type = markup_type.strip().lower()
        if clean_type not in ALLOWED_MARKUP_SUBTYPES:
            raise InvalidParameterError(
                f"Unsupported or disallowed markup type '{markup_type}'. "
                f"Must be one of: {sorted(set(ALLOWED_MARKUP_SUBTYPES.values()))}"
            )
        canonical_subtype = ALLOWED_MARKUP_SUBTYPES[clean_type]

        # Validate geometry, opacity, and text lengths
        for param_name, val in [("x", x), ("y", y), ("width", width), ("height", height), ("opacity", opacity), ("line_width", line_width)]:
            if not math.isfinite(val):
                raise InvalidParameterError(f"Markup parameter '{param_name}' must be finite, got {val}")

        if width <= 0 or height <= 0:
            raise InvalidParameterError(f"Markup width and height must be positive, got width={width}, height={height}")

        if not (0.0 <= opacity <= 1.0):
            raise InvalidParameterError(f"Opacity must be between 0.0 and 1.0, got {opacity}")

        if line_width < 0.0:
            raise InvalidParameterError(f"Line width must be non-negative, got {line_width}")

        if len(comment) > 65536:
            raise InvalidParameterError(f"Comment length {len(comment)} exceeds maximum permitted limit of 65536")

        if len(author) > 1024:
            raise InvalidParameterError(f"Author length {len(author)} exceeds maximum permitted limit of 1024")

        if len(subject) > 1024:
            raise InvalidParameterError(f"Subject length {len(subject)} exceeds maximum permitted limit of 1024")

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        if page_number > len(reader.pages):
            raise PageRangeError(
                f"Page number {page_number} exceeds document page count {len(reader.pages)}"
            )

        # Bluebeam Script AddMarkupFromDictionary uses 0-based page index
        page_0 = page_number - 1
        props: dict[str, Any] = {
            "type": canonical_subtype,
            "page": str(page_number),
            "author": author,
            "subject": subject,
            "comment": comment,
            "color": valid_color,
            "opacity": opacity,
            "linewidth": line_width,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
        }
        if valid_fill:
            props["colorfill"] = valid_fill

        builder = ScriptBuilder()
        builder.open(pdf_file)
        builder.add_command("AddMarkupFromDictionary", page_0, props)
        builder.save(out_file)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            markup_id = f"BB-MCP-{uuid.uuid4().hex[:12].upper()}"
            rgb_stroke = _hex_to_rgb(valid_color)
            rgb_fill = _hex_to_rgb(valid_fill) if valid_fill else None

            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            now_str = datetime.now().strftime("%Y%m%d%H%M%S")
            date_pdf = f"D:{now_str}"

            rect_arr = ArrayObject([
                FloatObject(x),
                FloatObject(y),
                FloatObject(x + width),
                FloatObject(y + height),
            ])

            # Generate appearance stream /AP /N
            ap_stream = _build_appearance_stream(
                width=width,
                height=height,
                line_width=line_width,
                rgb_stroke=rgb_stroke,
                rgb_fill=rgb_fill,
                canonical_subtype=canonical_subtype,
            )

            annot_dict = DictionaryObject({
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject(f"/{canonical_subtype}"),
                NameObject("/Rect"): rect_arr,
                NameObject("/Contents"): TextStringObject(comment),
                NameObject("/Subj"): TextStringObject(subject),
                NameObject("/T"): TextStringObject(author),
                NameObject("/NM"): TextStringObject(markup_id),
                NameObject("/M"): TextStringObject(date_pdf),
                NameObject("/CreationDate"): TextStringObject(date_pdf),
                NameObject("/CA"): FloatObject(opacity),
                NameObject("/F"): NumberObject(4),
                NameObject("/C"): ArrayObject([
                    FloatObject(rgb_stroke[0]),
                    FloatObject(rgb_stroke[1]),
                    FloatObject(rgb_stroke[2]),
                ]),
                NameObject("/BS"): DictionaryObject({
                    NameObject("/W"): FloatObject(line_width),
                    NameObject("/S"): NameObject("/S"),
                }),
                NameObject("/AP"): DictionaryObject({
                    NameObject("/N"): ap_stream,
                }),
            })

            if rgb_fill:
                annot_dict[NameObject("/IC")] = ArrayObject([
                    FloatObject(rgb_fill[0]),
                    FloatObject(rgb_fill[1]),
                    FloatObject(rgb_fill[2]),
                ])

            # Geometry additions per subtype
            if canonical_subtype == "Line":
                annot_dict[NameObject("/L")] = ArrayObject([
                    FloatObject(x),
                    FloatObject(y),
                    FloatObject(x + width),
                    FloatObject(y + height),
                ])
            elif canonical_subtype in ("Highlight", "Underline", "StrikeOut", "Squiggly"):
                annot_dict[NameObject("/QuadPoints")] = ArrayObject([
                    FloatObject(x),
                    FloatObject(y + height),
                    FloatObject(x + width),
                    FloatObject(y + height),
                    FloatObject(x),
                    FloatObject(y),
                    FloatObject(x + width),
                    FloatObject(y),
                ])
            elif canonical_subtype in ("PolyLine", "Polygon"):
                annot_dict[NameObject("/Vertices")] = ArrayObject([
                    FloatObject(x),
                    FloatObject(y),
                    FloatObject(x + width),
                    FloatObject(y),
                    FloatObject(x + width),
                    FloatObject(y + height),
                    FloatObject(x),
                    FloatObject(y + height),
                ])

            if canonical_subtype == "FreeText":
                r_s, g_s, b_s = rgb_stroke[0], rgb_stroke[1], rgb_stroke[2]
                annot_dict[NameObject("/DA")] = TextStringObject(f"{r_s} {g_s} {b_s} rg /Helv 12 Tf")
                escaped_comm = xml.sax.saxutils.escape(clean_xml_text(comment), {'"': "&quot;", "'": "&apos;"})
                annot_dict[NameObject("/RC")] = TextStringObject(
                    f'<?xml version="1.0"?><body xmlns="http://www.w3.org/1999/xhtml">{escaped_comm}</body>'
                )

            target_page = writer.pages[page_number - 1]
            if "/Annots" not in target_page:
                target_page[NameObject("/Annots")] = ArrayObject()
            target_page[NameObject("/Annots")].append(annot_dict)

            atomic_write_pdf(writer, out_file)

            return {
                "output_path": str(out_file),
                "markup_id": markup_id,
                "page_number": page_number,
                "markup_type": canonical_subtype,
                "rect": [x, y, x + width, y + height],
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 3: bb_markup_update
# ============================================================================

def bb_markup_update(
    pdf_path: str,
    output_path: str,
    page_number: int,
    markup_id: str,
    updates: dict[str, Any] | None = None,
    status: str | None = None,
    custom_columns: dict[str, str] | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Update properties, comment, review status, or custom columns of an existing markup by ID.

    Primary citations:
    - docs/citations/01_script_reference.md p. 8-9 (ColumnDataSet), p. 17 (MarkupSet), p. 18 (MarkupStatusSet)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdMarkupSet, SCmdMarkupStatusSet, SCmdColumnDataSet)
    """
    tool_name = "bb_markup_update"
    citations = [
        "docs/citations/01_script_reference.md p. 8-9 (ColumnDataSet), p. 17 (MarkupSet), p. 18 (MarkupStatusSet)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdMarkupSet, SCmdMarkupStatusSet, SCmdColumnDataSet)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        out_file = validate_path(output_path, mode="write", must_exist=False)
        validate_one_based_page(page_number)

        clean_id = markup_id.strip()
        if not clean_id:
            raise ValueError("markup_id argument cannot be empty")

        if updates:
            for k in updates:
                if k not in VALID_MARKUP_KEYS:
                    raise InvalidParameterError(
                        f"Invalid markup property key '{k}'. Supported keys: {sorted(VALID_MARKUP_KEYS)}"
                    )
            if "opacity" in updates:
                op = float(updates["opacity"])
                if not math.isfinite(op) or not (0.0 <= op <= 1.0):
                    raise InvalidParameterError(f"Opacity must be finite and between 0.0 and 1.0, got {op}")
            if "opacityfill" in updates:
                opf = float(updates["opacityfill"])
                if not math.isfinite(opf) or not (0.0 <= opf <= 1.0):
                    raise InvalidParameterError(f"opacityfill must be finite and between 0.0 and 1.0, got {opf}")
            if "linewidth" in updates:
                lw = float(updates["linewidth"])
                if not math.isfinite(lw) or lw < 0.0:
                    raise InvalidParameterError(f"linewidth must be finite and non-negative, got {lw}")
            for coord_k in ("x", "y"):
                if coord_k in updates:
                    c_v = float(updates[coord_k])
                    if not math.isfinite(c_v):
                        raise InvalidParameterError(f"{coord_k} must be finite number, got {c_v}")
            for dim_k in ("width", "height"):
                if dim_k in updates:
                    d_v = float(updates[dim_k])
                    if not math.isfinite(d_v) or d_v <= 0:
                        raise InvalidParameterError(f"{dim_k} must be finite positive number, got {d_v}")
            for color_k in ("color", "colorfill", "colortext"):
                if color_k in updates and updates[color_k]:
                    validate_color(updates[color_k])
            if "type" in updates:
                t_clean = str(updates["type"]).strip().lower()
                if t_clean not in ALLOWED_MARKUP_SUBTYPES:
                    raise InvalidParameterError(f"Unsupported markup type '{updates['type']}'")

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        if page_number > len(reader.pages):
            raise PageRangeError(
                f"Page number {page_number} exceeds document page count {len(reader.pages)}"
            )

        # Build BCS Script
        builder = ScriptBuilder()
        builder.open(pdf_file)
        if updates:
            builder.add_command("MarkupSet", page_number, clean_id, updates)
        if status:
            builder.add_command("MarkupStatusSet", page_number, clean_id, "Review", status)
        if custom_columns:
            builder.add_command("ColumnDataSet", page_number - 1, clean_id, custom_columns)
        builder.save(out_file)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            page_obj = writer.pages[page_number - 1]
            annots_entry = page_obj.get("/Annots")
            if not annots_entry:
                raise ValueError(f"Markup ID '{clean_id}' not found on page {page_number}")

            annots_list = annots_entry.get_object() if hasattr(annots_entry, "get_object") else annots_entry
            found_annot = None

            for annot_ref in annots_list:
                annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                if isinstance(annot, (dict, DictionaryObject)):
                    if str(annot.get("/NM", "")) == clean_id:
                        found_annot = annot
                        break

            if found_annot is None:
                raise ValueError(f"Markup ID '{clean_id}' not found on page {page_number}")

            needs_ap_regen = False
            cur_rect = [float(v) for v in found_annot.get("/Rect", [0.0, 0.0, 100.0, 100.0])]
            rx = cur_rect[0] if len(cur_rect) > 0 else 0.0
            ry = cur_rect[1] if len(cur_rect) > 1 else 0.0
            rw = (cur_rect[2] - cur_rect[0]) if len(cur_rect) > 2 else 100.0
            rh = (cur_rect[3] - cur_rect[1]) if len(cur_rect) > 3 else 100.0

            # Apply property updates
            if updates:
                if "comment" in updates:
                    new_comment = str(updates["comment"])
                    found_annot[NameObject("/Contents")] = TextStringObject(new_comment)
                    escaped_c = xml.sax.saxutils.escape(clean_xml_text(new_comment), {'"': "&quot;", "'": "&apos;"})
                    found_annot[NameObject("/RC")] = TextStringObject(
                        f'<?xml version="1.0"?><body xmlns="http://www.w3.org/1999/xhtml">{escaped_c}</body>'
                    )
                    needs_ap_regen = True

                if "subject" in updates:
                    found_annot[NameObject("/Subj")] = TextStringObject(str(updates["subject"]))
                if "author" in updates:
                    found_annot[NameObject("/T")] = TextStringObject(str(updates["author"]))

                if "color" in updates:
                    c_rgb = _hex_to_rgb(str(updates["color"]))
                    found_annot[NameObject("/C")] = ArrayObject([
                        FloatObject(c_rgb[0]),
                        FloatObject(c_rgb[1]),
                        FloatObject(c_rgb[2]),
                    ])
                    needs_ap_regen = True

                if "colorfill" in updates:
                    ic_rgb = _hex_to_rgb(str(updates["colorfill"]))
                    found_annot[NameObject("/IC")] = ArrayObject([
                        FloatObject(ic_rgb[0]),
                        FloatObject(ic_rgb[1]),
                        FloatObject(ic_rgb[2]),
                    ])
                    needs_ap_regen = True

                if "opacity" in updates:
                    found_annot[NameObject("/CA")] = FloatObject(float(updates["opacity"]))
                    needs_ap_regen = True

                if "linewidth" in updates:
                    if "/BS" not in found_annot:
                        found_annot[NameObject("/BS")] = DictionaryObject()
                    found_annot[NameObject("/BS")][NameObject("/W")] = FloatObject(float(updates["linewidth"]))
                    needs_ap_regen = True

                if any(k in updates for k in ("x", "y", "width", "height")):
                    rx = float(updates.get("x", rx))
                    ry = float(updates.get("y", ry))
                    rw = float(updates.get("width", rw))
                    rh = float(updates.get("height", rh))
                    found_annot[NameObject("/Rect")] = ArrayObject([
                        FloatObject(rx),
                        FloatObject(ry),
                        FloatObject(rx + rw),
                        FloatObject(ry + rh),
                    ])
                    needs_ap_regen = True

                if "locked" in updates:
                    cur_f = int(found_annot.get("/F", 0))
                    is_locked = bool(updates["locked"])
                    found_annot[NameObject("/F")] = NumberObject((cur_f | 128) if is_locked else (cur_f & ~128))

                if "type" in updates:
                    t_clean = str(updates["type"]).strip().lower()
                    canonical = ALLOWED_MARKUP_SUBTYPES[t_clean]
                    found_annot[NameObject("/Subtype")] = NameObject(f"/{canonical}")
                    needs_ap_regen = True

            if status:
                found_annot[NameObject("/ReviewStatus")] = TextStringObject(status)
                found_annot[NameObject("/State")] = TextStringObject(status)

            if custom_columns:
                col_dict = DictionaryObject({
                    NameObject(f"/{k}"): TextStringObject(str(v)) for k, v in custom_columns.items()
                })
                found_annot[NameObject("/CustomColumns")] = col_dict
                found_annot[NameObject("/BSIColumnData")] = col_dict

            now_str = datetime.now().strftime("%Y%m%d%H%M%S")
            found_annot[NameObject("/M")] = TextStringObject(f"D:{now_str}")

            if needs_ap_regen:
                stroke_c = [0.0, 0.0, 0.0]
                if "/C" in found_annot:
                    c_raw = found_annot["/C"]
                    if len(c_raw) >= 3:
                        stroke_c = [float(c_raw[0]), float(c_raw[1]), float(c_raw[2])]
                fill_c = None
                if "/IC" in found_annot:
                    ic_raw = found_annot["/IC"]
                    if len(ic_raw) >= 3:
                        fill_c = [float(ic_raw[0]), float(ic_raw[1]), float(ic_raw[2])]
                line_w = 1.0
                if "/BS" in found_annot and "/W" in found_annot["/BS"]:
                    line_w = float(found_annot["/BS"]["/W"])
                sub_type = str(found_annot.get("/Subtype", "/FreeText")).lstrip("/")
                new_ap = _build_appearance_stream(
                    width=rw,
                    height=rh,
                    line_width=line_w,
                    rgb_stroke=stroke_c,
                    rgb_fill=fill_c,
                    canonical_subtype=sub_type,
                )
                found_annot[NameObject("/AP")] = DictionaryObject({NameObject("/N"): new_ap})

            atomic_write_pdf(writer, out_file)

            return {
                "output_path": str(out_file),
                "markup_id": clean_id,
                "page_number": page_number,
                "updated_fields": list(updates.keys()) if updates else [],
                "status": status,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 4: bb_markup_delete
# ============================================================================

def bb_markup_delete(
    pdf_path: str,
    output_path: str,
    page_number: int,
    markup_id: str,
    all_matches: bool = False,
    purge_page: bool = False,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Delete a specific markup annotation or all matching annotations from a PDF page by ID.

    Primary citations:
    - docs/citations/01_script_reference.md p. 15-16 (MarkupDelete)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdMarkupDelete)
    """
    tool_name = "bb_markup_delete"
    citations = [
        "docs/citations/01_script_reference.md p. 15-16 (MarkupDelete)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdMarkupDelete)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        out_file = validate_path(output_path, mode="write", must_exist=False)
        validate_one_based_page(page_number)

        clean_id = markup_id.strip()
        if not clean_id and not purge_page:
            raise ValueError("markup_id argument cannot be empty")

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        if page_number > len(reader.pages):
            raise PageRangeError(
                f"Page number {page_number} exceeds document page count {len(reader.pages)}"
            )

        builder = ScriptBuilder()
        builder.open(pdf_file)
        builder.add_command("MarkupDelete", page_number, clean_id)
        builder.save(out_file)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            page_obj = writer.pages[page_number - 1]
            annots_entry = page_obj.get("/Annots")
            if not annots_entry:
                if purge_page:
                    atomic_write_pdf(writer, out_file)
                    return {"output_path": str(out_file), "markup_id": clean_id, "page_number": page_number, "deleted": True}
                raise ValueError(f"Markup ID '{clean_id}' not found on page {page_number}")

            annots_list = annots_entry.get_object() if hasattr(annots_entry, "get_object") else annots_entry
            deleted_ids: set[str] = set()
            if purge_page:
                page_obj[NameObject("/Annots")] = ArrayObject()
                atomic_write_pdf(writer, out_file)
                return {
                    "output_path": str(out_file),
                    "markup_id": clean_id,
                    "page_number": page_number,
                    "deleted": True,
                    "purged_page": True,
                }

            # First pass: find target annotation(s)
            matching_refs: list[Any] = []
            for annot_ref in annots_list:
                annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                if isinstance(annot, (dict, DictionaryObject)):
                    cur_nm = str(annot.get("/NM", ""))
                    if cur_nm == clean_id:
                        matching_refs.append(annot_ref)

            if not matching_refs:
                raise ValueError(f"Markup ID '{clean_id}' not found on page {page_number}")

            if len(matching_refs) > 1 and not all_matches:
                raise InvalidParameterError(
                    f"Multiple annotations ({len(matching_refs)}) share markup_id '{clean_id}' on page {page_number}; "
                    "pass all_matches=True to delete all duplicates"
                )

            deleted_ids.add(clean_id)
            deleted_obj_ids: set[int] = set()
            deleted_indirect_keys: set[tuple[int, int]] = set()
            deleted_popup_keys: set[tuple[int, int]] = set()
            deleted_popup_obj_ids: set[int] = set()

            for ref in matching_refs:
                obj = ref.get_object() if hasattr(ref, "get_object") else ref
                deleted_obj_ids.add(id(obj))
                if hasattr(ref, "idnum"):
                    deleted_indirect_keys.add((ref.idnum, getattr(ref, "generation", 0)))
                if isinstance(obj, (dict, DictionaryObject)) and "/Popup" in obj:
                    p_ref = obj["/Popup"]
                    if hasattr(p_ref, "idnum"):
                        deleted_popup_keys.add((p_ref.idnum, getattr(p_ref, "generation", 0)))
                    p_obj = p_ref.get_object() if hasattr(p_ref, "get_object") else p_ref
                    deleted_popup_obj_ids.add(id(p_obj))

            # Second pass: remove matching annotations and any associated /Popup or /IRT replies
            new_annots = ArrayObject()
            for annot_ref in annots_list:
                annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                ref_key = (annot_ref.idnum, getattr(annot_ref, "generation", 0)) if hasattr(annot_ref, "idnum") else None
                if id(annot) in deleted_obj_ids or (ref_key and ref_key in deleted_indirect_keys):
                    continue
                if id(annot) in deleted_popup_obj_ids or (ref_key and ref_key in deleted_popup_keys):
                    continue
                if isinstance(annot, (dict, DictionaryObject)):
                    cur_nm = str(annot.get("/NM", ""))
                    irt_val = annot.get("/IRT")
                    irt_str = str(irt_val) if irt_val is not None else ""
                    irt_obj = irt_val.get_object() if hasattr(irt_val, "get_object") else irt_val
                    irt_nm = str(irt_obj.get("/NM", "")) if isinstance(irt_obj, (dict, DictionaryObject)) else ""
                    if cur_nm in deleted_ids or irt_str in deleted_ids or irt_nm in deleted_ids or id(irt_obj) in deleted_obj_ids:
                        continue
                    subtype_str = str(annot.get("/Subtype", "")).lstrip("/")
                    if subtype_str == "Popup" and "/Parent" in annot:
                        parent_ref = annot["/Parent"]
                        parent_key = (parent_ref.idnum, getattr(parent_ref, "generation", 0)) if hasattr(parent_ref, "idnum") else None
                        parent_obj = parent_ref.get_object() if hasattr(parent_ref, "get_object") else parent_ref
                        parent_nm = str(parent_obj.get("/NM", "")) if isinstance(parent_obj, (dict, DictionaryObject)) else ""
                        if (
                            (parent_key and parent_key in deleted_indirect_keys)
                            or id(parent_obj) in deleted_obj_ids
                            or (parent_nm and parent_nm in deleted_ids)
                        ):
                            continue
                new_annots.append(annot_ref)

            page_obj[NameObject("/Annots")] = new_annots

            atomic_write_pdf(writer, out_file)

            return {
                "output_path": str(out_file),
                "markup_id": clean_id,
                "page_number": page_number,
                "deleted": True,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 5: bb_markup_flatten
# ============================================================================

def bb_markup_flatten(
    pdf_path: str,
    output_path: str,
    action: str = "flatten",
    recoverable: bool = True,
    flags: int | list[str] | None = None,
    page_range: str = "-1",
    unflatten: bool = False,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Flatten markups into page content using an 18-bit type mask, or reverse recoverable flattening.

    Primary citations:
    - docs/citations/01_script_reference.md p. 11-12 (Flatten), p. 29 (Unflatten)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdFlatten, SCmdUnflatten)
    """
    tool_name = "bb_markup_flatten"
    citations = [
        "docs/citations/01_script_reference.md p. 11-12 (Flatten), p. 29 (Unflatten)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdFlatten, SCmdUnflatten)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        out_file = validate_path(output_path, mode="write", must_exist=False)

        clean_action = "unflatten" if unflatten else action.strip().lower()
        if clean_action not in ("flatten", "unflatten"):
            raise ValueError(f"Invalid action '{action}'. Must be 'flatten' or 'unflatten'")

        bitmask = calculate_flatten_bitmask(flags)
        valid_range = validate_page_range(page_range)

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        total_pages = len(reader.pages)
        target_pages = _parse_target_pages(valid_range, total_pages)

        builder = ScriptBuilder()
        builder.open(pdf_file)
        if clean_action == "flatten":
            builder.add_command("Flatten", recoverable, bitmask, valid_range, "")
        else:
            builder.add_command("Unflatten", valid_range)
        builder.save(out_file)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            flattened_count = 0
            unflattened_count = 0

            # Eligible subtypes from flatten bitmask
            eligible_subtypes: set[str] = set()
            for bit, subtypes in FLATTEN_FLAG_SUBTYPES.items():
                if bitmask & bit:
                    eligible_subtypes.update(subtypes)

            # Retrieve existing recoverable markups
            root_obj = writer._root_object
            recov_raw = None
            if NameObject("/BBRecoverableMarkups") in root_obj:
                recov_raw = str(root_obj[NameObject("/BBRecoverableMarkups")])
            elif NameObject("/BluebeamRecoverableMarkups") in root_obj:
                recov_raw = str(root_obj[NameObject("/BluebeamRecoverableMarkups")])

            recoverable_data: dict[str, list[dict[str, Any]]] = {}
            if recov_raw:
                try:
                    parsed = json.loads(recov_raw)
                    if isinstance(parsed, dict):
                        recoverable_data = parsed
                    elif isinstance(parsed, list):
                        for item in parsed:
                            p_key = str(item.get("page", 1))
                            recoverable_data.setdefault(p_key, []).append(item)
                except Exception:
                    recoverable_data = {}

            if clean_action == "flatten":
                for p_num in target_pages:
                    page_obj = writer.pages[p_num - 1]
                    annots_entry = page_obj.get("/Annots")
                    if not annots_entry:
                        continue

                    annots_list = annots_entry.get_object() if hasattr(annots_entry, "get_object") else annots_entry
                    if not isinstance(annots_list, (list, ArrayObject)):
                        continue

                    candidate_retained: list[Any] = []
                    flattened_on_page: list[DictionaryObject] = []
                    flattened_obj_ids: set[int] = set()
                    flattened_indirect_keys: set[tuple[int, int]] = set()
                    flattened_nms: set[str] = set()
                    flattened_popup_keys: set[tuple[int, int]] = set()
                    flattened_popup_obj_ids: set[int] = set()

                    for annot_ref in annots_list:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        if not isinstance(annot, (dict, DictionaryObject)):
                            candidate_retained.append(annot_ref)
                            continue

                        subtype_pdf = str(annot.get("/Subtype", ""))
                        if not subtype_pdf.startswith("/"):
                            subtype_pdf = f"/{subtype_pdf}"

                        # Never flatten /Link or /Popup directly; only flatten /Widget if bit 65536 is set
                        if subtype_pdf in ("/Link", "/Popup"):
                            candidate_retained.append(annot_ref)
                            continue

                        if bitmask == 0 or subtype_pdf not in eligible_subtypes:
                            candidate_retained.append(annot_ref)
                            continue

                        # Mark as flattened
                        flattened_count += 1
                        flattened_on_page.append(annot)
                        flattened_obj_ids.add(id(annot))
                        if hasattr(annot_ref, "idnum"):
                            flattened_indirect_keys.add((annot_ref.idnum, getattr(annot_ref, "generation", 0)))
                        nm_val = str(annot.get("/NM", ""))
                        if nm_val:
                            flattened_nms.add(nm_val)
                        if "/Popup" in annot:
                            p_ref = annot["/Popup"]
                            if hasattr(p_ref, "idnum"):
                                flattened_popup_keys.add((p_ref.idnum, getattr(p_ref, "generation", 0)))
                            p_obj = p_ref.get_object() if hasattr(p_ref, "get_object") else p_ref
                            flattened_popup_obj_ids.add(id(p_obj))
                        if recoverable:
                            serialized = _serialize_annotation(annot, p_num)
                            recoverable_data.setdefault(str(p_num), []).append(serialized)

                    # Filter out orphan /Popup annotations whose parent markup was flattened (F-09)
                    retained_annots = ArrayObject()
                    for annot_ref in candidate_retained:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        ref_key = (annot_ref.idnum, getattr(annot_ref, "generation", 0)) if hasattr(annot_ref, "idnum") else None
                        if id(annot) in flattened_popup_obj_ids or (ref_key and ref_key in flattened_popup_keys):
                            continue
                        if isinstance(annot, (dict, DictionaryObject)):
                            subtype_pdf = str(annot.get("/Subtype", ""))
                            if not subtype_pdf.startswith("/"):
                                subtype_pdf = f"/{subtype_pdf}"
                            if subtype_pdf == "/Popup" and "/Parent" in annot:
                                parent_ref = annot["/Parent"]
                                parent_key = (parent_ref.idnum, getattr(parent_ref, "generation", 0)) if hasattr(parent_ref, "idnum") else None
                                parent_obj = parent_ref.get_object() if hasattr(parent_ref, "get_object") else parent_ref
                                parent_nm = str(parent_obj.get("/NM", "")) if isinstance(parent_obj, (dict, DictionaryObject)) else ""
                                if (
                                    (parent_key and parent_key in flattened_indirect_keys)
                                    or id(parent_obj) in flattened_obj_ids
                                    or (parent_nm and parent_nm in flattened_nms)
                                ):
                                    continue
                        retained_annots.append(annot_ref)

                    page_obj[NameObject("/Annots")] = retained_annots

                    # Render visual appearance into page /Contents
                    if flattened_on_page:
                        mb = page_obj.mediabox
                        pw = float(mb.width) if hasattr(mb, "width") else (float(mb[2]) - float(mb[0]))
                        ph = float(mb.height) if hasattr(mb, "height") else (float(mb[3]) - float(mb[1]))

                        buf = io.BytesIO()
                        c = canvas.Canvas(buf, pagesize=(pw, ph))
                        for fl_annot in flattened_on_page:
                            _render_annotation_to_canvas(c, fl_annot)
                        c.showPage()
                        c.save()
                        buf.seek(0)

                        overlay_reader = pypdf.PdfReader(buf)
                        page_obj.merge_page(overlay_reader.pages[0])

                if recoverable and recoverable_data:
                    serial_json = json.dumps(recoverable_data)
                    root_obj[NameObject("/BBRecoverableMarkups")] = TextStringObject(serial_json)
                    root_obj[NameObject("/BluebeamRecoverableMarkups")] = TextStringObject(serial_json)

            else:
                # Unflatten
                if not recoverable_data:
                    raise InvalidParameterError("No recoverable markups found to unflatten")

                for p_num in target_pages:
                    p_key = str(p_num)
                    if p_key in recoverable_data:
                        page_obj = writer.pages[p_num - 1]
                        if "/Annots" not in page_obj:
                            page_obj[NameObject("/Annots")] = ArrayObject()

                        for m_data in recoverable_data[p_key]:
                            re_annot = _deserialize_annotation(m_data)
                            page_obj[NameObject("/Annots")].append(re_annot)
                            unflattened_count += 1

                        del recoverable_data[p_key]

                if not recoverable_data:
                    if NameObject("/BBRecoverableMarkups") in root_obj:
                        del root_obj[NameObject("/BBRecoverableMarkups")]
                    if NameObject("/BluebeamRecoverableMarkups") in root_obj:
                        del root_obj[NameObject("/BluebeamRecoverableMarkups")]
                else:
                    serial_json = json.dumps(recoverable_data)
                    root_obj[NameObject("/BBRecoverableMarkups")] = TextStringObject(serial_json)
                    root_obj[NameObject("/BluebeamRecoverableMarkups")] = TextStringObject(serial_json)

            atomic_write_pdf(writer, out_file)

            return {
                "output_path": str(out_file),
                "action": clean_action,
                "recoverable": recoverable,
                "flags": bitmask if clean_action == "flatten" else None,
                "page_range": valid_range,
                "count": flattened_count if clean_action == "flatten" else unflattened_count,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 6: bb_pdf_stamp
# ============================================================================

def bb_pdf_stamp(
    pdf_path: str,
    output_path: str,
    stamp_path_or_text: str,
    x: float = 72.0,
    y: float = 72.0,
    width: float = 144.0,
    height: float = 50.0,
    origin: int = 0,
    rotation: int = 0,
    opacity: float = 1.0,
    blend_mode: int = 0,
    page_range: str = "-1",
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Apply a Bluebeam PDF stamp at specified origin, rotation, scale, opacity, and blend mode.

    Primary citations:
    - docs/citations/01_script_reference.md p. 27 (Stamp)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdStamp)
    - docs/citations/03_data_formats_and_markups.md Section 4 (Exact PDF Dictionary Structure of Bluebeam Stamps)
    """
    tool_name = "bb_pdf_stamp"
    citations = [
        "docs/citations/01_script_reference.md p. 27 (Stamp)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdStamp)",
        "docs/citations/03_data_formats_and_markups.md Section 4 (Exact PDF Dictionary Structure of Bluebeam Stamps)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        out_file = validate_path(output_path, mode="write", must_exist=False)

        origin_str = resolve_stamp_origin(origin)
        blend_str = resolve_stamp_blend_mode(blend_mode)
        valid_range = validate_page_range(page_range)

        if not math.isfinite(opacity) or not (0.0 <= opacity <= 1.0):
            raise InvalidParameterError(f"Opacity must be finite and between 0.0 and 1.0, got {opacity}")

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        total_pages = len(reader.pages)
        target_pages = _parse_target_pages(valid_range, total_pages)

        # Path vs text detection (Finding H-16)
        raw_stamp = stamp_path_or_text.strip()
        is_file_path = False
        if raw_stamp.lower().endswith((".pdf", ".btx")):
            is_file_path = True
        elif re.match(r"^[A-Za-z]:[\\/]", raw_stamp) or raw_stamp.startswith(("\\", "./", ".\\", "../", "..\\")):
            is_file_path = True
        else:
            shared_dir = Path(r"C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\Stamps")
            if (shared_dir / raw_stamp).exists() or (shared_dir / f"{raw_stamp}.pdf").exists():
                is_file_path = True

        resolved_stamp_file: Path | None = None
        stamp_text_label = stamp_path_or_text

        if is_file_path:
            shared_dir = Path(r"C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\Stamps")
            candidate_shared = shared_dir / raw_stamp
            candidate_shared_pdf = shared_dir / f"{raw_stamp}.pdf"
            if not os.path.isabs(raw_stamp) and candidate_shared.exists():
                resolved_stamp_file = validate_path(candidate_shared, mode="read", must_exist=True)
            elif not os.path.isabs(raw_stamp) and candidate_shared_pdf.exists():
                resolved_stamp_file = validate_path(candidate_shared_pdf, mode="read", must_exist=True)
            else:
                resolved_stamp_file = validate_path(raw_stamp, mode="read", must_exist=True)
            check_pdf_header(resolved_stamp_file)

        # Offsets in inches per BCS Stamp syntax (72 pt = 1 in)
        x_in = round(x / 72.0, 4)
        y_in = round(y / 72.0, 4)

        builder = ScriptBuilder()
        builder.open(pdf_file)
        stamp_arg = str(resolved_stamp_file) if resolved_stamp_file is not None else stamp_path_or_text
        builder.add_command(
            "Stamp",
            stamp_arg,
            origin_str,
            x_in,
            y_in,
            rotation,
            1.0,
            opacity,
            blend_str,
            valid_range,
            False,
        )
        builder.save(out_file)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            stamp_id = f"BB-STAMP-{uuid.uuid4().hex[:10].upper()}"
            stamp_text = stamp_text_label

            stamp_pdf_page: Any = None
            if resolved_stamp_file is not None:
                s_reader = pypdf.PdfReader(str(resolved_stamp_file))
                if s_reader.is_encrypted:
                    raise EncryptedPDFError(f"Stamp PDF file is encrypted: {resolved_stamp_file}")
                if s_reader.pages:
                    stamp_pdf_page = s_reader.pages[0]
                    # Extract text or title
                    annots = stamp_pdf_page.get("/Annots")
                    if annots:
                        annots_l = annots.get_object() if hasattr(annots, "get_object") else annots
                        if annots_l:
                            a0 = annots_l[0].get_object() if hasattr(annots_l[0], "get_object") else annots_l[0]
                            if isinstance(a0, (dict, DictionaryObject)) and "/Contents" in a0:
                                stamp_text = str(a0["/Contents"])
                    if not stamp_text and s_reader.metadata and s_reader.metadata.title:
                        stamp_text = str(s_reader.metadata.title)
                if not stamp_text:
                    stamp_text = resolved_stamp_file.stem

            for p_num in target_pages:
                tgt_page = writer.pages[p_num - 1]
                mb = tgt_page.mediabox
                pw = float(mb.width) if hasattr(mb, "width") else (float(mb[2]) - float(mb[0]))
                ph = float(mb.height) if hasattr(mb, "height") else (float(mb[3]) - float(mb[1]))

                # Calculate placement according to origin anchor
                origin_idx = STAMP_ORIGIN_NAMES.get(origin_str, 0)
                if origin_idx == 1:  # upperleft
                    final_x = x
                    final_y = ph - height - y
                elif origin_idx == 2:  # upperright
                    final_x = pw - width - x
                    final_y = ph - height - y
                elif origin_idx == 4:  # lowerright
                    final_x = pw - width - x
                    final_y = y
                elif origin_idx == 5:  # uppercenter
                    final_x = (pw - width) / 2.0 + x
                    final_y = ph - height - y
                elif origin_idx == 6:  # lowercenter
                    final_x = (pw - width) / 2.0 + x
                    final_y = y
                elif origin_idx == 3:  # lowerleft
                    final_x = x
                    final_y = y
                else:  # center (0)
                    if x == 72.0 and y == 72.0:
                        final_x = (pw - width) / 2.0
                        final_y = (ph - height) / 2.0
                    else:
                        final_x = x
                        final_y = y

                if stamp_pdf_page is not None:
                    # Merge existing PDF stamp page
                    stamp_copy = copy.copy(stamp_pdf_page)
                    sw = float(stamp_pdf_page.mediabox.width)
                    sh = float(stamp_pdf_page.mediabox.height)
                    scale_x = width / sw if sw > 0 else 1.0
                    scale_y = height / sh if sh > 0 else 1.0
                    trans = pypdf.Transformation().scale(scale_x, scale_y).translate(final_x, final_y)
                    if rotation != 0:
                        trans = trans.rotate(rotation)
                    stamp_copy.add_transformation(trans)
                    tgt_page.merge_page(stamp_copy)
                else:
                    # Render custom text stamp overlay
                    stamp_buf = io.BytesIO()
                    c = canvas.Canvas(stamp_buf, pagesize=(pw, ph))
                    c.saveState()
                    c.translate(final_x, final_y)
                    if rotation != 0:
                        c.rotate(rotation)
                    c.setFillAlpha(opacity)
                    c.setStrokeAlpha(opacity)

                    c.setStrokeColorRGB(0.8, 0.1, 0.1)
                    c.setFillColorRGB(1.0, 0.95, 0.95)
                    c.setLineWidth(2.0)
                    c.rect(0, 0, width, height, fill=1, stroke=1)

                    c.setFont("Helvetica-Bold", 14)
                    c.setFillColorRGB(0.8, 0.1, 0.1)
                    c.drawCentredString(width / 2.0, height / 2.0 - 5.0, stamp_text)
                    c.restoreState()
                    c.showPage()
                    c.save()
                    stamp_buf.seek(0)

                    overlay_reader = pypdf.PdfReader(stamp_buf)
                    tgt_page.merge_page(overlay_reader.pages[0])

                # Add /Stamp annotation entry
                if "/Annots" not in tgt_page:
                    tgt_page[NameObject("/Annots")] = ArrayObject()

                rect_arr = ArrayObject([
                    FloatObject(final_x),
                    FloatObject(final_y),
                    FloatObject(final_x + width),
                    FloatObject(final_y + height),
                ])

                stamp_annot = DictionaryObject({
                    NameObject("/Type"): NameObject("/Annot"),
                    NameObject("/Subtype"): NameObject("/Stamp"),
                    NameObject("/Rect"): rect_arr,
                    NameObject("/Contents"): TextStringObject(stamp_text),
                    NameObject("/Subj"): TextStringObject("Stamp"),
                    NameObject("/T"): TextStringObject("Bluebeam MCP"),
                    NameObject("/NM"): TextStringObject(stamp_id),
                    NameObject("/CA"): FloatObject(opacity),
                    NameObject("/Rotate"): NumberObject(rotation),
                    NameObject("/C"): ArrayObject([FloatObject(0.8), FloatObject(0.1), FloatObject(0.1)]),
                })
                tgt_page[NameObject("/Annots")].append(stamp_annot)

            atomic_write_pdf(writer, out_file)

            return {
                "output_path": str(out_file),
                "stamp": stamp_text,
                "origin": origin_str,
                "rect": [x, y, x + width, y + height],
                "page_range": valid_range,
                "pages_stamped": len(target_pages),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 7: bb_markup_export_bax
# ============================================================================

def bb_markup_export_bax(
    pdf_path: str,
    output_path: str,
    format_type: str = "bax",
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Export markups from the active PDF to a Bluebeam .bax (XML), .csv, or .json summary file.

    Primary citations:
    - docs/citations/01_script_reference.md p. 9 (ColumnsExport), p. 10 (Export)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdColumnsExport)
    - docs/citations/03_data_formats_and_markups.md Section 5 (Markup Export/Import Formats)
    """
    tool_name = "bb_markup_export_bax"
    citations = [
        "docs/citations/01_script_reference.md p. 9 (ColumnsExport), p. 10 (Export)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdColumnsExport)",
        "docs/citations/03_data_formats_and_markups.md Section 5 (Markup Export/Import Formats)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)

        fmt_clean = format_type.strip().lower()
        if fmt_clean not in ("bax", "xml", "csv", "json"):
            raise ValueError(
                f"Invalid format_type '{format_type}'. Must be 'bax', 'csv', or 'json'"
            )

        out_file = validate_path(output_path, mode="write", must_exist=False)

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")

        builder = ScriptBuilder()
        builder.open(pdf_file)
        if fmt_clean == "csv":
            builder.add_command("ColumnsExport", out_file)
        else:
            builder.add_command("Export", out_file, "")
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            markups: list[dict[str, Any]] = []

            for page_idx, page in enumerate(reader.pages, start=1):
                annots_entry = page.get("/Annots")
                if not annots_entry:
                    continue
                annots_list = annots_entry.get_object() if hasattr(annots_entry, "get_object") else annots_entry
                if not isinstance(annots_list, (list, ArrayObject)):
                    continue

                for annot_ref in annots_list:
                    try:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        if not isinstance(annot, (dict, DictionaryObject)):
                            continue

                        subtype = str(annot.get("/Subtype", "")).lstrip("/")
                        if subtype in ("Widget", "Link", "Popup"):
                            continue

                        rect_raw = annot.get("/Rect", [])
                        rect_coords = [float(val) for val in rect_raw] if rect_raw else [0.0, 0.0, 0.0, 0.0]

                        color_hex = _color_to_hex(annot.get("/C")) or "#000000"
                        fill_hex = _color_to_hex(annot.get("/IC")) or ""

                        opacity_val = float(annot.get("/CA", 1.0))
                        line_w = 1.0
                        if "/BS" in annot and isinstance(annot["/BS"], (dict, DictionaryObject)):
                            line_w = float(annot["/BS"].get("/W", 1.0))

                        status_val = str(annot.get("/ReviewStatus", annot.get("/State", "")))

                        verts = [float(v) for v in annot["/Vertices"]] if "/Vertices" in annot else []
                        quads = [float(v) for v in annot["/QuadPoints"]] if "/QuadPoints" in annot else []
                        ink_l = [[float(v) for v in stroke] for stroke in annot["/InkList"]] if "/InkList" in annot else []

                        markups.append({
                            "id": str(annot.get("/NM", "")),
                            "page": page_idx,
                            "type": subtype,
                            "subject": clean_xml_text(annot.get("/Subj", "")),
                            "author": clean_xml_text(annot.get("/T", "")),
                            "comment": clean_xml_text(annot.get("/Contents", "")),
                            "color": color_hex,
                            "fill_color": fill_hex,
                            "opacity": opacity_val,
                            "line_width": line_w,
                            "status": status_val,
                            "date_modified": str(annot.get("/M", "")),
                            "rect": rect_coords,
                            "vertices": verts,
                            "quad_points": quads,
                            "ink_list": ink_l,
                        })
                    except Exception:
                        continue

            out_file.parent.mkdir(parents=True, exist_ok=True)

            if fmt_clean in ("bax", "xml"):
                root = ET.Element("MarkupList", {"Version": "1"})
                for m in markups:
                    annot_el = ET.SubElement(root, "Annotation")
                    ET.SubElement(annot_el, "Subtype").text = m["type"]
                    ET.SubElement(annot_el, "Subj").text = m["subject"]
                    ET.SubElement(annot_el, "Author").text = m["author"]
                    ET.SubElement(annot_el, "Contents").text = m["comment"]
                    ET.SubElement(annot_el, "Page").text = str(m["page"])

                    rect_c = m["rect"]
                    rx = str(rect_c[0]) if len(rect_c) > 0 else "0"
                    ry = str(rect_c[1]) if len(rect_c) > 1 else "0"
                    rw = str(round(rect_c[2] - rect_c[0], 2)) if len(rect_c) > 2 else "0"
                    rh = str(round(rect_c[3] - rect_c[1], 2)) if len(rect_c) > 3 else "0"
                    ET.SubElement(annot_el, "Rect", {"X": rx, "Y": ry, "Width": rw, "Height": rh})

                    ET.SubElement(annot_el, "Color").text = m["color"]
                    if m["fill_color"]:
                        ET.SubElement(annot_el, "FillColor").text = m["fill_color"]
                    ET.SubElement(annot_el, "Opacity").text = str(m["opacity"])
                    ET.SubElement(annot_el, "LineWidth").text = str(m["line_width"])
                    if m["status"]:
                        ET.SubElement(annot_el, "Status").text = m["status"]
                    ET.SubElement(annot_el, "DateModified").text = m["date_modified"]

                    if m["vertices"]:
                        ET.SubElement(annot_el, "Vertices").text = ",".join(str(v) for v in m["vertices"])
                    if m["quad_points"]:
                        ET.SubElement(annot_el, "QuadPoints").text = ",".join(str(v) for v in m["quad_points"])
                    if m["ink_list"]:
                        ET.SubElement(annot_el, "InkList").text = json.dumps(m["ink_list"])

                xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                atomic_write_bytes(xml_bytes, out_file)

            elif fmt_clean == "json":
                json_bytes = json.dumps(markups, indent=2).encode("utf-8")
                atomic_write_bytes(json_bytes, out_file)

            elif fmt_clean == "csv":
                csv_buf = io.StringIO()
                writer_csv = csv.DictWriter(
                    csv_buf,
                    fieldnames=["id", "page", "type", "subject", "author", "comment", "color", "fill_color", "opacity", "line_width", "status", "date_modified", "rect"],
                )
                writer_csv.writeheader()
                for m in markups:
                    writer_csv.writerow({
                        "id": sanitize_csv_cell(m["id"]),
                        "page": sanitize_csv_cell(m["page"]),
                        "type": sanitize_csv_cell(m["type"]),
                        "subject": sanitize_csv_cell(m["subject"]),
                        "author": sanitize_csv_cell(m["author"]),
                        "comment": sanitize_csv_cell(m["comment"]),
                        "color": sanitize_csv_cell(m["color"]),
                        "fill_color": sanitize_csv_cell(m["fill_color"]),
                        "opacity": sanitize_csv_cell(m["opacity"]),
                        "line_width": sanitize_csv_cell(m["line_width"]),
                        "status": sanitize_csv_cell(m["status"]),
                        "date_modified": sanitize_csv_cell(m["date_modified"]),
                        "rect": sanitize_csv_cell(",".join(str(v) for v in m["rect"])),
                    })
                atomic_write_bytes(csv_buf.getvalue().encode("utf-8"), out_file)

            return {
                "output_path": str(out_file),
                "format": fmt_clean,
                "markup_count": len(markups),
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 8: bb_markup_import_bax
# ============================================================================

def bb_markup_import_bax(
    pdf_path: str,
    import_path: str,
    output_path: str,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Inspect or import markups from a .bax, .xfdf, .xml, or .pdf file into a PDF document.

    Primary citations:
    - docs/citations/01_script_reference.md p. 14 (Import)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdAddMarkupFromDictionary)
    - docs/citations/03_data_formats_and_markups.md Section 5 (Markup Export/Import Formats)
    """
    tool_name = "bb_markup_import_bax"
    citations = [
        "docs/citations/01_script_reference.md p. 14 (Import)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdAddMarkupFromDictionary)",
        "docs/citations/03_data_formats_and_markups.md Section 5 (Markup Export/Import Formats)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        imp_file = validate_path(import_path, mode="read", must_exist=True)
        out_file = validate_path(output_path, mode="write", must_exist=False)

        is_pdf_import = imp_file.suffix.lower() == ".pdf"
        xml_root: ET.Element | None = None
        if not is_pdf_import:
            # Defused safe XML parsing to catch XXE and billion laughs
            xml_root = parse_xml_safely(imp_file)

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")

        builder = ScriptBuilder()
        builder.open(pdf_file)
        builder.add_command("Import", imp_file)
        builder.save(out_file)
        builder.close(save=False)
        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            imported_count = 0
            now_str = datetime.now().strftime("%Y%m%d%H%M%S")

            if is_pdf_import:
                # PDF-to-PDF markup transfer
                src_reader = pypdf.PdfReader(str(imp_file))
                if src_reader.is_encrypted:
                    raise EncryptedPDFError(f"Source PDF file is encrypted: {imp_file}")
                for src_idx, src_page in enumerate(src_reader.pages, start=1):
                    if src_idx > len(writer.pages):
                        break
                    annots = src_page.get("/Annots")
                    if not annots:
                        continue
                    annots_l = annots.get_object() if hasattr(annots, "get_object") else annots
                    if not isinstance(annots_l, (list, ArrayObject)):
                        continue
                    dest_page = writer.pages[src_idx - 1]
                    if "/Annots" not in dest_page:
                        dest_page[NameObject("/Annots")] = ArrayObject()
                    for annot_ref in annots_l:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        if isinstance(annot, (dict, DictionaryObject)):
                            sub = str(annot.get("/Subtype", "")).lstrip("/")
                            if sub not in ("Widget", "Link", "Popup"):
                                dest_page[NameObject("/Annots")].append(annot)
                                imported_count += 1

            elif xml_root is not None:
                # BAX or XFDF XML import
                annot_nodes = xml_root.findall(".//Annotation")
                if not annot_nodes:
                    # Check XFDF structure
                    annot_nodes = xml_root.findall(".//{http://ns.adobe.com/xfdf/}annots/*") + xml_root.findall(".//annots/*")

                for annot_node in annot_nodes:
                    raw_sub = annot_node.findtext("Subtype") or annot_node.tag.split("}")[-1]
                    sub_clean = raw_sub.strip().lower()
                    canonical_sub = ALLOWED_MARKUP_SUBTYPES.get(sub_clean, "FreeText")

                    subj = annot_node.findtext("Subj", "Imported Markup")
                    author = annot_node.findtext("Author", "Bluebeam MCP")
                    comment = annot_node.findtext("Contents", "")
                    page_str = annot_node.findtext("Page", "1")
                    color = annot_node.findtext("Color", "#FF0000")
                    fill_col = annot_node.findtext("FillColor")
                    op_str = annot_node.findtext("Opacity", "1.0")
                    lw_str = annot_node.findtext("LineWidth", "1.0")

                    try:
                        page_num = int(page_str)
                    except ValueError:
                        page_num = 1

                    if page_num < 1 or page_num > len(writer.pages):
                        raise PageRangeError(f"Imported markup specifies invalid page {page_num} (document has {len(writer.pages)} pages)")

                    rect_node = annot_node.find("Rect")
                    if rect_node is not None:
                        try:
                            rx = float(rect_node.get("X", 72))
                            ry = float(rect_node.get("Y", 72))
                            rw = float(rect_node.get("Width", 144))
                            rh = float(rect_node.get("Height", 36))
                        except (ValueError, TypeError):
                            rx, ry, rw, rh = 72.0, 72.0, 144.0, 36.0
                    else:
                        rect_text = annot_node.findtext("rect", "")
                        if rect_text and "," in rect_text:
                            pts = [float(v) for v in rect_text.split(",")]
                            rx, ry = pts[0], pts[1]
                            rw, rh = (pts[2] - pts[0]), (pts[3] - pts[1])
                        else:
                            rx, ry, rw, rh = 72.0, 72.0, 144.0, 36.0

                    if not (math.isfinite(rx) and math.isfinite(ry) and math.isfinite(rw) and math.isfinite(rh)):
                        rx, ry, rw, rh = 72.0, 72.0, 144.0, 36.0
                    if rw <= 0:
                        rw = 144.0
                    if rh <= 0:
                        rh = 36.0

                    try:
                        opacity_val = float(op_str)
                    except ValueError:
                        opacity_val = 1.0

                    try:
                        line_w = float(lw_str)
                    except ValueError:
                        line_w = 1.0

                    rect_arr = ArrayObject([
                        FloatObject(rx),
                        FloatObject(ry),
                        FloatObject(rx + rw),
                        FloatObject(ry + rh),
                    ])
                    rgb_stroke = _hex_to_rgb(color)
                    rgb_fill = _hex_to_rgb(fill_col) if fill_col else None
                    markup_id = f"BB-IMP-{uuid.uuid4().hex[:10].upper()}"

                    ap_stream = _build_appearance_stream(
                        width=rw,
                        height=rh,
                        line_width=line_w,
                        rgb_stroke=rgb_stroke,
                        rgb_fill=rgb_fill,
                        canonical_subtype=canonical_sub,
                    )

                    annot_dict = DictionaryObject({
                        NameObject("/Type"): NameObject("/Annot"),
                        NameObject("/Subtype"): NameObject(f"/{canonical_sub}"),
                        NameObject("/Rect"): rect_arr,
                        NameObject("/Contents"): TextStringObject(comment),
                        NameObject("/Subj"): TextStringObject(subj),
                        NameObject("/T"): TextStringObject(author),
                        NameObject("/NM"): TextStringObject(markup_id),
                        NameObject("/M"): TextStringObject(f"D:{now_str}"),
                        NameObject("/CA"): FloatObject(opacity_val),
                        NameObject("/F"): NumberObject(4),
                        NameObject("/C"): ArrayObject([
                            FloatObject(rgb_stroke[0]),
                            FloatObject(rgb_stroke[1]),
                            FloatObject(rgb_stroke[2]),
                        ]),
                        NameObject("/BS"): DictionaryObject({
                            NameObject("/W"): FloatObject(line_w),
                            NameObject("/S"): NameObject("/S"),
                        }),
                        NameObject("/AP"): DictionaryObject({
                            NameObject("/N"): ap_stream,
                        }),
                    })

                    if rgb_fill:
                        annot_dict[NameObject("/IC")] = ArrayObject([
                            FloatObject(rgb_fill[0]),
                            FloatObject(rgb_fill[1]),
                            FloatObject(rgb_fill[2]),
                        ])

                    target_page = writer.pages[page_num - 1]
                    if "/Annots" not in target_page:
                        target_page[NameObject("/Annots")] = ArrayObject()
                    target_page[NameObject("/Annots")].append(annot_dict)
                    imported_count += 1

            atomic_write_pdf(writer, out_file)

            return {
                "output_path": str(out_file),
                "import_path": str(imp_file),
                "markups_imported": imported_count,
            }

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 9: bb_form_inspect_and_fill
# ============================================================================

def bb_form_inspect_and_fill(
    pdf_path: str,
    action: str = "inspect",
    field_values: dict[str, Any] | None = None,
    data_path: str | None = None,
    output_path: str | None = None,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Inspect AcroForm fields, populate field values, or import/export form data.

    Primary citations:
    - docs/citations/01_script_reference.md p. 12-13 (FormExport, FormImport, FormMerge)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdFormExport, SCmdFormImport, SCmdFormMerge)
    - docs/citations/03_data_formats_and_markups.md Section 5 (Form Data)
    """
    tool_name = "bb_form_inspect_and_fill"
    citations = [
        "docs/citations/01_script_reference.md p. 12-13 (FormExport, FormImport, FormMerge)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdFormExport, SCmdFormImport, SCmdFormMerge)",
        "docs/citations/03_data_formats_and_markups.md Section 5 (Form Data)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)

        act_clean = action.strip().lower()
        if act_clean not in ("inspect", "fill", "export", "import"):
            raise ValueError(
                f"Invalid action '{action}'. Must be 'inspect', 'fill', 'export', or 'import'"
            )

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")

        builder = ScriptBuilder()
        builder.open(pdf_file)

        out_resolved: Path | None = None
        data_resolved: Path | None = None

        if act_clean == "inspect":
            builder.close(save=False)
        elif act_clean == "fill":
            target_out = output_path if output_path else str(pdf_file)
            out_resolved = validate_path(target_out, mode="write", must_exist=False)
            builder.save(out_resolved)
            builder.close(save=False)
        elif act_clean == "export":
            if not data_path:
                raise ValueError("data_path argument is required for 'export' action")
            data_resolved = validate_path(data_path, mode="write", must_exist=False)
            builder.add_command("FormExport", data_resolved)
            builder.close(save=False)
        elif act_clean == "import":
            if not data_path:
                raise ValueError("data_path argument is required for 'import' action")
            data_resolved = validate_path(data_path, mode="read", must_exist=True)
            target_out = output_path if output_path else str(pdf_file)
            out_resolved = validate_path(target_out, mode="write", must_exist=False)
            builder.add_command("FormImport", data_resolved)
            builder.save(out_resolved)
            builder.close(save=False)

        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            if act_clean == "inspect":
                fields_raw = reader.get_fields() or {}
                inspected_fields: dict[str, Any] = {}
                for k, v in fields_raw.items():
                    val = v.get("/V", "")
                    ft = str(v.get("/FT", "")).lstrip("/")
                    inspected_fields[k] = {
                        "value": str(val) if val is not None else "",
                        "field_type": ft,
                    }
                return {
                    "pdf_path": str(pdf_file),
                    "action": "inspect",
                    "fields": inspected_fields,
                    "field_count": len(inspected_fields),
                }

            elif act_clean == "fill":
                if not field_values:
                    raise ValueError("field_values dictionary is required for 'fill' action")

                for k, v in field_values.items():
                    if isinstance(v, (dict, list)):
                        raise InvalidParameterError(f"Field value for '{k}' cannot be a dict or list: {type(v).__name__}")

                assert out_resolved is not None
                existing_fields = reader.get_fields() or {}
                writer = pypdf.PdfWriter(clone_from=reader)
                if "/AcroForm" not in writer._root_object and not existing_fields:
                    raise InvalidParameterError(
                        f"PDF does not contain an AcroForm dictionary or interactive form fields: {pdf_file.name}"
                    )
                if reader.metadata:
                    writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

                fields_updated = [k for k in field_values if k in existing_fields]
                fields_not_found = [k for k in field_values if k not in existing_fields]

                # Handle Checkbox/Radio button widgets directly
                for p in writer.pages:
                    annots = p.get("/Annots")
                    if not annots:
                        continue
                    annots_l = annots.get_object() if hasattr(annots, "get_object") else annots
                    if not isinstance(annots_l, (list, ArrayObject)):
                        continue
                    for a_ref in annots_l:
                        a = a_ref.get_object() if hasattr(a_ref, "get_object") else a_ref
                        if not isinstance(a, (dict, DictionaryObject)):
                            continue
                        t_name = str(a.get("/T", ""))
                        if t_name in field_values:
                            val = field_values[t_name]
                            ft = str(a.get("/FT", "")).lstrip("/")
                            if ft == "Btn" or "/AS" in a:
                                is_on = bool(val) and str(val).lower() not in ("off", "0", "false", "no")
                                on_state = NameObject("/Yes")
                                if "/AP" in a and "/N" in a["/AP"]:
                                    ap_n = a["/AP"]["/N"].get_object() if hasattr(a["/AP"]["/N"], "get_object") else a["/AP"]["/N"]
                                    if isinstance(ap_n, (dict, DictionaryObject)):
                                        for st_k in ap_n.keys():
                                            if str(st_k) != "/Off":
                                                on_state = NameObject(str(st_k))
                                                break
                                chosen = on_state if is_on else NameObject("/Off")
                                a[NameObject("/V")] = chosen
                                a[NameObject("/AS")] = chosen

                # Update text form fields
                for page in writer.pages:
                    writer.update_page_form_field_values(page, field_values, auto_regenerate=False)

                if "/AcroForm" in writer._root_object:
                    writer._root_object["/AcroForm"][NameObject("/NeedAppearances")] = BooleanObject(True)

                atomic_write_pdf(writer, out_resolved)

                return {
                    "output_path": str(out_resolved),
                    "action": "fill",
                    "fields_updated": fields_updated,
                    "fields_not_found": fields_not_found,
                    "field_count": len(fields_updated),
                }

            elif act_clean == "export":
                assert data_resolved is not None
                fields_raw = reader.get_fields() or {}
                simple_dict = {k: str(v.get("/V", "")) for k, v in fields_raw.items()}

                ext = data_resolved.suffix.lower()
                if ext == ".json":
                    atomic_write_bytes(json.dumps(simple_dict, indent=2).encode("utf-8"), data_resolved)
                elif ext == ".csv":
                    csv_buf = io.StringIO()
                    cw = csv.writer(csv_buf)
                    cw.writerow(["FieldName", "Value"])
                    for k, v in simple_dict.items():
                        cw.writerow([sanitize_csv_cell(k), sanitize_csv_cell(v)])
                    atomic_write_bytes(csv_buf.getvalue().encode("utf-8"), data_resolved)
                elif ext == ".fdf":
                    # FDF format
                    fdf_lines = ["%FDF-1.2", "1 0 obj", "<< /FDF << /Fields ["]
                    for k, v in simple_dict.items():
                        fdf_lines.append(f"<< /T ({k}) /V ({v}) >>")
                    fdf_lines.extend(["] >> >>", "endobj", "trailer", "<< /Root 1 0 R >>", "%%EOF", ""])
                    atomic_write_bytes("\n".join(fdf_lines).encode("utf-8"), data_resolved)
                else:
                    # XFDF XML format
                    root = ET.Element("xfdf", {"xmlns": "http://ns.adobe.com/xfdf/"})
                    fields_el = ET.SubElement(root, "fields")
                    for k, v in simple_dict.items():
                        f_el = ET.SubElement(fields_el, "field", {"name": k})
                        v_el = ET.SubElement(f_el, "value")
                        v_el.text = v
                    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                    atomic_write_bytes(xml_bytes, data_resolved)

                return {
                    "data_path": str(data_resolved),
                    "action": "export",
                    "fields_exported": len(simple_dict),
                }

            elif act_clean == "import":
                assert data_resolved is not None
                assert out_resolved is not None

                ext = data_resolved.suffix.lower()
                imported_vals: dict[str, Any] = {}

                if ext == ".json":
                    imported_vals = json.loads(data_resolved.read_text(encoding="utf-8"))
                elif ext == ".csv":
                    with open(data_resolved, "r", encoding="utf-8") as f_csv:
                        cr = csv.reader(f_csv)
                        next(cr, None)
                        for row in cr:
                            if len(row) >= 2:
                                imported_vals[row[0].strip()] = row[1].strip()
                elif ext == ".fdf":
                    content = data_resolved.read_text(encoding="utf-8", errors="replace")
                    for match in re.finditer(r"<<\s*/T\s*\((.*?)\)\s*/V\s*(?:\((.*?)\)|/([^\s>]+))\s*>>", content):
                        fname = match.group(1)
                        fval = match.group(2) if match.group(2) is not None else match.group(3)
                        imported_vals[fname] = fval
                else:
                    # XML / XFDF - support both namespaced and un-namespaced tags (Finding H-15)
                    x_root = parse_xml_safely(data_resolved)
                    field_nodes = x_root.findall(".//{http://ns.adobe.com/xfdf/}field") + x_root.findall(".//field")
                    for f_node in field_nodes:
                        fname = f_node.get("name")
                        val_node = f_node.find("{http://ns.adobe.com/xfdf/}value")
                        if val_node is None:
                            val_node = f_node.find("value")
                        fval = val_node.text if val_node is not None and val_node.text else ""
                        if fname:
                            imported_vals[fname] = fval

                writer = pypdf.PdfWriter(clone_from=reader)
                if "/AcroForm" not in writer._root_object and not (reader.get_fields()):
                    raise InvalidParameterError(
                        f"PDF does not contain an AcroForm dictionary or interactive form fields: {pdf_file.name}"
                    )
                if reader.metadata:
                    writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

                for page in writer.pages:
                    writer.update_page_form_field_values(page, imported_vals, auto_regenerate=False)

                if "/AcroForm" in writer._root_object:
                    writer._root_object["/AcroForm"][NameObject("/NeedAppearances")] = BooleanObject(True)

                atomic_write_pdf(writer, out_resolved)

                return {
                    "output_path": str(out_resolved),
                    "data_path": str(data_resolved),
                    "action": "import",
                    "fields_imported": len(imported_vals),
                }

            raise ValueError(f"Unhandled form action: {act_clean}")

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool 10: bb_pdf_color_and_optimize
# ============================================================================

def bb_pdf_color_and_optimize(
    pdf_path: str,
    output_path: str,
    operation: str = "reduce_size",
    reduce_level: str = "Low",
    image_dpi: int = 150,
    color_start: str = "Black",
    color_end: str = "White",
    color_scale: str | bool = "grayscale",
    process_images: bool = True,
    page_range: str = "-1",
    permission_password: str | None = None,
    open_password: str | None = None,
    permission_flags: int | list[str] = 193,
    encryption_level: str = "AES256",
    drop_fonts: bool = False,
    drop_misc: bool = False,
    compress_all: bool = True,
    execution_mode: Literal["auto", "script_only", "script_engine_strict", "native_only"] = "auto",
) -> dict[str, Any]:
    """Process page colors, reduce file size, or apply PDF security permissions.

    Primary citations:
    - docs/citations/01_script_reference.md p. 7-8 (ColorProcess), p. 22-23 (ReduceFileSize), p. 26 (SetPDFSecurity)
    - docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdColorProcess, SCmdReduceFileSize, SCmdSetPDFSecurity)
    """
    tool_name = "bb_pdf_color_and_optimize"
    citations = [
        "docs/citations/01_script_reference.md p. 7-8 (ColorProcess), p. 22-23 (ReduceFileSize), p. 26 (SetPDFSecurity)",
        "docs/citations/02_binary_and_dotnet_surface.md Section 5.2 (SCmdColorProcess, SCmdReduceFileSize, SCmdSetPDFSecurity)",
    ]

    try:
        pdf_file = validate_path(pdf_path, mode="read", must_exist=True)
        check_pdf_header(pdf_file)
        out_file = validate_path(output_path, mode="write", must_exist=False)

        op_clean = operation.strip().lower()
        if op_clean not in ("reduce_size", "color_process", "set_security"):
            raise ValueError(
                f"Invalid operation '{operation}'. Must be 'reduce_size', 'color_process', or 'set_security'"
            )

        reader = pypdf.PdfReader(str(pdf_file))
        if reader.is_encrypted:
            raise EncryptedPDFError(f"PDF file is encrypted: {pdf_file}")
        total_pages = len(reader.pages)
        valid_range = validate_page_range(page_range, max_pages=total_pages)
        target_pages = _parse_target_pages(valid_range, total_pages)

        # Validate operation parameters
        if op_clean == "reduce_size":
            if reduce_level.strip().lower() not in ("low", "medium", "high"):
                raise InvalidParameterError(f"Invalid reduce_level '{reduce_level}'. Must be 'Low', 'Medium', or 'High'")
            if not math.isfinite(image_dpi) or not (10 <= image_dpi <= 2400):
                raise InvalidParameterError(f"image_dpi must be between 10 and 2400, got {image_dpi}")

        elif op_clean == "color_process":
            scale_name = "grayscale"
            if isinstance(color_scale, str):
                scale_name = color_scale.strip().lower()
            elif isinstance(color_scale, bool):
                scale_name = "grayscale" if color_scale else "modify"

            allowed_scales = {"grayscale", "black_and_white", "monochrome", "tint", "modify"}
            if scale_name not in allowed_scales:
                raise InvalidParameterError(
                    f"Invalid color_scale '{color_scale}'. Supported values: {sorted(allowed_scales)}"
                )

        elif op_clean == "set_security":
            if not permission_password or not str(permission_password).strip():
                raise InvalidParameterError("permission_password cannot be empty for 'set_security' operation")
            if open_password == "":
                raise InvalidParameterError("open_password cannot be an empty string")

            enc_clean = encryption_level.strip().upper()
            if enc_clean not in ("RC4", "AES128", "AES256"):
                raise InvalidParameterError(
                    f"Invalid encryption_level '{encryption_level}'. Must be 'RC4', 'AES128', or 'AES256'"
                )

        builder = ScriptBuilder()
        builder.open(pdf_file)

        security_mask = 193
        if op_clean == "reduce_size":
            builder.add_command("ReduceFileSize", reduce_level, image_dpi, drop_fonts, drop_misc, compress_all)
            builder.save(out_file)
            builder.close(save=False)
        elif op_clean == "color_process":
            color_scale_arg = True if scale_name in ("grayscale", "black_and_white", "monochrome") else False
            builder.add_command("ColorProcess", color_start, color_end, color_scale_arg, process_images, valid_range)
            builder.save(out_file)
            builder.close(save=False)
        elif op_clean == "set_security":
            security_mask = calculate_security_bitmask(permission_flags)
            builder.set_pdf_security(
                permission_password=permission_password,
                flags=security_mask,
                open_password=open_password,
                encryption_level=encryption_level,
            )
            builder.save(out_file)
            builder.close(save=False)

        bcs_script = builder.build()

        def native_fn() -> dict[str, Any]:
            writer = pypdf.PdfWriter(clone_from=reader)
            if reader.metadata:
                writer.add_metadata({k: str(v) for k, v in reader.metadata.items() if k.startswith("/") and v is not None})

            orig_size = pdf_file.stat().st_size

            if op_clean == "reduce_size":
                # Downsample embedded images via PIL if process_images
                if process_images:
                    red_ratio = {"low": 0.9, "medium": 0.7, "high": 0.5}.get(reduce_level.lower(), 0.7)
                    for p in writer.pages:
                        if hasattr(p, "images"):
                            for img_f in p.images:
                                try:
                                    pil_im = img_f.image
                                    nw = max(1, int(pil_im.width * red_ratio))
                                    nh = max(1, int(pil_im.height * red_ratio))
                                    if nw < pil_im.width and nh < pil_im.height:
                                        downsampled = pil_im.resize((nw, nh), Image.Resampling.LANCZOS)
                                        img_f.replace(downsampled)
                                except Exception:
                                    pass

                writer.compress_identical_objects(remove_duplicates=True, remove_unreferenced=True)
                for page in writer.pages:
                    page.compress_content_streams()

            elif op_clean == "color_process":
                is_bw = scale_name in ("black_and_white", "monochrome")
                visited_xobjects: set[int] = set()

                def _lum_from_rgb(r: float, g: float, b: float) -> float:
                    lum = 0.299 * r + 0.587 * g + 0.114 * b
                    return (1.0 if lum >= 0.5 else 0.0) if is_bw else round(lum, 4)

                def _lum_from_cmyk(c_c: float, m_c: float, y_c: float, k_c: float) -> float:
                    r = 1.0 - min(1.0, c_c * (1.0 - k_c) + k_c)
                    g = 1.0 - min(1.0, m_c * (1.0 - k_c) + k_c)
                    b = 1.0 - min(1.0, y_c * (1.0 - k_c) + k_c)
                    return _lum_from_rgb(r, g, b)

                def _rewrite_stream_ops(stream_obj: Any, wrap_graphics_state: bool = False) -> bytes:
                    cs = ContentStream(stream_obj, writer)
                    new_ops: list[tuple[list[Any], bytes]] = []
                    for operands, op in cs.operations:
                        if op == b"INLINE IMAGE":
                            new_ops.append((operands, op))
                            continue
                        if op in (b"rg", b"RG") and len(operands) == 3:
                            try:
                                val = _lum_from_rgb(float(operands[0]), float(operands[1]), float(operands[2]))
                                new_ops.append(([FloatObject(val)], b"g" if op == b"rg" else b"G"))
                                continue
                            except Exception:
                                pass
                        elif op in (b"k", b"K") and len(operands) == 4:
                            try:
                                val = _lum_from_cmyk(
                                    float(operands[0]),
                                    float(operands[1]),
                                    float(operands[2]),
                                    float(operands[3]),
                                )
                                new_ops.append(([FloatObject(val)], b"g" if op == b"k" else b"G"))
                                continue
                            except Exception:
                                pass
                        elif op in (b"g", b"G") and len(operands) == 1 and is_bw:
                            try:
                                g_val = 1.0 if float(operands[0]) >= 0.5 else 0.0
                                new_ops.append(([FloatObject(g_val)], op))
                                continue
                            except Exception:
                                pass
                        elif op in (b"cs", b"CS") and len(operands) == 1:
                            cs_name = str(operands[0])
                            if cs_name in ("/DeviceRGB", "/DeviceCMYK"):
                                new_ops.append(([NameObject("/DeviceGray")], op))
                                continue
                        elif op in (b"sc", b"scn", b"SC", b"SCN"):
                            num_ops: list[float] = []
                            for o in operands:
                                if isinstance(o, (int, float, NumberObject, FloatObject)):
                                    num_ops.append(float(o))
                            if len(num_ops) == 3 and len(num_ops) == len(operands):
                                val = _lum_from_rgb(num_ops[0], num_ops[1], num_ops[2])
                                new_ops.append(([FloatObject(val)], b"sc" if op in (b"sc", b"scn") else b"SC"))
                                continue
                            elif len(num_ops) == 4 and len(num_ops) == len(operands):
                                val = _lum_from_cmyk(num_ops[0], num_ops[1], num_ops[2], num_ops[3])
                                new_ops.append(([FloatObject(val)], b"sc" if op in (b"sc", b"scn") else b"SC"))
                                continue
                            elif len(num_ops) == 1 and len(num_ops) == len(operands) and is_bw:
                                val = 1.0 if num_ops[0] >= 0.5 else 0.0
                                new_ops.append(([FloatObject(val)], op))
                                continue
                        new_ops.append((operands, op))

                    cs.operations = new_ops
                    rewritten = cs.get_data()
                    if wrap_graphics_state:
                        gs_prefix = b"q 0 g 0 G\n" if is_bw else b"q 0.0 g 0.0 G\n"
                        return gs_prefix + rewritten + b"\nQ\n"
                    return rewritten

                def _convert_form_xobject_in_place(xobj: Any) -> DecodedStreamObject:
                    new_data = _rewrite_stream_ops(xobj, wrap_graphics_state=False)
                    new_xo = DecodedStreamObject()
                    new_xo.set_data(new_data)
                    for xo_k, xo_v in xobj.items():
                        if str(xo_k) not in ("/Filter", "/DecodeParms", "/Length"):
                            new_xo[NameObject(str(xo_k))] = xo_v
                    if "/Resources" in new_xo:
                        _process_resources_dict(new_xo["/Resources"])
                    return new_xo

                def _process_resources_dict(res_entry: Any) -> None:
                    res_obj = res_entry.get_object() if hasattr(res_entry, "get_object") else res_entry
                    if not isinstance(res_obj, (dict, DictionaryObject)) or "/XObject" not in res_obj:
                        return
                    xobj_dict = res_obj["/XObject"].get_object() if hasattr(res_obj["/XObject"], "get_object") else res_obj["/XObject"]
                    if not isinstance(xobj_dict, (dict, DictionaryObject)):
                        return
                    for xk in list(xobj_dict.keys()):
                        xref = xobj_dict[xk]
                        xobj = xref.get_object() if hasattr(xref, "get_object") else xref
                        if id(xobj) in visited_xobjects:
                            continue
                        visited_xobjects.add(id(xobj))
                        if isinstance(xobj, (dict, DictionaryObject)) and str(xobj.get("/Subtype", "")) == "/Form":
                            try:
                                new_xo = _convert_form_xobject_in_place(xobj)
                                xobj_dict[NameObject(str(xk))] = writer._add_object(new_xo)
                            except Exception:
                                pass

                for p_num in target_pages:
                    p = writer.pages[p_num - 1]
                    contents = p.get_contents()
                    if contents is not None:
                        c_data = _rewrite_stream_ops(contents, wrap_graphics_state=True)
                    else:
                        c_data = b"q 0 g 0 G\nQ\n" if is_bw else b"q 0.0 g 0.0 G\nQ\n"
                    new_stream = DecodedStreamObject()
                    new_stream.set_data(c_data)
                    p[NameObject("/Contents")] = writer._add_object(new_stream)

                    if "/Resources" in p:
                        _process_resources_dict(p["/Resources"])

                    # Convert annotation colors and /AP appearance streams
                    annots = p.get("/Annots")
                    if annots:
                        annots_l = annots.get_object() if hasattr(annots, "get_object") else annots
                        if isinstance(annots_l, (list, ArrayObject)):
                            for a_ref in annots_l:
                                a = a_ref.get_object() if hasattr(a_ref, "get_object") else a_ref
                                if isinstance(a, (dict, DictionaryObject)):
                                    for col_k in ("/C", "/IC"):
                                        if col_k in a and isinstance(a[col_k], (list, tuple, ArrayObject)) and len(a[col_k]) >= 3:
                                            val = _lum_from_rgb(float(a[col_k][0]), float(a[col_k][1]), float(a[col_k][2]))
                                            a[NameObject(col_k)] = ArrayObject([FloatObject(val), FloatObject(val), FloatObject(val)])
                                    if "/AP" in a:
                                        ap_dict = a["/AP"].get_object() if hasattr(a["/AP"], "get_object") else a["/AP"]
                                        if isinstance(ap_dict, (dict, DictionaryObject)):
                                            for ap_k in list(ap_dict.keys()):
                                                ap_val = ap_dict[ap_k].get_object() if hasattr(ap_dict[ap_k], "get_object") else ap_dict[ap_k]
                                                if hasattr(ap_val, "get_data"):
                                                    try:
                                                        new_ap = _convert_form_xobject_in_place(ap_val)
                                                        ap_dict[NameObject(str(ap_k))] = writer._add_object(new_ap)
                                                    except Exception:
                                                        pass

                    # Convert images on page
                    if process_images and hasattr(p, "images"):
                        target_mode = "1" if is_bw else "L"
                        for img_f in p.images:
                            try:
                                pil_im = img_f.image
                                converted = pil_im.convert(target_mode)
                                img_f.replace(converted)
                            except Exception:
                                pass

            elif op_clean == "set_security":
                enc_map = {
                    "RC4": "RC4-128",
                    "AES128": "AES-128",
                    "AES256": "AES-256",
                }
                enc_alg = enc_map.get(encryption_level.strip().upper(), "AES-256")

                # Map Bluebeam security mask bits to ISO 32000-1 Table 22 /P bits
                # Initialize with reserved bits 7, 8, and 13-32 set to 1 (-3904 / 0xFFFFF0C0 signed; F-06)
                pdf_perm = -3904
                if security_mask & 1:
                    pdf_perm |= (1 << 2) | (1 << 11)  # Print
                elif security_mask & 2:
                    pdf_perm |= (1 << 2)  # Print low
                if security_mask & 4:
                    pdf_perm |= (1 << 8)  # Fill forms
                if security_mask & 8:
                    pdf_perm |= (1 << 5) | (1 << 8)  # Edit markups
                if security_mask & 16:
                    pdf_perm |= (1 << 3)  # Edit document
                if security_mask & 32:
                    pdf_perm |= (1 << 10)  # Page manipulation
                if security_mask & 64:
                    pdf_perm |= (1 << 4)  # Copy content
                if security_mask & 128:
                    pdf_perm |= (1 << 9)  # Accessibility

                writer.encrypt(
                    user_password=open_password or "",
                    owner_password=permission_password,
                    permissions_flag=pdf_perm,
                    algorithm=enc_alg,
                )

            atomic_write_pdf(writer, out_file)
            new_size = out_file.stat().st_size

            # pypdf re-encodes images losslessly, so on JPEG-heavy drawings the "reduced" file can be
            # larger than the source. A size reduction must never grow the file: ship the source bytes instead.
            size_note: str | None = None
            if op_clean == "reduce_size" and new_size >= orig_size:
                if out_file.resolve() != pdf_file.resolve():
                    tmp_copy = out_file.with_name(out_file.name + ".tmp-copy")
                    shutil.copyfile(pdf_file, tmp_copy)
                    os.replace(tmp_copy, out_file)
                new_size = out_file.stat().st_size
                size_note = (
                    "Native fallback produced a larger file than the source, so the output is an unchanged copy; "
                    "image downsampling of JPEG-encoded drawings requires ScriptEngine.exe."
                )

            result_data: dict[str, Any] = {
                "output_path": str(out_file),
                "operation": op_clean,
                "original_size": orig_size,
                "optimized_size": new_size,
                "page_count": len(writer.pages),
                "permission_flags": security_mask if op_clean == "set_security" else None,
            }
            if size_note:
                result_data["size_reduced"] = False
                result_data["fidelity_note"] = size_note
            elif op_clean == "reduce_size":
                result_data["size_reduced"] = True
            if op_clean == "color_process":
                result_data["fidelity_note"] = (
                    "Native fallback converts DeviceRGB, DeviceCMYK, and cs/sc/scn color operators "
                    "across page content streams, Form XObjects, annotations, and embedded images; "
                    "ICCBased, Separation, DeviceN, and Pattern color spaces require ScriptEngine.exe."
                )
            return result_data

        return execute_dual_engine(
            bcs_script=bcs_script,
            native_fn=native_fn,
            execution_mode=execution_mode,
            tool_name=tool_name,
            citations=citations,
        )

    except (BluebeamMCPError, FileNotFoundError, ValueError, Exception) as err:
        return format_error_envelope(err, tool_name=tool_name)


# ============================================================================
# Tool Registration Helper
# ============================================================================

def register_markup_tools(mcp: Any) -> None:
    """Register all 10 markup tools on a FastMCP instance.

    Citation: docs/ARCHITECTURE.md Section 6.2 (Category 2: Markup, Annotation, Flattening and Forms).
    """
    mcp.tool()(bb_markup_list)
    mcp.tool()(bb_markup_add)
    mcp.tool()(bb_markup_update)
    mcp.tool()(bb_markup_delete)
    mcp.tool()(bb_markup_flatten)
    mcp.tool()(bb_pdf_stamp)
    mcp.tool()(bb_markup_export_bax)
    mcp.tool()(bb_markup_import_bax)
    mcp.tool()(bb_form_inspect_and_fill)
    mcp.tool()(bb_pdf_color_and_optimize)


__all__ = [
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
]
