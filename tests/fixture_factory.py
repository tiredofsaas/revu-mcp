"""Deterministic test fixture factory for Bluebeam Revu 21 MCP.

Generates valid PDFs, forms, annotations, .btx tool sets, .bpx profiles,
.bax markup exports, and corrupt PDF edge cases for unit and integration testing.

All generated files are confined to tests/tmp/fixtures/.

Primary citations:
- docs/citations/01_script_reference.md Section 1, Section 2
- docs/citations/02_binary_and_dotnet_surface.md Section 7.2
- docs/citations/03_data_formats_and_markups.md Section 2 (BTX), Section 3 (BPX),
  Section 4 (Stamps/Annots), Section 5 (BAX)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Test Tiers), Section 3 (Edge Cases)
"""

from __future__ import annotations

import io
from pathlib import Path
import zlib

import pypdf
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    TextStringObject,
)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

FIXTURES_DIR = Path(__file__).resolve().parent / "tmp" / "fixtures"


def create_sample_pdf(
    path: Path,
    num_pages: int = 3,
    title: str = "Sample Drawing",
) -> Path:
    """Create a valid multi-page PDF document using reportlab and pypdf.

    Primary citations:
    - docs/citations/01_script_reference.md p. 18-20 (New, PageCount)
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.1
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(path), pagesize=letter)
    for i in range(1, num_pages + 1):
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 720, f"{title} - Page {i}")
        c.setFont("Helvetica", 11)
        c.drawString(100, 690, f"Automated test fixture page {i} of {num_pages}")
        c.drawString(100, 670, "Bluebeam Revu 21 MCP test suite")
        # Draw a border box simulating an architectural drawing sheet
        c.setLineWidth(1.5)
        c.rect(50, 50, 512, 692)
        c.showPage()
    c.save()
    return path


def create_form_pdf(path: Path) -> Path:
    """Create a PDF document containing AcroForm text fields and checkboxes.

    Primary citations:
    - docs/citations/01_script_reference.md p. 12-13 (FormExport, FormImport)
    - docs/citations/03_data_formats_and_markups.md Section 5
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 730, "Bluebeam Form Test Document")
    c.setFont("Helvetica", 11)

    c.drawString(100, 680, "Project Name:")
    c.acroForm.textfield(
        name="project_name",
        value="Hospital Expansion Wing B",
        x=220,
        y=670,
        width=250,
        height=20,
        fontSize=10,
    )

    c.drawString(100, 630, "Contractor:")
    c.acroForm.textfield(
        name="contractor",
        value="Acme General Contracting",
        x=220,
        y=620,
        width=250,
        height=20,
        fontSize=10,
    )

    c.drawString(100, 580, "Inspection Passed:")
    c.acroForm.checkbox(
        name="inspection_passed",
        checked=True,
        x=220,
        y=575,
        size=16,
    )

    c.showPage()
    c.save()
    return path


def create_annotated_pdf(path: Path) -> Path:
    """Create a PDF with /Annots FreeText and Square markups.

    Sets /Subj, /T (Author), /Contents, /NM (ID), /Rect, and /C (Color).

    Primary citations:
    - docs/citations/03_data_formats_and_markups.md Section 4 (Page Annotation Dictionary)
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Generate base page in memory
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, 720, "Annotated Drawing Sheet")
    c.drawString(100, 690, "Sheet with FreeText and Square annotations")
    c.showPage()
    c.save()
    buf.seek(0)

    reader = pypdf.PdfReader(buf)
    writer = pypdf.PdfWriter()
    page = writer.add_page(reader.pages[0])

    # Annotation 1: FreeText callout
    freetext_annot = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/FreeText"),
        NameObject("/Rect"): ArrayObject([
            FloatObject(100.0), FloatObject(500.0),
            FloatObject(320.0), FloatObject(550.0),
        ]),
        NameObject("/Contents"): TextStringObject("Verify duct clearance before install"),
        NameObject("/Subj"): TextStringObject("Text Box"),
        NameObject("/T"): TextStringObject("Lead Mechanical Engineer"),
        NameObject("/NM"): TextStringObject("BB-ANNOT-FREETEXT-001"),
        NameObject("/C"): ArrayObject([FloatObject(1.0), FloatObject(0.0), FloatObject(0.0)]),
    })

    # Annotation 2: Square inspection box
    square_annot = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Square"),
        NameObject("/Rect"): ArrayObject([
            FloatObject(150.0), FloatObject(300.0),
            FloatObject(280.0), FloatObject(420.0),
        ]),
        NameObject("/Contents"): TextStringObject("Shaft opening dimension critical"),
        NameObject("/Subj"): TextStringObject("Square"),
        NameObject("/T"): TextStringObject("Structural Reviewer"),
        NameObject("/NM"): TextStringObject("BB-ANNOT-SQUARE-002"),
        NameObject("/C"): ArrayObject([FloatObject(0.0), FloatObject(0.2), FloatObject(0.8)]),
    })

    page[NameObject("/Annots")] = ArrayObject([freetext_annot, square_annot])

    with open(path, "wb") as f:
        writer.write(f)

    return path


def create_sample_btx(path: Path) -> Path:
    """Create a valid Bluebeam Tool Set (.btx) XML file.

    Features <BluebeamRevuToolSet Version="1"> and zlib-compressed hex <Raw> payload.

    Primary citations:
    - docs/citations/03_data_formats_and_markups.md Section 2 (Tool Set Files Schema)
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Encode property dictionary payload and compress with zlib
    raw_payload = (
        b"Type=Bluebeam.PDF.Annotations.AnnotationFreeText\x00"
        b"Subject=Review Callout\x00"
        b"Author=Test Author\x00"
        b"Color=#FF0000\x00"
        b"LineWidth=1.5\x00"
    )
    compressed_hex = zlib.compress(raw_payload).hex()

    title_hex = zlib.compress(b"Sample Engineering Tools").hex()

    xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<BluebeamRevuToolSet Version="1">
  <Title>{title_hex}</Title>
  <ToolChestItem Version="2">
    <Name>ENG_CALLOUT_01</Name>
    <Type>Bluebeam.PDF.Annotations.AnnotationFreeText</Type>
    <Raw>{compressed_hex}</Raw>
    <X>100.5</X>
    <Y>250.0</Y>
    <Index>0</Index>
    <Mode>properties</Mode>
  </ToolChestItem>
</BluebeamRevuToolSet>
"""
    path.write_text(xml_content, encoding="utf-8")
    return path


def create_sample_bpx(path: Path) -> Path:
    """Create a valid Bluebeam Profile (.bpx) XML file.

    Features <RevuProfile Version="1"> and <Record Key="MarkupList"> with custom columns.

    Primary citations:
    - docs/citations/03_data_formats_and_markups.md Section 3 (Profile Files Schema)
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<RevuProfile Version="1" Name="Engineering Review Profile">
  <Record Key="MarkupList">
    <ActiveColumn>0</ActiveColumn>
    <Columns>
      <Column Key="Subject">
        <Width>198</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="Page">
        <Width>100</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="Status">
        <Width>108</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="Author">
        <Width>140</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="UserDefined0">
        <Width>136</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
    </Columns>
  </Record>
</RevuProfile>
"""
    path.write_text(xml_content, encoding="utf-8")
    return path


def create_sample_bax(path: Path) -> Path:
    """Create a valid Bluebeam Annotations XML export file (.bax).

    Primary citations:
    - docs/citations/03_data_formats_and_markups.md Section 5 (Markup Export/Import Formats)
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.2
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<MarkupList Version="1">
  <Annotation>
    <Subj>Text Box</Subj>
    <Author>Test Author</Author>
    <Contents>Field Inspection Note - Section A</Contents>
    <Page>1</Page>
    <Rect X="120" Y="450" Width="180" Height="40" />
    <Color>#0000FF</Color>
    <DateModified>2026-10-12T12:00:00Z</DateModified>
  </Annotation>
  <Annotation>
    <Subj>Square</Subj>
    <Author>Structural Reviewer</Author>
    <Contents>Coordinate Check Area</Contents>
    <Page>1</Page>
    <Rect X="200" Y="300" Width="100" Height="100" />
    <Color>#FF0000</Color>
    <DateModified>2026-10-12T12:05:00Z</DateModified>
  </Annotation>
</MarkupList>
"""
    path.write_text(xml_content, encoding="utf-8")
    return path


def create_zero_byte_pdf(path: Path) -> Path:
    """Create an empty 0-byte file simulating a truncated or interrupted download.

    Primary citations:
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.3 (Vector T3-01)
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return path


def create_corrupt_header_pdf(path: Path) -> Path:
    """Create a file with an invalid non-PDF header.

    Primary citations:
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.3 (Vector T3-02)
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"NOT_A_VALID_PDF_HEADER_DATA_12345\n%%EOF\n")
    return path


def create_truncated_pdf(path: Path) -> Path:
    """Create a PDF file with valid header but truncated body missing EOF and xref.

    Primary citations:
    - docs/TEST_AND_SECURITY_MATRIX.md Section 2.3 (Vector T3-03)
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    truncated_bytes = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
    )
    path.write_bytes(truncated_bytes)
    return path


__all__ = [
    "FIXTURES_DIR",
    "create_sample_pdf",
    "create_form_pdf",
    "create_annotated_pdf",
    "create_sample_btx",
    "create_sample_bpx",
    "create_sample_bax",
    "create_zero_byte_pdf",
    "create_corrupt_header_pdf",
    "create_truncated_pdf",
]
