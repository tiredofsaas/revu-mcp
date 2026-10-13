"""Pytest configuration and deterministic fixtures for Bluebeam Revu 21 MCP.

All fixture output is strictly confined to tests/tmp/.

Primary citations:
- docs/citations/01_script_reference.md Section 1, Section 2
- - docs/citations/03_data_formats_and_markups.md Section 2, Section 3, Section 4, Section 5
- docs/ARCHITECTURE.md Section 2.2 (Project Layout)
- docs/TEST_AND_SECURITY_MATRIX.md Section 2 (Test Tiers)
"""

from __future__ import annotations

# Site-specific protected roots are environment-driven; tests use a neutral placeholder vault path.
import os as _os
_os.environ.setdefault("BLUEBEAM_MCP_FORBIDDEN_ROOTS", r"E:\ProtectedVault;C:\Program Files\SOLIDWORKS Corp")

import os
from pathlib import Path
import sys

import pytest

# Ensure project root and src/ are on sys.path for test discovery
ROOT_PATH = Path(__file__).resolve().parent.parent
SRC_PATH = ROOT_PATH / "src"
for _p in (str(ROOT_PATH), str(SRC_PATH)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tests.fixture_factory import (
    FIXTURES_DIR,
    create_annotated_pdf,
    create_form_pdf,
    create_sample_bax,
    create_sample_bpx,
    create_sample_btx,
    create_sample_pdf,
)

BASE_TMP_DIR = Path(__file__).resolve().parent / "tmp"
SCRATCH_DIR = BASE_TMP_DIR


def pytest_sessionfinish(session: pytest.Session, exitstatus: int | pytest.ExitCode) -> None:
    """Clean up all files and subdirectories in tests/tmp after pytest completes."""
    import gc
    import shutil
    import time

    gc.collect()
    time.sleep(0.05)
    if BASE_TMP_DIR.exists():
        for item in list(BASE_TMP_DIR.iterdir()):
            for _ in range(3):
                try:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        item.unlink(missing_ok=True)
                    break
                except Exception:
                    gc.collect()
                    time.sleep(0.05)


@pytest.fixture(scope="session")
def scratch_dir() -> Path:
    """Provide scratch directory confined strictly to tests/tmp/."""
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    return SCRATCH_DIR


@pytest.fixture
def sample_pdf(scratch_dir: Path) -> Path:
    """Provide a valid 3-page sample PDF drawing fixture."""
    pdf_path = FIXTURES_DIR / "sample_drawing.pdf"
    return create_sample_pdf(pdf_path, num_pages=3, title="Sample Engineering Plan")


@pytest.fixture
def form_pdf(scratch_dir: Path) -> Path:
    """Provide a valid PDF form with AcroForm text fields and checkboxes."""
    pdf_path = FIXTURES_DIR / "sample_form.pdf"
    return create_form_pdf(pdf_path)


@pytest.fixture
def annotated_pdf(scratch_dir: Path) -> Path:
    """Provide a valid PDF with FreeText and Square /Annots annotations."""
    pdf_path = FIXTURES_DIR / "sample_annotated.pdf"
    return create_annotated_pdf(pdf_path)


@pytest.fixture
def sample_btx(scratch_dir: Path) -> Path:
    """Provide a valid Bluebeam Tool Set (.btx) XML fixture."""
    btx_path = FIXTURES_DIR / "sample_toolset.btx"
    return create_sample_btx(btx_path)


@pytest.fixture
def sample_bpx(scratch_dir: Path) -> Path:
    """Provide a valid Bluebeam Profile (.bpx) XML fixture."""
    bpx_path = FIXTURES_DIR / "sample_profile.bpx"
    return create_sample_bpx(bpx_path)


@pytest.fixture
def sample_bax(scratch_dir: Path) -> Path:
    """Provide a valid Bluebeam Annotations XML export (.bax) fixture."""
    bax_path = FIXTURES_DIR / "sample_markups.bax"
    return create_sample_bax(bax_path)
