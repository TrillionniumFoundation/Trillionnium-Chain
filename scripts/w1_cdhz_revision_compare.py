#!/usr/bin/env python3
"""Reproduce byte-pinned CDHZ January/March revision comparison.

Requires PyMuPDF and Poppler pdftotext. The renderer version is recorded,
and both versions are rendered by the same process. Example:
  python3 scripts/w1_cdhz_revision_compare.py january.pdf march.pdf --output manifest.json

This is a manuscript revision check, not independent proof certification.

Inputs are the two official archived PDFs, not titles or search-index records.
Outputs are derived metadata and hashes; full manuscript bytes are not emitted.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import fitz

EXPECTED = {
    "january": {"revision_id": "20260101:061307", "url": "https://eprint.iacr.org/archive/2025/2166/1767247987.pdf", "sha256": "215a62b9a1b5144c89ae103aaabaf6049eab23f7ccb23130bc7d65d597c1eac9", "bytes": 927381},
    "march": {"revision_id": "20260302:160701", "url": "https://eprint.iacr.org/archive/2025/2166/1772467621.pdf", "sha256": "2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30", "bytes": 927435},
}
THEOREMS = [
    ("1 (informal)", 5), ("2 (informal)", 5), ("3 (informal)", 6),
    ("5.4", 31), ("6.9", 44), ("6.10", 46), ("8.3", 53),
    ("8.4", 53), ("10.6", 72), ("11.3", 78), ("A.1", 98),
]
def sha(data):
    return hashlib.sha256(data).hexdigest()
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("january", type=Path)
    ap.add_argument("march", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    docs = {}
    captured = {}
    if args.output.resolve() in {args.january.resolve(), args.march.resolve()}:
        raise SystemExit("The manifest output must not replace an input PDF")
    for name in EXPECTED:
        path = getattr(args, name)
        expected = EXPECTED[name]
        with path.open("rb") as stream:
            data = stream.read(expected["bytes"] + 1)
        if len(data) != expected["bytes"] or sha(data) != expected["sha256"]:
            raise SystemExit(f"Unpinned {name} input; no comparison made")
        captured[name] = data
        # Analyze the same captured bytes whose digest was checked, even if
        # the original input path subsequently changes.
        docs[name] = fitz.open(stream=data, filetype="pdf")
        if len(docs[name]) != 102:
            raise SystemExit("Unexpected page count")
    pages = []
    for i in range(102):
        a, b = docs["january"][i], docs["march"][i]
        at, bt = a.get_text(), b.get_text()
        ax = a.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), colorspace=fitz.csRGB, alpha=False)
        bx = b.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), colorspace=fitz.csRGB, alpha=False)
        pages.append({
            "pdf_page": i + 1,
            "text_equal": at == bt,
            "rgb_pixels_equal": (ax.width, ax.height, ax.samples) == (bx.width, bx.height, bx.samples),
            "january_dimensions": [ax.width, ax.height],
            "march_dimensions": [bx.width, bx.height],
            "january_text_sha256": sha(at.encode()),
            "march_text_sha256": sha(bt.encode()),
            "january_rgb_sha256": sha(ax.samples),
            "march_rgb_sha256": sha(bx.samples),
        })
    text_diffs = {}
    poppler_version = subprocess.run(
        ["pdftotext", "-v"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.decode("utf-8").splitlines()[0]
    # Poppler reads private copies of the verified byte snapshots, never a
    # potentially changed original path. No machine paths enter the manifest.
    with tempfile.TemporaryDirectory(prefix="cdhz-revision-") as directory:
        snapshots = {}
        for name, data in captured.items():
            snapshots[name] = Path(directory) / (name + ".pdf")
            snapshots[name].write_bytes(data)
        for mode in ("layout", "raw"):
            texts = {
                name: subprocess.run(
                    ["pdftotext", "-" + mode, str(snapshots[name]), "-"],
                    check=True, stdout=subprocess.PIPE,
                ).stdout.decode("utf-8")
                for name in EXPECTED
            }
            delta = "".join(difflib.unified_diff(
                texts["january"].splitlines(True),
                texts["march"].splitlines(True),
                fromfile="January", tofile="March",
            ))
            text_diffs[mode] = {
                "january_sha256": sha(texts["january"].encode()),
                "march_sha256": sha(texts["march"].encode()),
                "unified_diff_sha256": sha(delta.encode()),
                "unified_diff": delta,
            }
    result = {
        "schema_version": 1,
        "observation_date": "2026-11-08",
        "source": {"title": "How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions", "authors": ["Alessandro Chiesa", "Zijing Di", "Zihan Hu", "Yuxi Zheng"], "history_url": "https://eprint.iacr.org/archive/versions/2025/2166", "pdfs": EXPECTED},
        "render": {"library": "PyMuPDF", "version": fitz.VersionBind, "scale": 1.5, "dpi": 108, "colorspace": "RGB", "alpha": False},
        "page_count": 102,
        "text_different_pages": [x["pdf_page"] for x in pages if not x["text_equal"]],
        "render_different_pages": [x["pdf_page"] for x in pages if not x["rgb_pixels_equal"]],
        "pages": pages,
        "theorem_start_pages": [{"identifier": name, "start_page": page, "start_page_text_equal": pages[page-1]["text_equal"], "start_page_render_equal": pages[page-1]["rgb_pixels_equal"]} for name,page in THEOREMS],
        "text_extractor": {"program": "pdftotext", "version": poppler_version},
        "whole_document_poppler_diffs": text_diffs,
        "claims": {"version_consistency_review": True, "independent_proof_correctness_certification": False, "implementation_security_certification": False},
    }
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
    print(json.dumps({"output": str(args.output), "sha256": sha(args.output.read_bytes()), "text_different_pages": result["text_different_pages"], "render_different_pages": result["render_different_pages"]}))
if __name__ == "__main__":
    main()
