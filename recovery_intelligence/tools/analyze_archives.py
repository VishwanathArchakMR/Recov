"""
Offline Archive Analysis Tool for RECOV.

Inspects raw/dd disk images without modifying them, extracts:
- image size and SHA-256
- archive signatures and candidates
- structural regions and headers
- fragmentation boundaries and candidate block sizes
- member metadata and checksums

Generates a machine-readable JSON analysis report.
"""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Union

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recovery.archive_adapter import (
    ARCHIVE_ADAPTERS,
    detect_archive_format,
    get_archive_adapter,
)


def analyze_archive_image(image_path: Union[str, Path]) -> Dict[str, Any]:
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    with open(path, "rb") as f:
        data = f.read()

    size = len(data)
    sha256 = hashlib.sha256(data).hexdigest()

    report: Dict[str, Any] = {
        "image_file": str(path),
        "image_size_bytes": size,
        "image_sha256": sha256,
        "detected_archives": [],
        "sector_aligned_structures": [],
        "summary": {},
    }

    # Scan for archive headers on 512-byte boundaries
    candidates = []
    for offset in range(0, size, 512):
        fmt = detect_archive_format(data, offset)
        if fmt:
            adapter = get_archive_adapter(fmt)
            if adapter:
                struct_meta = adapter.inspect_structure(data, offset)
                candidates.append({
                    "format": fmt,
                    "offset": offset,
                    "is_container": adapter.is_container(),
                    "metadata": struct_meta,
                })

    report["detected_archives"] = candidates
    report["summary"] = {
        "candidate_count": len(candidates),
        "formats_found": list({c["format"] for c in candidates}),
    }

    return report


def main():
    target_files = [
        "evidence/reference_archives/L1_Archive.dd",
        "evidence/reference_archives/L2_Archive.dd",
        "evidence/reference_archives/L4_Archive.dd",
        "evidence/reference_archives/L5_Archive.dd",
    ]
    if len(sys.argv) > 1:
        target_files = sys.argv[1:]

    all_reports = []
    for tf in target_files:
        if os.path.exists(tf):
            rep = analyze_archive_image(tf)
            all_reports.append(rep)
            print(f"Analyzed {tf}: found {rep['summary']['candidate_count']} candidate(s) - formats: {rep['summary']['formats_found']}")

    out_file = Path("results/archive_analysis_report.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(all_reports, f, indent=2)
    print(f"Wrote machine-readable analysis report to {out_file}")


if __name__ == "__main__":
    from typing import Union
    main()
