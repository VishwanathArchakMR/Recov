"""
Archive Recovery Benchmark & Evaluation Runner for RECOV.

Runs the RECOV pipeline against reference archive evidence images:
- evidence/reference_archives/L1_Archive.dd
- evidence/reference_archives/L2_Archive.dd
- evidence/reference_archives/L4_Archive.dd
- evidence/reference_archives/L5_Archive.dd

Measures and reports:
- Evidence SHA-256 & file size
- Carved fragments count & types
- Archive candidate reconstruction outcomes (complete, partial, invalid)
- Real parser / decompression validation count
- Nested and braided structural candidates
- Runtime (seconds) and memory metrics

Ground truth isolation:
Operates purely from evidence image bytes and parser validation.
Never uses ground truth in production reconstruction logic.
"""

import hashlib
import json
import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.orchestrator import run_full_pipeline
from recovery.archive_adapter import (
    ARCHIVE_ADAPTERS,
    ArchiveRecoveryState,
    detect_archive_format,
    get_archive_adapter,
)


def run_single_archive_benchmark(image_path: str) -> Dict[str, Any]:
    """Execute complete benchmark for a single archive evidence image."""
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Archive evidence not found: {path}")

    # 1. Image metadata
    with open(path, "rb") as f:
        raw_bytes = f.read()
    image_size = len(raw_bytes)
    evidence_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # 2. Measure pipeline execution
    tracemalloc.start()
    t_start = time.perf_counter()

    pipeline_result = run_full_pipeline(str(path))

    t_end = time.perf_counter()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    runtime_sec = round(t_end - t_start, 3)
    peak_mem_mb = round(peak_mem / (1024 * 1024), 2)

    # 3. Analyze fragments & archive candidates
    fragments = pipeline_result.fragments
    reconstructed_files = pipeline_result.reconstructed_files
    ranked_candidates = pipeline_result.ranked_results.files if pipeline_result.ranked_results else []

    archive_types = {"zip", "tar", "7z", "rar", "wim", "gz", "gzip", "bz2"}
    carved_archive_frags = [f for f in fragments if (f.type_hint or "").lower() in archive_types]
    archive_types_detected = sorted(list({(f.type_hint or "").lower() for f in carved_archive_frags}))

    archive_reconstructions = [
        r for r in reconstructed_files
        if (r.file_type or "").lower() in archive_types
    ]

    complete_candidates = []
    partial_candidates = []
    structurally_valid = []
    structurally_invalid = []
    parser_validated = []

    for r in archive_reconstructions:
        if r.is_validated_recovery:
            parser_validated.append(r.id)
            if r.structural_validity >= 1.0:
                complete_candidates.append(r.id)
                structurally_valid.append(r.id)
            else:
                partial_candidates.append(r.id)
                structurally_valid.append(r.id)
        else:
            structurally_invalid.append(r.id)

    # 4. Check for nested / braided candidate patterns
    nested_candidates = []
    braided_candidates = []
    for r in archive_reconstructions:
        if len(r.fragment_ids) > 1:
            # Multi-fragment archive
            offsets = r.source_offsets
            is_sequential = all(offsets[i] <= offsets[i+1] for i in range(len(offsets)-1))
            if not is_sequential:
                braided_candidates.append(r.id)
        if "nested" in (r.parser_message or "").lower():
            nested_candidates.append(r.id)

    report: Dict[str, Any] = {
        "evidence_image": str(path),
        "evidence_sha256": evidence_sha256,
        "image_size_bytes": image_size,
        "image_size_mb": round(image_size / (1024 * 1024), 2),
        "runtime_seconds": runtime_sec,
        "peak_memory_mb": peak_mem_mb,
        "carved_fragments_total": len(fragments),
        "carved_archive_fragments": len(carved_archive_frags),
        "archive_types_detected": archive_types_detected,
        "reconstruction_attempts_total": len(reconstructed_files),
        "archive_reconstructions_total": len(archive_reconstructions),
        "complete_candidates_count": len(complete_candidates),
        "partial_candidates_count": len(partial_candidates),
        "structurally_valid_count": len(structurally_valid),
        "structurally_invalid_count": len(structurally_invalid),
        "parser_validated_count": len(parser_validated),
        "nested_candidates_count": len(nested_candidates),
        "braided_candidates_count": len(braided_candidates),
        "candidate_details": [
            {
                "id": r.id,
                "file_type": r.file_type,
                "fragment_count": r.fragment_count,
                "recovered_bytes": r.recovered_bytes,
                "structural_validity": r.structural_validity,
                "is_validated": r.is_validated_recovery,
                "parser_message": r.parser_message,
            }
            for r in archive_reconstructions
        ],
    }

    return report


def run_all_benchmarks(output_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    images = [
        "evidence/reference_archives/L1_Archive.dd",
        "evidence/reference_archives/L2_Archive.dd",
        "evidence/reference_archives/L4_Archive.dd",
        "evidence/reference_archives/L5_Archive.dd",
    ]

    results = []
    print("=" * 70)
    print("RECOV — ARCHIVE RECOVERY ENGINE BENCHMARK RUNNER")
    print("=" * 70)

    for img in images:
        if os.path.exists(img):
            print(f"\nRunning benchmark for: {img}")
            res = run_single_archive_benchmark(img)
            results.append(res)
            print(f"  SHA-256: {res['evidence_sha256']}")
            print(f"  Size: {res['image_size_mb']} MB, Runtime: {res['runtime_seconds']}s, Peak Mem: {res['peak_memory_mb']} MB")
            print(f"  Carved Fragments: {res['carved_fragments_total']} (Archive: {res['carved_archive_fragments']})")
            print(f"  Detected Types: {res['archive_types_detected']}")
            print(f"  Archive Candidates: {res['archive_reconstructions_total']} (Valid: {res['structurally_valid_count']}, Validated: {res['parser_validated_count']}, Invalid: {res['structurally_invalid_count']})")
        else:
            print(f"Skipping missing image: {img}")

    out_path = output_file or Path("results/archive_benchmark_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved benchmark results to {out_path}")
    print("=" * 70)
    return results


if __name__ == "__main__":
    run_all_benchmarks()
