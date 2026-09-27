import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter

from models.cluster import FragmentCluster
from models.fragment import Fragment
from models.reconstructed_file import ReconstructedFile
from config.settings import settings
from .validation import validate_reconstruction
from .text_reconstruction import read_fragment_bytes, compute_gap_information


EXTENSION_MAP = {
    "jpeg": ".jpg",
    "jpg": ".jpg",
    "png": ".png",
    "gif": ".gif",
    "bmp": ".bmp",
    "tiff": ".tiff",
    "tif": ".tiff",
    "pcx": ".pcx",
    "pdf": ".pdf",
    "docx": ".docx",
    "xlsx": ".xlsx",
    "pptx": ".pptx",
    "zip": ".zip",
    "tar": ".tar",
    "7z": ".7z",
    "rar": ".rar",
    "wim": ".wim",
    "gz": ".gz",
    "gzip": ".gz",
    "bz2": ".bz2",
    "sqlite": ".sqlite",
    "sqlite3": ".sqlite",
    "db": ".sqlite",
    "wav": ".wav",
    "text": ".txt",
    "txt": ".txt",
    "raw": ".bin",
    "unknown": ".bin",
}


def infer_cluster_file_type(cluster: FragmentCluster, fragments: List[Fragment]) -> str:
    """Infer candidate file type from cluster inferred_type or fragment type hints."""
    if cluster.inferred_type and cluster.inferred_type.lower() not in ("unknown", "raw"):
        return cluster.inferred_type.lower()
    
    # Check fragment type hints
    hints = [f.type_hint.lower() for f in fragments if f.type_hint and f.type_hint.lower() not in ("unknown", "raw")]
    if hints:
        most_common = Counter(hints).most_common(1)[0][0]
        return most_common
    
    # Check first fragment magic bytes
    if fragments:
        first_frag = min(fragments, key=lambda f: (f.offset, f.id))
        raw_b = read_fragment_bytes(first_frag)
        if raw_b.startswith(b"\xff\xd8"):
            return "jpeg"
        elif raw_b.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        elif raw_b.startswith(b"GIF87a") or raw_b.startswith(b"GIF89a"):
            return "gif"
        elif raw_b.startswith(b"BM"):
            return "bmp"
        elif raw_b.startswith(b"II\x2a\x00") or raw_b.startswith(b"MM\x00\x2a"):
            return "tiff"
        elif len(raw_b) >= 1 and raw_b[0] == 0x0A and len(raw_b) >= 4 and raw_b[1] in (0, 2, 3, 4, 5):
            return "pcx"
        elif raw_b.startswith(b"%PDF-"):
            return "pdf"
        elif raw_b.startswith(b"PK\x03\x04"):
            return "zip"
        elif raw_b.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7z"
        elif raw_b.startswith(b"Rar!\x1a\x07"):
            return "rar"
        elif raw_b.startswith(b"MSWIM\x00\x00\x00"):
            return "wim"
        elif raw_b.startswith(b"BZh"):
            return "bz2"
        elif raw_b.startswith(b"\x1f\x8b"):
            return "gz"
        elif len(raw_b) >= 512 and b"ustar" in raw_b[257:265]:
            return "tar"
        elif raw_b.startswith(b"SQLite format 3\x00"):
            return "sqlite"
        elif len(raw_b) >= 12 and raw_b[:4] == b"RIFF" and raw_b[8:12] == b"WAVE":
            return "wav"
    
    return "unknown"


def reconstruct_structured_file(
    cluster: FragmentCluster,
    fragments: List[Fragment],
    output_dir: Optional[Path] = None,
) -> ReconstructedFile:
    """
    Reconstruct a candidate structured binary or document file from a fragment cluster.
    
    Orders fragment members deterministically by evidence offset, computes union coverage
    and gap metadata, assembles candidate bytes, writes the candidate to disk, and
    validates with the corresponding real parser.
    """
    # 1. Determine candidate file type
    file_type = infer_cluster_file_type(cluster, fragments)
    
    # If archive type, delegate to format-aware archive reconstructor
    archive_types = {"zip", "tar", "7z", "rar", "wim", "gz", "gzip", "bz2"}
    if file_type in archive_types:
        from .archive_reconstruction import reconstruct_archive_cluster
        return reconstruct_archive_cluster(cluster, fragments, output_dir=output_dir)

    candidate_id = f"recon_{cluster.cluster_id}"
    out_dir = output_dir or settings.RECOVERED_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if not fragments:
        return ReconstructedFile(
            id=candidate_id,
            candidate_id=candidate_id,
            cluster_id=cluster.cluster_id,
            file_type=cluster.inferred_type or "unknown",
            fragment_ids=[],
            gap_information={"has_gaps": False, "gap_count": 0, "total_gap_bytes": 0, "gaps": []},
            structural_validity=0.0,
            status="cluster_only",
            parser_message="No member fragments available in cluster for reconstruction",
            ambiguous=False,
            is_validated_recovery=False,
            recovery_status="UNRECOVERABLE",
            recovery_state="UNRECOVERABLE",
        )
    ext = EXTENSION_MAP.get(file_type, ".bin")
    candidate_path = out_dir / f"{candidate_id}{ext}"

    # 2. Order fragment members deterministically by evidence offset (tie-break by ID)
    ordered_fragments = sorted(fragments, key=lambda f: (f.offset, f.id))

    # 3. Read bytes in read-only mode & compute union coverage & gap information
    gap_info = compute_gap_information(ordered_fragments)
    
    byte_chunks = []
    for frag in ordered_fragments:
        chunk = read_fragment_bytes(frag)
        byte_chunks.append(chunk)
    
    # 4. Assemble candidate bytes
    assembled_bytes = b"".join(byte_chunks)

    # 5. Write candidate to recovered/ with deterministic name
    with open(candidate_path, "wb") as f_out:
        f_out.write(assembled_bytes)

    # 6. Open candidate using REAL parser
    valid, parser_msg = validate_reconstruction(file_type, assembled_bytes)

    # 7. Record reconstruction result + reason
    if valid:
        status = "reconstructed"
        structural_validity = 1.0
        val_status = "VALIDATED"
    else:
        status = "validation_failed"
        structural_validity = 0.0
        val_status = "FAILED"

    unique_rec = gap_info.get("unique_recovered_bytes", len(assembled_bytes))
    raw_bytes = gap_info.get("raw_fragment_bytes", len(assembled_bytes))
    missing_b = gap_info.get("total_gap_bytes", 0)
    obs_span = gap_info.get("observed_candidate_span", unique_rec + missing_b)
    obs_ratio = round(unique_rec / obs_span, 4) if obs_span > 0 else 1.0

    return ReconstructedFile(
        id=candidate_id,
        candidate_id=candidate_id,
        cluster_id=cluster.cluster_id,
        file_type=file_type,
        fragment_ids=[f.id for f in ordered_fragments],
        fragment_count=len(ordered_fragments),
        source_offsets=[f.offset for f in ordered_fragments],
        source_ranges=gap_info.get("source_ranges", []),
        raw_fragment_bytes=raw_bytes,
        unique_recovered_bytes=unique_rec,
        recovered_bytes=unique_rec,
        overlap_bytes=gap_info.get("overlap_bytes", 0),
        duplicate_bytes=gap_info.get("overlap_bytes", 0),
        gap_count=gap_info.get("gap_count", 0),
        missing_or_unknown_bytes=missing_b,
        observed_candidate_span=obs_span,
        observed_recovery_ratio=obs_ratio,
        gap_information=gap_info,
        structural_validity=structural_validity,
        parser_validation_status=val_status,
        is_validated_recovery=valid,
        status=status,
        parser_message=parser_msg,
        ambiguous=False,
    )
