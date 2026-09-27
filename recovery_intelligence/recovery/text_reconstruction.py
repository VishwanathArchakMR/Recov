import os
import itertools
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable
from models.cluster import FragmentCluster
from models.fragment import Fragment
from models.reconstructed_file import ReconstructedFile
from config.settings import settings
from .validation import validate_reconstruction


def read_fragment_bytes(fragment: Fragment) -> bytes:
    """Read fragment bytes strictly in read-only mode from metadata or evidence source."""
    if fragment.metadata and "raw_bytes" in fragment.metadata:
        raw = fragment.metadata["raw_bytes"]
        if isinstance(raw, bytes):
            return raw
        elif isinstance(raw, str):
            return raw.encode("utf-8")
    if not fragment.source or not os.path.exists(fragment.source):
        return b""
    try:
        with open(fragment.source, "rb") as f:
            f.seek(fragment.offset)
            return f.read(fragment.length)
    except Exception:
        return b""


def compute_union_coverage(fragments: List[Fragment]) -> Dict[str, Any]:
    """
    Compute disjoint union intervals, unique byte coverage, overlap bytes,
    and gap information from fragment evidence offsets.
    """
    if not fragments:
        return {
            "source_ranges": [],
            "source_offsets": [],
            "raw_fragment_bytes": 0,
            "unique_recovered_bytes": 0,
            "overlap_bytes": 0,
            "duplicate_bytes": 0,
            "has_gaps": False,
            "gap_count": 0,
            "total_gap_bytes": 0,
            "gaps": [],
            "observed_candidate_span": 0,
        }

    raw_fragment_bytes = sum(f.length for f in fragments)
    source_offsets = [f.offset for f in sorted(fragments, key=lambda f: (f.offset, f.id))]

    # Sort intervals by start offset, then end offset
    raw_intervals = sorted([(f.offset, f.offset + f.length) for f in fragments if f.length > 0])
    if not raw_intervals:
        return {
            "source_ranges": [],
            "source_offsets": source_offsets,
            "raw_fragment_bytes": 0,
            "unique_recovered_bytes": 0,
            "overlap_bytes": 0,
            "duplicate_bytes": 0,
            "has_gaps": False,
            "gap_count": 0,
            "total_gap_bytes": 0,
            "gaps": [],
            "observed_candidate_span": 0,
        }

    # Merge overlapping or contiguous intervals into disjoint ranges
    merged_ranges: List[List[int]] = []
    for start, end in raw_intervals:
        if not merged_ranges:
            merged_ranges.append([start, end])
        else:
            prev_start, prev_end = merged_ranges[-1]
            if start <= prev_end:  # Overlapping or adjacent
                merged_ranges[-1][1] = max(prev_end, end)
            else:
                merged_ranges.append([start, end])

    unique_recovered_bytes = sum(end - start for start, end in merged_ranges)
    overlap_bytes = max(0, raw_fragment_bytes - unique_recovered_bytes)

    # Compute gaps between disjoint merged ranges
    sorted_frags = sorted(fragments, key=lambda f: (f.offset, f.id))
    gaps = []
    total_gap_bytes = 0
    for i in range(len(merged_ranges) - 1):
        gap_start = merged_ranges[i][1]
        gap_end = merged_ranges[i + 1][0]
        gap_size = gap_end - gap_start
        if gap_size > 0:
            prev_f = max((f for f in sorted_frags if f.offset + f.length <= gap_start), key=lambda f: f.offset + f.length, default=None)
            next_f = min((f for f in sorted_frags if f.offset >= gap_end), key=lambda f: f.offset, default=None)
            gaps.append({
                "prev_fragment_id": prev_f.id if prev_f else "",
                "next_fragment_id": next_f.id if next_f else "",
                "gap_start": gap_start,
                "gap_end": gap_end,
                "gap_length": gap_size,
                "gap_size": gap_size,
            })
            total_gap_bytes += gap_size

    observed_span = unique_recovered_bytes + total_gap_bytes

    return {
        "source_ranges": merged_ranges,
        "source_offsets": source_offsets,
        "raw_fragment_bytes": raw_fragment_bytes,
        "unique_recovered_bytes": unique_recovered_bytes,
        "overlap_bytes": overlap_bytes,
        "duplicate_bytes": overlap_bytes,
        "has_gaps": len(gaps) > 0,
        "gap_count": len(gaps),
        "total_gap_bytes": total_gap_bytes,
        "gaps": gaps,
        "observed_candidate_span": observed_span,
    }


def compute_gap_information(ordered_fragments: List[Fragment]) -> Dict[str, Any]:
    """Compute deterministic gap and interval union information."""
    cov = compute_union_coverage(ordered_fragments)
    return {
        "has_gaps": cov["has_gaps"],
        "gap_count": cov["gap_count"],
        "total_gap_bytes": cov["total_gap_bytes"],
        "gaps": cov["gaps"],
        "source_ranges": cov["source_ranges"],
        "unique_recovered_bytes": cov["unique_recovered_bytes"],
        "raw_fragment_bytes": cov["raw_fragment_bytes"],
        "overlap_bytes": cov["overlap_bytes"],
        "observed_candidate_span": cov["observed_candidate_span"],
    }


def score_text_transition(text_a: str, text_b: str, offset_a: int, offset_b: int) -> float:
    """
    Score transition continuity between text fragment A and text fragment B.
    
    Checks sentence boundary continuity, word wrap, and offset ordering.
    """
    score = 0.0
    # Offset order consistency
    if offset_b >= offset_a:
        score += 1.0
    
    if not text_a or not text_b:
        return score

    # Clean whitespace for edge check
    tail = text_a.rstrip()
    head = text_b.lstrip()

    if not tail or not head:
        return score

    # Sentence boundary: A ends with sentence terminator, B starts with uppercase or newline
    if tail[-1] in ".!?" and head[0].isupper():
        score += 2.0
    # Sentence continuation across line: A ends with comma/colon/semicolon, B starts with lowercase
    elif tail[-1] in ",;:" and head[0].islower():
        score += 2.0
    # Mid-word split: A ends with alphanumeric, B starts with lowercase alphanumeric
    elif tail[-1].isalnum() and head[0].islower():
        score += 2.5
    # Natural paragraph break: A ends with newline
    elif text_a.endswith("\n") or text_a.endswith("\r\n"):
        score += 1.5

    return score


def reconstruct_small_text_cluster(
    cluster: FragmentCluster,
    fragments: List[Fragment],
    output_dir: Optional[Path] = None,
) -> ReconstructedFile:
    """
    Reconstruct small text cluster (<= 6 fragments) using brute-force
    continuity and sentence boundary scoring.
    
    If multiple candidate permutations tie with identical high scores,
    marks candidate as ambiguous rather than forcing a winner.
    """
    candidate_id = f"recon_{cluster.cluster_id}"
    out_dir = output_dir or settings.RECOVERED_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    candidate_path = out_dir / f"{candidate_id}.txt"

    if not fragments:
        return ReconstructedFile(
            id=candidate_id,
            cluster_id=cluster.cluster_id,
            file_type="text",
            fragment_ids=[],
            gap_information={"has_gaps": False, "gap_count": 0, "total_gap_bytes": 0, "gaps": []},
            structural_validity=0.0,
            status="cluster_only",
            parser_message="No member fragments provided for text reconstruction",
            ambiguous=False,
        )

    # Read bytes and extract text for each fragment
    frag_data = {}
    frag_text = {}
    for f in fragments:
        raw_b = read_fragment_bytes(f)
        frag_data[f.id] = raw_b
        try:
            frag_text[f.id] = raw_b.decode("utf-8")
        except UnicodeDecodeError:
            frag_text[f.id] = raw_b.decode("latin-1", errors="replace")

    frag_map = {f.id: f for f in fragments}

    # If only 1 fragment, trivial ordering
    if len(fragments) == 1:
        ordered_frags = fragments
        is_ambiguous = False
        ambiguity_reason = ""
    elif len(fragments) <= 6:
        # Evaluate permutations for continuity scoring
        scored_permutations: List[Tuple[float, Tuple[Fragment, ...]]] = []
        for p in itertools.permutations(fragments):
            total_score = 0.0
            for i in range(len(p) - 1):
                f_a = p[i]
                f_b = p[i + 1]
                total_score += score_text_transition(
                    frag_text[f_a.id], frag_text[f_b.id], f_a.offset, f_b.offset
                )
            scored_permutations.append((total_score, p))
        
        # Sort by score descending; break ties deterministically by fragment IDs
        scored_permutations.sort(
            key=lambda item: (item[0], [f.offset for f in item[1]], [f.id for f in item[1]]),
            reverse=True
        )
        
        best_score = scored_permutations[0][0]
        # Check if top 2 distinct orderings have identical score
        top_candidates = [p for s, p in scored_permutations if abs(s - best_score) < 1e-6]
        if len(top_candidates) > 1 and len(fragments) > 1:
            # Check if orderings are actually different
            order1 = [f.id for f in top_candidates[0]]
            order2 = [f.id for f in top_candidates[1]]
            if order1 != order2:
                is_ambiguous = True
                ambiguity_reason = (
                    f"Ambiguous candidate: {len(top_candidates)} candidate orderings tied "
                    f"with identical continuity score ({best_score:.2f})"
                )
            else:
                is_ambiguous = False
                ambiguity_reason = ""
        else:
            is_ambiguous = False
            ambiguity_reason = ""
        
        ordered_frags = list(scored_permutations[0][1])
    else:
        # Fallback to deterministic offset ordering
        ordered_frags = sorted(fragments, key=lambda f: (f.offset, f.id))
        is_ambiguous = False
        ambiguity_reason = ""

    # Assemble candidate bytes
    assembled_bytes = b"".join(frag_data[f.id] for f in ordered_frags)

    # Compute gap information
    gap_info = compute_gap_information(ordered_frags)

    # Write candidate to recovered/
    with open(candidate_path, "wb") as f_out:
        f_out.write(assembled_bytes)

    # Validate reconstructed text
    valid, val_msg = validate_reconstruction("text", assembled_bytes)

    if is_ambiguous:
        status = "ambiguous"
        parser_message = f"{ambiguity_reason}; {val_msg}"
    elif valid:
        status = "reconstructed"
        parser_message = val_msg
    else:
        status = "validation_failed"
        parser_message = val_msg

    return ReconstructedFile(
        id=candidate_id,
        cluster_id=cluster.cluster_id,
        file_type="text",
        fragment_ids=[f.id for f in ordered_frags],
        gap_information=gap_info,
        structural_validity=1.0 if valid else 0.0,
        status=status,
        parser_message=parser_message,
        ambiguous=is_ambiguous,
    )


def reconstruct_large_text_cluster(
    cluster: FragmentCluster,
    fragments: List[Fragment],
    output_dir: Optional[Path] = None,
    llm_callable: Optional[Callable[[List[Dict[str, Any]]], List[str]]] = None,
) -> ReconstructedFile:
    """
    Reconstruct large text cluster (> 6 fragments) using constrained fragment ordering.
    
    Permits ONE constrained LLM call for ordering if provided.
    Strictly validates that returned IDs match the exact set of member fragment IDs.
    Rejects any hallucinated, missing, or duplicate IDs and falls back to deterministic
    offset ordering.
    """
    candidate_id = f"recon_{cluster.cluster_id}"
    out_dir = output_dir or settings.RECOVERED_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    candidate_path = out_dir / f"{candidate_id}.txt"

    if not fragments:
        return ReconstructedFile(
            id=candidate_id,
            cluster_id=cluster.cluster_id,
            file_type="text",
            fragment_ids=[],
            gap_information={"has_gaps": False, "gap_count": 0, "total_gap_bytes": 0, "gaps": []},
            structural_validity=0.0,
            status="cluster_only",
            parser_message="No member fragments provided for large text reconstruction",
            ambiguous=False,
        )

    frag_map = {f.id: f for f in fragments}
    actual_ids = set(frag_map.keys())

    # Read bytes for each fragment
    frag_data = {}
    for f in fragments:
        frag_data[f.id] = read_fragment_bytes(f)

    llm_used = False
    llm_rejected = False
    llm_rejection_reason = ""
    ordered_ids = []

    if llm_callable is not None:
        try:
            # Prepare minimal fragment representation for LLM
            prompt_fragments = []
            for f in sorted(fragments, key=lambda x: (x.offset, x.id)):
                raw_b = frag_data[f.id]
                snippet = raw_b[:80].decode("utf-8", errors="replace")
                prompt_fragments.append({
                    "id": f.id,
                    "offset": f.offset,
                    "length": f.length,
                    "snippet": snippet,
                })
            
            returned_ids = llm_callable(prompt_fragments)
            
            # STRICT VALIDATION: Must be list, exact same set of IDs, exact same length
            if not isinstance(returned_ids, list):
                llm_rejected = True
                llm_rejection_reason = "LLM response is not a list"
            elif set(returned_ids) != actual_ids or len(returned_ids) != len(actual_ids):
                hallucinated = set(returned_ids) - actual_ids
                missing = actual_ids - set(returned_ids)
                llm_rejected = True
                llm_rejection_reason = (
                    f"LLM returned invalid fragment IDs (hallucinated: {list(hallucinated)}, "
                    f"missing: {list(missing)})"
                )
            else:
                ordered_ids = returned_ids
                llm_used = True
        except Exception as e:
            llm_rejected = True
            llm_rejection_reason = f"LLM execution error: {str(e)}"

    # If LLM wasn't used or was rejected, use deterministic offset order
    if not llm_used:
        ordered_frags = sorted(fragments, key=lambda f: (f.offset, f.id))
    else:
        ordered_frags = [frag_map[fid] for fid in ordered_ids]

    # Assemble candidate bytes
    assembled_bytes = b"".join(frag_data[f.id] for f in ordered_frags)

    # Compute gap information
    gap_info = compute_gap_information(ordered_frags)

    # Write candidate to recovered/
    with open(candidate_path, "wb") as f_out:
        f_out.write(assembled_bytes)

    # Validate reconstructed text
    valid, val_msg = validate_reconstruction("text", assembled_bytes)

    if llm_rejected:
        parser_message = f"LLM proposal rejected ({llm_rejection_reason}); fell back to offset ordering; {val_msg}"
    elif llm_used:
        parser_message = f"Constrained LLM ordering accepted; {val_msg}"
    else:
        parser_message = f"Deterministic offset ordering; {val_msg}"

    return ReconstructedFile(
        id=candidate_id,
        cluster_id=cluster.cluster_id,
        file_type="text",
        fragment_ids=[f.id for f in ordered_frags],
        gap_information=gap_info,
        structural_validity=1.0 if valid else 0.0,
        status="reconstructed" if valid else "validation_failed",
        parser_message=parser_message,
        ambiguous=False,
    )
