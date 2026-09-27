import math
from typing import List, Dict, Any, Optional
import numpy as np

from config import settings
from models.fragment import Fragment
from models.feature_vector import FeatureVector


def calculate_cosine_similarity(vector_a: List[float], vector_b: List[float]) -> float:
    """
    Calculate defensive, deterministic cosine similarity between two float vectors.
    
    Returns:
        Float bounded in [-1.0, 1.0] (rounded to 4 decimal places). Returns 0.0 for zero vectors.
    """
    if not vector_a or not vector_b:
        return 0.0

    a = np.array(vector_a, dtype=np.float64)
    b = np.array(vector_b, dtype=np.float64)

    a = np.nan_to_num(a, nan=0.0, posinf=0.0, neginf=0.0)
    b = np.nan_to_num(b, nan=0.0, posinf=0.0, neginf=0.0)

    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))

    if norm_a == 0.0 or norm_b == 0.0 or math.isnan(norm_a) or math.isnan(norm_b):
        return 0.0

    dot = float(np.dot(a, b))
    sim = dot / (norm_a * norm_b)
    sim = max(-1.0, min(1.0, sim))
    return round(sim, 4)


def calculate_offset_proximity(fragment_a: Fragment, fragment_b: Fragment) -> float:
    """
    Derive deterministic physical proximity signal between two fragments in the same evidence source.
    
    Returns:
        Float in [0.0, 1.0] decaying exponentially with byte distance gap.
    """
    if fragment_a.source and fragment_b.source and fragment_a.source != fragment_b.source:
        return 0.0

    start_a, end_a = fragment_a.offset, fragment_a.offset + fragment_a.length
    start_b, end_b = fragment_b.offset, fragment_b.offset + fragment_b.length

    # Calculate gap between intervals
    if start_b >= end_a:
        gap = start_b - end_a
    elif start_a >= end_b:
        gap = start_a - end_b
    else:
        gap = 0  # Overlapping or adjacent

    scale = max(1.0, float(settings.PROXIMITY_DECAY_SCALE))
    proximity = math.exp(-gap / scale)
    return round(max(0.0, min(1.0, proximity)), 4)


def calculate_type_compatibility(fragment_a: Fragment, fragment_b: Fragment) -> float:
    """
    Determine deterministic file type and structural compatibility between two fragments.
    
    Returns:
        Float in [0.0, 1.0].
    """
    type_a = (fragment_a.type_hint or "unknown").lower()
    type_b = (fragment_b.type_hint or "unknown").lower()

    char_a = fragment_a.metadata.get("characterization", "binary")
    char_b = fragment_b.metadata.get("characterization", "binary")

    # Identical known file types
    if type_a == type_b and type_a != "unknown":
        return 1.0

    # Both classified as text fragments
    if char_a == "text" and char_b == "text":
        return 0.85

    # One is unknown, one is known
    if type_a == "unknown" or type_b == "unknown":
        return 0.20

    # Incompatible distinct known types (e.g. JPEG vs PDF)
    return 0.0


def calculate_edge_weight(similarity: float, proximity: float, type_match: float) -> float:
    """
    Compute multi-signal weighted relationship edge weight.
    
    Formula:
        edge_weight = w_sim * similarity + w_prox * proximity + w_type * type_match
    """
    w_sim = float(settings.SIMILARITY_WEIGHT)
    w_prox = float(settings.OFFSET_PROXIMITY_WEIGHT)
    w_type = float(settings.TYPE_MATCH_WEIGHT)

    total_w = w_sim + w_prox + w_type
    if total_w > 0:
        w_sim /= total_w
        w_prox /= total_w
        w_type /= total_w

    weight = (w_sim * max(0.0, similarity)) + (w_prox * proximity) + (w_type * type_match)
    return round(max(0.0, min(1.0, weight)), 4)


def build_relationship_graph(
    fragments: List[Fragment],
    features: List[FeatureVector],
    min_weight: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Construct weighted relationship graph between fragments from feature vectors and metadata.
    
    Returns:
        JSON-serializable dictionary with 'nodes' and 'edges' lists.
    """
    min_w = min_weight if min_weight is not None else float(settings.MIN_GRAPH_EDGE_WEIGHT)
    
    feature_map = {fv.fragment_id: fv for fv in features}
    frag_map = {f.id: f for f in fragments}
    
    nodes: List[Dict[str, Any]] = []
    for f in fragments:
        nodes.append({
            "id": f.id,
            "type_hint": f.type_hint,
            "offset": f.offset,
            "length": f.length,
            "entropy": f.entropy,
            "characterization": f.metadata.get("characterization", "binary"),
            "header": f.header_flag,
            "footer": f.footer_flag,
        })

    edges: List[Dict[str, Any]] = []
    n = len(fragments)

    for i in range(n):
        for j in range(i + 1, n):
            frag_a = fragments[i]
            frag_b = fragments[j]

            fv_a = feature_map.get(frag_a.id)
            fv_b = feature_map.get(frag_b.id)

            if not fv_a or not fv_b:
                continue

            sim = calculate_cosine_similarity(fv_a.vector, fv_b.vector)
            prox = calculate_offset_proximity(frag_a, frag_b)
            type_m = calculate_type_compatibility(frag_a, frag_b)

            weight = calculate_edge_weight(sim, prox, type_m)

            if weight >= min_w or sim >= float(settings.COSINE_SIMILARITY_THRESHOLD):
                # Classify relationship basis
                archive_types = {"zip", "tar", "7z", "rar", "wim", "gz", "bz2"}
                is_archive_pair = (frag_a.type_hint in archive_types or frag_b.type_hint in archive_types)

                if is_archive_pair and frag_a.type_hint == frag_b.type_hint and (frag_a.offset + frag_a.length == frag_b.offset or frag_b.offset + frag_b.length == frag_a.offset):
                    rel_basis = "ARCHIVE_STRUCTURAL_CONTINUITY"
                    rel_type = "MUST_FOLLOW"
                elif is_archive_pair and frag_a.type_hint == frag_b.type_hint:
                    rel_basis = "ARCHIVE_SAME_CONTAINER"
                    rel_type = "SAME_ARCHIVE"
                elif prox >= 0.50 and type_m >= 0.80:
                    rel_basis = "STRUCTURAL_SPATIAL"
                    rel_type = "MAY_FOLLOW"
                elif frag_a.metadata.get("extent_linked") or frag_b.metadata.get("extent_linked"):
                    rel_basis = "FILESYSTEM_EXTENT"
                    rel_type = "SAME_MEMBER"
                else:
                    rel_basis = "HEURISTIC_SIMILARITY"
                    rel_type = "MAY_FOLLOW"

                # Build human-readable reason
                reasons = []
                if is_archive_pair and frag_a.type_hint == frag_b.type_hint:
                    reasons.append(f"archive {frag_a.type_hint.upper()} structural continuity")
                if sim >= 0.7:
                    reasons.append(f"high vector similarity ({sim:.2f})")
                elif sim >= 0.4:
                    reasons.append(f"moderate vector similarity ({sim:.2f})")
                if prox >= 0.8:
                    reasons.append("close offset proximity")
                if type_m >= 0.8:
                    reasons.append(f"compatible type ({frag_a.type_hint})")
                
                reason_str = ", ".join(reasons) if reasons else "composite signal correlation"

                edges.append({
                    "source": frag_a.id,
                    "target": frag_b.id,
                    "similarity": sim,
                    "offset_proximity": prox,
                    "type_match": type_m,
                    "edge_weight": weight,
                    "relationship_basis": rel_basis,
                    "relationship_type": rel_type,
                    "reason": reason_str,
                })

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }