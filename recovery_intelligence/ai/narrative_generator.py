import json
import logging
from typing import Dict, Any, Optional, Union, List
from models.narrative import Narrative, NarrativeReportSchema
from models.pipeline_result import PipelineResult
from models.ranked_results import RankedResults
from ai.llm_client import get_llm_client, GeminiLLMProvider

logger = logging.getLogger(__name__)

GEMINI_SYSTEM_INSTRUCTION = (
    "You are the narrative-reporting assistant for RECOV, an intelligent digital evidence recovery system.\n\n"
    "RECOV has already performed all forensic processing.\n\n"
    "Your only task is to transform the supplied structured RECOV results into a professional analyst narrative.\n\n"
    "Do not perform recovery yourself.\n"
    "Do not invent facts.\n"
    "Do not modify metrics.\n"
    "Do not change validation results.\n"
    "Do not infer unsupported causes or events.\n\n"
    "Every factual statement must be supported by the supplied RECOV data.\n\n"
    "Clearly distinguish complete recovery, partial recovery, invalid candidates, and uncertainty.\n\n"
    "When information is unavailable, explicitly state: 'Not available from the RECOV results.'\n\n"
    "Use professional, concise, evidence-grounded language."
)


def _extract_compact_summary(results: Union[PipelineResult, RankedResults, Dict[str, Any], Any]) -> Dict[str, Any]:
    """Extract a compact, telemetry-only JSON summary of RECOV's final structured results."""
    summary: Dict[str, Any] = {
        "evidence": {},
        "summary_metrics": {},
        "reconstructed_candidates": [],
        "clusters_count": 0,
        "orphans_count": 0,
    }

    if isinstance(results, PipelineResult):
        ev_size = getattr(results.evidence, "size_bytes", None) if results.evidence else None
        summary["evidence"] = {
            "sha256": results.evidence_sha256 or "Not available from the RECOV results.",
            "path": results.evidence_path or "Not available from the RECOV results.",
            "size_bytes": f"{ev_size:,} bytes" if ev_size is not None else "Not available from the RECOV results.",
        }
        total_frags = len(results.fragments)
        summary["summary_metrics"]["total_carved_fragments"] = total_frags
        summary["clusters_count"] = len(results.clusters)
        summary["orphans_count"] = len(results.orphans)
        
        recons = results.reconstructed_files
    elif isinstance(results, RankedResults):
        summary["evidence"] = {
            "sha256": results.evidence_image_hash or "Not available from the RECOV results.",
            "path": "Not available from the RECOV results.",
            "size_bytes": "Not available from the RECOV results.",
        }
        summary["clusters_count"] = len(results.clusters)
        summary["orphans_count"] = len(results.orphans)
        recons = results.files
    elif isinstance(results, dict):
        summary["evidence"] = {
            "sha256": results.get("evidence_sha256", results.get("evidence_image_hash", "Not available from the RECOV results.")),
            "path": results.get("evidence_path", "Not available from the RECOV results."),
            "size_bytes": results.get("evidence_size", "Not available from the RECOV results."),
        }
        summary["clusters_count"] = len(results.get("clusters", []))
        summary["orphans_count"] = len(results.get("orphans", []))
        recons = results.get("reconstructed_files", results.get("files", []))
    else:
        recons = getattr(results, "reconstructed_files", getattr(results, "files", []))

    valid_count = 0
    partial_count = 0
    invalid_count = 0

    for r in recons:
        cid = getattr(r, "candidate_id", None) or getattr(r, "id", "UNKNOWN")
        ftype = getattr(r, "file_type", "unknown")
        state = getattr(r, "recovery_state", "UNKNOWN")
        is_val = getattr(r, "is_successfully_recovered", False) or getattr(r, "is_valid", False) or state in ("FULL_RECOVERY", "VALIDATED_RECOVERY")
        
        if is_val:
            valid_count += 1
        elif state == "PARTIAL_RECONSTRUCTION":
            partial_count += 1
        else:
            invalid_count += 1

        cand_info = {
            "candidate_id": cid,
            "file_type": ftype,
            "recovery_state": state,
            "is_valid": is_val,
            "parser_message": getattr(r, "parser_message", "") or getattr(r, "recovery_reason", "None"),
            "recovered_bytes": getattr(r, "recovered_bytes", 0),
            "missing_or_unknown_bytes": getattr(r, "missing_or_unknown_bytes", 0),
            "observed_recovery_ratio": round(getattr(r, "observed_recovery_ratio", 0.0), 4),
            "priority_score": round(getattr(r, "priority_score", 0.0), 4),
            "sensitivity_level": getattr(r, "sensitivity_level", "NONE") or "NONE",
            "detected_categories": getattr(r, "detected_categories", []) or [],
            "integrity_signals": {
                "reconstruction_confidence": round(getattr(r, "reconstruction_confidence", 0.0), 4),
                "structural_validity": round(getattr(r, "structural_validity", 0.0), 4),
                "completeness_score": round(getattr(r, "completeness_score", 0.0), 4),
                "corruption_score": round(getattr(r, "corruption_score", 0.0), 4),
            },
            "output_sha256": getattr(r, "output_sha256", "Not available from the RECOV results.") or "Not available from the RECOV results.",
        }
        summary["reconstructed_candidates"].append(cand_info)

    summary["summary_metrics"]["total_candidates"] = len(recons)
    summary["summary_metrics"]["validated_candidates"] = valid_count
    summary["summary_metrics"]["partial_candidates"] = partial_count
    summary["summary_metrics"]["invalid_candidates"] = invalid_count

    return summary


def generate_deterministic_narrative(results: Union[PipelineResult, RankedResults, Dict[str, Any], Any]) -> Narrative:
    """Generate a 100% deterministic fallback narrative from structured RECOV results."""
    compact = _extract_compact_summary(results)
    ev = compact.get("evidence", {})
    metrics = compact.get("summary_metrics", {})
    candidates = compact.get("reconstructed_candidates", [])

    observed = [
        f"Evidence Image SHA-256: {ev.get('sha256', 'Not available from the RECOV results.')}",
        f"Evidence Path: {ev.get('path', 'Not available from the RECOV results.')}",
        f"Total Ingested/Carved Fragments: {metrics.get('total_carved_fragments', len(candidates))}",
        f"Total Reconstruction Candidates: {metrics.get('total_candidates', len(candidates))}",
        f"Validated Recovery Candidates: {metrics.get('validated_candidates', 0)}",
        f"Partial Recovery Candidates: {metrics.get('partial_candidates', 0)}",
        f"Invalid/Unrecoverable Candidates: {metrics.get('invalid_candidates', 0)}",
    ]

    inferred = []
    for c in candidates:
        inferred.append(
            f"Candidate {c['candidate_id']} ({c['file_type'].upper()}): State={c['recovery_state']}, "
            f"Recovery Ratio={c['observed_recovery_ratio']*100:.1f}%, Priority={c['priority_score']:.2f}, "
            f"Validation='{c['parser_message']}'"
        )

    unknown = [
        f"Unallocated / Orphan Fragment Count: {compact.get('orphans_count', 0)}",
        "Logical filesystem original timestamps and directory tree structures are not available from unallocated space.",
        "Internal byte gaps in partial candidates represent missing sectors.",
    ]

    exec_summary = (
        f"Forensic processing completed for evidence {ev.get('sha256', 'N/A')[:16]}... "
        f"Generated {metrics.get('total_candidates', 0)} candidates "
        f"({metrics.get('validated_candidates', 0)} validated, {metrics.get('partial_candidates', 0)} partial, "
        f"{metrics.get('invalid_candidates', 0)} invalid)."
    )

    ev_overview = (
        f"Evidence SHA-256: {ev.get('sha256')}\n"
        f"File Path: {ev.get('path')}\n"
        f"Evidence Size: {ev.get('size_bytes')}\n"
        f"Clusters Formed: {compact.get('clusters_count', 0)}, Orphans: {compact.get('orphans_count', 0)}"
    )

    rec_findings = "\n".join([
        f"- Candidate {c['candidate_id']} [{c['file_type'].upper()}]: {c['recovery_state']} "
        f"({c['recovered_bytes']} recovered bytes, {c['missing_or_unknown_bytes']} missing bytes, "
        f"Parser Status: {c['parser_message']})"
        for c in candidates
    ]) or "No reconstruction candidates generated."

    integ_assessment = "\n".join([
        f"- Candidate {c['candidate_id']}: Confidence={c['integrity_signals']['reconstruction_confidence']:.2f}, "
        f"Validity={c['integrity_signals']['structural_validity']:.2f}, "
        f"Completeness={c['integrity_signals']['completeness_score']:.2f}, "
        f"Corruption={c['integrity_signals']['corruption_score']:.2f}"
        for c in candidates
    ]) or "No integrity signal metrics available."

    imp_findings = "\n".join([
        f"- Candidate {c['candidate_id']} ({c['file_type']}): Sensitivity Level={c['sensitivity_level']}, "
        f"Categories={c['detected_categories']}, Priority Score={c['priority_score']:.4f}"
        for c in candidates if c.get("sensitivity_level") != "NONE" or c.get("priority_score", 0) > 0.5
    ]) or "No high-sensitivity or elevated-priority items flagged."

    limitations = (
        "- Format validation confirms container/stream syntax integrity; missing unallocated sectors cannot be synthesized.\n"
        "- Filesystem metadata (original filenames, MACB timestamps) unavailable in unallocated fragment carving."
    )

    conclusion = (
        f"Recovery engine processed {metrics.get('total_candidates', 0)} artifact candidate(s). "
        f"{metrics.get('validated_candidates', 0)} artifact(s) passed format parser validation and are ready for forensic examination."
    )

    return Narrative(
        observed=observed,
        inferred=inferred,
        unknown=unknown,
        citations=[ev.get("sha256", "")],
        generated_text=exec_summary,
        executive_summary=exec_summary,
        evidence_overview=ev_overview,
        recovery_findings=rec_findings,
        integrity_assessment=integ_assessment,
        important_findings=imp_findings,
        limitations=limitations,
        analyst_conclusion=conclusion,
        is_ai_generated=False,
    )


def generate_investigative_narrative(
    results: Union[PipelineResult, RankedResults, Dict[str, Any], Any],
    llm_provider: Optional[Any] = None,
) -> Narrative:
    """
    Generate an analyst-friendly narrative report from structured RECOV results.
    Attempts Gemini 3.1 Flash-Lite AI narrative generation via Google GenAI SDK.
    Falls back gracefully to deterministic RECOV narrative if Gemini is unavailable,
    unconfigured, timed out, or rate-limited.
    """
    # 1. Build compact structured data payload
    compact_summary = _extract_compact_summary(results)
    
    # 2. Get LLM Provider
    provider = llm_provider or get_llm_client()
    
    # If no provider or no API key, return deterministic report with failure status
    if not provider:
        det = generate_deterministic_narrative(results)
        det.generation_error = "AI narrative unavailable. Deterministic RECOV report remains available."
        return det

    prompt = (
        "Generate a complete 7-section professional forensic narrative report based strictly on "
        "the following structured RECOV pipeline results:\n\n"
        f"{json.dumps(compact_summary, indent=2)}\n\n"
        "Remember: Use exact values from the data. If any value is unavailable, output 'Not available from the RECOV results.'"
    )

    try:
        structured_resp: Optional[NarrativeReportSchema] = provider.generate_structured_response(
            prompt=prompt,
            schema=NarrativeReportSchema,
            system_instruction=GEMINI_SYSTEM_INSTRUCTION,
        )

        if structured_resp:
            # Successfully generated structured AI narrative
            det = generate_deterministic_narrative(results)
            return Narrative(
                observed=det.observed,
                inferred=det.inferred,
                unknown=det.unknown,
                citations=det.citations,
                generated_text=structured_resp.executive_summary,
                executive_summary=structured_resp.executive_summary,
                evidence_overview=structured_resp.evidence_overview,
                recovery_findings=structured_resp.recovery_findings,
                integrity_assessment=structured_resp.integrity_assessment,
                important_findings=structured_resp.important_findings,
                limitations=structured_resp.limitations,
                analyst_conclusion=structured_resp.analyst_conclusion,
                is_ai_generated=True,
                ai_model=getattr(provider, "model", "gemini-3.1-flash-lite"),
            )
        
        # Fallback to text generation if structured output returned None
        text_resp = provider.generate_text(prompt=prompt, system_instruction=GEMINI_SYSTEM_INSTRUCTION)
        if text_resp:
            det = generate_deterministic_narrative(results)
            det.is_ai_generated = True
            det.ai_model = getattr(provider, "model", "gemini-3.1-flash-lite")
            det.executive_summary = text_resp
            det.generated_text = text_resp
            return det

    except Exception as e:
        logger.warning(f"AI narrative generation encountered error: {e}")

    # Graceful fallback on any failure
    det = generate_deterministic_narrative(results)
    det.generation_error = "AI narrative unavailable. Deterministic RECOV report remains available."
    return det
