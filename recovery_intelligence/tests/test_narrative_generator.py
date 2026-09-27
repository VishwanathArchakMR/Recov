import os
import pytest
from unittest.mock import MagicMock, patch
from pydantic import BaseModel

from models.narrative import Narrative, NarrativeReportSchema
from models.ranked_results import RankedResults
from models.reconstructed_file import ReconstructedFile
from models.cluster import FragmentCluster
from models.fragment import Fragment
from ai.llm_client import GeminiLLMProvider, get_llm_client
from ai.narrative_generator import (
    generate_investigative_narrative,
    generate_deterministic_narrative,
    _extract_compact_summary,
    GEMINI_SYSTEM_INSTRUCTION,
)


@pytest.fixture
def sample_ranked_results():
    """Create a sample mock RankedResults object for narrative tests."""
    file1 = ReconstructedFile(
        id="file_001",
        candidate_id="cand_001",
        cluster_id="cluster_001",
        file_type="zip",
        recovery_state="FULL_RECOVERY",
        is_valid=True,
        is_successfully_recovered=True,
        parser_message="Valid ZIP container with 3 records",
        recovered_bytes=4096,
        missing_or_unknown_bytes=0,
        observed_candidate_span=4096,
        observed_recovery_ratio=1.0,
        reconstruction_confidence=0.95,
        structural_validity=1.0,
        completeness_score=1.0,
        corruption_score=0.0,
        priority_score=0.88,
        sensitivity_level="CONFIDENTIAL",
        detected_categories=["FINANCIAL", "CREDENTIALS"],
        output_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    )
    file2 = ReconstructedFile(
        id="file_002",
        candidate_id="cand_002",
        cluster_id="cluster_001",
        file_type="tar",
        recovery_state="PARTIAL_RECONSTRUCTION",
        is_valid=False,
        is_successfully_recovered=False,
        parser_message="Partial TAR container with missing middle sector",
        recovered_bytes=2048,
        missing_or_unknown_bytes=512,
        observed_candidate_span=2560,
        observed_recovery_ratio=0.8,
        reconstruction_confidence=0.65,
        structural_validity=0.7,
        completeness_score=0.8,
        corruption_score=0.2,
        priority_score=0.55,
        sensitivity_level="NONE",
        detected_categories=[],
        output_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    )
    cluster = FragmentCluster(
        cluster_id="cluster_001",
        member_fragment_ids=["frag_0", "frag_1"],
        inferred_type="zip",
        confidence=0.9,
    )
    orphan = Fragment(
        id="frag_99",
        offset=65536,
        length=512,
    )
    return RankedResults(
        evidence_image_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        files=[file1, file2],
        clusters=[cluster],
        orphans=[orphan],
    )


def test_extract_compact_summary(sample_ranked_results):
    """Test compact summary extractor does not include raw payloads."""
    compact = _extract_compact_summary(sample_ranked_results)
    assert compact["evidence"]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert compact["summary_metrics"]["total_candidates"] == 2
    assert compact["summary_metrics"]["validated_candidates"] == 1
    assert compact["summary_metrics"]["partial_candidates"] == 1
    assert len(compact["reconstructed_candidates"]) == 2
    # Ensure no raw byte payloads exist
    assert "raw_bytes" not in compact


def test_deterministic_narrative_generation(sample_ranked_results):
    """Test deterministic narrative generation creates complete factual sections."""
    narrative = generate_deterministic_narrative(sample_ranked_results)
    assert isinstance(narrative, Narrative)
    assert narrative.is_ai_generated is False
    assert len(narrative.observed) > 0
    assert len(narrative.inferred) == 2
    assert len(narrative.unknown) > 0
    assert "e3b0c442" in narrative.executive_summary
    assert "ZIP" in narrative.recovery_findings


def test_gemini_successful_structured_generation(sample_ranked_results):
    """Test successful Gemini structured narrative generation using mocked provider."""
    mock_provider = MagicMock(spec=GeminiLLMProvider)
    mock_provider.model = "gemini-3.1-flash-lite"
    mock_report = NarrativeReportSchema(
        executive_summary="AI Executive Summary: Successfully recovered 2 artifacts from disk image.",
        evidence_overview="Evidence SHA-256 is e3b0c442... Ingested 1 cluster and 1 orphan fragment.",
        recovery_findings="Candidate cand_001 (ZIP) achieved full recovery. Candidate cand_002 (TAR) was partial.",
        integrity_assessment="cand_001 achieved 1.0 structural validity; cand_002 scored 0.70 validity.",
        important_findings="cand_001 flagged as CONFIDENTIAL with FINANCIAL and CREDENTIALS hits.",
        limitations="cand_002 missing 512 bytes due to unallocated gap.",
        analyst_conclusion="Evidence is ready for forensic investigator inspection.",
    )
    mock_provider.generate_structured_response.return_value = mock_report

    narrative = generate_investigative_narrative(sample_ranked_results, llm_provider=mock_provider)

    assert isinstance(narrative, Narrative)
    assert narrative.is_ai_generated is True
    assert narrative.ai_model == "gemini-3.1-flash-lite"
    assert narrative.executive_summary == mock_report.executive_summary
    assert narrative.evidence_overview == mock_report.evidence_overview
    assert narrative.recovery_findings == mock_report.recovery_findings
    assert narrative.integrity_assessment == mock_report.integrity_assessment
    assert narrative.important_findings == mock_report.important_findings
    assert narrative.limitations == mock_report.limitations
    assert narrative.analyst_conclusion == mock_report.analyst_conclusion


def test_gemini_missing_api_key_graceful_fallback(sample_ranked_results, monkeypatch):
    """Test graceful fallback to deterministic narrative when GEMINI_API_KEY is missing."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    provider = GeminiLLMProvider(api_key=None)

    narrative = generate_investigative_narrative(sample_ranked_results, llm_provider=provider)

    assert isinstance(narrative, Narrative)
    assert narrative.is_ai_generated is False
    assert narrative.generation_error == "AI narrative unavailable. Deterministic RECOV report remains available."
    assert narrative.executive_summary is not None
    assert len(narrative.observed) > 0


def test_gemini_api_failure_exception_handling(sample_ranked_results):
    """Test graceful fallback when Gemini API raises a network/timeout exception."""
    mock_provider = MagicMock(spec=GeminiLLMProvider)
    mock_provider.generate_structured_response.side_effect = RuntimeError("503 Service Unavailable / Timeout")
    mock_provider.generate_text.side_effect = RuntimeError("503 Service Unavailable / Timeout")

    narrative = generate_investigative_narrative(sample_ranked_results, llm_provider=mock_provider)

    assert isinstance(narrative, Narrative)
    assert narrative.is_ai_generated is False
    assert narrative.generation_error == "AI narrative unavailable. Deterministic RECOV report remains available."
    assert narrative.executive_summary is not None


def test_gemini_malformed_response_fallback(sample_ranked_results):
    """Test fallback when structured response returns None and plain text is attempted."""
    mock_provider = MagicMock(spec=GeminiLLMProvider)
    mock_provider.model = "gemini-3.1-flash-lite"
    mock_provider.generate_structured_response.return_value = None
    mock_provider.generate_text.return_value = "Unstructured Plain Text AI Narrative Summary."

    narrative = generate_investigative_narrative(sample_ranked_results, llm_provider=mock_provider)

    assert isinstance(narrative, Narrative)
    assert narrative.is_ai_generated is True
    assert narrative.executive_summary == "Unstructured Plain Text AI Narrative Summary."
