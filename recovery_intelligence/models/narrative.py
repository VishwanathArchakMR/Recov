from pydantic import BaseModel, Field
from typing import List, Optional


class NarrativeReportSchema(BaseModel):
    """Structured 7-section narrative report schema for Gemini output."""
    executive_summary: str = Field(..., description="High-level executive summary of recovery outcome and evidence state")
    evidence_overview: str = Field(..., description="Evidence SHA-256, size, ingested fragments and clustering overview")
    recovery_findings: str = Field(..., description="Detailed recovered candidate files, formats, validated vs partial counts")
    integrity_assessment: str = Field(..., description="Decomposed 4-signal integrity metrics and structural parser validation")
    important_findings: str = Field(..., description="High priority items, sensitivity/PII detections, or key artifacts")
    limitations: str = Field(..., description="Limitations, unknown gaps, missing fragments, corruption, and technical caveats")
    analyst_conclusion: str = Field(..., description="Forensic conclusion and recommended next steps for the investigator")


class Narrative(BaseModel):
    """Structured investigative report explicitly separating empirical observations from AI inferences."""
    observed: List[str] = Field(default_factory=list)
    inferred: List[str] = Field(default_factory=list)
    unknown: List[str] = Field(default_factory=list)
    citations: List[str] = Field(default_factory=list)
    generated_text: str = ""

    # 7-Section Structured Narrative Report
    executive_summary: Optional[str] = None
    evidence_overview: Optional[str] = None
    recovery_findings: Optional[str] = None
    integrity_assessment: Optional[str] = None
    important_findings: Optional[str] = None
    limitations: Optional[str] = None
    analyst_conclusion: Optional[str] = None
    is_ai_generated: bool = False
    ai_model: Optional[str] = None
    generation_error: Optional[str] = None
