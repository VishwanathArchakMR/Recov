import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

class Settings(BaseModel):
    """Application settings and configuration paths."""
    
    # Project Paths
    BASE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    EVIDENCE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "evidence")
    RECOVERED_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "recovered")
    CACHE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "cache")
    RESULTS_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "results")
    DATASET_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "dataset")
    
    # Carving & Fragment Settings
    PIPELINE_VERSION: str = "1.0.0"
    DEFAULT_FRAGMENT_SIZE: int = 512
    MAX_EVIDENCE_SIZE_MB: int = 1024
    
    # Stage 2 Entropy & Characterization Settings
    ENTROPY_WINDOW_SIZE: int = 128
    ENTROPY_STEP_SIZE: int = 32
    PRINTABLE_RATIO_TEXT_THRESHOLD: float = 0.85
    PRINTABLE_RATIO_BINARY_THRESHOLD: float = 0.30
    ENTROPY_TEXT_MAX: float = 5.8
    ENTROPY_BINARY_MIN: float = 6.5
    MIXED_ENTROPY_DELTA: float = 1.8
    
    # Stage 3 Fingerprinting & Embedding Settings
    BINARY_TFIDF_NGRAM_RANGE: tuple = (2, 2)
    BINARY_SVD_COMPONENTS: int = 64
    FINGERPRINT_DIMENSION: int = 64
    
    # Stage 4 Relationship & Clustering Settings
    COSINE_SIMILARITY_THRESHOLD: float = 0.50
    SIMILARITY_WEIGHT: float = 0.60
    OFFSET_PROXIMITY_WEIGHT: float = 0.20
    TYPE_MATCH_WEIGHT: float = 0.20
    PROXIMITY_DECAY_SCALE: float = 65536.0
    DBSCAN_EPS: float = 0.30
    DBSCAN_MIN_SAMPLES: int = 2
    MIN_GRAPH_EDGE_WEIGHT: float = 0.40
    
    # Stage 6 Decomposed Integrity Scoring Weights
    RECONSTRUCTION_CONFIDENCE_WEIGHT: float = 0.25
    COMPLETENESS_WEIGHT: float = 0.25
    STRUCTURAL_VALIDITY_WEIGHT: float = 0.35
    CORRUPTION_WEIGHT: float = 0.15

    # Stage 8 Investigative Priority Ranking Weights
    PRIORITY_INTEGRITY_WEIGHT: float = 0.25
    PRIORITY_RECOVERABILITY_WEIGHT: float = 0.20
    PRIORITY_STRUCTURAL_WEIGHT: float = 0.15
    PRIORITY_SENSITIVITY_WEIGHT: float = 0.30
    PRIORITY_SIZE_WEIGHT: float = 0.10
    PRIORITY_AMBIGUITY_PENALTY: float = 0.15
    PRIORITY_CORRUPTION_PENALTY: float = 0.10
    PRIORITY_SIZE_NORMALIZATION_BYTES: float = 65536.0
    
    # AI Models
    EMBEDDING_MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"

    LLM_PROVIDER: str = "gemini"  # "gemini" or "anthropic"
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY", None)
    
    # Thresholds
    ENTROPY_HIGH_THRESHOLD: float = 7.5
    ENTROPY_LOW_THRESHOLD: float = 3.0
    SIMILARITY_THRESHOLD: float = 0.75
    
    class Config:
        arbitrary_types_allowed = True

settings = Settings()