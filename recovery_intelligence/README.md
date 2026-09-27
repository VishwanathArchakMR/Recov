# RECOV
**CALMSTACKS 24H HACKATHON PROJECT**

## Project Overview
An intelligent, local digital forensics and evidence reconstruction system designed to analyze damaged, deleted, or fragmented storage images (`.dd`, raw byte streams), carve fragments, compute structural and semantic relationships, reconstruct candidate files, validate structural integrity, assess data sensitivity (PII/Aadhaar/PAN), score integrity across four isolated signals, and generate an analyst-friendly investigative narrative.

## Directory Structure
```
recovery_intelligence/
├── app.py                     # Streamlit web UI entry point
├── config/                    # Application settings and feature flags
├── models/                    # Pydantic data schemas & contracts
├── pipeline/                  # Orchestration and execution workflow
├── recovery/                  # Carving, entropy, fingerprinting, clustering, reconstruction
├── intelligence/              # Scoring, sensitivity, PII/keyword detection, priority
├── ai/                        # Vector embeddings, LLM provider abstraction, narrative generator
├── visualization/             # Streamlit dashboard renderers
├── storage/                   # JSON persistence, cache, and serializers
├── evaluation/                # Ground truth loader, evaluation metrics (ISOLATED)
├── dataset/                   # Benchmark datasets and ground_truth.json
├── evidence/                  # Raw input disk images (.dd)
├── recovered/                 # Output reconstructed files
├── cache/                     # Cached pipeline execution runs
├── results/                   # Persisted analysis outputs
└── tests/                     # Test suite
```

## Architectural Principles
1. **Local-First & Single App**: Built strictly as a local Python + Streamlit application. No cloud dependencies or microservices required.
2. **Evaluation Isolation**: The recovery engine and production pipeline **NEVER** import or inspect `ground_truth.json`. Ground truth is strictly isolated to `evaluation/`.
3. **Four-Signal Scoring**: Never collapse relationship confidence, completeness, structural validity, and corruption estimate into one unexplained score.
4. **No Fake Metrics**: No hardcoded 100% recovery claims, no attribution claims, and no courtroom-grade guarantees.

## Getting Started

### Prerequisites
- Python 3.11+

### Installation
```bash
cd recovery_intelligence
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### Running the Dashboard
```bash
streamlit run app.py
```

## Storage Folders
- Put raw evidence `.dd` images in `evidence/`
- Output recovered files land in `recovered/`
- Pipeline result runs are saved in `cache/` and `results/`
