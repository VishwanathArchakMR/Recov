from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from pipeline.orchestrator import run_full_pipeline


def test_streamlit_app_full_workflow():
    """
    End-to-End Streamlit Acceptance Test:
    1. App loads without errors.
    2. Primary button 'RUN FULL RECOVERY ANALYSIS' exists.
    3. Views can be navigated without triggering rerun of stages.
    4. Session state retains completed pipeline result.
    """
    app_path = Path(__file__).resolve().parent.parent / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=60)
    at.run()
    assert not at.exception, f"App raised exception on initial run: {at.exception}"

    # Verify title
    assert "Recov" in at.title[0].value

    # Verify primary button is present in sidebar
    full_run_buttons = [b for b in at.sidebar.button if "RUN FULL RECOVERY ANALYSIS" in b.label]
    assert len(full_run_buttons) == 1, "Primary run button not found in sidebar"

    # Select evidence image from dropdown
    assert len(at.sidebar.selectbox) >= 1
    evidence_selector = at.sidebar.selectbox[0]
    # Set evidence to valid file
    options = evidence_selector.options
    target_evidence = next((opt for opt in options if opt != "None"), None)
    assert target_evidence is not None, f"No evidence options found in {options}"
    evidence_selector.select(target_evidence)
    at.run()
    assert not at.exception

    # Click fresh RUN FULL RECOVERY ANALYSIS button
    run_btn = [b for b in at.sidebar.button if "RUN FULL RECOVERY ANALYSIS" in b.label][0]
    run_btn.click()
    at.run()
    assert not at.exception, f"App raised exception during full pipeline run: {at.exception}"

    # Verify session state retains result
    assert at.session_state["pipeline_completed"] is True
    assert at.session_state["active_pipeline_result"] is not None
    res = at.session_state["active_pipeline_result"]
    assert res.evidence_sha256 is not None

    # Test navigation across all views without re-executing stages
    radio = at.sidebar.radio[0]
    all_views = [
        "Analyst Workspace",
        "Overview",
        "Recovered Files",
        "Ranked Results",
        "Stage 1: Carving",
        "Stage 2: Characterization",
        "Stage 3: Fingerprinting",
        "Stage 4: Relationships & Clusters",
        "Stage 5: Reconstruction",
        "Stage 6: Integrity Scoring",
        "Stage 7: Recoverability",
        "Stage 8: Classification & Priority",
        "File Detail",
        "Relationship Graph",
        "Narrative Report",
    ]

    for view in all_views:
        # Streamlit AppTest Radio uses set_value
        radio = at.sidebar.radio[0]
        radio.set_value(view)
        at.run()
        assert not at.exception, f"App raised exception rendering view '{view}': {at.exception}"
        # Ensure session state result remains active and unmodified
        assert at.session_state["active_pipeline_result"] == res
