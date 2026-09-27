import streamlit as st
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add project root directory to python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import settings
from models.evidence import Evidence
from models.fragment import Fragment
from models.feature_vector import FeatureVector
from models.cluster import FragmentCluster
from models.reconstructed_file import ReconstructedFile
from models.pipeline_result import PipelineResult
from visualization import (
    render_overview,
    render_ranked_results,
    render_file_detail,
    render_relationship_graph,
    render_integrity_signals,
    render_narrative,
    render_file_preview,
    render_recovered_files_view,
    render_analyst_workspace,
)
from storage import load_cached_results, load_pipeline_cache
from pipeline import (
    run_full_pipeline,
    run_pipeline,
    run_stage_1,
    run_stage_2,
    run_stage_3,
    run_stage_4,
    run_stage_5,
    run_stage_6,
    run_stage_7,
    run_stage_8,
)

st.set_page_config(
    page_title="Recov",
    page_icon="🔍",
    layout="wide",
)

st.title("Recov")
st.caption("CALMSTACKS 24H HACKATHON Project | Full End-to-End Autonomous Pipeline & Forensic Recovery Workspace")


# Ensure required directories exist
settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
settings.CACHE_DIR.mkdir(parents=True, exist_ok=True)
settings.RECOVERED_DIR.mkdir(parents=True, exist_ok=True)

# Session state initialization
if "active_evidence_sha256" not in st.session_state:
    st.session_state.active_evidence_sha256 = None
if "active_pipeline_result" not in st.session_state:
    st.session_state.active_pipeline_result = None
if "pipeline_status" not in st.session_state:
    st.session_state.pipeline_status = "idle"
if "pipeline_progress" not in st.session_state:
    st.session_state.pipeline_progress = 0.0
if "pipeline_error" not in st.session_state:
    st.session_state.pipeline_error = None
if "pipeline_completed" not in st.session_state:
    st.session_state.pipeline_completed = False

if "evidence_record" not in st.session_state:
    st.session_state.evidence_record = None
if "carved_fragments" not in st.session_state:
    st.session_state.carved_fragments = []
if "characterized_fragments" not in st.session_state:
    st.session_state.characterized_fragments = []
if "feature_vectors" not in st.session_state:
    st.session_state.feature_vectors = []
if "relationship_graph" not in st.session_state:
    st.session_state.relationship_graph = {}
if "clusters" not in st.session_state:
    st.session_state.clusters = []
if "orphans" not in st.session_state:
    st.session_state.orphans = []
if "reconstructed_files" not in st.session_state:
    st.session_state.reconstructed_files = []
if "current_results" not in st.session_state:
    st.session_state.current_results = None

# Sidebar Controls
st.sidebar.title("Forensic Controls")
st.sidebar.markdown("---")

view_mode = st.sidebar.radio(
    "Select Dashboard View",
    [
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
    ],
)

st.sidebar.markdown("---")
st.sidebar.subheader("Evidence Ingestion")

# File Selection / Upload
evidence_files = sorted(
    list(settings.EVIDENCE_DIR.glob("*.dd"))
    + list(settings.EVIDENCE_DIR.glob("*.img"))
    + list(settings.EVIDENCE_DIR.glob("*.raw"))
    + list(settings.EVIDENCE_DIR.glob("*.bin"))
)

selected_evidence = st.sidebar.selectbox(
    "Select Local Evidence Image",
    options=["None"] + [f.name for f in evidence_files],
)

uploaded_file = st.sidebar.file_uploader(
    "Or Upload Evidence Segment",
    type=["dd", "img", "raw", "bin"],
)

st.sidebar.markdown("---")
st.sidebar.subheader("Cached Runs")
cache_files = list(settings.CACHE_DIR.glob("run_*.json"))
selected_cache = st.sidebar.selectbox(
    "Load Cached Pipeline Run",
    options=["None"] + [f.stem.replace("run_", "") for f in cache_files],
)

if selected_cache != "None" and st.sidebar.button("Load Cached Run"):
    results = load_cached_results(selected_cache)
    if results:
        st.session_state.current_results = results
        st.session_state.reconstructed_files = results.files
        st.session_state.clusters = results.clusters
        st.session_state.orphans = [f.id for f in results.orphans]
        st.sidebar.success(f"Loaded run '{selected_cache}' successfully!")
    else:
        st.sidebar.error("Failed to load cached run.")

st.sidebar.markdown("---")

# Target Path Resolution
target_path: Optional[str] = None
if selected_evidence != "None":
    target_path = str(settings.EVIDENCE_DIR / selected_evidence)
elif uploaded_file is not None:
    dest_path = settings.EVIDENCE_DIR / uploaded_file.name
    with open(dest_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    target_path = str(dest_path)

# ============================================================
# PRIMARY ONE-CLICK EXECUTION
# ============================================================
st.sidebar.subheader("One-Click Autonomous Recovery")
force_rerun_toggle = st.sidebar.checkbox("Force Re-analysis (Bypass Cache)", value=False)
run_full_clicked = st.sidebar.button("🚀 RUN FULL RECOVERY ANALYSIS", type="primary", use_container_width=True)

# Secondary / Advanced Developer Controls in Collapsed Expander
with st.sidebar.expander("🛠️ Advanced / Developer Stage Controls", expanded=False):
    col_btn1, col_btn2 = st.columns(2)
    run_stage1_clicked = col_btn1.button("Run Stage 1 Carve")
    run_stage2_clicked = col_btn2.button("Run Stage 2 Characterize")

    col_btn3, col_btn4 = st.columns(2)
    run_stage3_clicked = col_btn3.button("Run Stage 3 Fingerprint")
    run_stage4_clicked = col_btn4.button("Run Stage 4 Relationships")

    col_btn5, col_btn6 = st.columns(2)
    run_stage5_clicked = col_btn5.button("Run Stage 5 Reconstruct")
    run_stage6_clicked = col_btn6.button("Run Stage 6 Score")

    col_btn7, col_btn8 = st.columns(2)
    run_stage7_clicked = col_btn7.button("Run Stage 7 Recover")
    run_stage8_clicked = col_btn8.button("Run Stage 8 Classify & Rank")

if run_stage1_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Calculating SHA-256 and carving candidate fragments..."):
                evidence, fragments = run_stage_1(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = fragments
                st.sidebar.success(f"Carved {len(fragments)} fragments!")
        except Exception as e:
            st.sidebar.error(f"Stage 1 Ingestion Error: {e}")

if run_stage2_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 2: entropy + characterization..."):
                evidence, characterized = run_stage_2(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.sidebar.success(f"Characterized {len(characterized)} fragments!")
        except Exception as e:
            st.sidebar.error(f"Stage 2 Characterization Error: {e}")

if run_stage3_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 3: generating 64D feature vectors..."):
                evidence, characterized, features = run_stage_3(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.session_state.feature_vectors = features
                st.sidebar.success(f"Generated {len(features)} 64D feature vectors!")
        except Exception as e:
            st.sidebar.error(f"Stage 3 Fingerprinting Error: {e}")

if run_stage4_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 4: relationship mapping and DBSCAN clustering..."):
                evidence, characterized, features, graph, clusters, orphans = run_stage_4(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.session_state.feature_vectors = features
                st.session_state.relationship_graph = graph
                st.session_state.clusters = clusters
                st.session_state.orphans = orphans
                st.sidebar.success(f"Found {len(graph.get('edges', []))} relationships, {len(clusters)} clusters, {len(orphans)} orphans!")
        except Exception as e:
            st.sidebar.error(f"Stage 4 Analysis Error: {e}")

if run_stage5_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 5: file reconstruction and structural validation..."):
                evidence, characterized, features, graph, clusters, orphans, reconstructed = run_stage_5(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.session_state.feature_vectors = features
                st.session_state.relationship_graph = graph
                st.session_state.clusters = clusters
                st.session_state.orphans = orphans
                st.session_state.reconstructed_files = reconstructed
                st.sidebar.success(f"Reconstructed and validated {len(reconstructed)} candidate files!")
        except Exception as e:
            st.sidebar.error(f"Stage 5 Reconstruction Error: {e}")

if run_stage6_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 6: decomposed integrity scoring..."):
                evidence, characterized, features, graph, clusters, orphans, scored_files = run_stage_6(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.session_state.feature_vectors = features
                st.session_state.relationship_graph = graph
                st.session_state.clusters = clusters
                st.session_state.orphans = orphans
                st.session_state.reconstructed_files = scored_files
                st.sidebar.success(f"Evaluated decomposed integrity scores for {len(scored_files)} candidates!")
        except Exception as e:
            st.sidebar.error(f"Stage 6 Scoring Error: {e}")

if run_stage7_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 7: recoverability assessment & candidate artifact generation..."):
                evidence, characterized, features, graph, clusters, orphans, assessed_files = run_stage_7(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.session_state.feature_vectors = features
                st.session_state.relationship_graph = graph
                st.session_state.clusters = clusters
                st.session_state.orphans = orphans
                st.session_state.reconstructed_files = assessed_files
                st.sidebar.success(f"Assessed recoverability for {len(assessed_files)} candidates & generated artifacts!")
        except Exception as e:
            st.sidebar.error(f"Stage 7 Recoverability Error: {e}")

if run_stage8_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        try:
            with st.spinner("Running Stage 8: sensitivity classification & investigative priority ranking..."):
                evidence, characterized, features, graph, clusters, orphans, ranked_files = run_stage_8(target_path)
                st.session_state.evidence_record = evidence
                st.session_state.carved_fragments = characterized
                st.session_state.characterized_fragments = characterized
                st.session_state.feature_vectors = features
                st.session_state.relationship_graph = graph
                st.session_state.clusters = clusters
                st.session_state.orphans = orphans
                st.session_state.reconstructed_files = ranked_files
                st.sidebar.success(f"Classified & ranked {len(ranked_files)} candidates by investigative priority!")
        except Exception as e:
            st.sidebar.error(f"Stage 8 Classification & Priority Error: {e}")


if run_full_clicked:
    if not target_path:
        st.sidebar.warning("Please select or upload an evidence image first.")
    else:
        progress_bar = st.sidebar.progress(0.0)
        status_text = st.sidebar.empty()

        def live_status_callback(p_status):
            pct = max(0.0, min(1.0, float(getattr(p_status, "progress", 0.0))))
            progress_bar.progress(pct)
            msg = getattr(p_status, "message", "")
            stage_name = getattr(getattr(p_status, "stage", None), "value", "Running")
            status_text.text(f"[{stage_name}] {msg}")

        try:
            with st.spinner("Executing autonomous end-to-end recovery pipeline..."):
                result = run_full_pipeline(
                    target_path,
                    status_callback=live_status_callback,
                    force_rerun=force_rerun_toggle,
                )
                st.session_state.active_pipeline_result = result
                st.session_state.active_evidence_sha256 = result.evidence_sha256
                st.session_state.pipeline_completed = True
                st.session_state.pipeline_status = "completed"
                st.session_state.pipeline_progress = 1.0
                st.session_state.pipeline_error = None

                st.session_state.evidence_record = result.evidence
                st.session_state.carved_fragments = result.fragments
                st.session_state.characterized_fragments = result.characterized_fragments
                st.session_state.feature_vectors = result.feature_vectors
                st.session_state.relationship_graph = result.relationship_graph
                st.session_state.clusters = result.clusters
                st.session_state.orphans = result.orphans
                st.session_state.reconstructed_files = result.reconstructed_files
                st.session_state.current_results = result.ranked_results

                progress_bar.progress(1.0)
                if result.cached:
                    st.sidebar.success(f"⚡ Loaded cached analysis ({result.evidence_sha256[:12]}...)")
                else:
                    st.sidebar.success(f"✅ Recovery complete in {result.total_duration:.2f}s ({len(result.reconstructed_files)} candidates)!")
        except Exception as e:
            st.session_state.pipeline_error = str(e)
            st.session_state.pipeline_status = "failed"
            st.sidebar.error(f"Pipeline Error: {e}")

# Main Content Render
if view_mode == "Analyst Workspace":
    render_analyst_workspace(st.session_state.active_pipeline_result)
elif view_mode == "Overview":
    render_overview(st.session_state.active_pipeline_result or st.session_state.current_results)
elif view_mode == "Recovered Files":
    render_recovered_files_view(st.session_state.reconstructed_files)
elif view_mode == "Ranked Results":
    render_ranked_results(st.session_state.active_pipeline_result or st.session_state.current_results)
elif view_mode == "Stage 1: Carving":
    st.header("Stage 1: Evidence Ingestion & Magic-Byte Carving")
    
    evidence: Optional[Evidence] = st.session_state.evidence_record
    fragments: list[Fragment] = st.session_state.carved_fragments
    
    if not evidence:
        st.info("No evidence image analyzed yet. Select or upload an evidence file from the sidebar and click 'Run Stage 1 Carve'.")
    else:
        st.subheader("Evidence Integrity & Source")
        c1, c2, c3 = st.columns([1, 1, 2])
        c1.metric("Evidence ID", evidence.evidence_id)
        c2.metric("Size (Bytes)", f"{evidence.metadata.get('size_bytes', 0):,}")
        c3.text_input("SHA-256 Cryptographic Hash", value=evidence.sha256, disabled=True)
        st.caption(f"Source Path: `{evidence.source_path}` | Ingested At: `{evidence.created_at}`")
        
        st.markdown("---")
        st.subheader("Carving Statistics")
        
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        stat_col1.metric("Total Candidates", len(fragments))
        jpeg_count = sum(1 for f in fragments if f.type_hint == "jpeg")
        pdf_count = sum(1 for f in fragments if f.type_hint == "pdf")
        zip_count = sum(1 for f in fragments if f.type_hint == "zip")
        sqlite_count = sum(1 for f in fragments if f.type_hint == "sqlite")
        
        stat_col2.metric("JPEG Candidates", jpeg_count)
        stat_col3.metric("PDF Candidates", pdf_count)
        stat_col4.metric("ZIP / SQLite", f"{zip_count} ZIP / {sqlite_count} SQLite")
        
        st.markdown("---")
        st.subheader("Carved Fragments Table")
        
        if not fragments:
            st.warning("No candidate fragments matching supported signatures were found in this evidence file.")
        else:
            table_data = [
                {
                    "Fragment ID": f.id,
                    "Offset": f"{f.offset} (0x{f.offset:08X})",
                    "Length": f"{f.length} B",
                    "Type Hint": f.type_hint.upper(),
                    "Header": "✓ Found" if f.header_flag else "✗ Missing",
                    "Footer": "✓ Found" if f.footer_flag else "—",
                    "Source": Path(f.source).name,
                }
                for f in fragments
            ]
            st.dataframe(table_data, use_container_width=True)
            
            with st.expander("Inspect Raw Fragment Metadata (JSON)"):
                st.json([f.model_dump() for f in fragments])

elif view_mode == "Stage 2: Characterization":
    st.header("Stage 2: Fragment Characterization (Entropy Analysis)")
    fragments = st.session_state.characterized_fragments

    if not fragments:
        st.info(
            "No characterized fragments yet. Select an evidence file and click "
            "**Run Stage 2 Characterize** in the sidebar."
        )
    else:
        evidence = st.session_state.evidence_record
        if evidence:
            st.caption(
                f"Evidence: `{evidence.source_path}` | SHA-256: `{evidence.sha256[:16]}…` | "
                f"{len(fragments)} fragments characterized"
            )

        text_c = sum(1 for f in fragments if f.metadata.get("characterization") == "text")
        binary_c = sum(1 for f in fragments if f.metadata.get("characterization") == "binary")
        mixed_c = sum(1 for f in fragments if f.metadata.get("characterization") == "mixed")
        avg_entropy = sum(f.entropy for f in fragments) / len(fragments) if fragments else 0.0

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Fragments", len(fragments))
        m2.metric("Text", text_c)
        m3.metric("Binary", binary_c)
        m4.metric("Mixed", mixed_c)
        m5.metric("Avg Entropy", f"{avg_entropy:.3f}")

        st.markdown("---")
        st.subheader("Characterized Fragments Table")

        table_data = [
            {
                "Fragment ID": f.id,
                "Offset": f"{f.offset} (0x{f.offset:08X})",
                "Length": f"{f.length} B",
                "Type Hint": f.type_hint.upper(),
                "Entropy": f"{f.entropy:.4f}",
                "Characterization": f.metadata.get("characterization", "-").upper(),
                "Printable Ratio": f"{f.metadata.get('printable_ratio', 0.0):.3f}",
                "Header": "✓" if f.header_flag else "✗",
                "Footer": "✓" if f.footer_flag else "—",
            }
            for f in fragments
        ]
        st.dataframe(table_data, use_container_width=True)

        st.markdown("---")
        st.subheader("Entropy Window Chart (Select Fragment)")

        frag_ids = [f.id for f in fragments]
        selected_id = st.selectbox("Select fragment to inspect:", frag_ids)
        selected_frag = next((f for f in fragments if f.id == selected_id), None)

        if selected_frag:
            windows = selected_frag.metadata.get("entropy_windows", [])
            if windows and len(windows) > 0:
                offsets = [int(w.get("start", 0)) for w in windows]
                entropies = [float(w.get("entropy", 0.0)) for w in windows]
                if len(entropies) > 1 and not all(e is None for e in entropies):
                    import pandas as pd
                    chart_data = {
                        "Byte Offset": offsets,
                        "Window Entropy": entropies,
                    }
                    df = pd.DataFrame(chart_data).set_index("Byte Offset")
                    if not df.empty and len(df) > 1 and not df["Window Entropy"].isna().all():
                        st.line_chart(df, height=250)
                    else:
                        st.info("No entropy window data available for this candidate.")
                elif len(entropies) == 1:
                    st.info(f"Single entropy window: {entropies[0]:.4f} at offset {offsets[0]}. Insufficient points for chart.")
                else:
                    st.info("No entropy window data available for this candidate.")
                st.caption(
                    f"Whole-fragment entropy: **{selected_frag.entropy:.4f}** | "
                    f"Characterization: **{selected_frag.metadata.get('characterization', '-').upper()}** | "
                    f"Printable ratio: **{selected_frag.metadata.get('printable_ratio', 0.0):.3f}**"
                )
            else:
                st.info("No entropy window data available for this candidate.")

elif view_mode == "Stage 3: Fingerprinting":
    st.header("Stage 3: Fragment Fingerprinting (64D Feature Vectors)")
    features: List[FeatureVector] = st.session_state.feature_vectors

    if not features:
        st.info(
            "No feature vectors generated yet. Select an evidence file and click "
            "**Run Stage 3 Fingerprint** in the sidebar."
        )
    else:
        evidence = st.session_state.evidence_record
        if evidence:
            st.caption(
                f"Evidence: `{evidence.source_path}` | SHA-256: `{evidence.sha256[:16]}…` | "
                f"{len(features)} 64-dimensional feature vectors generated"
            )

        binary_c = sum(1 for fv in features if fv.metadata.get("fingerprint_method") == "binary_2gram_tfidf_svd")
        text_emb_c = sum(1 for fv in features if fv.metadata.get("fingerprint_method") == "text_minilm_embedding")
        text_fb_c = sum(1 for fv in features if fv.metadata.get("fingerprint_method") == "text_tfidf_fallback")

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Vectors", len(features))
        m2.metric("Vector Dimension", "64D")
        m3.metric("Binary 2-Gram SVD", binary_c)
        m4.metric("Text Embeddings", text_emb_c)
        m5.metric("Text TF-IDF Fallback", text_fb_c)

        st.markdown("---")
        st.subheader("Feature Vectors Table")

        table_data = [
            {
                "Fragment ID": fv.fragment_id,
                "Dimension": f"{fv.dimension}D",
                "Fingerprint Method": fv.metadata.get("fingerprint_method", "-"),
                "L2 Norm": f"{fv.metadata.get('norm', 0.0):.4f}",
                "Sample Dimension Preview": str([round(x, 4) for x in fv.vector[:6]]) + "...",
            }
            for fv in features
        ]
        st.dataframe(table_data, use_container_width=True)

        st.markdown("---")
        st.subheader("Feature Vector Inspector (64 Dimensions)")

        fv_ids = [fv.fragment_id for fv in features]
        selected_id = st.selectbox("Select fragment vector to inspect:", fv_ids)
        selected_fv = next((fv for fv in features if fv.fragment_id == selected_id), None)

        if selected_fv:
            if selected_fv.vector and len(selected_fv.vector) > 1 and not all(v is None for v in selected_fv.vector):
                import pandas as pd
                chart_df = pd.DataFrame({
                    "Dimension Index": list(range(1, len(selected_fv.vector) + 1)),
                    "Value": [float(v) for v in selected_fv.vector],
                }).set_index("Dimension Index")
                if not chart_df.empty and len(chart_df) > 1 and not chart_df["Value"].isna().all():
                    st.line_chart(chart_df, height=250)
                else:
                    st.info("No vector data available for this candidate.")
            elif selected_fv.vector and len(selected_fv.vector) == 1:
                st.info(f"Single vector value: {selected_fv.vector[0]:.4f}. Insufficient points for chart.")
            else:
                st.info("No vector data available for this candidate.")

            st.caption(
                f"Method: `{selected_fv.metadata.get('fingerprint_method', '-')}` | "
                f"Vector Length: `{len(selected_fv.vector)}` | "
                f"L2 Norm: `{selected_fv.metadata.get('norm', 0.0):.4f}`"
            )

            with st.expander("View Complete 64-Dimensional Float Array"):
                st.write(selected_fv.vector)

elif view_mode == "Stage 4: Relationships & Clusters":
    st.header("Stage 4: Relationship Analysis & DBSCAN Fragment Clustering")
    
    graph: Dict[str, Any] = st.session_state.relationship_graph
    clusters: List[FragmentCluster] = st.session_state.clusters
    orphans: List[str] = st.session_state.orphans

    if not graph or not graph.get("nodes"):
        st.info(
            "No relationship or cluster data available yet. Select an evidence file and click "
            "**Run Stage 4 Relationships** in the sidebar."
        )
    else:
        evidence = st.session_state.evidence_record
        if evidence:
            st.caption(
                f"Evidence: `{evidence.source_path}` | SHA-256: `{evidence.sha256[:16]}…` | "
                f"{len(graph.get('nodes', []))} fragments analyzed"
            )

        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        col_m1.metric("Total Fragments", len(graph.get("nodes", [])))
        col_m2.metric("Relationship Edges", len(graph.get("edges", [])))
        col_m3.metric("DBSCAN Clusters", len(clusters))
        col_m4.metric("Orphan Fragments", len(orphans))

        st.markdown("---")
        st.subheader("Discovered Fragment Clusters")

        if not clusters:
            st.warning("No multi-fragment clusters met the DBSCAN density threshold (eps=0.30, min_samples=2).")
        else:
            cluster_table = [
                {
                    "Cluster ID": c.cluster_id,
                    "Members Count": len(c.member_fragment_ids),
                    "Member IDs": ", ".join(c.member_fragment_ids),
                    "Inferred Type": c.inferred_type.upper(),
                    "Confidence": f"{c.confidence:.2f}",
                    "Reason": c.reason,
                }
                for c in clusters
            ]
            st.dataframe(cluster_table, use_container_width=True)

        st.markdown("---")
        st.subheader("Weighted Relationship Edges")

        edges = graph.get("edges", [])
        if not edges:
            st.info("No pairwise relationship edges exceeded the minimum graph edge weight threshold.")
        else:
            edge_table = [
                {
                    "Source": e["source"],
                    "Target": e["target"],
                    "Vector Similarity": f"{e['similarity']:.4f}",
                    "Offset Proximity": f"{e['offset_proximity']:.4f}",
                    "Type Compatibility": f"{e['type_match']:.2f}",
                    "Final Edge Weight": f"{e['edge_weight']:.4f}",
                    "Reason": e.get("reason", "-"),
                }
                for e in edges
            ]
            st.dataframe(edge_table, use_container_width=True)

        st.markdown("---")
        st.subheader("Orphan / Noise Fragments")

        if not orphans:
            st.success("All analyzed fragments were assigned to cohesive clusters!")
        else:
            frag_map = {f.id: f for f in st.session_state.carved_fragments}
            orphan_table = [
                {
                    "Fragment ID": oid,
                    "Type Hint": frag_map[oid].type_hint.upper() if oid in frag_map else "UNKNOWN",
                    "Offset": f"{frag_map[oid].offset} (0x{frag_map[oid].offset:08X})" if oid in frag_map else "-",
                    "Length": f"{frag_map[oid].length} B" if oid in frag_map else "-",
                    "Entropy": f"{frag_map[oid].entropy:.4f}" if oid in frag_map else "-",
                    "Characterization": frag_map[oid].metadata.get("characterization", "-").upper() if oid in frag_map else "-",
                }
                for oid in orphans
            ]
            st.dataframe(orphan_table, use_container_width=True)

        st.markdown("---")
        render_relationship_graph(graph)

elif view_mode == "Stage 5: Reconstruction":
    st.header("Stage 5: Candidate File Reconstruction & Structural Validation")
    st.caption("Assembly of cluster fragments by deterministic offset order and real parser validation (Pillow, pypdf/PyPDF2, python-docx, zipfile, sqlite3).")

    reconstructed_list: List[ReconstructedFile] = st.session_state.reconstructed_files
    clusters_list = st.session_state.clusters

    if not reconstructed_list:
        st.info("No reconstruction results available. Select or upload an evidence image and click 'Run Stage 5 Reconstruction' from the sidebar.")
    else:
        # Summary Metrics
        st.subheader("Reconstruction & Validation Summary")
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Candidate Clusters", len(clusters_list))
        m2.metric("Reconstruction Attempts", len(reconstructed_list))

        success_count = sum(1 for r in reconstructed_list if r.status == "reconstructed")
        failed_count = sum(1 for r in reconstructed_list if r.status == "validation_failed")
        ambiguous_count = sum(1 for r in reconstructed_list if r.ambiguous or r.status == "ambiguous")

        m3.metric("Successfully Validated", success_count)
        m4.metric("Validation Failed", failed_count)
        m5.metric("Ambiguous", ambiguous_count)

        st.markdown("---")
        st.subheader("Reconstruction Candidates")

        # Table
        recon_rows = []
        for r in reconstructed_list:
            recon_rows.append({
                "Candidate ID": r.id,
                "Cluster": r.cluster_id,
                "File Type": r.file_type.upper(),
                "Fragments": len(r.fragment_ids),
                "Status": r.status.upper(),
                "Structural Validity": f"{r.structural_validity:.1f}",
                "Parser Message": r.parser_message,
            })
        st.dataframe(recon_rows, use_container_width=True)

        st.markdown("---")
        st.subheader("Candidate Detail Inspector")

        cand_options = [r.id for r in reconstructed_list]
        selected_cand_id = st.selectbox("Select Candidate to Inspect", options=cand_options)

        selected_recon = next((r for r in reconstructed_list if r.id == selected_cand_id), None)
        if selected_recon:
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.markdown(f"**Cluster ID:** `{selected_recon.cluster_id}`")
                st.markdown(f"**Inferred File Type:** `{selected_recon.file_type}`")
                st.markdown(f"**Status:** `{selected_recon.status}`")
                st.markdown(f"**Structural Validity:** `{selected_recon.structural_validity}`")
                st.markdown(f"**Ordered Fragment IDs:** {', '.join(f'`{fid}`' for fid in selected_recon.fragment_ids) if selected_recon.fragment_ids else 'None'}")

            with col_d2:
                # Find candidate file on disk
                ext = ".jpg" if selected_recon.file_type == "jpeg" else (f".{selected_recon.file_type}" if selected_recon.file_type != "unknown" else ".bin")
                cand_path = settings.RECOVERED_DIR / f"{selected_recon.id}{ext}"
                if not cand_path.exists():
                    cand_path = settings.RECOVERED_DIR / f"{selected_recon.id}.bin"

                st.markdown(f"**Candidate File Path:** `{cand_path}`")
                st.markdown(f"**File Exists on Disk:** `{cand_path.exists()}`")
                st.markdown(f"**Parser Result / Message:** {selected_recon.parser_message}")

                if cand_path.exists():
                    try:
                        with open(cand_path, "rb") as cf:
                            file_bytes = cf.read()
                        st.download_button(
                            label=f"Download {cand_path.name} ({len(file_bytes):,} B)",
                            data=file_bytes,
                            file_name=cand_path.name,
                            mime="application/octet-stream",
                        )
                    except Exception:
                        pass

            st.markdown("##### Gap Information")
            gap_info = selected_recon.gap_information
            if not gap_info or not gap_info.get("has_gaps"):
                st.success("No gaps detected between fragments. Fragments form a continuous sequence.")
            else:
                st.warning(f"Detected {gap_info.get('gap_count', 0)} non-contiguous gap(s) totaling {gap_info.get('total_gap_bytes', 0):,} missing bytes.")
                gaps = gap_info.get("gaps", [])
                if gaps:
                    gap_rows = [
                        {
                            "From Fragment": g.get("prev_fragment_id"),
                            "To Fragment": g.get("next_fragment_id"),
                            "Gap Offset Start": f"{g.get('gap_start')} (0x{g.get('gap_start', 0):08X})",
                            "Gap Length": f"{g.get('gap_length')} B",
                        }
                        for g in gaps
                    ]
                    st.dataframe(gap_rows, use_container_width=True)

elif view_mode == "Stage 6: Integrity Scoring":
    st.header("Stage 6: Decomposed Integrity Scoring")
    st.caption("Four independent engineering signals (Confidence, Completeness, Validity, Corruption) combined into a transparent composite score for candidate prioritization.")

    reconstructed_list: List[ReconstructedFile] = st.session_state.reconstructed_files

    if not reconstructed_list:
        st.info("No candidates scored yet. Select or upload an evidence image and click 'Run Stage 6 Score' from the sidebar.")
    else:
        # Summary Metrics
        st.subheader("Integrity Scoring Summary")
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Candidates", len(reconstructed_list))

        validated_cnt = sum(1 for r in reconstructed_list if r.status == "reconstructed" or r.structural_validity >= 1.0)
        failed_cnt = sum(1 for r in reconstructed_list if r.status == "validation_failed" or r.structural_validity == 0.0)
        ambig_cnt = sum(1 for r in reconstructed_list if r.ambiguous or r.status == "ambiguous")
        avg_integ = sum(r.composite_integrity_score for r in reconstructed_list) / max(1, len(reconstructed_list))

        m2.metric("Validated", validated_cnt)
        m3.metric("Failed", failed_cnt)
        m4.metric("Ambiguous", ambig_cnt)
        m5.metric("Average Integrity", f"{avg_integ * 100:.1f}%")

        st.markdown("---")
        st.subheader("Candidate Integrity Table")

        score_table = [
            {
                "Candidate ID": r.id,
                "Cluster": r.cluster_id,
                "File Type": r.file_type.upper(),
                "Reconstruction Confidence": f"{r.reconstruction_confidence * 100:.1f}%",
                "Completeness": f"{r.completeness * 100:.1f}%",
                "Structural Validity": f"{r.structural_validity * 100:.1f}%",
                "Corruption Estimate": f"{r.corruption_estimate * 100:.1f}%",
                "Composite Integrity": f"{r.composite_integrity_score * 100:.1f}%",
                "Status": r.status.upper(),
            }
            for r in reconstructed_list
        ]
        st.dataframe(score_table, use_container_width=True)

        st.markdown("---")
        st.subheader("Candidate Signal Breakdown & Inspection")

        cand_options = [r.id for r in reconstructed_list]
        selected_cand_id = st.selectbox("Select Candidate to Inspect Signals", options=cand_options)
        selected_recon = next((r for r in reconstructed_list if r.id == selected_cand_id), None)

        if selected_recon:
            render_integrity_signals(selected_recon)

elif view_mode == "Stage 7: Recoverability":
    st.header("Stage 7: Real Recoverability Assessment & Disrupted-File Reconstruction")
    st.caption("Factual quantification of surviving fragment bytes vs missing/unknown gaps, deterministic recovery status, and disk artifact generation.")

    reconstructed_list: List[ReconstructedFile] = st.session_state.reconstructed_files

    if not reconstructed_list:
        st.info("No recoverability assessment performed yet. Select or upload an evidence image and click 'Run Stage 7 Recover' from the sidebar.")
    else:
        # 1. Summary Metrics
        st.subheader("Recoverability Status Breakdown")
        
        c_tot = len(reconstructed_list)
        c_full = sum(1 for r in reconstructed_list if r.recovery_status == "FULLY_RECONSTRUCTED")
        c_partial = sum(1 for r in reconstructed_list if r.recovery_status == "PARTIALLY_RECONSTRUCTED")
        c_struct_partial = sum(1 for r in reconstructed_list if r.recovery_status == "STRUCTURALLY_VALID_PARTIAL")
        c_invalid = sum(1 for r in reconstructed_list if r.recovery_status == "STRUCTURALLY_INVALID")
        c_ambig = sum(1 for r in reconstructed_list if r.recovery_status == "AMBIGUOUS")
        c_unrec = sum(1 for r in reconstructed_list if r.recovery_status == "UNRECOVERABLE")

        m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
        m1.metric("Candidates", c_tot)
        m2.metric("Fully Recon", c_full)
        m3.metric("Partial Recon", c_partial)
        m4.metric("Struct Valid Partial", c_struct_partial)
        m5.metric("Invalid", c_invalid)
        m6.metric("Ambiguous", c_ambig)
        m7.metric("Unrecoverable", c_unrec)

        st.markdown("---")

        # 2. Metric Definition Notice
        st.info(
            "📌 **Observed Recovery Ratio**: Recovered bytes relative to the observed candidate span; "
            "this is not the original-file recovery percentage."
        )

        # 3. Candidates Recoverability Table
        st.subheader("Candidate Recoverability Table")

        recov_table = [
            {
                "Candidate ID": r.candidate_id or r.id,
                "File Type": r.file_type.upper(),
                "Fragments Used": r.fragment_count or len(r.fragment_ids),
                "Recovered Bytes": f"{r.recovered_bytes:,} B",
                "Missing/Unknown Bytes": f"{r.missing_or_unknown_bytes:,} B",
                "Observed Candidate Span": f"{r.observed_candidate_span:,} B",
                "Observed Recovery Ratio": f"{r.observed_recovery_ratio * 100:.1f}% ({r.observed_recovery_ratio:.4f})",
                "Reconstruction Confidence": f"{r.reconstruction_confidence * 100:.1f}%",
                "Completeness": f"{r.completeness * 100:.1f}%",
                "Structural Validity": f"{r.structural_validity * 100:.1f}%",
                "Corruption Estimate": f"{r.corruption_estimate * 100:.1f}%",
                "Composite Integrity": f"{r.composite_integrity_score * 100:.1f}%",
                "Recovery Status": r.recovery_status,
                "Output SHA-256": r.output_sha256 if r.output_sha256 else "—",
                "Output File Path": r.output_path if r.output_path else "—",
            }
            for r in reconstructed_list
        ]
        st.dataframe(recov_table, use_container_width=True)

        st.markdown("---")

        # 4. Detailed Candidate Inspector & Artifact Download
        st.subheader("Recovered Candidate Inspection & Download")

        cand_options = [r.candidate_id or r.id for r in reconstructed_list]
        selected_cand_id = st.selectbox("Select Candidate to Inspect & Download", options=cand_options)
        selected_recon = next((r for r in reconstructed_list if (r.candidate_id or r.id) == selected_cand_id), None)

        if selected_recon:
            col_left, col_right = st.columns([3, 2])

            with col_left:
                st.markdown("##### Machine-Generated Recovery Summary")
                st.info(selected_recon.recovery_reason if selected_recon.recovery_reason else "No summary available.")

                st.markdown("##### Recoverability Details")
                d_c1, d_c2, d_c3 = st.columns(3)
                d_c1.metric("Recovered Bytes", f"{selected_recon.recovered_bytes:,} B")
                d_c2.metric("Missing/Unknown Bytes", f"{selected_recon.missing_or_unknown_bytes:,} B")
                d_c3.metric("Observed Span", f"{selected_recon.observed_candidate_span:,} B")

                st.markdown(f"**Observed Recovery Ratio:** `{selected_recon.observed_recovery_ratio * 100:.2f}%` ({selected_recon.observed_recovery_ratio:.4f})")
                st.markdown(f"**Recovery Status:** `{selected_recon.recovery_status}`")
                st.markdown(f"**Structural Validity:** `{selected_recon.structural_validity * 100:.1f}%`")
                st.markdown(f"**Parser Result / Diagnostic:** {selected_recon.parser_message if selected_recon.parser_message else 'None'}")

            with col_right:
                st.markdown("##### Recovered Artifact File")
                cand_path = Path(selected_recon.output_path) if selected_recon.output_path else None
                file_exists = cand_path.exists() if cand_path else False

                st.markdown(f"**Artifact Path:** `{cand_path}`")
                st.markdown(f"**Artifact Exists on Disk:** `{file_exists}`")
                st.markdown(f"**SHA-256 Digest:** `{selected_recon.output_sha256 if selected_recon.output_sha256 else 'N/A'}`")

                if file_exists:
                    try:
                        with open(cand_path, "rb") as af:
                            artifact_data = af.read()
                        
                        st.metric("Artifact Size", f"{len(artifact_data):,} Bytes")
                        st.download_button(
                            label=f"⬇️ Download {cand_path.name} ({len(artifact_data):,} B)",
                            data=artifact_data,
                            file_name=cand_path.name,
                            mime="application/octet-stream",
                            type="primary",
                        )
                    except Exception as e:
                        st.error(f"Error reading artifact for download: {e}")
                else:
                    st.warning("No artifact file written on disk for this candidate.")

            # Gap Details
            st.markdown("##### Fragment & Gap Sequence")
            gap_info = selected_recon.gap_information
            if not gap_info or not gap_info.get("has_gaps"):
                st.success("No internal gaps between associated fragments.")
            else:
                st.warning(f"Contains {gap_info.get('gap_count', 0)} gap(s) totaling {gap_info.get('total_gap_bytes', 0):,} missing bytes.")
                gaps = gap_info.get("gaps", [])
                if gaps:
                    gap_rows = [
                        {
                            "From Fragment": g.get("prev_fragment_id"),
                            "To Fragment": g.get("next_fragment_id"),
                            "Gap Offset Start": f"{g.get('gap_start')} (0x{g.get('gap_start', 0):08X})",
                            "Gap Length": f"{g.get('gap_length')} B",
                        }
                        for g in gaps
                    ]
                    st.dataframe(gap_rows, use_container_width=True)

elif view_mode == "Stage 8: Classification & Priority":
    st.header("Stage 8: Sensitivity Classification & Investigative Priority Ranking")
    st.caption("Deterministic pattern detection of sensitive identifiers and factual investigative prioritization grounded in observable recovered content and pipeline signals.")

    reconstructed_list: List[ReconstructedFile] = st.session_state.reconstructed_files

    if not reconstructed_list:
        st.info("No candidates classified yet. Select or upload an evidence image and click 'Run Stage 8 Classify & Rank' from the sidebar.")
    else:
        # 1. Summary Metrics
        st.subheader("Classification & Priority Overview")
        
        c_tot = len(reconstructed_list)
        c_sensitive = sum(1 for r in reconstructed_list if (r.sensitivity_level or "NONE") != "NONE")
        c_high = sum(1 for r in reconstructed_list if (r.sensitivity_level or "NONE") == "HIGH")
        c_med = sum(1 for r in reconstructed_list if (r.sensitivity_level or "NONE") == "MEDIUM")
        c_low_none = sum(1 for r in reconstructed_list if (r.sensitivity_level or "NONE") in ("LOW", "NONE"))
        c_struct_valid = sum(1 for r in reconstructed_list if (r.structural_validity or 0.0) >= 1.0)
        c_ranked = len([r for r in reconstructed_list if r.priority_score is not None])

        m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
        m1.metric("Total Candidates", c_tot)
        m2.metric("Sensitive Candidates", c_sensitive)
        m3.metric("High Sensitivity", c_high)
        m4.metric("Medium Sensitivity", c_med)
        m5.metric("Low/None", c_low_none)
        m6.metric("Candidates with Structural Validation", c_struct_valid)
        m7.metric("Ranked Candidates", c_ranked)

        st.markdown("---")

        # 2. Informational Notice
        st.info(
            "ℹ️ **Deterministic Sensitivity & Priority Policy**: "
            "Detections are factual matches against defined technical patterns (regex/keywords) and indicate potential "
            "sensitive identifiers. They do not assert live identity, individual ownership, or courtroom admissibility. "
            "Priority ordering is an objective investigative filter based strictly on observable integrity, recoverability, and sensitivity."
        )

        # 3. Ranked Table
        st.subheader("Investigative Priority Ranked Candidates")

        ranked_table = [
            {
                "Rank": idx + 1,
                "Candidate": r.candidate_id or r.id,
                "File Type": r.file_type.upper(),
                "Recovery Status": r.recovery_status or r.status,
                "Observed Recovery Ratio": f"{r.observed_recovery_ratio * 100:.1f}%",
                "Integrity": f"{r.composite_integrity_score * 100:.1f}%",
                "Sensitivity": r.sensitivity_level or "NONE",
                "Detected Categories": ", ".join(r.detected_categories) if r.detected_categories else "None",
                "Priority": f"{r.priority_score:.4f}" if r.priority_score is not None else "0.0000",
                "Output": Path(r.output_path).name if r.output_path else "—",
            }
            for idx, r in enumerate(reconstructed_list)
        ]
        st.dataframe(ranked_table, use_container_width=True)

        st.markdown("---")

        # 4. Detailed Candidate Inspector
        st.subheader("Candidate Priority & Sensitivity Inspector")

        cand_options = [r.candidate_id or r.id for r in reconstructed_list]
        selected_cand_id = st.selectbox("Select Candidate to Inspect", options=cand_options)
        selected_recon = next((r for r in reconstructed_list if (r.candidate_id or r.id) == selected_cand_id), None)

        if selected_recon:
            col_left, col_right = st.columns([3, 2])

            with col_left:
                st.markdown("##### Factual Priority Reason")
                st.success(selected_recon.priority_reason if selected_recon.priority_reason else "No priority reason computed.")

                st.markdown("##### Sensitivity Classification Findings")
                s1, s2, s3 = st.columns(3)
                s1.metric("Sensitivity Level", selected_recon.sensitivity_level or "NONE")
                s2.metric("Categories Found", len(selected_recon.detected_categories) if selected_recon.detected_categories else 0)
                s3.metric("Pattern Matches", len(selected_recon.sensitivity_matches) if selected_recon.sensitivity_matches else 0)

                if selected_recon.detected_categories:
                    st.markdown(f"**Detected Categories:** `{', '.join(selected_recon.detected_categories)}`")
                else:
                    st.markdown("**Detected Categories:** `None`")

                if selected_recon.sensitivity_matches:
                    st.markdown("###### Matched Pattern Snippets (Masked)")
                    match_rows = [
                        {
                            "Category": m.get("category", ""),
                            "Masked Text": m.get("masked_text", ""),
                            "Byte Offset": m.get("offset", 0),
                            "Pattern Name": m.get("pattern_name", ""),
                            "Context": m.get("context", ""),
                        }
                        for m in selected_recon.sensitivity_matches
                    ]
                    st.dataframe(match_rows, use_container_width=True)

                st.markdown("##### Recovery Metrics")
                r1, r2, r3, r4 = st.columns(4)
                r1.metric("Recovered Bytes", f"{selected_recon.recovered_bytes:,} B")
                r2.metric("Missing/Unknown", f"{selected_recon.missing_or_unknown_bytes:,} B")
                r3.metric("Observed Span", f"{selected_recon.observed_candidate_span:,} B")
                r4.metric("Recovery Ratio", f"{selected_recon.observed_recovery_ratio * 100:.1f}%")

            with col_right:
                st.markdown("##### Recovered Artifact File")
                cand_path = Path(selected_recon.output_path) if selected_recon.output_path else None
                file_exists = cand_path.exists() if cand_path else False

                st.markdown(f"**Artifact Path:** `{cand_path}`")
                st.markdown(f"**Artifact Exists on Disk:** `{file_exists}`")
                st.markdown(f"**SHA-256 Digest:** `{selected_recon.output_sha256 if selected_recon.output_sha256 else 'N/A'}`")
                st.markdown(f"**Investigative Priority Score:** `{selected_recon.priority_score:.4f}`")

                if file_exists:
                    try:
                        with open(cand_path, "rb") as af:
                            artifact_data = af.read()
                        st.download_button(
                            label=f"⬇️ Download {cand_path.name} ({len(artifact_data):,} B)",
                            data=artifact_data,
                            file_name=cand_path.name,
                            mime="application/octet-stream",
                            type="secondary",
                        )
                    except Exception as e:
                        st.error(f"Error reading artifact: {e}")

            st.markdown("---")
            st.markdown("##### Preserved Stage 6 Integrity Signals")
            render_integrity_signals(selected_recon)

elif view_mode == "File Detail":
    selected_file = None
    ev_sha = st.session_state.active_evidence_sha256 or (st.session_state.evidence_record.sha256 if st.session_state.evidence_record else "")
    if st.session_state.reconstructed_files:
        cand_ids = [r.candidate_id or r.id for r in st.session_state.reconstructed_files]
        chosen_id = st.selectbox("Select Candidate File", options=cand_ids)
        selected_file = next((r for r in st.session_state.reconstructed_files if (r.candidate_id or r.id) == chosen_id), None)
    elif st.session_state.current_results and hasattr(st.session_state.current_results, "reconstructed_files") and st.session_state.current_results.reconstructed_files:
        selected_file = st.session_state.current_results.reconstructed_files[0]
    elif st.session_state.current_results and hasattr(st.session_state.current_results, "files") and st.session_state.current_results.files:
        selected_file = st.session_state.current_results.files[0]
    render_file_detail(selected_file, evidence_sha256=ev_sha)
elif view_mode == "Relationship Graph":
    graph_data = st.session_state.relationship_graph if st.session_state.relationship_graph else (st.session_state.current_results.relationship_graph if hasattr(st.session_state.current_results, "relationship_graph") else None)
    render_relationship_graph(graph_data)
elif view_mode == "Narrative Report":
    narrative_data = getattr(st.session_state.current_results, "narrative", None)
    res_obj = st.session_state.active_pipeline_result or st.session_state.current_results
    render_narrative(narrative=narrative_data, pipeline_result=res_obj)