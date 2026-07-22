"""
ForenSight - Layer 5: Visualization (Streamlit dashboard).

UX designed with basic Human-Computer-Interaction principles:
  * Progressive disclosure   - work is grouped into TABS (Triage / Scan / Integrity /
                               Reports) instead of one long scrolling page.
  * Recognition over recall  - every control has a help tooltip; sections are labelled.
  * Visibility of status     - spinners and success/error messages on every action.
  * Colour coding for severity - High=red, Medium=amber, Low=green throughout.
  * Interactive charts        - a dropdown chooses the distribution; bars have tooltips.

Run with:  streamlit run dashboard.py
Every action is wrapped defensively so a missing file, an odd value or an old Streamlit
version cannot crash a live demo.
"""
import os
import json
import sqlite3
import pandas as pd
import altair as alt
import streamlit as st

from config import DB_PATH
from acquisition import sha256_of_file
from evidence_view import classify, text_preview, hex_preview, open_in_default_app
import integrity
from pipeline import run_pipeline

st.set_page_config(page_title="ForenSight Triage", layout="wide",
                   page_icon="🔎")

PRIORITY_RANGE = ["High", "Medium", "Low"]
PRIORITY_HEX = {"High": "#C0392B", "Medium": "#E67E22", "Low": "#27AE60"}
PRIORITY_BG = {"High": "#f8d7da", "Medium": "#fff3cd", "Low": "#d4edda"}
TABLE_COLS = ["name", "extension", "true_mime", "priority", "dfi_score",
              "integrity_score", "relevance_score", "entropy", "score_reasons"]


@st.cache_data
def load_data():
    conn = sqlite3.connect(DB_PATH)
    try:
        return pd.read_sql_query("SELECT * FROM artifacts ORDER BY dfi_score DESC", conn)
    finally:
        conn.close()


def safe_load():
    try:
        return load_data()
    except Exception:
        return pd.DataFrame()


def native(row):
    """Convert a pandas row to plain Python types so st.json shows clean values
    (fixes the 'np.int64(155)' display; NaN becomes null)."""
    try:
        return json.loads(pd.Series(row).to_json())
    except Exception:
        return {k: (None if pd.isna(v) else v) for k, v in dict(row).items()}


def style_priority(frame):
    """Colour the priority cells by severity (returns a pandas Styler)."""
    def paint(val):
        return f"background-color: {PRIORITY_BG.get(val, '')}"
    try:
        return frame.style.applymap(paint, subset=["priority"])
    except Exception:
        return frame


def render_detail(row):
    """Full evidence detail: scores, live hash check, clean metadata, preview, open."""
    path = str(row.get("path", ""))
    st.markdown(f"### {row.get('name', '(unknown)')}")

    c = st.columns(4)
    c[0].metric("DFI", int(row.get("dfi_score", 0)))
    c[1].metric("Integrity", int(row.get("integrity_score", 0)))
    c[2].metric("Relevance", int(row.get("relevance_score", 0)))
    c[3].metric("Priority", str(row.get("priority", "-")))
    st.caption(f"Reasons: {row.get('score_reasons', '')}")

    st.markdown("**Hash verification (live)**")
    stored = str(row.get("sha256") or "")
    if path and os.path.exists(path):
        try:
            current = sha256_of_file(path)
            if current == stored:
                st.success("Integrity OK — current hash matches the baseline.")
            else:
                st.error("MODIFIED — current hash does NOT match the baseline.")
            st.code(f"baseline: {stored}\ncurrent : {current}")
        except Exception as e:
            st.warning(f"Could not re-hash: {e}")
    else:
        st.warning("File not found at the recorded path (possible deletion/move).")

    with st.expander("Metadata"):
        clean = native(row)                     # numpy -> plain Python (no np.int64)
        keys = ["path", "true_mime", "claimed_mime", "extension", "size_bytes",
                "physical_size", "created_time", "modified_time", "accessed_time",
                "changed_time", "timestamp_notes", "is_deleted", "hidden_file",
                "is_in_unallocated", "case_id"]
        st.json({k: (clean.get(k) if clean.get(k) is not None else "N/A") for k in keys})

    st.markdown("**Preview**")
    mime = str(row.get("true_mime", ""))
    if path and os.path.exists(path):
        try:
            if mime.startswith("image/"):
                st.image(path, caption=row.get("name"), width=320)
            else:
                kind = classify(path)
                if kind == "text":
                    st.code(text_preview(path)[:2000] or "(empty)")
                elif kind == "binary":
                    st.code(hex_preview(path))
                else:
                    st.caption(f"({kind} — no preview)")
        except Exception as e:
            st.caption(f"(preview unavailable: {e})")
    else:
        st.caption("(no file to preview)")

    st.markdown("**Open evidence**")
    key = str(abs(hash(path)))
    b1, b2 = st.columns(2)
    if b1.button("Open file in default app", key="open_f_" + key):
        ok, msg = open_in_default_app(path)
        (st.success if ok else st.error)(msg)
    if b2.button("Open containing folder", key="open_d_" + key):
        ok, msg = open_in_default_app(os.path.dirname(path))
        (st.success if ok else st.error)(msg)
    if path and os.path.exists(path):
        try:
            if os.path.getsize(path) <= 20 * 1024 * 1024:
                with open(path, "rb") as fh:
                    st.download_button("Download evidence", fh.read(),
                                       file_name=row.get("name", "evidence"),
                                       key="dl_" + key)
        except Exception:
            pass


# True modal pop-up on recent Streamlit; inline panel as a fallback.
if hasattr(st, "dialog"):
    @st.dialog("Evidence detail")
    def _evidence_dialog(row):
        render_detail(row)

    def open_evidence(row):
        _evidence_dialog(row)
else:
    def open_evidence(row):
        with st.container(border=True):
            render_detail(row)


# ============================================================================
st.title("🔎 ForenSight — Evidence Triage Dashboard")
st.caption("Automated forensic triage: ingest, score, verify integrity, and report.")

df = safe_load()

# ---- Global filters live in the sidebar (apply to the Triage tab) ----
st.sidebar.header("Filters")
if not df.empty:
    case_opts = ["(all)"] + sorted(df["case_id"].dropna().unique().tolist())
    sel_case = st.sidebar.selectbox("Case", case_opts,
                                    help="Show artifacts from one case, or all cases.")
    sel_levels = st.sidebar.multiselect("Priority", PRIORITY_RANGE, default=PRIORITY_RANGE,
                                        help="Filter the table and chart by priority.")
else:
    sel_case, sel_levels = "(all)", PRIORITY_RANGE

tab_cases, tab_triage, tab_scan, tab_integrity, tab_timeline, tab_reports = st.tabs(
    ["📋 Cases", "📊 Triage", "📂 Scan", "🛡 Integrity", "⏱ Timeline", "📄 Reports"])

# ---------------------------------------------------------------------------
# TAB: CASES  (Improvement 2: case-level summary view)
# ---------------------------------------------------------------------------
with tab_cases:
    st.subheader("Case overview")
    if df.empty:
        st.info("No cases yet. Use the **Scan** tab to begin.")
    else:
        case_ids = sorted(df["case_id"].dropna().unique())
        rows = []
        for cid in case_ids:
            cdf = df[df["case_id"] == cid]
            rows.append({
                "Case": cid,
                "Files": len(cdf),
                "High": int((cdf["priority"] == "High").sum()),
                "Medium": int((cdf["priority"] == "Medium").sum()),
                "Low": int((cdf["priority"] == "Low").sum()),
                "Mismatches": int(cdf["type_mismatch"].sum()),
                "Deleted": int(cdf["is_deleted"].sum()) if "is_deleted" in cdf.columns else 0,
                "Disk images": int(cdf["is_disk_image"].sum()) if "is_disk_image" in cdf.columns else 0,
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# TAB: SCAN  (dynamic path scanning)
# ---------------------------------------------------------------------------
with tab_scan:
    st.subheader("Scan a folder")
    st.write("Point ForenSight at any folder. If the folder contains disk images "
             "(.dd/.E01/.img), they are automatically ingested (including deleted files).")
    sc1, sc2, sc3 = st.columns([3, 1, 1])
    scan_path = sc1.text_input("Folder path", placeholder="/home/kali/evidence",
                               help="An existing folder of files to triage.")
    scan_case = sc2.text_input("Case ID", value="CASE001",
                               help="Groups results; also names the case file.")
    scan_examiner = sc3.text_input("Examiner", value="analyst")
    if st.button("Run scan", type="primary"):
        if not scan_path or not os.path.isdir(scan_path):
            st.error("Enter a valid folder path that exists on this machine.")
        else:
            try:
                with st.spinner(f"Scanning {scan_path} (disk images will be auto-ingested)..."):
                    arts = run_pipeline(scan_path, scan_case, scan_examiner)
                load_data.clear()
                st.success(f"Scanned {len(arts)} files into case '{scan_case}'.")
                st.rerun()
            except Exception as e:
                st.error(f"Scan failed: {e}")

# ---------------------------------------------------------------------------
# TAB: TRIAGE  (metrics, interactive distribution, table, inspect pop-up)
# ---------------------------------------------------------------------------
with tab_triage:
    if df.empty:
        st.info("No scans yet. Use the **Scan** tab to analyse a folder.")
    else:
        view = df[df["priority"].isin(sel_levels)]
        if sel_case != "(all)":
            view = view[view["case_id"] == sel_case]

        m = st.columns(4)
        m[0].metric("Artifacts", len(view))
        m[1].metric("High priority", int((view["priority"] == "High").sum()))
        m[2].metric("Type mismatches", int(view["type_mismatch"].sum()))
        m[3].metric("High entropy", int(view["high_entropy"].sum()))

        # ---- Interactive distribution chart (dropdown chooses what to plot) ----
        st.subheader("Forensic distribution")
        chart_kind = st.selectbox(
            "Show distribution of", ["Priority", "File type", "DFI score"],
            help="Choose which distribution to visualise. Hover bars for exact counts.")

        if view.empty:
            st.info("No artifacts match the current filters.")
        elif chart_kind == "Priority":
            dd = (view["priority"].value_counts()
                  .reindex(PRIORITY_RANGE).fillna(0).reset_index())
            dd.columns = ["priority", "count"]
            chart = (alt.Chart(dd).mark_bar()
                     .encode(x=alt.X("priority:N", sort=PRIORITY_RANGE, title="Priority"),
                             y=alt.Y("count:Q", title="Number of files"),
                             color=alt.Color("priority:N",
                                             scale=alt.Scale(domain=PRIORITY_RANGE,
                                                             range=[PRIORITY_HEX[p] for p in PRIORITY_RANGE]),
                                             legend=None),
                             tooltip=["priority", "count"])
                     .properties(height=280))
            st.altair_chart(chart, use_container_width=True)
        elif chart_kind == "File type":
            dd = view["true_mime"].value_counts().head(10).reset_index()
            dd.columns = ["file_type", "count"]
            chart = (alt.Chart(dd).mark_bar(color="#2E75B6")
                     .encode(x=alt.X("count:Q", title="Number of files"),
                             y=alt.Y("file_type:N", sort="-x", title="True file type"),
                             tooltip=["file_type", "count"])
                     .properties(height=320))
            st.altair_chart(chart, use_container_width=True)
        else:  # DFI score histogram
            chart = (alt.Chart(view).mark_bar(color="#8E44AD")
                     .encode(x=alt.X("dfi_score:Q", bin=alt.Bin(maxbins=20),
                                     title="DFI score"),
                             y=alt.Y("count():Q", title="Number of files"),
                             tooltip=[alt.Tooltip("count():Q", title="files")])
                     .properties(height=280))
            st.altair_chart(chart, use_container_width=True)

        # ---- Ranked, severity-coloured evidence table ----
        st.subheader("Prioritized evidence")
        cols = [c for c in TABLE_COLS if c in view.columns]
        st.dataframe(style_priority(view[cols]), use_container_width=True, height=340)

        # ---- Inspect a file (clickable pop-up) ----
        st.subheader("Inspect a file")
        if not view.empty:
            chosen = st.selectbox("Select a file", view["name"].tolist(),
                                  help="Open a pop-up with details, live hash check and preview.")
            if st.button("Open evidence details", type="primary"):
                open_evidence(view[view["name"] == chosen].iloc[0])

# ---------------------------------------------------------------------------
# TAB: INTEGRITY
# ---------------------------------------------------------------------------
with tab_integrity:
    st.subheader("Integrity re-check")
    st.write("Re-hash a case and detect **modified, renamed, deleted or new** files.")
    if df.empty:
        st.info("Scan a folder first (Scan tab).")
    else:
        cases = sorted(df["case_id"].dropna().unique().tolist())
        iv1, iv2 = st.columns([1, 2])
        chk_case = iv1.selectbox("Case", cases, key="verify_case")
        chk_root = iv2.text_input("Folder to re-hash", key="verify_root",
                                  help="Needed to detect renamed and new files.")
        if st.button("Verify integrity now", type="primary"):
            try:
                changes, summary = integrity.verify(chk_case, chk_root or None)
                mm = st.columns(6)
                mm[0].metric("Baseline", summary["baseline_files"])
                mm[1].metric("Unchanged", summary["unchanged"])
                mm[2].metric("Modified", summary["modified"])
                mm[3].metric("Renamed", summary["renamed"])
                mm[4].metric("Deleted", summary["deleted"])
                mm[5].metric("New", summary["new"])
                if summary.get("seal_match") is not None:
                    if summary["seal_match"]:
                        st.success("Evidence seal MATCHES the baseline — nothing changed.")
                    else:
                        st.error("Evidence seal CHANGED — the evidence set was altered.")
                if changes:
                    cdf = pd.DataFrame(changes)
                    show_cols = ["status", "name", "baseline_mtime", "current_mtime",
                                 "old_sha256", "new_sha256", "detail"]
                    show_cols = [c for c in show_cols if c in cdf.columns]
                    st.dataframe(cdf[show_cols], use_container_width=True)
                else:
                    st.success("No changes — every baseline file still matches its hash.")
                try:
                    import case_metadata
                    case_metadata.add_custody_entry(
                        chk_case,
                        purpose=(f"Integrity verification (dashboard): "
                                 f"{summary['modified']} modified, {summary['renamed']} renamed, "
                                 f"{summary['deleted']} deleted, {summary['new']} new"),
                        method_of_transfer="ForenSight re-hash",
                        released_by="ForenSight", received_by="analyst",
                        hash_value=summary.get("current_seal") or summary.get("baseline_seal") or "")
                except Exception:
                    pass
            except Exception as e:
                st.error(f"Verification failed: {e}")

# ---------------------------------------------------------------------------
# TAB: TIMELINE  (Improvement 4: activity window visualization)
# ---------------------------------------------------------------------------
with tab_timeline:
    st.subheader("Evidence timeline")
    st.write("Files ordered by their **modified timestamp**, colored by priority — "
             "shows the activity window at a glance.")
    if df.empty:
        st.info("Scan a folder first (Scan tab).")
    else:
        tl_cases = ["(all)"] + sorted(df["case_id"].dropna().unique().tolist())
        tl_case = st.selectbox("Case", tl_cases, key="tl_case")
        tview = df.copy()
        if tl_case != "(all)":
            tview = tview[tview["case_id"] == tl_case]
        tview = tview.dropna(subset=["modified_time"])
        if tview.empty:
            st.info("No artifacts with timestamps in this case.")
        else:
            tview["mod_dt"] = pd.to_datetime(tview["modified_time"], errors="coerce",
                                             utc=True)
            tview = tview.dropna(subset=["mod_dt"]).sort_values("mod_dt")
            chart = (alt.Chart(tview).mark_circle(size=60)
                     .encode(
                         x=alt.X("mod_dt:T", title="Modified time (UTC)"),
                         y=alt.Y("dfi_score:Q", title="DFI score"),
                         color=alt.Color("priority:N",
                                         scale=alt.Scale(
                                             domain=PRIORITY_RANGE,
                                             range=[PRIORITY_HEX[p] for p in PRIORITY_RANGE]),
                                         legend=alt.Legend(title="Priority")),
                         tooltip=["name:N", "priority:N", "dfi_score:Q",
                                  alt.Tooltip("mod_dt:T", title="Modified")])
                     .properties(height=350))
            st.altair_chart(chart, use_container_width=True)

            st.caption("Files sorted by modified time:")
            st.dataframe(
                tview[["name", "modified_time", "priority", "dfi_score",
                       "true_mime", "is_deleted", "hidden_file"]]
                .rename(columns={"modified_time": "modified (UTC)"}),
                use_container_width=True, height=250)

# ---------------------------------------------------------------------------
# TAB: REPORTS
# ---------------------------------------------------------------------------
with tab_reports:
    st.subheader("Reports & export")
    st.write("Generate the case report and download it here, or export schema XML.")
    if df.empty:
        st.info("Scan a folder first (Scan tab).")
    else:
        all_cases = sorted(df["case_id"].dropna().unique().tolist())
        rc1, rc2 = st.columns(2)
        report_case = rc1.selectbox("Case", all_cases, key="report_case")
        report_examiner = rc2.text_input("Examiner", value="analyst", key="report_examiner")
        g1, g2 = st.columns(2)
        if g1.button("Generate PDF report", type="primary"):
            try:
                import report as report_mod
                with st.spinner("Building report..."):
                    path = report_mod.build_report(report_case, report_examiner)
                with open(path, "rb") as fh:
                    st.session_state["report_bytes"] = fh.read()
                    st.session_state["report_name"] = os.path.basename(path)
                st.success(f"Report ready: {os.path.basename(path)}")
            except Exception as e:
                st.error(f"Report generation failed: {e}")
        if g2.button("Generate XML export"):
            try:
                import export_xml
                path = export_xml.build_xml(report_case)
                with open(path, "rb") as fh:
                    st.session_state["xml_bytes"] = fh.read()
                    st.session_state["xml_name"] = os.path.basename(path)
                st.success(f"XML ready: {os.path.basename(path)}")
            except Exception as e:
                st.error(f"XML export failed: {e}")
        if st.session_state.get("report_bytes"):
            st.download_button("⬇ Download PDF report", st.session_state["report_bytes"],
                               file_name=st.session_state.get("report_name", "report.pdf"),
                               mime="application/pdf")
        if st.session_state.get("xml_bytes"):
            st.download_button("⬇ Download XML export", st.session_state["xml_bytes"],
                               file_name=st.session_state.get("xml_name", "export.xml"),
                               mime="application/xml")
