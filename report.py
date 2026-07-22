"""
ForenSight - Automated forensic report (PDF), organised to a standard DFIR structure.

Section order (standards-aligned):
    1. Case Information
    2. Chain of Custody
    3. Evidence Source (Acquisition)
    4. Examination Tools & Method
    5. Findings - Triage Summary (with a priority-distribution chart)
    6. File Integrity Verification (changes detected)
    Appendix A. Evidence Item Information (per-file, schema-aligned)

Reports are NEVER overwritten: each file is named
    forensight_report_<case>_<YYYYMMDD_HHMMSS>.pdf

Chain of Custody and Evidence Source come from case_<case>.json (auto-populated on each
scan; edit that file to add or correct narrative details).
"""
import argparse
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

from database import load_dataframe, load_latest_integrity
from case_metadata import load_case

NAVY = colors.HexColor("#1F3864")
PRIORITY_COLORS = {"High": colors.HexColor("#C0392B"),
                   "Medium": colors.HexColor("#E67E22"),
                   "Low": colors.HexColor("#27AE60")}

# A small paragraph style so text WRAPS inside narrow table cells instead of being cut off.
_STYLES = getSampleStyleSheet()
CELL = ParagraphStyle("cell", parent=_STYLES["BodyText"], fontSize=6.5, leading=8)
CELL_B = ParagraphStyle("cellb", parent=CELL, fontName="Helvetica-Bold")


def _P(text):
    """Wrap a value in a small Paragraph (wraps to multiple lines, never truncates)."""
    return Paragraph("-" if text in (None, "") else str(text), CELL)


def _fmt_ts(value):
    """Format any stored ISO time as 'YYYY-MM-DD HH:MM:SS UTC' for forensic logging.
    Full hours/minutes/seconds are shown on every date field to preserve chronology."""
    if not value:
        return "-"
    s = str(value)
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return s.replace("T", " ")


def _hash(value):
    """Format a SHA-256 for a report table: show first 16 + last 8 chars with ellipsis.
    Readable and identifiable without overflowing a narrow column.
    The full hash is always available in the Evidence Source and audit log."""
    s = str(value or "").strip()
    if not s or s == "-":
        return _P("-")
    if len(s) <= 20:
        return _P(s)
    return _P(f"{s[:16]}...{s[-8:]}")


def _path(value):
    """Show just the last two path components so long absolute paths don't overflow cells.
    E.g. /home/kali/PROJECT/forensight_aplus/evidence -> ...forensight_aplus/evidence"""
    s = str(value or "").strip()
    if not s or s == "-":
        return _P("-")
    parts = s.replace("\\", "/").rstrip("/").split("/")
    if len(parts) <= 2:
        return _P(s)
    return _P("..." + "/".join(parts[-2:]))


def _kv_table(pairs):
    """Two-column key/value table used for Case Info, Custody narrative, Evidence Source."""
    data = [[Paragraph(f"<b>{k}</b>", CELL), _P(v)] for k, v in pairs]
    tbl = Table(data, colWidths=[2.2 * inch, 4.3 * inch])
    tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0FA"))]))
    return tbl


def _priority_chart(counts):
    """A colored vertical bar chart of the High/Medium/Low counts (High=red ... Low=green)."""
    order = ["High", "Medium", "Low"]
    drawing = Drawing(420, 170)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.height, chart.width = 40, 25, 120, 340
    chart.data = [[int(counts.get(k, 0)) for k in order]]
    chart.categoryAxis.categoryNames = order
    chart.valueAxis.valueMin = 0
    chart.barWidth = 18
    chart.groupSpacing = 30
    for i, name in enumerate(order):           # colour each bar by severity
        chart.bars[(0, i)].fillColor = PRIORITY_COLORS[name]
    drawing.add(chart)
    return drawing


def build_report(case_id, examiner, out=None):
    df = load_dataframe()
    if case_id:
        df = df[df["case_id"] == case_id]
    case = load_case(case_id) or {}

    styles = _STYLES
    title = ParagraphStyle("t", parent=styles["Title"], textColor=NAVY)
    story = [Paragraph("ForenSight Forensic Triage Report", title), Spacer(1, 0.1 * inch)]

    # ---- 1. Case Information ----
    story.append(Paragraph("1. Case Information", styles["Heading2"]))
    story.append(_kv_table([
        ("Case ID", case_id or "ALL"),
        ("Examiner", examiner),
        ("Report generated (UTC)", datetime.now(timezone.utc).isoformat()),
        ("Tool", "ForenSight v1 (rule-based triage framework)"),
    ]))
    story.append(Spacer(1, 0.18 * inch))

    # ---- 1b. Executive Summary (auto-generated from the data) ----
    total = len(df)
    counts = {k: int((df["priority"] == k).sum()) for k in ("High", "Medium", "Low")} \
        if total else {"High": 0, "Medium": 0, "Low": 0}
    mism = int(df["type_mismatch"].sum()) if total else 0
    deleted_n = int(df["is_deleted"].sum()) if total and "is_deleted" in df.columns else 0
    hidden_n = int(df["hidden_file"].sum()) if total and "hidden_file" in df.columns else 0
    ievents_sum = load_latest_integrity(case_id) if case_id else None
    changes_n = len(ievents_sum) if ievents_sum is not None and not ievents_sum.empty else 0

    summary_parts = [f"{total} artifact(s) were examined"]
    if counts["High"]:
        summary_parts.append(f"{counts['High']} flagged High priority")
    if mism:
        summary_parts.append(f"{mism} type mismatch(es) detected")
    if deleted_n:
        summary_parts.append(f"{deleted_n} recovered deleted file(s)")
    if hidden_n:
        summary_parts.append(f"{hidden_n} hidden file(s)")
    if changes_n:
        summary_parts.append(f"{changes_n} file change(s) detected since acquisition")
    summary_text = "; ".join(summary_parts) + "."

    story.append(Paragraph("Executive Summary", styles["Heading3"]))
    story.append(Paragraph(summary_text, styles["Normal"]))
    story.append(Spacer(1, 0.12 * inch))

    # ---- 2. Chain of Custody ----
    coc = case.get("chain_of_custody", {})
    story.append(Paragraph("2. Chain of Custody", styles["Heading2"]))
    story.append(_kv_table([
        ("Date", _fmt_ts(coc.get("date"))),
        ("Received/Seized from", coc.get("received_seized_from")),
        ("Received/Seized by", coc.get("received_seized_by")),
        ("Reason obtained", coc.get("reason_obtained")),
        ("Location from where obtained",
         "..." + "/".join((coc.get("location_obtained") or "").replace("\\", "/")
                          .rstrip("/").split("/")[-2:]) if coc.get("location_obtained") else "-"),
        ("Description of evidence", coc.get("description_of_evidence")),
    ]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Change of custody log", styles["Heading3"]))
    log = coc.get("custody_log", [])
    if log:
        # Header + rows, every cell a wrapping Paragraph so nothing is truncated.
        header = ["Purpose", "Method", "Released by", "Released",
                  "Received by", "Received", "Hash"]
        rows = [[Paragraph(f"<b>{h}</b>", CELL_B) for h in header]]
        for e in log:
            rows.append([
                _P(e.get("purpose_of_change")), _P(e.get("method_of_transfer")),
                _P(e.get("released_by")), _P(_fmt_ts(e.get("released_date"))),
                _P(e.get("received_by")), _P(_fmt_ts(e.get("received_date"))),
                _hash(e.get("hash_value"))])
        # Widths sum to 6.5" (letter minus 1" margins). Purpose/Hash get the most room.
        widths = [1.15, 0.9, 0.7, 0.95, 0.7, 0.95, 1.15]
        t = Table(rows, colWidths=[w * inch for w in widths], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F2F5FB")])]))
        story.append(t)
    else:
        story.append(Paragraph("No custody transfers recorded.", styles["Italic"]))
    story.append(Spacer(1, 0.18 * inch))

    # ---- 3. Evidence Source (Acquisition) ----
    src = case.get("evidence_source", {})
    story.append(Paragraph("3. Evidence Source (Acquisition)", styles["Heading2"]))
    if src:
        # Format specific fields for readability: hash shortened, path shortened.
        hash_fields = {"EvidenceFileChecksum"}
        path_fields = {"EvidenceFilePath"}
        src_pairs = []
        for k, v in src.items():
            if k in hash_fields:
                src_pairs.append((k, _hash(v)))
            elif k in path_fields:
                src_pairs.append((k, _path(v)))
            else:
                src_pairs.append((k, v))
        # Use a custom kv_table that accepts pre-built Paragraphs in the value column.
        data = []
        for k, v in src_pairs:
            cell_v = v if hasattr(v, "text") else _P(v)
            data.append([Paragraph(f"<b>{k}</b>", CELL), cell_v])
        src_tbl = Table(data, colWidths=[2.2 * inch, 4.3 * inch])
        src_tbl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0FA"))]))
        story.append(src_tbl)
    else:
        story.append(Paragraph("No Evidence Source recorded.", styles["Italic"]))
    story.append(Spacer(1, 0.18 * inch))

    # ---- 4. Examination Tools & Method ----
    story.append(Paragraph("4. Examination Tools & Method", styles["Heading2"]))
    story.append(Paragraph(
        "Files were ingested and hashed (SHA-256), typed by content (libmagic) and "
        "compared against their extension, checked for anti-forensic indicators "
        "(hidden, double-extension, timestamp anomalies, high entropy), then scored by a "
        "transparent rule-based engine (Integrity, Relevance and DFI scores). Integrity "
        "was preserved via per-file hashing and a case-level evidence seal.", styles["Normal"]))
    story.append(Spacer(1, 0.18 * inch))

    # ---- 5. Findings - Triage Summary ----
    total = len(df)
    counts = {k: int((df["priority"] == k).sum()) for k in ("High", "Medium", "Low")} \
        if total else {"High": 0, "Medium": 0, "Low": 0}
    mism = int(df["type_mismatch"].sum()) if total else 0
    story.append(Paragraph("5. Findings - Triage Summary", styles["Heading2"]))
    story.append(Paragraph(
        f"Total artifacts: {total} &nbsp;|&nbsp; High: {counts['High']} &nbsp;|&nbsp; "
        f"Medium: {counts['Medium']} &nbsp;|&nbsp; Low: {counts['Low']} &nbsp;|&nbsp; "
        f"Type mismatches: {mism}", styles["Normal"]))
    story.append(Paragraph("Priority distribution:", styles["Heading3"]))
    story.append(_priority_chart(counts))
    story.append(Spacer(1, 0.15 * inch))

    # ---- 6. File Integrity Verification ----
    story.append(Paragraph("6. File Integrity Verification", styles["Heading2"]))
    ievents = load_latest_integrity(case_id) if case_id else None
    if ievents is not None and not ievents.empty:
        story.append(Paragraph(
            f"Last verified: {_fmt_ts(ievents.iloc[0]['checked_at'])}", styles["Italic"]))
        header = ["Status", "File", "Baseline modified", "Current modified",
                  "Old hash", "New hash", "Detail"]
        rows = [[Paragraph(f"<b>{h}</b>", CELL_B) for h in header]]
        for _, e in ievents.iterrows():
            rows.append([_P(e["status"]), _P(e["name"]),
                         _P(_fmt_ts(e.get("baseline_mtime"))),
                         _P(_fmt_ts(e.get("current_mtime"))),
                         _P(e["old_sha256"]), _P(e["new_sha256"]),
                         _P(e["detail"])])
        widths = [0.6, 0.85, 0.95, 0.95, 1.1, 1.1, 0.95]
        t = Table(rows, colWidths=[w * inch for w in widths], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#FBEAEA")])]))
        story.append(t)
    else:
        story.append(Paragraph(
            "No integrity re-check has been recorded for this case. Run "
            "'python pipeline.py verify --case &lt;id&gt; --root &lt;folder&gt;' "
            "or use the dashboard to populate this section.", styles["Italic"]))
    story.append(Spacer(1, 0.18 * inch))

    # ---- Appendix A. Evidence Item Information ----
    story.append(Paragraph("Appendix A. Evidence Item Information", styles["Heading2"]))
    header = ["FileName", "FileType", "LogicalSize", "Checksum",
              "Created", "Modified", "Hidden", "Deleted", "Priority"]
    rows = [[Paragraph(f"<b>{h}</b>", CELL_B) for h in header]]
    for _, r in df.sort_values("dfi_score", ascending=False).head(40).iterrows():
        rows.append([_P(r.get("name")), _P(r.get("true_mime")), _P(r.get("size_bytes")),
                     _P(r.get("sha256")), _P(_fmt_ts(r.get("created_time"))),
                     _P(_fmt_ts(r.get("modified_time"))),
                     _P("Yes" if r.get("hidden_file") else "No"),
                     _P("Yes" if r.get("is_deleted") else "No"), _P(r.get("priority"))])
    widths = [1.0, 0.85, 0.5, 0.95, 0.85, 0.85, 0.4, 0.4, 0.5]
    t = Table(rows, colWidths=[w * inch for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#EFEFEF")])]))
    story.append(t)

    # ---- Appendix B. Scope & Supported Input Formats ----
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Appendix B. Scope & Supported Input Formats",
                           styles["Heading2"]))
    story.append(Paragraph(
        "ForenSight performs <b>disk / file-system and file-media triage</b> for "
        "high-volume digital evidence. Memory (RAM), network (pcap), mobile and cloud "
        "forensics are out of scope by design and are noted as future work.",
        styles["Normal"]))
    fmt_rows = [["Format", "Extensions", "Handling"],
                ["Raw / dd", ".dd .raw .img .001", "native (Sleuth Kit)"],
                ["Expert Witness (EWF)", ".E01 .Ex01", "native (libewf)"],
                ["Advanced Forensics Format", ".aff .aff4", "convert-to-raw (--normalize)"],
                ["Virtual disks", ".vmdk .vhd .vhdx .qcow2", "convert-to-raw (--normalize)"],
                ["Logical folder", "-", "native (scan)"]]
    ft = Table([[Paragraph(f"<b>{c}</b>", CELL_B) if i == 0 else _P(c)
                 for c in row] for i, row in enumerate(fmt_rows)],
               colWidths=[1.8 * inch, 2.2 * inch, 2.5 * inch], repeatRows=1)
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(Spacer(1, 0.06 * inch))
    story.append(ft)

    if out is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = f"forensight_report_{case_id or 'ALL'}_{stamp}.pdf"
    SimpleDocTemplate(out, pagesize=letter,
                      title=f"ForenSight Report {case_id}").build(story)
    print(f"[+] Report written to {out}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default=None)
    ap.add_argument("--examiner", default="unknown")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    build_report(args.case, args.examiner, args.out)
