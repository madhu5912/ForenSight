"""
ForenSight - XML export aligned to the EvidenceSource / EvidenceItemInformation schema.

Produces an XML document whose structure mirrors the two industry schemas you provided,
so the output can be consumed by, or compared against, standards-based forensic tooling.
Each scanned file becomes one <EvidenceItemInformation> element with the schema fields;
the case's acquisition details become the <EvidenceSource> element.

Usage:
    python export_xml.py --case CASE001
"""
import argparse
from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, ElementTree, indent

from database import load_dataframe
from case_metadata import load_case


def _text(parent, tag, value):
    """Add <tag>value</tag>, using 'N/A' for missing values so the schema stays full."""
    el = SubElement(parent, tag)
    el.text = "N/A" if value is None or value == "" else str(value)
    return el


def build_xml(case_id, out=None):
    df = load_dataframe()
    df = df[df["case_id"] == case_id]
    case = load_case(case_id) or {}
    source = case.get("evidence_source", {})

    root = Element("ForenSightReport", {"case": case_id,
                                        "generated": datetime.now(timezone.utc).isoformat()})

    # ---- EvidenceSource (acquisition-level metadata) ----
    src_el = SubElement(root, "EvidenceSource")
    for field in ("EvidenceFileName", "EvidenceFilePath", "EvidenceFileType",
                  "EvidenceFileSize", "EvidenceFileChecksum", "EvidenceFileSystemTime",
                  "EvidenceFileSystemUsersInfo", "EvidenceFileWriteBlockMethod",
                  "EvidenceFileEncryption", "EvidenceFileFileSystem",
                  "EvidenceFileOSVersion", "EvidenceFilePartitionsInfo"):
        _text(src_el, field, source.get(field, ""))

    # ---- One EvidenceItemInformation per scanned file ----
    items_el = SubElement(root, "EvidenceItems")
    for _, r in df.iterrows():
        item = SubElement(items_el, "EvidenceItemInformation")
        _text(item, "FileName", r.get("name"))
        _text(item, "FilePath", r.get("path"))
        _text(item, "FileType", r.get("true_mime"))
        _text(item, "Category", r.get("category"))
        _text(item, "LogicalSize", r.get("size_bytes"))
        _text(item, "PhysicalSize", r.get("physical_size"))
        _text(item, "Checksum", r.get("sha256"))
        _text(item, "CreatedDate", r.get("created_time"))
        _text(item, "ModifiedDate", r.get("modified_time"))
        _text(item, "AccessedDate", r.get("accessed_time"))
        _text(item, "Sector", "N/A")     # requires disk-image-level analysis
        _text(item, "Cluster", "N/A")    # requires disk-image-level analysis
        _text(item, "IsDeleted", bool(r.get("is_deleted")))
        _text(item, "IsHidden", bool(r.get("hidden_file")))
        _text(item, "IsInUnallocatedCluster", bool(r.get("is_in_unallocated")))
        # ForenSight triage findings (extra, beyond the base schema)
        _text(item, "DFIScore", r.get("dfi_score"))
        _text(item, "Priority", r.get("priority"))

    out = out or f"forensight_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    tree = ElementTree(root)
    indent(tree, space="  ")             # pretty-print (Python 3.9+)
    tree.write(out, encoding="utf-8", xml_declaration=True)
    print(f"[+] XML written to {out}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    build_xml(args.case, args.out)
