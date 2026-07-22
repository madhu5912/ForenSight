"""
ForenSight - Synthetic forensic artifact generator.

Creates a self-contained, LABELED set of synthetic evidence that deliberately exercises
every detection rule: clean files, extension-spoofed files, a double-extension malware
disguise, a hidden file, high-entropy ("encrypted") blobs, and a file with a future
(tampered) timestamp. A manifest.csv records the expected verdict for each file, so this
set doubles as a small ground-truth dataset for the demo and the report.

Usage:
    python synthetic_artifacts.py --out synthetic_evidence
"""
import os
import csv
import time
import argparse

# Minimal valid file bodies (enough for libmagic to identify the true type).
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806"
    "0000001f15c4890000000a49444154789c6360000002000154a2"
    "4f5f0000000049454e44ae426082")
GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000"
    "002c00000000010001000002024401003b")
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def write(out, name, data, future=False):
    path = os.path.join(out, name)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    if future:
        # Set modified & accessed time ~1 year in the future to trip the
        # timestamp-anomaly rule (a sign of clock tampering / forgery).
        future_ts = time.time() + 365 * 24 * 3600
        os.utime(path, (future_ts, future_ts))
    return path


def generate(out="synthetic_evidence"):
    os.makedirs(out, exist_ok=True)
    manifest = []

    def add(name, data, expected_priority, note, future=False):
        write(out, name, data, future=future)
        manifest.append({"name": name, "expected_priority": expected_priority,
                         "rationale": note})

    # --- Clean files (correct extension for their true type) -> Low ---
    add("annual_report.pdf", PDF, "Low", "genuine pdf, correct extension")
    add("family_photo.png", PNG, "Low", "genuine png, correct extension")
    add("banner.gif", GIF, "Low", "genuine gif, correct extension")
    add("meeting_notes.txt", "Project meeting notes. " * 40, "Low", "genuine text")

    # --- Extension spoofing (true type != extension) -> High ---
    add("vacation.jpg", PNG, "High", "PNG bytes disguised as .jpg")
    add("invoice.pdf", PNG, "High", "PNG bytes disguised as .pdf")
    add("logo.docx", PDF, "High", "PDF bytes disguised as .docx")

    # --- Double extension (classic malware disguise) -> High ---
    add("payslip.pdf.exe", PNG, "High", "double extension: looks like pdf, isn't")

    # --- Hidden file -> Low/Medium ---
    add(".private_keys.txt", "secret data " * 10, "Low", "hidden (dot-prefixed) file")

    # --- High entropy (encrypted / packed) -> relevance boost ---
    add("vault.bin", os.urandom(8192), "Low", "high-entropy blob (possibly encrypted)")
    add("ransom_note.enc", os.urandom(8192), "Low", "high-entropy, suspicious extension")

    # --- Timestamp anomaly (future date) -> integrity hit ---
    add("backdated.pdf", PDF, "Medium", "future timestamp (possible tampering)",
        future=True)

    manifest_path = (out.rstrip("/\\") or "synthetic") + "_manifest.csv"
    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "expected_priority",
                                               "rationale"])
        writer.writeheader()
        writer.writerows(manifest)

    print(f"[+] Generated {len(manifest)} synthetic artifacts in {out}/ "
          f"(expected verdicts in {manifest_path})")
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="synthetic_evidence")
    args = ap.parse_args()
    generate(args.out)
