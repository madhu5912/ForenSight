"""
ForenSight - Pipeline orchestrator + command-line interface.

This is where the five layers are INTEGRATED. Layer 1 creates each artifact dict; it
is passed through Layers 2, 3 and 4 in order (each adds fields); the result is written
to the database (the input to Layer 5, the dashboard). Every run is recorded in the
chain-of-custody audit log.

    Layer 1 acquire -> Layer 2 process -> Layer 3 detect
        -> Layer 4 assess -> Storage -> Layer 5 dashboard (separate app)

Usage:
    python pipeline.py scan <folder> --case CASE001 --examiner "I. Robin"
    python pipeline.py verify-audit
"""
import os
import time
import argparse
from datetime import datetime, timezone
from acquisition import acquire
from processing import process
from antiforensics import detect
from intelligence import assess
from database import save_artifacts
from audit import log_event, verify_chain
import integrity
import case_metadata


def detect_filesystem(path):
    """Best-effort: return the filesystem type of the volume holding `path` on Linux,
    by matching the longest mount point in /proc/mounts (e.g. 'ext4', 'vfat'). Returns
    '' if it cannot be determined - we never guess."""
    try:
        target = os.path.abspath(path)
        best_mnt, best_fs = "", ""
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and target.startswith(parts[1]) \
                        and len(parts[1]) >= len(best_mnt):
                    best_mnt, best_fs = parts[1], parts[2]
        return best_fs
    except Exception:
        return ""


def _safe_defaults(art):
    """Guarantee an artifact has valid fields even if a layer failed, so the scan
    never crashes on one odd file and the row still stores cleanly."""
    art.setdefault("true_mime", "unknown")
    art.setdefault("claimed_mime", "unknown")
    art.setdefault("entropy", 0.0)
    for flag in ("type_mismatch", "high_entropy", "hidden_file",
                 "double_extension", "extension_spoofing", "timestamp_anomaly"):
        art.setdefault(flag, False)
    art.setdefault("dfi_score", 0)
    art.setdefault("integrity_score", 0)
    art.setdefault("relevance_score", 0)
    art.setdefault("priority", "Low")
    art.setdefault("score_reasons", "processing error")
    return art


def run_pipeline(target_dir, case_id, examiner, deleted_paths=None, hidden_paths=None):
    """Scan target_dir and store results. `deleted_paths` / `hidden_paths` (optional) are
    sets of absolute paths that a disk-image ingester found to be DELETED or HIDDEN inside
    the image (that filesystem metadata is lost once files are extracted to a folder, so
    the ingester reads it from the image and passes it here)."""
    deleted_paths = deleted_paths or set()
    hidden_paths = hidden_paths or set()
    log_event("scan_started", case_id, examiner, {"target": target_dir})
    start = time.time()

    print(f"[*] Layer 1: acquiring files from {target_dir}")
    artifacts = acquire(target_dir)
    print(f"    -> {len(artifacts)} files")

    print("[*] Layers 2-4: processing, detecting, scoring")
    for art in artifacts:
        try:
            process(art)     # Layer 2: type fields + entropy + disk-image flag
            detect(art)      # Layer 3: anti-forensic flags
            if art["path"] in deleted_paths:      # tag recovered-deleted files
                art["is_deleted"] = True
            if art["path"] in hidden_paths:       # tag filesystem-hidden files
                art["hidden_file"] = True
            assess(art)      # Layer 4: integrity/relevance/DFI + priority
        except Exception as e:
            # One problematic file must never abort the whole scan.
            print(f"[WARN] processing failed for {art.get('path')}: {e}")
            _safe_defaults(art)

    print("[*] Storage: writing to SQLite")
    save_artifacts(artifacts, case_id)

    elapsed = time.time() - start
    high = sum(1 for a in artifacts if a["priority"] == "High")
    rate = len(artifacts) / elapsed if elapsed else 0.0
    # Evidence seal: one fingerprint over every file's hash. Recomputing it later and
    # comparing proves whether the evidence SET changed (see integrity.verify).
    seal = integrity.manifest_hash({a["path"]: a.get("sha256") for a in artifacts})
    print(f"[+] Done in {elapsed:.2f}s ({rate:.1f} files/s). "
          f"{high} HIGH-priority artifact(s) flagged for review.")
    print(f"[+] Evidence seal (manifest hash): {seal}")

    # Auto chain-of-custody: record this acquisition so the report is never empty and
    # the custody trail reflects what actually happened (aligns with the proposal's
    # chain-of-custody preservation goal). Manual narrative fields can still be edited.
    try:
        total = sum(a.get("size_bytes") or 0 for a in artifacts)
        case_metadata.set_evidence_source(
            case_id,
            EvidenceFileName=os.path.basename(os.path.normpath(target_dir)) or target_dir,
            EvidenceFilePath=os.path.abspath(target_dir),
            EvidenceFileType="folder scan / recovered files",
            EvidenceFileSize=f"{total} bytes across {len(artifacts)} files",
            EvidenceFileChecksum=seal,
            EvidenceFileSystemTime=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            # Truthfully derivable even for a folder scan:
            EvidenceFileWriteBlockMethod="Logical read-only access "
                                         "(files opened read-only; evidence not modified)",
            EvidenceFileFileSystem=detect_filesystem(target_dir) or "")
        case_metadata.add_custody_entry(
            case_id, purpose="Evidence acquisition (automated scan)",
            method_of_transfer="ForenSight automated ingestion",
            released_by=examiner, received_by="ForenSight", hash_value=seal)
        # Fill the narrative custody fields so the report is populated, not blank.
        # Full ISO timestamp (date + HH:MM:SS + timezone) per forensic logging standards.
        case_metadata.set_custody_info(
            case_id,
            date=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            received_seized_from=os.path.basename(os.path.normpath(target_dir)) or target_dir,
            received_seized_by=examiner,
            reason_obtained="Digital forensic triage and analysis",
            location_obtained=os.path.abspath(target_dir),
            description_of_evidence=(
                f"{len(artifacts)} file(s); {high} high-priority; "
                f"{sum(1 for a in artifacts if a.get('type_mismatch'))} type mismatches"))
    except Exception as e:
        print(f"[WARN] could not record custody automatically: {e}")

    log_event("scan_completed", case_id, examiner,
              {"files": len(artifacts), "high_priority": high,
               "seconds": round(elapsed, 3), "evidence_seal": seal})

    # --- Improvement 1: auto-ingest disk images found in the scanned folder ---
    # If the scan encountered any .dd / .E01 / .img etc., automatically run the image
    # ingester on each one (with --all) so their CONTENTS (including deleted/hidden files)
    # are added to the SAME case. This means one `scan` command handles mixed evidence.
    disk_images = [a for a in artifacts if a.get("is_disk_image")]
    if disk_images:
        from ingest_image import ingest
        for img in disk_images:
            imgpath = img["path"]
            imgname = os.path.basename(imgpath)
            outdir = os.path.join(os.path.dirname(imgpath),
                                  f"_recovered_{imgname}")
            print(f"\n[*] Auto-ingesting disk image: {imgname}")
            try:
                ingest(imgpath, case_id, examiner, outdir,
                       recover_all=True, normalize=False, hash_image=True)
            except Exception as e:
                print(f"[WARN] auto-ingest of {imgname} failed: {e}")

    return artifacts


def main():
    ap = argparse.ArgumentParser(description="ForenSight forensic triage")
    sub = ap.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a folder of evidence")
    scan.add_argument("folder")
    scan.add_argument("--case", default="CASE000")
    scan.add_argument("--examiner", default="unknown")

    sub.add_parser("verify-audit",
                   help="check the AUDIT LOG hash chain (not the evidence files)")

    ver = sub.add_parser("verify",
                         help="re-hash EVIDENCE and report changed/renamed/deleted files")
    ver.add_argument("--case", required=True)
    ver.add_argument("--root", default=None,
                     help="folder to re-hash (needed to detect RENAMED and NEW files)")

    ci = sub.add_parser("case-init", help="create case_<id>.json (Chain of Custody)")
    ci.add_argument("--case", required=True)

    cl = sub.add_parser("custody-log", help="append a change-of-custody entry")
    cl.add_argument("--case", required=True)
    cl.add_argument("--purpose", required=True)
    cl.add_argument("--method", default="")
    cl.add_argument("--released-by", default="")
    cl.add_argument("--received-by", default="")
    cl.add_argument("--hash", dest="hash_value", default="")

    args = ap.parse_args()
    if args.cmd == "scan":
        run_pipeline(args.folder, args.case, args.examiner)

    elif args.cmd == "verify-audit":
        # NOTE: this verifies the integrity of the AUDIT LOG itself - i.e. whether the
        # record of actions was tampered with. It does NOT re-hash evidence files, so it
        # stays "intact" even if you edit an evidence file. To detect evidence changes,
        # use the 'verify' command below.
        ok = verify_chain()
        print("Audit LOG chain intact (the custody record was not altered)."
              if ok else "AUDIT LOG CHAIN BROKEN - the custody record was tampered with!")
        print("Note: this does not check evidence files. Run "
              "'python pipeline.py verify --case <id> --root <folder>' for that.")

    elif args.cmd == "verify":
        changes, s = integrity.verify(args.case, args.root)
        print(f"\nEvidence integrity check for case {args.case}:")
        print(f"  baseline files : {s['baseline_files']}")
        print(f"  unchanged      : {s['unchanged']}")
        print(f"  MODIFIED       : {s['modified']}")
        print(f"  RENAMED/MOVED  : {s['renamed']}")
        print(f"  DELETED        : {s['deleted']}")
        print(f"  NEW            : {s['new']}")
        if s["seal_match"] is not None:
            print(f"  evidence seal  : {'MATCH' if s['seal_match'] else 'CHANGED'}")
        for c in changes:
            old = (c["old_sha256"] or "")[:12]
            new = (c["new_sha256"] or "")[:12]
            print(f"  [{c['status']:<9}] {c['name']}  {c['detail']}")
            if c["status"] in ("MODIFIED", "RENAMED"):
                print(f"             hash {old}... -> {new}...")
        # Record the verification as a custody event so it shows in the report.
        try:
            case_metadata.add_custody_entry(
                args.case,
                purpose=(f"Integrity verification: {s['modified']} modified, "
                         f"{s['renamed']} renamed, {s['deleted']} deleted, {s['new']} new"),
                method_of_transfer="ForenSight re-hash",
                released_by="ForenSight", received_by="examiner",
                hash_value=s.get("current_seal") or s.get("baseline_seal") or "")
        except Exception as e:
            print(f"[WARN] could not record custody: {e}")

    elif args.cmd == "case-init":
        case_metadata.init_case(args.case)

    elif args.cmd == "custody-log":
        case_metadata.add_custody_entry(
            args.case, args.purpose, args.method, args.released_by,
            args.received_by, args.hash_value)


if __name__ == "__main__":
    main()
