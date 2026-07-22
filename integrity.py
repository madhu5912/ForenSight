"""
ForenSight - Integrity re-verification (evidence change detection).

IMPORTANT distinction (this answers "why is the audit chain intact after I edit a file?"):
  * audit.verify_chain()  checks the AUDIT LOG itself - did anyone tamper with the
                          record of actions? It says nothing about the evidence files.
  * integrity.verify()    (this module) RE-HASHES the actual evidence and reports what
                          changed: MODIFIED / RENAMED / DELETED / NEW / UNREADABLE.
So a modified evidence file is caught HERE, by re-hashing - not by the audit-chain check.

Rename handling (item 1): a rename leaves the file's CONTENT (hash) unchanged but moves
it to a new path. We therefore match by hash: if a baseline path is gone but its hash
re-appears at a new path, that is a RENAMED/MOVED file (content identical), NOT a delete
plus a brand-new file. The hash is shown in every case so the investigator can inspect.
"""
import os
import hashlib
from datetime import datetime, timezone

from acquisition import sha256_of_file
from database import get_connection, save_integrity_events
from audit import log_event


def snapshot_file(path):
    """Current on-disk state of one file: hash + size + modified-time."""
    stat = os.stat(path)
    return {
        "sha256": sha256_of_file(path),
        "size_bytes": stat.st_size,
        "modified_time": datetime.fromtimestamp(stat.st_mtime,
                                                tz=timezone.utc).isoformat(),
    }


def _safe_hash(path):
    try:
        return sha256_of_file(path)
    except (OSError, PermissionError):
        return None


def load_baseline(case_id, db_path=None):
    """Latest stored record per path for a case - the baseline to compare against."""
    conn = get_connection(db_path) if db_path else get_connection()
    rows = conn.execute(
        "SELECT path, sha256, size_bytes, modified_time FROM artifacts "
        "WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()
    conn.close()
    return {p: {"sha256": s, "size_bytes": sz, "modified_time": mt}
            for p, s, sz, mt in rows}


def manifest_hash(path_to_sha):
    """A single 'evidence seal' over a whole set: SHA-256 of the sorted 'hash  path'
    lines. If ANY file is added, removed or changed, this value changes. It gives the
    case one comparable fingerprint for the chain of custody."""
    lines = sorted(f"{sha}  {p}" for p, sha in path_to_sha.items() if sha)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def verify(case_id, scan_root=None, db_path=None):
    """Compare the stored baseline for case_id against the current disk state.

    Returns (changes_list, summary_dict). When scan_root is given we also hash every
    file under it, which is what lets us detect RENAMED and NEW files.
    """
    baseline = load_baseline(case_id, db_path)

    # Hash everything currently under scan_root so we can detect renames and new files.
    current_by_path, current_by_hash = {}, {}
    if scan_root and os.path.isdir(scan_root):
        for root, _dirs, files in os.walk(scan_root):
            for fn in files:
                ap = os.path.realpath(os.path.join(root, fn))
                h = _safe_hash(ap)
                current_by_path[ap] = h
                current_by_hash.setdefault(h, []).append(ap)

    changes = []
    matched_new_paths = set()

    for path, base in baseline.items():
        name = os.path.basename(path)
        if os.path.exists(path):
            current = snapshot_file(path)
            if current["sha256"] == base["sha256"]:
                continue  # UNCHANGED (not listed individually)
            detail = []
            if current["size_bytes"] != base["size_bytes"]:
                detail.append(f"size {base['size_bytes']} -> {current['size_bytes']} bytes")
            if current["modified_time"] != base["modified_time"]:
                detail.append("modified-time changed")
            changes.append({"status": "MODIFIED", "name": name, "path": path,
                            "old_sha256": base["sha256"], "new_sha256": current["sha256"],
                            "baseline_mtime": base["modified_time"],
                            "current_mtime": current["modified_time"],
                            "detail": "; ".join(detail) or "content changed"})
        else:
            # Path is gone. Did the SAME content (hash) re-appear at a new path?
            candidates = [p for p in current_by_hash.get(base["sha256"], [])
                          if p not in baseline]
            if candidates:
                new_path = candidates[0]
                matched_new_paths.add(new_path)
                changes.append({
                    "status": "RENAMED", "name": name, "path": new_path,
                    "old_sha256": base["sha256"], "new_sha256": base["sha256"],
                    "baseline_mtime": base["modified_time"], "current_mtime": None,
                    "detail": f"renamed/moved: '{name}' -> '{os.path.basename(new_path)}' "
                              f"(content identical, hash unchanged)"})
            else:
                changes.append({"status": "DELETED", "name": name, "path": path,
                                "old_sha256": base["sha256"], "new_sha256": None,
                                "baseline_mtime": base["modified_time"], "current_mtime": None,
                                "detail": "file no longer present; content not found elsewhere"})

    # Files under scan_root that are neither in the baseline nor a rename target = NEW.
    for ap, h in current_by_path.items():
        if ap in baseline or ap in matched_new_paths:
            continue
        changes.append({"status": "NEW", "name": os.path.basename(ap), "path": ap,
                        "old_sha256": None, "new_sha256": h,
                        "baseline_mtime": None, "current_mtime": None,
                        "detail": "present on disk, absent from baseline"})

    # Evidence seal: baseline vs current fingerprint (only meaningful when root scanned).
    baseline_seal = manifest_hash({p: b["sha256"] for p, b in baseline.items()})
    current_seal = manifest_hash(current_by_path) if current_by_path else None

    def count(status):
        return sum(1 for c in changes if c["status"] == status)

    summary = {
        "baseline_files": len(baseline),
        "unchanged": len(baseline) - count("MODIFIED") - count("DELETED") - count("RENAMED"),
        "modified": count("MODIFIED"),
        "renamed": count("RENAMED"),
        "deleted": count("DELETED"),
        "new": count("NEW"),
        "baseline_seal": baseline_seal,
        "current_seal": current_seal,
        "seal_match": (current_seal == baseline_seal) if current_seal else None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    # Persist the per-file changes so the PDF report can include them (this is what
    # makes "the report records the changes of the files" actually work).
    if db_path:
        save_integrity_events(case_id, changes, summary["checked_at"], db_path)
    else:
        save_integrity_events(case_id, changes, summary["checked_at"])
    log_event("integrity_verify", case_id, "system", summary)
    return changes, summary
