"""
ForenSight - Chain-of-custody audit logging.

Every run appends records to an append-only JSONL file. Each record stores a hash of
the previous record, forming a hash chain: if anyone edits or deletes a past line,
verify_chain() will detect it. This is a lightweight, defensible custody trail.
"""
import os
import json
import hashlib
from datetime import datetime, timezone
from config import AUDIT_LOG


def _hash_line(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _last_hash(path):
    """Hash of the final non-empty line, or 64 zeros if the log is empty."""
    if not os.path.exists(path):
        return "0" * 64
    last = "0" * 64
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = _hash_line(line)
    return last


def log_event(action, case_id, examiner, details=None, path=AUDIT_LOG):
    """Append one audit record chained to the previous one."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "examiner": examiner,
        "action": action,
        "details": details or {},
        "prev_hash": _last_hash(path),
    }
    line = json.dumps(record, sort_keys=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return record


def verify_chain(path=AUDIT_LOG):
    """Return True if the hash chain is intact (no record altered or removed)."""
    if not os.path.exists(path):
        return True
    prev = "0" * 64
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec["prev_hash"] != prev:
                return False
            prev = _hash_line(line)
    return True
