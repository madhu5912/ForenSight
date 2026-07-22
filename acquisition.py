"""
ForenSight - Layer 1: Acquisition.

Walks a target folder and builds the base 'artifact' record per file. The fields are
named to line up with the industry 'EvidenceItemInformation' schema:
    FileName, FilePath, FileType, LogicalSize, PhysicalSize, Checksum,
    CreatedDate, ModifiedDate, AccessedDate, IsHidden, IsDeleted, ...
We capture all THREE forensic timestamps (created / modified / accessed) because
inconsistencies between them are a classic sign of timestamp tampering ("timestomping").
The SHA-256 is read in chunks so a huge file never loads fully into memory.
"""
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path


def sha256_of_file(filepath, chunk_size=65536):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _iso(ts):
    """Convert a POSIX timestamp to an ISO-8601 UTC string, or None if missing."""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _created_timestamp(stat):
    """Best-effort file CREATION time (the schema's CreatedDate).

    Not every OS/filesystem records a true birth time. We prefer st_birthtime when the
    platform exposes it (macOS, some Linux), and otherwise fall back to st_ctime, which
    on Windows IS creation but on Linux is the inode-change time. We return None when we
    genuinely cannot tell, so the report can honestly show 'N/A' rather than guess.
    """
    if hasattr(stat, "st_birthtime"):
        return stat.st_birthtime
    if os.name == "nt":           # on Windows, st_ctime is creation time
        return stat.st_ctime
    return None                   # unknown on this platform/filesystem


def collect_metadata(filepath):
    """Build the base artifact record for one file (EvidenceItemInformation fields)."""
    fp = Path(filepath)
    stat = fp.stat()

    # LogicalSize = real byte length; PhysicalSize = bytes actually allocated on disk
    # (st_blocks counts 512-byte blocks). PhysicalSize >= LogicalSize due to slack.
    physical = stat.st_blocks * 512 if hasattr(stat, "st_blocks") else stat.st_size

    record = {
        "path": str(fp.resolve()),                     # FilePath
        "name": fp.name,                               # FileName
        "extension": fp.suffix.lower().lstrip("."),    # '' when no extension
        "size_bytes": stat.st_size,                    # LogicalSize
        "physical_size": physical,                     # PhysicalSize
        "created_time": _iso(_created_timestamp(stat)),  # CreatedDate (may be None)
        "modified_time": _iso(stat.st_mtime),          # ModifiedDate
        "accessed_time": _iso(stat.st_atime),          # AccessedDate
        "changed_time": _iso(stat.st_ctime),           # inode metadata-change time
        # IsDeleted / IsInUnallocatedCluster are only knowable from disk-image analysis;
        # a normal folder scan sees live files, so they default to False here. The image
        # ingester (ingest_image.py) can pre-set them to True for recovered/deleted items
        # before the record reaches the database.
        "is_deleted": False,
        "is_in_unallocated": False,
    }
    try:
        record["sha256"] = sha256_of_file(filepath)    # Checksum
        record["hash_ok"] = True
    except (OSError, PermissionError):
        record["sha256"] = None
        record["hash_ok"] = False
    return record


def acquire(target_dir):
    """Walk target_dir recursively; return a list of artifact records."""
    artifacts = []
    for root, _dirs, files in os.walk(target_dir):
        for filename in files:
            full_path = os.path.join(root, filename)
            try:
                artifacts.append(collect_metadata(full_path))
            except (OSError, PermissionError) as e:
                # Forensic principle: never crash on one bad file - log and continue.
                print(f"[WARN] Could not read {full_path}: {e}")
    return artifacts
