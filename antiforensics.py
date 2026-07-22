"""
ForenSight - Layer 3: Anti-Forensic Detection.

Flags signs that someone tried to hide or disguise evidence. Each rule is simple and
explainable so every flag can be defended in a report or viva.

Timestamp analysis (the "IF conditions" for created / modified / accessed) is the part
investigators care about most, because file timestamps are routinely forged. We compare
the three timestamps against each other and against the current time, and record WHICH
condition fired in `timestamp_notes` so the investigator sees the reasoning, not just a
flag.
"""
from datetime import datetime, timezone


def is_hidden(artifact):
    """Unix convention: a leading dot marks a hidden file."""
    return artifact["name"].startswith(".")


def has_double_extension(artifact):
    """Detect disguises like invoice.pdf.exe - a real document/image extension
    sitting in front of the true (often executable) extension."""
    parts = artifact["name"].lower().split(".")
    if len(parts) < 3:
        return False
    decoys = {"pdf", "doc", "docx", "jpg", "jpeg", "png", "txt", "xls", "xlsx"}
    return parts[-2] in decoys


def _parse(ts):
    """Parse an ISO timestamp string to a datetime, or None if missing/invalid."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def analyse_timestamps(artifact):
    """Return (is_anomalous, notes) after checking the created/modified/accessed times.

    The IF conditions, each a recognised timestomping indicator:
      1. Any timestamp set in the FUTURE        -> clock tampering / forged metadata
      2. CreatedDate AFTER ModifiedDate         -> a file cannot be modified before it
                                                   exists, so creation > modification is
                                                   impossible on an untouched file
      3. AccessedDate BEFORE CreatedDate        -> accessed before it existed
    We only apply checks 2 and 3 when a real CreatedDate is available (some Linux
    filesystems do not record one).
    """
    now = datetime.now(timezone.utc)
    created = _parse(artifact.get("created_time"))
    modified = _parse(artifact.get("modified_time"))
    accessed = _parse(artifact.get("accessed_time"))
    notes = []

    # 1) future timestamps
    for label, value in (("created", created), ("modified", modified),
                         ("accessed", accessed)):
        if value and value > now:
            notes.append(f"{label} time is in the future")

    # 2) created after modified (only if we trust a real creation time)
    if created and modified and created > modified:
        notes.append("created-date is later than modified-date")

    # 3) accessed before created
    if created and accessed and accessed < created:
        notes.append("accessed-date is earlier than created-date")

    return (len(notes) > 0), "; ".join(notes)


def detect(artifact):
    """Enrich one artifact with anti-forensic flags."""
    artifact["hidden_file"] = is_hidden(artifact)
    artifact["double_extension"] = has_double_extension(artifact)
    # 'Extension spoofing' is the security framing of a content/extension mismatch.
    artifact["extension_spoofing"] = artifact.get("type_mismatch", False)

    anomalous, notes = analyse_timestamps(artifact)
    artifact["timestamp_anomaly"] = anomalous
    artifact["timestamp_notes"] = notes          # human-readable "why" for the report

    # IsDeleted / IsHidden feed the schema and the report; keep them present.
    artifact.setdefault("is_deleted", False)
    artifact.setdefault("is_in_unallocated", False)
    return artifact
