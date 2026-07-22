"""
ForenSight - Layer 4: Intelligence Engine.

Produces the three named scores from the project design and a final priority:
  - Integrity score : confidence the evidence is intact / untampered (higher = better)
  - Relevance score : how investigatively interesting the artifact is
  - DFI score       : overall Digital Forensic Intelligence suspicion (drives priority)
All rule-based and transparent: every point added is recorded in score_reasons.
"""
import os
from config import (DFI_WEIGHTS, RELEVANCE_BY_PREFIX, RELEVANCE_DEFAULT,
                    PRIORITY_HIGH, PRIORITY_MEDIUM, INTEGRITY_START,
                    INTEGRITY_TIMESTAMP_PENALTY, INTEGRITY_UNHASHED_PENALTY,
                    KNOWN_BAD_HASHES, KNOWN_GOOD_HASHES)


def _load_hashes(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


KNOWN_BAD = _load_hashes(KNOWN_BAD_HASHES)
KNOWN_GOOD = _load_hashes(KNOWN_GOOD_HASHES)


def integrity_score(artifact):
    score = INTEGRITY_START
    if not artifact.get("hash_ok", True):
        score -= INTEGRITY_UNHASHED_PENALTY
    if artifact.get("timestamp_anomaly"):
        score -= INTEGRITY_TIMESTAMP_PENALTY
    return max(0, score)


def relevance_score(artifact):
    mime = artifact.get("true_mime") or ""
    score = RELEVANCE_DEFAULT
    for prefix, value in RELEVANCE_BY_PREFIX.items():
        if mime.startswith(prefix):
            score = value
            break
    if artifact.get("high_entropy"):
        score += 20    # encrypted/compressed content is often relevant
    if artifact.get("extension_spoofing"):
        score += 15    # someone bothered to disguise it
    if artifact.get("is_deleted"):
        score += 25    # a deleted file that was recovered is high interest
    if artifact.get("is_disk_image"):
        score = 100    # a disk image is a whole case; maximum relevance
    return min(100, score)


def dfi_score(artifact):
    """Return (score, reasons). Rule-based suspicion score, 0-100."""
    score = 0
    reasons = []
    sha = (artifact.get("sha256") or "").lower()
    flags = dict(artifact)
    flags["known_bad_hash"] = sha in KNOWN_BAD
    for flag, points in DFI_WEIGHTS.items():
        if flags.get(flag):
            score += points
            reasons.append(f"{flag} (+{points})")
    # NSRL-style allowlist: a known-good file is noise, so suppress it entirely.
    if sha and sha in KNOWN_GOOD:
        return 0, ["known_good_hash (suppressed)"]
    return min(100, score), reasons


def assess(artifact):
    """Attach all three scores, the priority, and the reasons to the artifact."""
    dfi, reasons = dfi_score(artifact)
    artifact["dfi_score"] = dfi
    artifact["integrity_score"] = integrity_score(artifact)
    artifact["relevance_score"] = relevance_score(artifact)
    if dfi >= PRIORITY_HIGH:
        artifact["priority"] = "High"
    elif dfi >= PRIORITY_MEDIUM:
        artifact["priority"] = "Medium"
    else:
        artifact["priority"] = "Low"
    artifact["score_reasons"] = "; ".join(reasons) if reasons else "no flags"
    # Actionable guidance: a disk image cannot be triaged as a single file - the
    # investigator must open it to analyse the files (incl. deleted/hidden) inside.
    if artifact.get("is_disk_image"):
        artifact["score_reasons"] += \
            "  [DISK IMAGE - run: python ingest_image.py <file> --all]"
    return artifact
