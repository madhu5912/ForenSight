"""
ForenSight - Layer 2: Processing.

Content-based type detection (magic bytes), extension-mismatch flagging, and Shannon
entropy. High entropy hints at encryption, compression or packing - a useful signal
that something may be deliberately obscured.
"""
import math
import magic
import mimetypes
from collections import Counter
from config import (EXPECTED_EXTENSIONS, ENTROPY_SAMPLE_BYTES,
                    ENTROPY_HIGH_THRESHOLD, categorize,
                    DISK_IMAGE_EXTENSIONS, DISK_IMAGE_MAGIC_HINTS)


def shannon_entropy(filepath, sample_bytes=ENTROPY_SAMPLE_BYTES):
    """Entropy in bits/byte over a sample (0 = uniform, 8 = fully random)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(sample_bytes)
    except (OSError, PermissionError):
        return 0.0
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def process(artifact):
    """Enrich one artifact with type analysis, mismatch flag, and entropy."""
    path = artifact["path"]
    true_mime = magic.from_file(path, mime=True)        # looks at the bytes
    claimed_mime, _ = mimetypes.guess_type(path)        # looks at the extension
    ext = artifact["extension"]

    expected = EXPECTED_EXTENSIONS.get(true_mime, set())
    artifact["true_mime"] = true_mime
    artifact["claimed_mime"] = claimed_mime or "unknown"
    artifact["category"] = categorize(true_mime)   # Document/Image/Archive/Email/...
    # Mismatch only when we know the expected extensions AND this one is not among them.
    artifact["type_mismatch"] = bool(expected) and ext not in expected

    # --- Disk-image container detection ---------------------------------------
    # A .dd/.E01/.img etc. is NOT a normal file: it holds a whole filesystem (possibly
    # with deleted and hidden files). A plain scan can only see it as one opaque blob,
    # so we flag it here for deeper analysis with ingest_image.py. We check both the
    # extension and the libmagic *description* (so an extensionless raw image is caught).
    description = ""
    try:
        description = magic.from_file(path).lower()     # human-readable magic text
    except Exception:
        description = ""
    artifact["is_disk_image"] = (
        ext in DISK_IMAGE_EXTENSIONS
        or any(hint in description for hint in DISK_IMAGE_MAGIC_HINTS))

    entropy = shannon_entropy(path)
    artifact["entropy"] = round(entropy, 3)
    artifact["high_entropy"] = entropy >= ENTROPY_HIGH_THRESHOLD
    return artifact
