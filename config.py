"""
ForenSight - Central configuration.

Every tunable number lives here so the rest of the codebase stays clean and so your
evaluation chapter can point to one file and justify each weight and threshold.
"""

# --- Layer 2: true MIME type -> the file extensions we expect for it ---
# Grouped by the investigative CATEGORIES that matter in high-volume triage. libmagic
# still identifies the true type of ANY file; this table only defines which extensions
# are "expected" so a content/extension mismatch can be flagged.
EXPECTED_EXTENSIONS = {
    # --- Documents ---
    "application/pdf": {"pdf"},
    "application/msword": {"doc"},
    "application/vnd.ms-excel": {"xls"},
    "application/vnd.ms-powerpoint": {"ppt"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {"docx"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {"xlsx"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {"pptx"},
    "application/vnd.oasis.opendocument.text": {"odt"},
    "application/rtf": {"rtf"},
    "text/rtf": {"rtf"},
    "text/plain": {"txt", "csv", "log", "md", "ini", "cfg"},
    "text/csv": {"csv"},
    "text/html": {"html", "htm"},
    "application/xml": {"xml"},
    "text/xml": {"xml"},
    # --- Images ---
    "image/jpeg": {"jpg", "jpeg"},
    "image/png": {"png"},
    "image/gif": {"gif"},
    "image/bmp": {"bmp"},
    "image/tiff": {"tif", "tiff"},
    "image/webp": {"webp"},
    "image/heic": {"heic"},
    "image/heif": {"heif"},
    # --- Video ---
    "video/mp4": {"mp4", "m4v"},
    "video/quicktime": {"mov"},
    "video/x-msvideo": {"avi"},
    "video/x-matroska": {"mkv"},
    "video/mpeg": {"mpg", "mpeg"},
    # --- Audio ---
    "audio/mpeg": {"mp3"},
    "audio/x-wav": {"wav"},
    "audio/wav": {"wav"},
    "audio/flac": {"flac"},
    "audio/mp4": {"m4a"},
    # --- Archives / containers (often used to hide material) ---
    "application/zip": {"zip", "docx", "xlsx", "pptx", "odt", "jar", "apk"},  # OOXML/ODF are zips
    "application/x-rar": {"rar"},
    "application/vnd.rar": {"rar"},
    "application/x-7z-compressed": {"7z"},
    "application/x-tar": {"tar"},
    "application/gzip": {"gz", "tgz"},
    "application/x-bzip2": {"bz2"},
    # --- Email ---
    "application/vnd.ms-outlook": {"pst", "ost", "msg"},
    "message/rfc822": {"eml"},
    # --- Executables / scripts (malware, tooling) ---
    "application/x-dosexec": {"exe", "dll"},
    "application/x-executable": {"elf", "bin"},
    "application/x-sharedlib": {"so"},
    "application/x-msdownload": {"exe", "dll"},
    "text/x-shellscript": {"sh"},
    "text/x-python": {"py"},
    # --- Databases (app data, chat histories) ---
    "application/vnd.sqlite3": {"sqlite", "db", "sqlite3"},
    "application/x-sqlite3": {"sqlite", "db", "sqlite3"},
}

# Broad investigative category for each true-MIME prefix (used in reports/relevance).
FILE_CATEGORY_PREFIXES = {
    "application/pdf": "Document", "application/msword": "Document",
    "application/vnd.ms-": "Document", "application/vnd.openxmlformats": "Document",
    "application/vnd.oasis": "Document", "application/rtf": "Document",
    "text/": "Document/Text",
    "image/": "Image", "video/": "Video", "audio/": "Audio",
    "application/zip": "Archive", "application/x-rar": "Archive",
    "application/vnd.rar": "Archive", "application/x-7z": "Archive",
    "application/x-tar": "Archive", "application/gzip": "Archive",
    "application/x-bzip2": "Archive",
    "application/vnd.ms-outlook": "Email", "message/rfc822": "Email",
    "application/x-dosexec": "Executable", "application/x-executable": "Executable",
    "application/x-sharedlib": "Executable", "application/x-msdownload": "Executable",
    "application/vnd.sqlite3": "Database", "application/x-sqlite3": "Database",
}


def categorize(mime):
    """Return a broad investigative category for a true MIME type."""
    mime = mime or ""
    for prefix, category in FILE_CATEGORY_PREFIXES.items():
        if mime.startswith(prefix):
            return category
    return "Other"

# --- Layer 4: Relevance score by broad MIME category (investigative interest) ---
RELEVANCE_BY_PREFIX = {
    "application/x-dosexec": 80,   # executables: high interest
    "application/pdf": 70,
    "application/msword": 70,
    "application/vnd": 70,         # office documents
    "image/": 65,
    "application/zip": 60,
    "video/": 60,
    "audio/": 55,
    "text/": 40,
}
RELEVANCE_DEFAULT = 30

# --- Layer 4: DFI (suspicion) rule weights. Tune during evaluation. ---
DFI_WEIGHTS = {
    "known_bad_hash": 50,
    "is_disk_image": 45,       # a container that must be sub-analysed (ingest_image)
    "extension_spoofing": 40,
    "double_extension": 35,
    "type_mismatch": 30,
    "timestamp_anomaly": 30,
    "is_deleted": 30,          # a recovered/deleted file is investigatively significant
    "high_entropy": 20,
    "hidden_file": 15,
}

# Extensions that indicate a forensic DISK IMAGE (a container of other files, not a
# normal document). A plain `scan` treats these as one opaque blob; they must be opened
# with ingest_image.py. ForenSight flags them so they are never silently ignored.
DISK_IMAGE_EXTENSIONS = {
    "dd", "raw", "img", "001", "e01", "ex01", "aff", "aff4",
    "vmdk", "vhd", "vhdx", "qcow2", "dmg", "iso",
}
# libmagic description keywords that also indicate a disk image / filesystem container.
DISK_IMAGE_MAGIC_HINTS = (
    "boot sector", "filesystem", "partition", "disk image",
    "expert witness", "ewf", "qemu", "vmware", "ntfs", "fat (", "iso 9660",
)

# --- Priority thresholds applied to the DFI score ---
PRIORITY_HIGH = 60
PRIORITY_MEDIUM = 30

# --- Layer 4: Integrity score deductions ---
INTEGRITY_START = 100
INTEGRITY_TIMESTAMP_PENALTY = 40    # suspicious timestamps -> possible tampering
INTEGRITY_UNHASHED_PENALTY = 100    # could not hash -> integrity unknown

# --- Entropy (Layer 2) ---
ENTROPY_SAMPLE_BYTES = 262144       # sample first 256 KB for speed (scalability)
ENTROPY_HIGH_THRESHOLD = 7.5        # bits/byte; > 7.5 hints encryption/compression

# --- File locations ---
DB_PATH = "forensight.db"
AUDIT_LOG = "audit_log.jsonl"
KNOWN_BAD_HASHES = "known_bad_hashes.txt"     # one sha256 per line (optional)
KNOWN_GOOD_HASHES = "known_good_hashes.txt"   # NSRL-style allowlist (optional)
