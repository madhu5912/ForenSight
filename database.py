"""
ForenSight - Storage (SQLite).

One table holds the fully-enriched artifact records, with columns named to match the
industry 'EvidenceItemInformation' schema where possible. SQLite ships with Python and
needs no server. To move to PostgreSQL later you change only this file.

_ensure_columns() performs a tiny automatic migration: if you re-use a database created
by an older version of ForenSight, any newly-added columns are added on the fly so the
app never crashes on an out-of-date schema.
"""
import sqlite3
from config import DB_PATH

# Column order used for INSERTs. Comments map each column to the schema field it serves.
COLUMNS = [
    "path", "name", "extension",
    "size_bytes",          # LogicalSize
    "physical_size",       # PhysicalSize
    "created_time",        # CreatedDate
    "modified_time",       # ModifiedDate
    "accessed_time",       # AccessedDate
    "changed_time",
    "sha256",              # Checksum
    "hash_ok",
    "true_mime",           # FileType
    "category",            # investigative category (Document/Image/Archive/...)
    "is_disk_image",       # container that needs sub-analysis (ingest_image)
    "claimed_mime",
    "type_mismatch",
    "entropy", "high_entropy",
    "hidden_file",         # IsHidden
    "double_extension",
    "extension_spoofing",
    "timestamp_anomaly",
    "timestamp_notes",
    "is_deleted",          # IsDeleted
    "is_in_unallocated",   # IsInUnallocatedCluster
    "dfi_score", "integrity_score", "relevance_score",
    "priority", "score_reasons", "case_id",
]

# (column, SQL type) used both for table creation and for migrating old databases.
COLUMN_TYPES = [
    ("path", "TEXT"), ("name", "TEXT"), ("extension", "TEXT"),
    ("size_bytes", "INTEGER"), ("physical_size", "INTEGER"),
    ("created_time", "TEXT"), ("modified_time", "TEXT"),
    ("accessed_time", "TEXT"), ("changed_time", "TEXT"),
    ("sha256", "TEXT"), ("hash_ok", "INTEGER"),
    ("true_mime", "TEXT"), ("category", "TEXT"), ("is_disk_image", "INTEGER"),
    ("claimed_mime", "TEXT"), ("type_mismatch", "INTEGER"),
    ("entropy", "REAL"), ("high_entropy", "INTEGER"),
    ("hidden_file", "INTEGER"), ("double_extension", "INTEGER"),
    ("extension_spoofing", "INTEGER"), ("timestamp_anomaly", "INTEGER"),
    ("timestamp_notes", "TEXT"),
    ("is_deleted", "INTEGER"), ("is_in_unallocated", "INTEGER"),
    ("dfi_score", "INTEGER"), ("integrity_score", "INTEGER"),
    ("relevance_score", "INTEGER"),
    ("priority", "TEXT"), ("score_reasons", "TEXT"), ("case_id", "TEXT"),
]

SCHEMA = ("CREATE TABLE IF NOT EXISTS artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, "
          + ", ".join(f"{c} {t}" for c, t in COLUMN_TYPES) + ");")


def _ensure_columns(conn):
    """Add any columns missing from an older database (forward-compatible migration)."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)")}
    for col, sqltype in COLUMN_TYPES:
        if col not in existing:
            conn.execute(f"ALTER TABLE artifacts ADD COLUMN {col} {sqltype}")
    conn.commit()


INTEGRITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS integrity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT, checked_at TEXT, status TEXT, name TEXT, path TEXT,
    old_sha256 TEXT, new_sha256 TEXT, baseline_mtime TEXT, current_mtime TEXT, detail TEXT
);
"""


def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    conn.execute(INTEGRITY_SCHEMA)
    _ensure_columns(conn)
    return conn


def save_artifacts(artifacts, case_id, db_path=DB_PATH):
    conn = get_connection(db_path)
    placeholders = ",".join(["?"] * len(COLUMNS))
    sql = f"INSERT INTO artifacts ({','.join(COLUMNS)}) VALUES ({placeholders})"
    for art in artifacts:
        art = dict(art)
        art["case_id"] = case_id
        # SQLite has no boolean type, so store True/False as 1/0.
        values = [int(art[c]) if isinstance(art.get(c), bool) else art.get(c)
                  for c in COLUMNS]
        conn.execute(sql, values)
    conn.commit()
    conn.close()


def load_dataframe(db_path=DB_PATH):
    import pandas as pd
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM artifacts ORDER BY dfi_score DESC", conn)
    conn.close()
    return df


def save_integrity_events(case_id, changes, checked_at, db_path=DB_PATH):
    """Persist one verification run's per-file changes so the REPORT can show them.
    Each change is one row, tagged with checked_at so we can fetch 'the latest run'."""
    conn = get_connection(db_path)
    for c in changes:
        conn.execute(
            "INSERT INTO integrity_events "
            "(case_id, checked_at, status, name, path, old_sha256, new_sha256, "
            "baseline_mtime, current_mtime, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (case_id, checked_at, c["status"], c["name"], c["path"],
             c.get("old_sha256"), c.get("new_sha256"),
             c.get("baseline_mtime"), c.get("current_mtime"), c.get("detail")))
    conn.commit()
    conn.close()


def load_latest_integrity(case_id, db_path=DB_PATH):
    """Return the most recent verification run's changes for a case (as a DataFrame)."""
    import pandas as pd
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(
            "SELECT status, name, path, old_sha256, new_sha256, "
            "baseline_mtime, current_mtime, detail, checked_at "
            "FROM integrity_events WHERE case_id = ? AND checked_at = "
            "(SELECT MAX(checked_at) FROM integrity_events WHERE case_id = ?)",
            conn, params=(case_id, case_id))
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df
