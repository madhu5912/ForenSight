"""
ForenSight - Unit tests (pytest).

Run from the project root:  pytest -q
These tests use temporary files, so they leave no artifacts behind.
"""
import os
import tempfile

from acquisition import collect_metadata
from processing import shannon_entropy, process
from antiforensics import detect, has_double_extension
from intelligence import assess

# A minimal valid 1x1 PNG.
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806"
    "0000001f15c4890000000a49444154789c6360000002000154a2"
    "4f5f0000000049454e44ae426082"
)


def _write(tmp, name, data):
    path = os.path.join(tmp, name)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    return path


def test_entropy_low_for_zeros():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "zeros.bin", b"\x00" * 2000)
        assert shannon_entropy(path) < 1.0


def test_entropy_high_for_random():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "rand.bin", os.urandom(8192))
        assert shannon_entropy(path) > 7.0


def test_spoofed_file_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "disguised.jpg", PNG)   # PNG bytes, .jpg name
        art = collect_metadata(path)
        process(art)
        detect(art)
        assess(art)
        assert art["type_mismatch"] is True
        assert art["extension_spoofing"] is True
        assert art["priority"] in ("High", "Medium")


def test_clean_file_low_priority():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "clean.png", PNG)        # PNG bytes, .png name
        art = collect_metadata(path)
        process(art)
        detect(art)
        assess(art)
        assert art["type_mismatch"] is False
        assert art["priority"] == "Low"


def test_double_extension_helper():
    assert has_double_extension({"name": "invoice.pdf.exe"}) is True
    assert has_double_extension({"name": "report.pdf"}) is False
    assert has_double_extension({"name": "archive.tar.gz"}) is False


def test_three_scores_present():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "clean.png", PNG)
        art = collect_metadata(path)
        process(art)
        detect(art)
        assess(art)
        for key in ("dfi_score", "integrity_score", "relevance_score"):
            assert key in art and isinstance(art[key], int)


def test_integrity_detects_change_delete_new(tmp_path):
    import database
    import integrity
    from acquisition import collect_metadata
    from processing import process
    from antiforensics import detect
    from intelligence import assess

    dbp = str(tmp_path / "t.db")
    f = tmp_path / "evidenceA.txt"
    f.write_text("version one")
    art = collect_metadata(str(f))
    process(art); detect(art); assess(art)
    database.save_artifacts([art], "CASET", db_path=dbp)

    # unchanged
    _, summ = integrity.verify("CASET", db_path=dbp)
    assert summ["unchanged"] == 1 and summ["modified"] == 0

    # modified
    f.write_text("version two is longer")
    changes, summ = integrity.verify("CASET", db_path=dbp)
    assert summ["modified"] == 1
    assert any(c["status"] == "MODIFIED" for c in changes)

    # deleted + new (under root)
    f.unlink()
    (tmp_path / "evidenceB.txt").write_text("brand new file")
    changes, summ = integrity.verify("CASET", scan_root=str(tmp_path), db_path=dbp)
    assert summ["deleted"] == 1
    assert summ["new"] >= 1


def test_evidence_view(tmp_path):
    from evidence_view import classify, hex_preview, text_preview
    t = tmp_path / "a.txt"
    t.write_text("hello world")
    assert classify(str(t)) == "text"
    assert "hello" in text_preview(str(t))
    b = tmp_path / "b.bin"
    b.write_bytes(bytes(range(256)))
    assert classify(str(b)) == "binary"
    assert "00 01 02" in hex_preview(str(b))
    assert classify(str(tmp_path / "nope.x")) == "missing"


def test_rename_is_detected_not_deleted(tmp_path):
    import database, integrity
    from acquisition import collect_metadata
    from processing import process
    from antiforensics import detect
    from intelligence import assess

    dbp = str(tmp_path / "t.db")
    original = tmp_path / "report.txt"
    original.write_text("confidential content")
    art = collect_metadata(str(original))
    process(art); detect(art); assess(art)
    database.save_artifacts([art], "RC", db_path=dbp)

    # rename the file (content unchanged) and verify
    renamed = tmp_path / "holiday.txt"
    original.rename(renamed)
    changes, summary = integrity.verify("RC", scan_root=str(tmp_path), db_path=dbp)
    assert summary["renamed"] == 1
    assert summary["deleted"] == 0
    rec = next(c for c in changes if c["status"] == "RENAMED")
    assert rec["old_sha256"] == rec["new_sha256"]      # content identical
    assert rec["name"] == "report.txt"


def test_timestamp_if_conditions():
    from datetime import datetime, timezone, timedelta
    from antiforensics import analyse_timestamps
    now = datetime.now(timezone.utc)

    # future modified time
    a1 = {"created_time": None,
          "modified_time": (now + timedelta(days=400)).isoformat(),
          "accessed_time": now.isoformat()}
    flag, notes = analyse_timestamps(a1)
    assert flag and "future" in notes

    # created AFTER modified (impossible on an untouched file)
    a2 = {"created_time": now.isoformat(),
          "modified_time": (now - timedelta(days=2)).isoformat(),
          "accessed_time": now.isoformat()}
    flag, notes = analyse_timestamps(a2)
    assert flag and "created-date is later than modified-date" in notes

    # all consistent -> no anomaly
    a3 = {"created_time": (now - timedelta(days=2)).isoformat(),
          "modified_time": (now - timedelta(days=1)).isoformat(),
          "accessed_time": now.isoformat()}
    flag, _ = analyse_timestamps(a3)
    assert flag is False


def test_case_metadata_roundtrip(tmp_path, monkeypatch):
    import case_metadata
    monkeypatch.chdir(tmp_path)
    case_metadata.init_case("CX")
    case = case_metadata.load_case("CX")
    assert case is not None and case["case_id"] == "CX"
    case_metadata.add_custody_entry("CX", purpose="seized", method_of_transfer="hand",
                                    released_by="A", received_by="B", hash_value="abc123")
    case = case_metadata.load_case("CX")
    log = case["chain_of_custody"]["custody_log"]
    assert len(log) == 1 and log[0]["hash_value"] == "abc123"


def test_disk_image_is_flagged(tmp_path):
    """A .dd/.E01 container must be flagged for further analysis, not scored Low."""
    from acquisition import collect_metadata
    from processing import process
    from antiforensics import detect
    from intelligence import assess
    p = tmp_path / "evidence.dd"
    p.write_bytes(b"\x00" * 2048)
    a = collect_metadata(str(p))
    process(a); detect(a); assess(a)
    assert a["is_disk_image"] is True
    assert a["priority"] in ("Medium", "High")
    assert "DISK IMAGE" in a["score_reasons"]


def test_deleted_file_is_scored():
    """A recovered deleted file should be flagged (not Low)."""
    from intelligence import assess
    a = {"sha256": "abc", "true_mime": "text/plain", "is_deleted": True}
    assess(a)
    assert "is_deleted" in a["score_reasons"]
    assert a["priority"] in ("Medium", "High")
