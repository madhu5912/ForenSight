# ForenSight — Final Guide & Walkthrough

A complete, presentation-ready reference for the digital-forensic triage prototype.
Everything here has been run and verified. Read top to bottom before your demo.

---

## 0. What we are looking at (the big picture)

**The problem.** Seized digital evidence arrives faster than investigators can examine
it. A single drive can hold millions of files. Canada's *R. v. Jordan* (2016) puts hard
time limits on trials, so slow evidence processing directly threatens prosecutions
(the RCMP backlog in the proposal).

**What ForenSight does.** It automatically *triages* a large body of evidence so the
investigator looks at the most suspicious items first, while preserving evidentiary
integrity and chain of custody. It ingests evidence (a folder or a forensic disk image),
fingerprints and analyses every file, scores and ranks each one, re-verifies integrity on
demand, and produces a standards-aligned report.

**Where it sits in digital forensics.** ForenSight is **disk / file-system + file-media
triage** — deliberately the *highest-volume* category (seized drives with millions of
files). This is stated as the scope on purpose; the boundaries below are a strength, not a
gap.

| Forensic type | In scope? |
|---|---|
| Disk / file-system forensics | **Core — this is the project** |
| File / media forensics (documents, images) | **Core — the triage target** |
| Email / database forensics | Partial (triages such files if present) |
| Malware forensics | Adjacent (entropy + anti-forensic hints, not full RE) |
| Memory (RAM), Network (pcap), Mobile, Cloud | Out of scope (future work) |

**The five layers.**
1. **Acquisition** — walk files, capture metadata + all three timestamps, SHA-256.
2. **Processing** — true type by content (libmagic), extension mismatch, entropy, category.
3. **Anti-Forensic Detection** — hidden, double-extension, spoofing, timestamp anomalies.
4. **Intelligence Engine** — rule-based Integrity, Relevance, and DFI scores → priority.
5. **Visualization** — Streamlit dashboard (tabs, interactive charts, evidence pop-up).

Cross-cutting: SQLite storage, tamper-evident audit log, integrity re-verification with an
evidence seal, automatic chain of custody, and PDF + XML reporting.

---

## 1. Methodology alignment (for your write-up)

| Proposal / methodology goal | Where it lives |
|---|---|
| Automated evidence ingestion | `acquisition.py`, `ingest_image.py` |
| File validation / obfuscation detection | `processing.py`, `antiforensics.py` |
| Risk-based prioritization | `intelligence.py` (DFI / Integrity / Relevance) |
| Evidentiary integrity | SHA-256 + `integrity.py` + evidence seal |
| Chain-of-custody preservation | `audit.py` + `case_metadata.py` (auto-recorded) |
| Scalable, high-volume triage | folder + disk-image input, throughput metrics |
| Evaluation vs baseline | `benchmark.py` + `evaluate.py` (precision/recall/F1) |
| Investigator dashboard + reporting | `dashboard.py`, `report.py`, `export_xml.py` |

---

## 2. Supported input formats & file categories

### 2.1 Storage / container formats (how the evidence is packaged)
| Format | Extensions | Handling |
|---|---|---|
| Raw / dd | `.dd .raw .img .001` | native (Sleuth Kit) |
| Expert Witness (EWF) | `.E01 .Ex01` | native (libewf) — EnCase/FTK/X-Ways/SMART |
| Advanced Forensics Format | `.aff .aff4` | convert-to-raw via `--normalize` (AFFLIB) |
| Virtual disks | `.vmdk .vhd .vhdx .qcow2` | convert-to-raw via `--normalize` (qemu-img) |
| Logical folder | — | native (`scan`) |

Design note for the viva: ForenSight keeps **two native readers** (raw + EWF, the two
dominant real-world formats) and normalizes everything else to raw. That is exactly how
production tools handle the long tail, and it means broad coverage without fragile
native libraries.

### 2.2 File categories (what is inside the evidence)
libmagic identifies the true type of *any* file; these categories drive mismatch
detection and reporting: **Document, Image, Video, Audio, Archive, Email, Executable,
Database.** Extend the table in `config.py` (`EXPECTED_EXTENSIONS`).

---

## 3. Install (Kali Linux)

```bash
sudo apt update
sudo apt install -y libmagic1 python3-venv python3-pip sleuthkit
cd forensight_aplus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -c "import magic; print(magic.from_buffer(b'%PDF-1.4', mime=True))"   # -> application/pdf
```

Optional — only if you will ingest AFF or virtual-disk images:
```bash
sudo apt install -y ewf-tools afflib-tools qemu-utils
```
Run every command from inside `forensight_aplus/` with the venv active, so the database
and `case_<id>.json` files stay together.

---

## 4. The demo walkthrough (golden path)

### Step 1 — Create test evidence
```bash
python synthetic_artifacts.py --out synthetic_evidence
```

### Step 2 — Scan (starts the chain of custody automatically)
```bash
python pipeline.py scan synthetic_evidence --case CASE001 --examiner "I. Robin"
```
Prints an **evidence seal**; auto-creates `case_CASE001.json` with an acquisition custody
entry (full timestamp), the Evidence Source checksum, the detected filesystem, and the
read-only write-block note.

### Step 3 — Dashboard
```bash
streamlit run dashboard.py
```
Tabs: **Triage** (metrics, an interactive distribution chart with a dropdown —
Priority / File type / DFI score — a severity-coloured table, and a clickable evidence
pop-up with a live hash check and "open the real file"); **Scan** (scan a folder from the
UI); **Integrity** (re-check); **Reports** (generate and **download** the PDF/XML).

### Step 4 — Simulate tampering, then prove it
```bash
echo "tamper" >> synthetic_evidence/meeting_notes.txt      # modify
mv synthetic_evidence/banner.gif synthetic_evidence/ad.gif # rename
rm synthetic_evidence/family_photo.png                     # delete
python pipeline.py verify --case CASE001 --root synthetic_evidence
```
Reports **MODIFIED** (old→new hash), **RENAMED** (hash unchanged), **DELETED**, and flips
the evidence seal to CHANGED. Saved to the DB and recorded in custody.

### Step 5 — Real forensic image (CFReDS)
```bash
wget -O rm1.E01 "https://cfreds-archive.nist.gov/data_leakage_case/images/rm%231/cfreds_2015_data_leakage_rm%231.E01"
python ingest_image.py rm1.E01 --case LEAK_RM1 --examiner "I. Robin"
```
`tsk_recover` reads the `.E01` directly; Evidence Source (image name, checksum,
filesystem, partitions, write-block method) is filled from the image.

Other formats (AFF / VMDK / VHD): add `--normalize`:
```bash
python ingest_image.py disk.vmdk --case CASE02 --normalize
```

**Important — a `.dd` is a container, not a file.** If you point `scan` at a folder that
holds a `disk.dd`, ForenSight can only see it as one opaque blob — but it now *flags* it
(priority Medium, reason "DISK IMAGE — run ingest_image.py") so it is never ignored. To
analyse the files **inside** the image, run `ingest_image.py`. To also recover **deleted**
files, add `--all`:
```bash
python ingest_image.py disk.dd --case CASE02 --examiner "you" --all
```
During ingestion ForenSight uses `fls` to find deleted entries and `istat` to read the
FAT/NTFS **hidden** attribute (both are lost once files are extracted to Linux), then tags
the recovered files: deleted files score is_deleted (+30, ≥ Medium) and hidden files score
hidden_file (+15). So a deleted, disguised or hidden file inside the image surfaces near
the top of the triage list.

### Step 6 — Report and XML (CLI) — or download from the dashboard
```bash
python report.py --case CASE001 --examiner "I. Robin"   # timestamped PDF, never overwrites
python export_xml.py --case CASE001                     # schema-aligned XML
```
Report sections: 1. Case Information · 2. Chain of Custody · 3. Evidence Source ·
4. Examination Tools & Method · 5. Findings (with priority chart) · 6. File Integrity ·
Appendix A. Evidence Item Information · Appendix B. Scope & Supported Formats. Every date
field shows full `YYYY-MM-DD HH:MM:SS UTC`.

### Step 7 — Audit-log check (know the difference!)
```bash
python pipeline.py verify-audit
```
Checks the **audit log** (was the record of actions tampered with) — NOT the evidence.
Evidence tampering is caught by `verify` (Step 4). Two complementary checks.

### Step 8 — Quantitative evaluation
```bash
python benchmark.py <folder-of-real-files> --out benchmark --limit 500
python evaluate.py --benchmark benchmark        # confusion matrix + precision/recall/F1
```

### Step 9 — Tests
```bash
PYTHONPATH=. pytest -q
```

---

## 5. Command reference

| Command | Purpose |
|---|---|
| `pipeline.py scan <folder> --case C --examiner E` | Scan; auto custody + seal |
| `pipeline.py verify --case C --root <folder>` | Re-hash; MODIFIED/RENAMED/DELETED/NEW |
| `pipeline.py verify-audit` | Check the audit LOG chain (not evidence) |
| `pipeline.py case-init --case C` | Create a blank custody file to edit |
| `pipeline.py custody-log --case C ...` | Append a custody entry |
| `report.py --case C --examiner E` | Timestamped PDF report |
| `export_xml.py --case C` | Schema-aligned XML export |
| `ingest_image.py <img> --case C [--normalize] [--all]` | Ingest a disk image |
| `synthetic_artifacts.py` / `make_test_data.py` | Generate test evidence |
| `streamlit run dashboard.py` | Dashboard (scan, verify, inspect, download report) |

Download the report: **UI** — Reports tab → Generate → Download; **CLI** — `report.py`.

---

## 6. Troubleshooting

- **A `.dd`/`.E01` shows as one Low file** → you ran `scan`, which sees the image as a
  single blob. It is now flagged "DISK IMAGE — run ingest_image". Use
  `ingest_image.py <image> --all` to analyse the files (incl. deleted/hidden) inside.
- **Deleted files not appearing** → add `--all` (uses `tsk_recover -e`); without it, only
  allocated files are recovered.
- **Report custody/changes blank** → run from the project folder (so `forensight.db` and
  `case_<id>.json` match), and use the same `--case` id you scanned with. A scan fills
  custody; a `verify` fills the changes section.
- **Blank Evidence Source fields on a folder scan** → expected: WriteBlockMethod,
  FileSystem, OSVersion, Partitions, Users and Encryption describe a *disk image*. They
  fill during `ingest_image.py`, or you enter them by hand in `case_<id>.json`.
- **`Image file not found`** → `ls -lh` first; pass the exact filename.
- **`qemu-img/affconvert/ewfexport not found`** → install the optional tools (Section 3).
- **`failed to find libmagic`** (Windows) → `pip install python-magic-bin`.

---

## 7. Talk track for July 20 (≈4–5 min)

1. Problem: evidence backlog + R. v. Jordan; scope = high-volume disk/file triage.
2. Scan `synthetic_evidence`; dashboard → spoofed file ranked High; click it → live hash OK.
3. Switch the distribution chart dropdown (Priority → File type → DFI) to show the data shape.
4. Modify + rename a file; **Verify** → RENAMED vs MODIFIED with hashes, seal CHANGED.
5. `verify-audit` → explain it checks the log, not the evidence (custody understanding).
6. Ingest a CFReDS `.E01` → Evidence Source auto-filled from the image.
7. **Download the PDF** from the dashboard → Chain of Custody (full timestamps), changes
   table, Evidence Item Information, and the Scope appendix.
8. Close: rule-based (no training data, court-defensible) now; ML as future work.
