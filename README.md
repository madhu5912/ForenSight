# ForenSight — Scalable Digital Forensic Triage Framework

A working prototype that ingests a folder of files and automatically triages them so an
investigator examines the most suspicious evidence first, while preserving evidentiary
integrity. Built as a Master's final project (Team 9: Immanuel Robin & Madhu Purnima).

The pipeline is **rule-based and transparent** — every decision is explainable, and no
training data is required. That is a deliberate design choice: it removes the
"no real-world data to train a model" risk and produces results you can defend.

---

## 1. What makes this stand out (A+ features)

- **Five integrated layers** with a clean per-layer contract (see Section 6).
- **Three named scores** that mirror the project design:
  - *Integrity score* — confidence the evidence is intact / untampered.
  - *Relevance score* — how investigatively interesting the artifact is.
  - *DFI score* — overall Digital Forensic Intelligence suspicion (drives priority).
- **Shannon entropy** detection (flags encrypted / compressed / packed files).
- **Anti-forensic detection**: extension spoofing, double extensions (`invoice.pdf.exe`),
  hidden files, impossible timestamps.
- **Known-hash allow/deny lists** (NSRL-style): suppress known-good files, escalate
  known-bad ones.
- **Tamper-evident audit log** — a SHA-256 hash chain; any edit to a past record is
  detected by `verify-audit` (chain-of-custody rigor).
- **Quantitative evaluation**: a labeled-benchmark builder + an evaluation harness that
  reports a confusion matrix, precision, recall, F1, accuracy, and throughput.
- **Auto-generated PDF forensic report**, a **command-line interface**, a single
  **config file** for all weights/thresholds, and **unit tests** (pytest).

### How it maps to your slides

| Slide layer | Module |
|---|---|
| Layer 1: Acquisition | `acquisition.py` |
| Layer 2: Processing | `processing.py` |
| Layer 3: Anti-Forensic Detection | `antiforensics.py` |
| Layer 4: Intelligence Engine (DFI / Integrity / Relevance) | `intelligence.py` |
| Layer 5: Visualization | `dashboard.py` |

### Industry-standards alignment
- **Evidence metadata** follows the `EvidenceItemInformation` schema: FileName, FilePath,
  FileType, LogicalSize, PhysicalSize, Checksum, CreatedDate, ModifiedDate, AccessedDate,
  IsDeleted, IsHidden, IsInUnallocatedCluster. (Sector/Cluster and the deleted/unallocated
  flags require disk-image-level analysis; folder scans leave them as N/A or False, and the
  image ingester can populate them.)
- **Acquisition metadata** follows the `EvidenceSource` schema, recorded per case.
- **Chain of Custody** follows the standard form (date, seized-from, seized-by, reason,
  location, description, and a change-of-custody log with hash values).
- `export_xml.py` emits an XML document conforming to both schemas.

### Two DIFFERENT integrity checks (important — read this)
- `python pipeline.py verify-audit` checks the **audit log** itself — whether the *record
  of actions* was tampered with. It does **not** re-hash evidence, so it stays "intact"
  even after you edit an evidence file. That is correct, by design.
- `python pipeline.py verify --case <id> --root <folder>` re-hashes the **evidence** and
  reports MODIFIED / RENAMED / DELETED / NEW files (with old-vs-new hashes) plus a single
  **evidence seal** (a manifest hash over the whole set). This is what catches a changed
  or renamed file. A rename shows as **RENAMED** (content/hash identical, name changed),
  not as a deletion.

---

## 2. File map

```
config.py            All tunable weights, thresholds, and the type table (one place to tune)
audit.py             Chain-of-custody hash-chained audit log
acquisition.py       Layer 1: walk folder, metadata, SHA-256
processing.py        Layer 2: true type, extension mismatch, entropy
antiforensics.py     Layer 3: hidden / spoof / double-ext / timestamp flags
intelligence.py      Layer 4: Integrity, Relevance, DFI scores + priority
database.py          SQLite storage (swap to PostgreSQL by editing this file only)
pipeline.py          Orchestrator + CLI (scan / verify / verify-audit)
integrity.py         Re-hash evidence; report MODIFIED / RENAMED / DELETED / NEW + seal
evidence_view.py     Safe file preview + open-in-default-app helpers (dashboard)
case_metadata.py     Chain of Custody + Evidence Source (case_<id>.json)
export_xml.py        Export findings as EvidenceSource / EvidenceItemInformation XML
ingest_image.py      Disk-image ingestion (CFReDS E01/raw -> extract -> scan)
dashboard.py         Layer 5: Streamlit dashboard
report.py            Auto-generated PDF forensic report
benchmark.py         Build a LABELED test set from a source folder (for evaluation)
evaluate.py          Compute confusion matrix, precision/recall/F1, throughput
synthetic_artifacts.py  Generate a labeled synthetic evidence set (all rules + manifest)
make_test_data.py    Generate a tiny known-answer test set
tests/               pytest unit tests
requirements.txt     Python dependencies
```

---

## 3. Install (Kali Linux)

Both team machines are on Kali. Install `libmagic`, the Python packages, and the
Sleuth Kit + ewf-tools needed to read CFReDS disk images:

```bash
sudo apt update
sudo apt install -y libmagic1 python3-venv python3-pip sleuthkit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

**Verify libmagic works:**
```bash
python -c "import magic; print(magic.from_buffer(b'%PDF-1.4', mime=True))"
# expected: application/pdf
```

(The code is pure Python and also runs on Windows/macOS; only `libmagic` differs there.
Windows: `pip install python-magic-bin`. macOS: `brew install libmagic`. Disk-image
ingestion, however, expects the Kali forensic tools above.)

---

## 4. Quickstart (5 commands)

```bash
python make_test_data.py                                   # create known-answer files
python pipeline.py scan sample_evidence --case CASE001 --examiner "I. Robin"
streamlit run dashboard.py                                 # open the dashboard
python report.py --case CASE001 --examiner "M. Purnima"    # PDF report
python pipeline.py verify --case CASE001 --root sample_evidence   # detect changed files
python pipeline.py verify-audit                            # custody check
```
Expected from the scan: `disguised.jpg`, `secret.pdf` and `invoice.pdf.exe` are flagged
**High**; `clean_image.png` stays **Low**.

### What the dashboard does
- **Scan a folder** straight from the UI (top expander) — type a path, click *Run scan*.
- **Click a file → pop-up** with its scores, metadata, a content preview, a **live hash
  re-check** (matches baseline or flags MODIFIED), and buttons that **open the real
  evidence file** in the host's default app or download it.
- **Integrity re-check** panel: pick a case, click *Verify*, and see every MODIFIED /
  NEW / DELETED file with old-vs-new hash. Demo it by editing a scanned file, then
  re-verifying — the change shows up immediately (also available on the CLI via
  `python pipeline.py verify --case CASE001 --root <folder>`).

### Chain of custody, report and XML
```bash
python pipeline.py case-init --case CASE001          # creates case_CASE001.json to edit
python pipeline.py custody-log --case CASE001 --purpose "Imaging" \
    --method "write-blocker" --released-by "Officer A" --received-by "I. Robin" \
    --hash "<sha256>"                                 # appends a custody entry
python report.py --case CASE001 --examiner "I. Robin"   # timestamped PDF (never overwrites)
python export_xml.py --case CASE001                   # schema-conformant XML
```
Edit `case_CASE001.json` to fill in the Chain of Custody (date, seized-from/by, reason,
location, description) and the Evidence Source fields; both appear in the PDF report.

---

## 5. Datasets and evaluation (the part examiners reward)

You use three complementary data sources, matching your proposal: **synthetic
artifacts** (controlled, labeled), **Govdocs1** (real-world scale), and **CFReDS**
(real forensic disk images).

### 5.1 Synthetic forensic artifacts (start here)
A self-contained, labeled set that deliberately triggers every detection rule
(spoofing, double extension, hidden file, high entropy, future timestamp).

```bash
python synthetic_artifacts.py --out synthetic_evidence
python pipeline.py scan synthetic_evidence --case SYNTH01 --examiner "M. Purnima"
```
`synthetic_evidence_manifest.csv` lists the expected verdict for each file, so you can
show predicted vs expected in the demo. This satisfies the "synthetic forensic
artifacts" element of the proposal and is the safest thing to demo live.

### 5.2 Get a real corpus — Govdocs1
~1 million real, freely-redistributable files crawled from `.gov` domains.
- Browse / download: https://digitalcorpora.org/corpora/file-corpora/files/
- Files are organised into numbered zips (~1,000 files each), e.g.
  `https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/000.zip`
  (also on AWS Open Data: https://registry.opendata.aws/tag/digital-forensics/).

**Do not download all 1M files.** One or two zips (a few thousand files) is plenty to
demonstrate scale and to time against a baseline.

```bash
mkdir govdocs && cd govdocs
# download one zip (or grab it from the website if a specific number 404s)
curl -O https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/000.zip
unzip 000.zip && cd ..
```

### 5.3 Build a LABELED benchmark from Govdocs1 (ground truth for free)
Real malicious "spoofed" files with labels are hard to obtain, so we manufacture them:
take real files and rename a known fraction to the *wrong* extension. The renamed ones
are labeled spoofed (1), the rest clean (0). This yields perfect ground truth.

```bash
python benchmark.py govdocs/000 --out benchmark --spoof-rate 0.5 --limit 2000
python evaluate.py --benchmark benchmark
```
`evaluate.py` prints a confusion matrix and precision/recall/F1/accuracy and writes
`metrics.json`. Put that table straight into your results chapter.

### 5.4 CFReDS — real forensic disk images (required by your proposal)
CFReDS ships **disk images**, not loose files, so there is one extra step: extract the
files, then scan them. `ingest_image.py` does both. On Kali, The Sleuth Kit reads `.E01`
images **directly** — no `ewfmount`, no FUSE, no `/mnt` mountpoint.

**Recommended small image — Data Leakage Case, Removable Media #1** (~74 MB exFAT E01).
Download it with a simple local name (the `-O` avoids the `#` that NIST puts in the
original filename, which would otherwise break the shell):

```bash
wget -O rm1.E01 "https://cfreds-archive.nist.gov/data_leakage_case/images/rm%231/cfreds_2015_data_leakage_rm%231.E01"
ls -lh rm1.E01                       # confirm the file is actually here
python ingest_image.py rm1.E01 --case LEAK_RM1 --examiner "I. Robin"
```

Richer alternatives from the same case page
(https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html):
- Removable Media #2 (the suspect's USB, more leaked files): `rm#2` DD `.7z` (~219 MB)
  or E01 (~243 MB).
- Full PC image (20 GB, NTFS): `pc.E01`..`pc.E04` (~7 GB) — only if you want the full
  Windows system; too big for a quick demo.

Add `--all` to also recover deleted/unallocated files:
```bash
python ingest_image.py rm1.E01 --case LEAK_RM1 --all
```

> If `ls` shows the file but ingestion reports "Image file not found", you typed a
> different name than the file actually has — copy it exactly from `ls`. The earlier
> `ewfmount` errors were just that: the placeholder names `evidence.dd` / `image.E01`
> didn't exist. With `tsk_recover` reading E01 directly, you no longer need `ewfmount`
> at all.

### 5.5 NapierOne (optional)
A modern mixed-type set (500k+ files, 44 types) on AWS Open Data
(https://registry.opendata.aws/tag/digital-forensics/), useful as a future-work mention.

> **Honesty note for your report:** on controlled synthetic files you will see very high
> scores. On raw Govdocs1 / CFReDS expect a few files `libmagic` cannot type and the odd
> edge case — *report those real numbers and discuss them.* A short "limitations and
> false positives" paragraph reads as more rigorous than a naive "100% accuracy" claim.

---

## 6. How the layers integrate (orchestration)

One **artifact dictionary** is created per file and flows through every layer, gaining
fields as it goes. Each layer is a function that takes the dict and returns it enriched;
`pipeline.py` simply calls them in order. That is the whole integration story.

```
target folder
   -> Layer 1 acquire()  : path, name, ext, size, timestamps, sha256, hash_ok
   -> Layer 2 process()  : true_mime, claimed_mime, type_mismatch, entropy, high_entropy
   -> Layer 3 detect()   : hidden_file, double_extension, extension_spoofing, timestamp_anomaly
   -> Layer 4 assess()   : dfi_score, integrity_score, relevance_score, priority, score_reasons
   -> Storage (SQLite)   : one row per artifact
   -> Layer 5 dashboard  : reads the DB, ranks by dfi_score
```

**The contract:** each layer only *adds* keys and never removes keys it did not create.
That single rule is why the orchestrator is trivial and the design is safe to extend.

---

## 7. Tests

```bash
PYTHONPATH=. pytest -q
```

---

## 8. Suggested talk track for the July 20 review

1. The problem: evidence backlog + R. v. Jordan time limits (30 sec).
2. Live demo: `scan` the known-answer set, open the dashboard, show a spoofed file at
   the top with its reasons.
3. Show the `evaluate.py` output on a Govdocs1 benchmark (confusion matrix + F1).
4. Show `verify-audit` catching a tampered record (the integrity story).
5. Close with the three scores and why rule-based is the right v1 choice; ML as future
   work.

---

## 9. Future work (write these up — they show scope awareness)
- ML-based scoring once labeled operational data exists.
- Carving and parsing *deleted/unallocated* artifacts more deeply (the `--all` flag
  already recovers them; richer analysis is the next step).
- Full timeline reconstruction across artifacts; mobile and cloud acquisition.
- NSRL full hash-set integration for large-scale known-file filtering.
