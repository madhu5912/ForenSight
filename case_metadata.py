"""
ForenSight - Case metadata: Chain of Custody + Evidence Source.

This holds the human-recorded, standards-based case information that a forensic report
must contain but that cannot be derived automatically from the files:

  * Chain of Custody (your section D): date, seized-from, seized-by, reason, location,
    description, and a change-of-custody log (purpose, method of transfer, released-by,
    released-date, received-by, received-date, hash value).
  * Evidence Source (the 'EvidenceSource' schema): the acquisition-level description of
    the device/image - name, path, type, size, checksum, system time, users, write-block
    method, encryption, file system, OS version, partitions.

Each case is stored as a plain JSON file (case_<CASE_ID>.json) so it is easy to read,
edit by hand, and show to a professor. The report and XML export read this file.
"""
import os
import json
from datetime import datetime, timezone


def case_file_path(case_id):
    return f"case_{case_id}.json"


def _template(case_id):
    """A blank, standards-aligned case record for the team to fill in."""
    return {
        "case_id": case_id,
        # ---- Chain of Custody (section D, items 1-6; item 7 is the log below) ----
        "chain_of_custody": {
            "date": "",                       # D1
            "received_seized_from": "",        # D2
            "received_seized_by": "",          # D3
            "reason_obtained": "",             # D4
            "location_obtained": "",           # D5
            "description_of_evidence": "",     # D6
            "custody_log": []                  # D7 (list of change-of-custody entries)
        },
        # ---- Evidence Source (acquisition-level, the 'EvidenceSource' schema) ----
        "evidence_source": {
            "EvidenceFileName": "",
            "EvidenceFilePath": "",
            "EvidenceFileType": "",
            "EvidenceFileSize": "",
            "EvidenceFileChecksum": "",
            "EvidenceFileSystemTime": "",
            "EvidenceFileSystemUsersInfo": "",
            "EvidenceFileWriteBlockMethod": "",
            "EvidenceFileEncryption": "",
            "EvidenceFileFileSystem": "",
            "EvidenceFileOSVersion": "",
            "EvidenceFilePartitionsInfo": ""
        }
    }


def init_case(case_id):
    """Create case_<id>.json from the template if it does not already exist."""
    path = case_file_path(case_id)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_template(case_id), f, indent=2)
        print(f"[+] Created {path} - fill in the Chain of Custody and Evidence Source.")
    else:
        print(f"[=] {path} already exists; leaving it untouched.")
    return path


def load_case(case_id):
    """Return the case dict, or None if no case file has been created yet."""
    path = case_file_path(case_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_case(case_id):
    """Return the case dict, creating the file from the template if it does not exist.
    Unlike init_case this is quiet - used by automated steps (scan / verify)."""
    case = load_case(case_id)
    if case is None:
        case = _template(case_id)
        with open(case_file_path(case_id), "w", encoding="utf-8") as f:
            json.dump(case, f, indent=2)
    return case


def _save(case_id, case):
    with open(case_file_path(case_id), "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2)


def set_evidence_source(case_id, **fields):
    """Fill in Evidence Source fields that we CAN derive automatically (e.g. during a
    scan). Only non-empty values overwrite, so manual edits are preserved."""
    case = ensure_case(case_id)
    for key, value in fields.items():
        if value not in (None, "") and key in case["evidence_source"]:
            case["evidence_source"][key] = value
    _save(case_id, case)
    return case


def set_custody_info(case_id, **fields):
    """Fill the Chain-of-Custody NARRATIVE fields (date, seized-from, seized-by, reason,
    location, description). Only fills fields that are still blank, so anything the
    investigator typed by hand is preserved. Called automatically on each scan so the
    report is never empty."""
    case = ensure_case(case_id)
    coc = case["chain_of_custody"]
    for key, value in fields.items():
        if key in coc and key != "custody_log" and coc.get(key) in (None, "") \
                and value not in (None, ""):
            coc[key] = value
    _save(case_id, case)
    return case


def add_custody_entry(case_id, purpose, method_of_transfer, released_by,
                      received_by, hash_value, released_date=None, received_date=None):
    """Append one change-of-custody log entry (section D, item 7).
    Dates default to 'now' (UTC) if not supplied."""
    case = load_case(case_id)
    if case is None:
        init_case(case_id)
        case = load_case(case_id)
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "purpose_of_change": purpose,
        "method_of_transfer": method_of_transfer,
        "released_by": released_by,
        "released_date": released_date or now,
        "received_by": received_by,
        "received_date": received_date or now,
        "hash_value": hash_value,
    }
    case["chain_of_custody"]["custody_log"].append(entry)
    with open(case_file_path(case_id), "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2)
    print(f"[+] Added custody entry for case {case_id}.")
    return entry
