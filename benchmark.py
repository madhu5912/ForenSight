"""
ForenSight - Labeled benchmark builder.

Builds a LABELED test set from a source folder (e.g. a Govdocs1 subset). For each
usable file we either keep a correct extension (label 0 = not spoofed) or rename it to
a wrong extension (label 1 = spoofed). Ground truth is written to ground_truth.csv, so
the evaluator can compute precision/recall/F1 with zero manual labelling.

Usage:
    python benchmark.py <source_folder> --out benchmark --spoof-rate 0.5 --limit 1000
"""
import os
import csv
import shutil
import random
import argparse
import magic
from config import EXPECTED_EXTENSIONS

WRONG_POOL = ["jpg", "pdf", "txt", "png", "docx", "zip"]


def correct_ext_for(mime):
    exts = EXPECTED_EXTENSIONS.get(mime)
    return sorted(exts)[0] if exts else None


def build(source, out_dir="benchmark", spoof_rate=0.5, limit=None, seed=42):
    random.seed(seed)
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    n = 0
    for root, _dirs, files in os.walk(source):
        for fn in files:
            src = os.path.join(root, fn)
            try:
                mime = magic.from_file(src, mime=True)
            except (OSError, PermissionError):
                continue
            correct = correct_ext_for(mime)
            if not correct:
                continue  # only use files whose type we can label confidently
            spoof = random.random() < spoof_rate
            if spoof:
                ext = random.choice([e for e in WRONG_POOL if e != correct])
            else:
                ext = correct
            dst = os.path.join(out_dir, f"file_{n:05d}.{ext}")
            try:
                shutil.copyfile(src, dst)
            except (OSError, PermissionError):
                continue
            rows.append({"path": os.path.abspath(dst), "true_mime": mime,
                         "correct_ext": correct, "given_ext": ext,
                         "is_spoofed": int(spoof)})
            n += 1
            if limit and n >= limit:
                break
        if limit and n >= limit:
            break

    with open(os.path.join(out_dir, "ground_truth.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "true_mime", "correct_ext",
                                               "given_ext", "is_spoofed"])
        writer.writeheader()
        writer.writerows(rows)

    spoofed = sum(r["is_spoofed"] for r in rows)
    print(f"[+] Built {n} labeled files in {out_dir}/ ({spoofed} spoofed, "
          f"{n - spoofed} clean)")
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("--out", default="benchmark")
    ap.add_argument("--spoof-rate", type=float, default=0.5)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    build(args.source, args.out, args.spoof_rate, args.limit)
