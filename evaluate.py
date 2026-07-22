"""
ForenSight - Evaluation harness.

Runs the detection layers over the labeled benchmark and computes a confusion matrix,
precision, recall, F1, accuracy and throughput, then writes metrics.json. This is the
quantitative core of your results chapter.

Usage:
    python evaluate.py --benchmark benchmark
"""
import os
import csv
import json
import time
import argparse
from acquisition import collect_metadata
from processing import process
from antiforensics import detect


def load_truth(benchmark_dir):
    truth = {}
    with open(os.path.join(benchmark_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            truth[row["path"]] = int(row["is_spoofed"])
    return truth


def evaluate(benchmark_dir="benchmark"):
    truth = load_truth(benchmark_dir)
    tp = fp = tn = fn = 0
    start = time.time()
    for path, is_spoofed in truth.items():
        art = collect_metadata(path)
        process(art)
        detect(art)
        predicted = 1 if art["extension_spoofing"] else 0
        if predicted and is_spoofed:
            tp += 1
        elif predicted and not is_spoofed:
            fp += 1
        elif not predicted and not is_spoofed:
            tn += 1
        else:
            fn += 1
    elapsed = time.time() - start
    n = len(truth)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    rate = n / elapsed if elapsed else 0.0

    metrics = {
        "n_files": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "accuracy": round(accuracy, 4),
        "seconds": round(elapsed, 3), "files_per_second": round(rate, 1),
    }

    print("\n=== ForenSight evaluation: extension-spoofing detection ===")
    print(f"Files evaluated : {n}")
    print(f"Confusion matrix: TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Precision={metrics['precision']}  Recall={metrics['recall']}  "
          f"F1={metrics['f1']}  Accuracy={metrics['accuracy']}")
    print(f"Throughput      : {metrics['files_per_second']} files/s")

    with open("metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("[+] metrics.json written")
    return metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmark", default="benchmark")
    args = ap.parse_args()
    evaluate(args.benchmark)
