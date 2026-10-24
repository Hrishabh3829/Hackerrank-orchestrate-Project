"""Analyze sample output patterns."""
import csv
import json
import sys

sys.path.insert(0, "code")

with open("dataset/sample_output.csv", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    for row in reader:
        steps = json.loads(row["steps_json"])
        cid = row["case_id"]
        status = row["deletion_status"]
        print(f"=== {cid} ({status}) - {len(steps)} steps ===")
        for s in steps:
            print(f"  #{s['step_no']} {s['phase']:14s} {s['system_id']:24s} {s['resource_id']:28s} {s['operation']:30s} {s['state']:12s} {s['evidence_id']}")
        print()
