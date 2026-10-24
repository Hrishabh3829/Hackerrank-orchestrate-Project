"""Detailed mismatch analysis between predicted and expected."""
import csv
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "code")

from data_loading import load_dataset
from evidence import load_evidence
from investigation import investigate_case
from output_generation import write_output

dataset = load_dataset("dataset")
corpus = load_evidence(dataset)

predictions = [investigate_case(request, dataset, corpus) for request in dataset.sample_requests]

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "pred.csv"
    write_output(out, predictions)
    with out.open("r", encoding="utf-8") as f:
        pred_rows = {r["case_id"]: r for r in csv.DictReader(f)}

exp_rows = {r["case_id"]: r for r in dataset.sample_output}

for case_id in sorted(exp_rows.keys()):
    exp = exp_rows[case_id]
    pred = pred_rows.get(case_id)
    if not pred:
        print(f"MISSING: {case_id}")
        continue
    exp_steps = json.loads(exp["steps_json"])
    pred_steps = json.loads(pred["steps_json"])
    
    if exp["deletion_status"] != pred["deletion_status"] or exp_steps != pred_steps:
        print(f"\n{'='*80}")
        print(f"MISMATCH: {case_id}")
        print(f"  Status: expected={exp['deletion_status']} predicted={pred['deletion_status']}")
        print(f"  Expected steps ({len(exp_steps)}):")
        for s in exp_steps:
            print(f"    #{s['step_no']} {s['phase']:14s} {s['system_id']:24s} {s['resource_id']:28s} {s['operation']:30s} {s['state']:12s} ev={s['evidence_id']}")
        print(f"  Predicted steps ({len(pred_steps)}):")
        for s in pred_steps:
            print(f"    #{s['step_no']} {s['phase']:14s} {s['system_id']:24s} {s['resource_id']:28s} {s['operation']:30s} {s['state']:12s} ev={s['evidence_id']}")
        
        # Find what's missing
        exp_tuples = [(s['system_id'], s['resource_id'], s['operation']) for s in exp_steps]
        pred_tuples = [(s['system_id'], s['resource_id'], s['operation']) for s in pred_steps]
        
        missing = [t for t in exp_tuples if t not in pred_tuples]
        extra = [t for t in pred_tuples if t not in exp_tuples]
        
        if missing:
            print(f"  MISSING from prediction:")
            for t in missing:
                print(f"    {t}")
        if extra:
            print(f"  EXTRA in prediction:")
            for t in extra:
                print(f"    {t}")
