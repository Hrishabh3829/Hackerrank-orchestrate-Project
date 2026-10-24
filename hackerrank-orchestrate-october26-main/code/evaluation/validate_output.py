"""Validate output.csv against the participant-facing submission contract."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from data_loading import load_dataset  # noqa: E402
from output_generation import OUTPUT_COLUMNS  # noqa: E402


PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}
STEP_FIELDS = {
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id",
}


def validate_output(dataset_dir: Path, output_path: Path) -> dict[str, object]:
    dataset = load_dataset(dataset_dir)
    if not output_path.is_file():
        raise ValueError(f"Output file does not exist: {output_path}")

    with output_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != OUTPUT_COLUMNS:
            raise ValueError(f"Expected columns {OUTPUT_COLUMNS}, found {reader.fieldnames}")
        rows = list(reader)

    expected_ids = [request["case_id"] for request in dataset.requests]
    actual_ids = [row["case_id"] for row in rows]
    errors: list[str] = []
    if len(rows) != len(expected_ids):
        errors.append(f"Expected {len(expected_ids)} data rows; found {len(rows)}")
    if len(actual_ids) != len(set(actual_ids)):
        errors.append("Output contains duplicate case_id values")
    if actual_ids != sorted(actual_ids):
        errors.append("Output rows are not sorted by case_id")
    if set(actual_ids) != set(expected_ids):
        errors.append("Output case IDs do not exactly match deletion_requests.csv")

    valid_evidence_ids = set(dataset.evidence_manifest)
    valid_evidence_ids.update(row["activity_id"] for row in dataset.system_activity)
    valid_evidence_ids.update(row["audit_id"] for row in dataset.identity_audit_log)
    status_counts: Counter[str] = Counter()
    total_steps = 0

    for row in rows:
        case_id = row["case_id"]
        status = row["deletion_status"]
        status_counts[status] += 1
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{case_id}: invalid deletion_status {status!r}")
        try:
            steps = json.loads(row["steps_json"])
        except (TypeError, json.JSONDecodeError):
            errors.append(f"{case_id}: steps_json is invalid JSON")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json is not a JSON array")
            continue
        total_steps += len(steps)
        if status == "NOT_APPLICABLE" and steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must have an empty steps array")
        if status == "COMPLETE" and (not steps or any(step.get("phase") != "VERIFICATION" for step in steps if isinstance(step, dict))):
            errors.append(f"{case_id}: COMPLETE must contain verification steps only")

        ordering_keys: list[tuple[int, int, str, str]] = []
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"{case_id}: step {index} is not an object")
                continue
            if set(step) != STEP_FIELDS:
                errors.append(f"{case_id}: step {index} has incorrect fields")
            if step.get("step_no") != index:
                errors.append(f"{case_id}: step numbers must be consecutive from 1")

            operation = step.get("operation", "")
            expected_phase_state = OPERATION_STATES.get(operation)
            if expected_phase_state != (step.get("phase"), step.get("state")):
                errors.append(f"{case_id}: invalid operation/phase/state at step {index}")
            if not step.get("system_id") or not step.get("resource_id"):
                errors.append(f"{case_id}: step {index} has an empty system_id or resource_id")
            if operation not in OPERATION_ORDER or step.get("phase") not in PHASE_ORDER:
                continue
            ordering_keys.append((
                PHASE_ORDER[step["phase"]], OPERATION_ORDER[operation],
                str(step.get("system_id", "")), str(step.get("resource_id", "")),
            ))

            evidence_id = step.get("evidence_id", "")
            if step.get("phase") == "FINDING" and not evidence_id:
                errors.append(f"{case_id}: finding step {index} has no evidence reference")
            if status == "COMPLETE" and step.get("phase") == "VERIFICATION" and not evidence_id:
                errors.append(f"{case_id}: complete verification step {index} has no evidence reference")
            if evidence_id and evidence_id not in valid_evidence_ids:
                errors.append(f"{case_id}: step {index} cites an unknown evidence reference")
            if status == "INCOMPLETE" and step.get("phase") != "FINDING" and evidence_id:
                errors.append(f"{case_id}: proposed/future step {index} must have an empty evidence reference")

        if ordering_keys != sorted(ordering_keys):
            errors.append(f"{case_id}: steps do not follow the required phase/operation/system/resource ordering")

    if errors:
        preview = "\n".join(f"- {error}" for error in errors[:25])
        remainder = len(errors) - min(len(errors), 25)
        if remainder:
            preview += f"\n- ... and {remainder} more validation errors"
        raise ValueError(preview)

    return {
        "rows": len(rows),
        "columns": list(OUTPUT_COLUMNS),
        "status_counts": dict(sorted(status_counts.items())),
        "steps": total_steps,
        "json_steps_valid": True,
        "case_ids_sorted_and_complete": True,
        "evidence_references_valid": True,
        "step_order_valid": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, default=CODE_DIR.parent / "dataset")
    parser.add_argument("--output", type=Path, default=CODE_DIR.parent / "output.csv")
    args = parser.parse_args()
    print(json.dumps(validate_output(args.dataset_dir, args.output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
