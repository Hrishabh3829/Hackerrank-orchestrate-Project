"""Validate and write the required deterministic output CSV."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
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


@dataclass(frozen=True)
class Step:
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def as_dict(self, step_no: int) -> dict[str, object]:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass(frozen=True)
class CasePrediction:
    case_id: str
    deletion_status: str
    steps: tuple[Step, ...] = ()


def _serialized_steps(prediction: CasePrediction) -> str:
    if prediction.deletion_status not in VALID_STATUSES:
        raise ValueError(f"Invalid deletion_status for {prediction.case_id}: {prediction.deletion_status}")
    if prediction.deletion_status == "NOT_APPLICABLE" and prediction.steps:
        raise ValueError(f"NOT_APPLICABLE case {prediction.case_id} must have no steps")
    if prediction.deletion_status == "COMPLETE" and any(step.phase != "VERIFICATION" for step in prediction.steps):
        raise ValueError(f"COMPLETE case {prediction.case_id} may contain verification steps only")

    phase_ranks = [PHASE_ORDER.get(step.phase, -1) for step in prediction.steps]
    if -1 in phase_ranks or phase_ranks != sorted(phase_ranks):
        raise ValueError(f"Steps for {prediction.case_id} have invalid or out-of-order phases")

    serialized: list[dict[str, object]] = []
    for step_no, step in enumerate(prediction.steps, start=1):
        expected = OPERATION_STATES.get(step.operation)
        if expected != (step.phase, step.state):
            raise ValueError(f"Invalid operation/phase/state combination in {prediction.case_id}: {step.operation}")
        if not step.system_id or not step.resource_id:
            raise ValueError(f"Step in {prediction.case_id} is missing system_id or resource_id")
        if step.phase == "FINDING" and not step.evidence_id:
            raise ValueError(f"Finding in {prediction.case_id} must cite evidence")
        if step.phase == "VERIFICATION" and prediction.deletion_status == "COMPLETE" and not step.evidence_id:
            raise ValueError(f"Complete verification in {prediction.case_id} must cite evidence")
        if prediction.deletion_status == "INCOMPLETE" and step.phase != "FINDING" and step.evidence_id:
            raise ValueError(f"Future step in {prediction.case_id} must have an empty evidence_id")
        serialized.append(step.as_dict(step_no))

    return json.dumps(serialized, ensure_ascii=False, separators=(",", ":"))


def write_output(path: str | Path, predictions: Iterable[CasePrediction]) -> None:
    """Write one sorted, contract-checked output row per prediction."""
    rows = list(predictions)
    case_ids = [row.case_id for row in rows]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Predictions contain duplicate case_id values")
    rows.sort(key=lambda row: row.case_id)

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for prediction in rows:
            writer.writerow({
                "case_id": prediction.case_id,
                "deletion_status": prediction.deletion_status,
                "steps_json": _serialized_steps(prediction),
            })
