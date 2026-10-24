"""Compare the agent with the public sample answers without changing inputs."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from data_loading import load_dataset  # noqa: E402
from evidence import load_evidence  # noqa: E402
from investigation import investigate_case  # noqa: E402
from output_generation import write_output  # noqa: E402


STEP_FIELDS = (
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id",
)


def _normalized_steps(value: str) -> list[dict[str, object]]:
    steps = json.loads(value)
    if not isinstance(steps, list):
        raise ValueError("steps_json must decode to a list")
    if not all(isinstance(step, dict) for step in steps):
        raise ValueError("every steps_json element must be an object")
    return steps


def compare_samples(dataset_dir: Path, include_details: bool = False) -> dict[str, object]:
    dataset = load_dataset(dataset_dir)
    corpus = load_evidence(dataset)
    predictions = [
        investigate_case(request, dataset, corpus)
        for request in dataset.sample_requests
    ]

    with tempfile.TemporaryDirectory(prefix="deletion-audit-sample-") as temporary_dir:
        output_path = Path(temporary_dir) / "sample_predictions.csv"
        write_output(output_path, predictions)
        with output_path.open("r", encoding="utf-8", newline="") as source:
            predicted_rows = {row["case_id"]: row for row in csv.DictReader(source)}

    expected_rows = {row["case_id"]: row for row in dataset.sample_output}
    case_ids = sorted(set(expected_rows) | set(predicted_rows))
    if not case_ids:
        raise ValueError("No public sample requests and answers were found")

    status_matches = 0
    row_matches = 0
    sequence_matches = 0
    correct_fields = 0
    possible_fields = 0
    exact_steps = 0
    possible_steps = 0
    case_diagnostics: list[dict[str, object]] = []

    for case_id in case_ids:
        expected = expected_rows.get(case_id)
        predicted = predicted_rows.get(case_id)
        if expected is None or predicted is None:
            possible_fields += 1 + len(STEP_FIELDS)
            possible_steps += 1
            continue
        if expected["deletion_status"] == predicted["deletion_status"]:
            status_matches += 1

        expected_steps = _normalized_steps(expected["steps_json"])
        predicted_steps = _normalized_steps(predicted["steps_json"])
        if expected["deletion_status"] == predicted["deletion_status"] and expected_steps == predicted_steps:
            row_matches += 1
        if expected_steps == predicted_steps:
            sequence_matches += 1
        if expected["deletion_status"] != predicted["deletion_status"] or expected_steps != predicted_steps:
            case_diagnostics.append({
                "case_id": case_id,
                "expected_status": expected["deletion_status"],
                "predicted_status": predicted["deletion_status"],
                "expected_step_count": len(expected_steps),
                "predicted_step_count": len(predicted_steps),
                "expected_operations": [step.get("operation") for step in expected_steps],
                "predicted_operations": [step.get("operation") for step in predicted_steps],
            })

        aligned_count = max(len(expected_steps), len(predicted_steps))
        for index in range(aligned_count):
            possible_steps += 1
            possible_fields += len(STEP_FIELDS)
            if index >= len(expected_steps) or index >= len(predicted_steps):
                continue
            expected_step = expected_steps[index]
            predicted_step = predicted_steps[index]
            if expected_step == predicted_step:
                exact_steps += 1
            correct_fields += sum(
                expected_step.get(field) == predicted_step.get(field)
                for field in STEP_FIELDS
            )

    sample_count = len(case_ids)
    metrics: dict[str, object] = {
        "sample_cases": sample_count,
        "status_correct": status_matches,
        "status_accuracy": status_matches / sample_count,
        "exact_rows": row_matches,
        "row_accuracy": row_matches / sample_count,
        "exact_step_matches": exact_steps,
        "possible_aligned_steps": possible_steps,
        "step_accuracy": exact_steps / possible_steps if possible_steps else 1.0,
        "correct_step_fields": correct_fields,
        "possible_step_fields": possible_fields,
        "field_accuracy": correct_fields / possible_fields if possible_fields else 1.0,
        "exact_sequences": sequence_matches,
        "sequence_accuracy": sequence_matches / sample_count,
    }
    if include_details:
        metrics["mismatches"] = case_diagnostics
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=CODE_DIR.parent / "dataset",
        help="Participant-facing dataset directory.",
    )
    parser.add_argument("--details", action="store_true", help="Include case-level operation differences.")
    args = parser.parse_args()
    print(json.dumps(compare_samples(args.dataset_dir, include_details=args.details), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
