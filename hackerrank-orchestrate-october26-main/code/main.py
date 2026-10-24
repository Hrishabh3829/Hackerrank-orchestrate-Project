"""Command-line entry point for the Ghost Data Still Exists project."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from data_loading import DatasetError, load_dataset
from evidence import EvidenceReadError, load_evidence
from investigation import investigate_case
from output_generation import write_output


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit deletion requests using the supplied evidence and policies.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=PROJECT_ROOT / "dataset",
        help="Path to the participant-facing dataset directory (default: ./dataset).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "output.csv",
        help="Output CSV path (default: repository-root output.csv).",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        dataset = load_dataset(args.dataset_dir)
        corpus = load_evidence(dataset)
        predictions = [investigate_case(request, dataset, corpus) for request in dataset.requests]
        write_output(args.output, predictions)
    except (DatasetError, EvidenceReadError, ValueError) as exc:
        raise SystemExit(f"Dataset error: {exc}") from exc

    counts = Counter(prediction.deletion_status for prediction in predictions)
    print(f"Dataset: {dataset.dataset_dir}")
    print(f"Requests audited: {len(predictions)}")
    print(f"Evidence records indexed: {len(corpus.records)}")
    print(f"Evidence snapshot scopes indexed: {len(corpus.coverage)}")
    print(f"Status counts: {dict(sorted(counts.items()))}")
    print(f"Output written: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
