"""Command-line entry point for the Ghost Data Still Exists project."""

from __future__ import annotations

import argparse
from pathlib import Path

from data_loading import DatasetError, load_dataset


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Load and inspect deletion-audit inputs.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=PROJECT_ROOT / "dataset",
        help="Path to the participant-facing dataset directory (default: ./dataset).",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        dataset = load_dataset(args.dataset_dir)
    except DatasetError as exc:
        raise SystemExit(f"Dataset error: {exc}") from exc

    print(f"Dataset: {dataset.dataset_dir}")
    print(f"Deletion requests: {len(dataset.requests)}")
    print(f"Current identity snapshots: {len(dataset.identities)}")
    print(f"Identity audit events: {len(dataset.identity_audit_log)}")
    print(f"System activity events: {len(dataset.system_activity)}")
    print(f"Deletion rules: {len(dataset.deletion_rules)}")
    print(f"Evidence files in manifest: {len(dataset.evidence_manifest)}")
    print("Input loading is ready. Case investigation and output generation will be wired in the next step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
