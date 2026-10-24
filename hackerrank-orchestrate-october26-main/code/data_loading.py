"""Load the participant-facing CSV inputs and evidence manifest."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


class DatasetError(ValueError):
    """Raised when a required dataset file is missing or malformed."""


@dataclass(frozen=True)
class Dataset:
    """Participant-facing inputs needed by the audit pipeline."""

    dataset_dir: Path
    requests: tuple[dict[str, str], ...]
    identities: tuple[dict[str, str], ...]
    identity_audit_log: tuple[dict[str, str], ...]
    system_activity: tuple[dict[str, str], ...]
    deletion_rules: tuple[dict[str, str], ...]
    evidence_manifest: dict[str, dict[str, str]]

    def evidence_path(self, file_id: str) -> Path:
        """Return the on-disk path for a manifest entry."""
        try:
            entry = self.evidence_manifest[file_id]
        except KeyError as exc:
            raise DatasetError(f"Unknown evidence file_id: {file_id}") from exc
        return self.dataset_dir / entry["file_path"]


_INPUTS = {
    "requests": ("deletion_requests.csv", {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"}),
    "identities": ("user_identities.csv", {"user_id", "name", "email", "phone", "email_hash", "updated_at"}),
    "identity_audit_log": ("user_audit_log.csv", {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"}),
    "system_activity": ("system_activity.csv", {"activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"}),
    "deletion_rules": ("deletion_rules.csv", {"rule_id", "data_category", "condition", "required_action"}),
    "evidence_manifest": ("evidence_files.csv", {"file_id", "file_path", "origin", "captured_at"}),
}


def _read_csv(path: Path, required_columns: set[str]) -> list[dict[str, str]]:
    if not path.is_file():
        raise DatasetError(f"Required input is missing: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise DatasetError(f"CSV has no header: {path}")
        missing = required_columns.difference(reader.fieldnames)
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise DatasetError(f"CSV {path} is missing required columns: {missing_text}")
        return [dict(row) for row in reader]


def load_dataset(dataset_dir: str | Path) -> Dataset:
    """Load required CSVs and confirm every manifest path exists."""
    base = Path(dataset_dir).resolve()
    if not base.is_dir():
        raise DatasetError(f"Dataset directory does not exist: {base}")

    tables: dict[str, list[dict[str, str]]] = {}
    for key, (filename, columns) in _INPUTS.items():
        tables[key] = _read_csv(base / filename, columns)

    request_ids = [row["case_id"] for row in tables["requests"]]
    if len(request_ids) != len(set(request_ids)):
        raise DatasetError("deletion_requests.csv contains duplicate case_id values")

    manifest_rows = tables["evidence_manifest"]
    manifest_ids = [row["file_id"] for row in manifest_rows]
    if len(manifest_ids) != len(set(manifest_ids)):
        raise DatasetError("evidence_files.csv contains duplicate file_id values")

    evidence_root = base.resolve()
    manifest: dict[str, dict[str, str]] = {}
    for row in manifest_rows:
        candidate = (base / row["file_path"]).resolve()
        try:
            candidate.relative_to(evidence_root)
        except ValueError as exc:
            raise DatasetError(f"Evidence path escapes the dataset directory: {row['file_path']}") from exc
        if not candidate.is_file():
            raise DatasetError(f"Evidence file listed in manifest is missing: {row['file_path']}")
        manifest[row["file_id"]] = row

    return Dataset(
        dataset_dir=base,
        requests=tuple(tables["requests"]),
        identities=tuple(tables["identities"]),
        identity_audit_log=tuple(tables["identity_audit_log"]),
        system_activity=tuple(tables["system_activity"]),
        deletion_rules=tuple(tables["deletion_rules"]),
        evidence_manifest=manifest,
    )
