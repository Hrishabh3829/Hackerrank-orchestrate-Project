"""Build a case-scoped, cutoff-aware view over evidence and activity."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from evidence import EvidenceCorpus, EvidenceCoverage, EvidenceRecord
from identity_resolution import ResolvedSubject


RESOURCE_REFERENCE_FIELDS = {
    "resource_id", "source_resource_id", "parent_resource_id", "customer_reference",
    "subject_reference", "account_reference", "archive_key", "object_key", "order_reference",
}
RESOURCE_ID_PATTERN = re.compile(
    r"\b(?:account|search|support|support_attachment|analytics|audit_record|tombstone|data_flow|backup|export|"
    r"marketing|cache|telemetry|email_delivery|secondary_identifier|legal_hold)_[0-9][A-Za-z0-9_-]*\b",
    re.IGNORECASE,
)

RESOURCE_SCOPE_HINTS = (
    ("account_", "account_service", "USER_PROFILE"),
    ("search_", "search_service", "SEARCH_INDEX_ENTRY"),
    ("analytics_", "analytics_platform", "ANALYTICS_PROFILE"),
    ("audit_record_", "security_service", "SECURITY_AUDIT_LOG"),
    ("tombstone_", "identity_service", "ACCOUNT_TOMBSTONE"),
    ("data_flow_", "integration_service", "DATA_FLOW"),
    ("backup_", "backup_service", "BACKUP_ARCHIVE"),
    ("export_", "export_service", "USER_EXPORT"),
    ("marketing_", "marketing_service", "MARKETING_PROFILE"),
    ("cache_", "cache_service", "CACHE_ENTRY"),
    ("telemetry_", "telemetry_service", "PRODUCT_TELEMETRY"),
    ("email_delivery_", "email_delivery_service", "EMAIL_DELIVERY_LOG"),
)


def scope_hint(resource_id: str) -> tuple[str, str] | None:
    lowered = resource_id.casefold()
    for prefix, system_id, category in RESOURCE_SCOPE_HINTS:
        if lowered.startswith(prefix):
            return system_id, category
    return None


@dataclass(frozen=True)
class CaseTimeline:
    subject: ResolvedSubject
    audit_at: str
    evidence_records: tuple[EvidenceRecord, ...]
    coverage: tuple[EvidenceCoverage, ...]
    activity_events: tuple[Mapping[str, str], ...]
    resource_ids: frozenset[str]


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def timestamp_is_at_or_before(value: str, cutoff: str) -> bool:
    timestamp = parse_timestamp(value)
    cutoff_time = parse_timestamp(cutoff)
    return timestamp is not None and cutoff_time is not None and timestamp <= cutoff_time


def _ascii_fold(text: str) -> str:
    """Normalize text for case-insensitive identifier matching."""
    normalized = unicodedata.normalize("NFKD", text.casefold())
    return "".join(
        char for char in normalized
        if not unicodedata.combining(char)
    )


def _contains_identifier(text: str, identifier: str) -> bool:
    candidate = identifier.strip()
    if not candidate:
        return False
    folded_text = _ascii_fold(text)
    folded_candidate = _ascii_fold(candidate)
    if "@" in candidate:
        return candidate.casefold() in text.casefold()
    digits = re.sub(r"\D", "", candidate)
    if len(digits) >= 7 and len(digits) > len(candidate) // 2:
        return digits in re.sub(r"\D", "", text)
    if any(char.isspace() for char in candidate):
        return " ".join(folded_candidate.split()) in " ".join(folded_text.split())
    return re.search(rf"(?<![\w]){re.escape(folded_candidate)}(?![\w])", folded_text, re.IGNORECASE) is not None


def _subject_matches(record: EvidenceRecord, subject: ResolvedSubject) -> bool:
    searchable = record.text
    for identifier in subject.identifiers:
        if _contains_identifier(searchable, identifier):
            return True
    return False


def _extract_resource_references(record: EvidenceRecord) -> set[str]:
    found: set[str] = set()
    for key, value in record.fields.items():
        if key.casefold() not in RESOURCE_REFERENCE_FIELDS:
            continue
        if isinstance(value, str) and value.strip():
            found.add(value.strip())
    return found


def build_case_timeline(
    corpus: EvidenceCorpus,
    subject: ResolvedSubject,
    audit_at: str,
    system_activity: Iterable[Mapping[str, str]],
) -> CaseTimeline:
    """Connect subject records, related resource IDs, and events up to cutoff."""
    if parse_timestamp(audit_at) is None:
        raise ValueError(f"Invalid audit_at timestamp: {audit_at}")

    eligible_records = tuple(
        record for record in corpus.records
        if timestamp_is_at_or_before(record.available_at, audit_at)
        and timestamp_is_at_or_before(record.observed_at, audit_at)
    )
    eligible_coverage = tuple(
        item for item in corpus.coverage
        if timestamp_is_at_or_before(item.available_at, audit_at)
        and timestamp_is_at_or_before(item.observed_at, audit_at)
    )

    selected: set[int] = set()
    resource_ids = set(subject.linked_resource_ids)
    for index, record in enumerate(eligible_records):
        if _subject_matches(record, subject):
            selected.add(index)
            if record.resource_id:
                resource_ids.add(record.resource_id)
            resource_ids.update(_extract_resource_references(record))

    relevant_activities: list[Mapping[str, str]] = []
    for event in system_activity:
        if not timestamp_is_at_or_before(event.get("event_time", ""), audit_at):
            continue
        details = event.get("details", "")
        event_resource = event.get("resource_id", "")
        if event_resource not in resource_ids and not _subject_matches_text(details, subject):
            continue
        relevant_activities.append(event)
        if event_resource:
            resource_ids.add(event_resource)
        resource_ids.update(RESOURCE_ID_PATTERN.findall(details))

    # Follow explicit resource references only; do not expand arbitrary text
    # mentions into unrelated records.
    changed = True
    while changed:
        changed = False
        for index, record in enumerate(eligible_records):
            if index in selected:
                continue
            if record.resource_id and record.resource_id in resource_ids:
                selected.add(index)
                resource_ids.update(_extract_resource_references(record))
                changed = True
                continue
            references = _extract_resource_references(record)
            if references.intersection(resource_ids):
                selected.add(index)
                if record.resource_id:
                    resource_ids.add(record.resource_id)
                resource_ids.update(references)
                changed = True

    relevant_records = tuple(sorted(
        (eligible_records[index] for index in selected),
        key=lambda record: (record.observed_at, record.evidence_id, record.system_id, record.resource_id),
    ))
    relevant_coverage = tuple(
        item for item in eligible_coverage
        if item.present_resource_ids.intersection(resource_ids)
        or any(record.system_id == item.system_id and record.data_category == item.data_category for record in relevant_records)
        or any(scope_hint(resource_id) == (item.system_id, item.data_category) for resource_id in resource_ids)
    )

    return CaseTimeline(
        subject=subject,
        audit_at=audit_at,
        evidence_records=relevant_records,
        coverage=relevant_coverage,
        activity_events=tuple(sorted(relevant_activities, key=lambda event: (event.get("event_time", ""), event.get("activity_id", "")))),
        resource_ids=frozenset(resource_ids),
    )


def _subject_matches_text(text: str, subject: ResolvedSubject) -> bool:
    return any(_contains_identifier(text, identifier) for identifier in subject.identifiers)
