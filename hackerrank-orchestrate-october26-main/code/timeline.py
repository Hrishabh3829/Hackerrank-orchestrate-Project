"""Build a case-scoped, cutoff-aware view over evidence and activity."""

from __future__ import annotations

import re
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable, Mapping

from evidence import EvidenceCorpus, EvidenceCoverage, EvidenceRecord
from identity_resolution import ResolvedSubject


RESOURCE_REFERENCE_FIELDS = {
    "resource_id", "source_resource_id", "parent_resource_id", "customer_reference",
    "subject_reference", "account_reference", "archive_key", "object_key", "order_reference",
}
TRACE_LINK_FIELDS = {"trace_id", "correlation_id", "correlation_key", "request_id", "span_id"}
RESOURCE_ID_PATTERN = re.compile(
    r"\b(?:account|search|support|support_attachment|analytics|audit_record|tombstone|data_flow|backup|export|order|"
    r"marketing|cache|telemetry|email_delivery|secondary_identifier|legal_hold)[_-][0-9][A-Za-z0-9_-]*\b",
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
        if lowered.startswith(prefix) or lowered.startswith(prefix[:-1] + "-"):
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


@dataclass(frozen=True)
class _RecordLinkIndex:
    by_resource: Mapping[str, frozenset[int]]
    by_reference: Mapping[str, frozenset[int]]
    by_trace: Mapping[tuple[str, str, str], frozenset[int]]


_RECORD_LINK_INDEX: tuple[tuple[EvidenceRecord, ...], _RecordLinkIndex] | None = None


@lru_cache(maxsize=65536)
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


@lru_cache(maxsize=65536)
def _ascii_fold(text: str) -> str:
    """Normalize text for case-insensitive identifier matching."""
    normalized = unicodedata.normalize("NFKD", text.casefold())
    return "".join(
        char for char in normalized
        if not unicodedata.combining(char)
    )


@lru_cache(maxsize=65536)
def _digits_only(text: str) -> str:
    return re.sub(r"\D", "", text)


@lru_cache(maxsize=65536)
def _phone_digit_sequences(text: str) -> tuple[str, ...]:
    """Extract bounded digit groups once per evidence text for repeat matching."""
    chunks = tuple(re.finditer(r"\d+", text))
    found: set[str] = set()
    for start, first in enumerate(chunks):
        combined = first.group(0)
        if 7 <= len(combined) <= 15:
            found.add(combined)
        for end in range(start + 1, min(len(chunks), start + 19)):
            gap = text[chunks[end - 1].end():chunks[end].start()]
            if not re.fullmatch(r"[+\s().-]*", gap):
                break
            combined += chunks[end].group(0)
            if 7 <= len(combined) <= 15:
                found.add(combined)
            if len(combined) > 15:
                break
    return tuple(found)


@lru_cache(maxsize=4096)
def _whole_token_pattern(identifier: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w]){re.escape(identifier)}(?![\w])", re.IGNORECASE)


def _contains_identifier(text: str, identifier: str) -> bool:
    candidate = identifier.strip()
    if not candidate:
        return False
    if "@" in candidate:
        return candidate.casefold() in text.casefold()
    # Email hashes are opaque identifiers, not telephone numbers. Treating a
    # hexadecimal hash as digits caused false phone matches and missed the
    # exact hashed value in downstream evidence.
    if re.fullmatch(r"[0-9a-f]{64}", candidate, re.IGNORECASE):
        return candidate.casefold() in text.casefold()
    digits = _digits_only(candidate)
    if len(digits) >= 7 and len(digits) > len(candidate) // 2:
        return any(
            sequence == digits
            or 1 <= len(sequence) - len(digits) <= 3 and sequence.endswith(digits)
            for sequence in _phone_digit_sequences(text)
        )
    if any(char.isspace() for char in candidate) or not candidate.isascii():
        folded_text = _ascii_fold(text)
        folded_candidate = _ascii_fold(candidate)
        if not any(char.isspace() for char in candidate):
            return _whole_token_pattern(folded_candidate).search(folded_text) is not None
        return " ".join(folded_candidate.split()) in " ".join(folded_text.split())
    return _whole_token_pattern(candidate).search(text) is not None


def _subject_matches(record: EvidenceRecord, subject: ResolvedSubject) -> bool:
    searchable = record.text
    for identifier in subject.identifiers - subject.name_identifiers:
        if _contains_identifier(searchable, identifier):
            return True
    return any(_contains_identifier(searchable, identifier) for identifier in subject.weak_identifiers)


def _extract_resource_references(record: EvidenceRecord) -> set[str]:
    found: set[str] = set()
    for key, value in record.fields.items():
        if key.casefold() not in RESOURCE_REFERENCE_FIELDS:
            continue
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if (
                candidate.casefold() not in {"null", "none", "n/a", "unknown", "undefined"}
                and RESOURCE_ID_PATTERN.fullmatch(candidate)
            ):
                found.add(candidate)
    return found


def _extract_trace_links(record: EvidenceRecord) -> set[tuple[str, str, str]]:
    links: set[tuple[str, str, str]] = set()
    for key, value in record.fields.items():
        normalized_key = key.casefold()
        if normalized_key not in TRACE_LINK_FIELDS or not isinstance(value, str):
            continue
        candidate = value.strip().casefold()
        if candidate and candidate not in {"null", "none", "n/a", "unknown", "undefined"}:
            # Trace identifiers are scoped to their evidence artifact and field
            # to avoid accidental joins across unrelated files or key types.
            links.add((record.evidence_id, normalized_key, candidate))
    return links


def _record_link_index(records: tuple[EvidenceRecord, ...]) -> _RecordLinkIndex:
    global _RECORD_LINK_INDEX
    if _RECORD_LINK_INDEX is not None and _RECORD_LINK_INDEX[0] is records:
        return _RECORD_LINK_INDEX[1]

    by_resource: dict[str, set[int]] = defaultdict(set)
    by_reference: dict[str, set[int]] = defaultdict(set)
    by_trace: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    for index, record in enumerate(records):
        if record.resource_id:
            by_resource[record.resource_id].add(index)
        for reference in _extract_resource_references(record):
            by_reference[reference].add(index)
        for trace_link in _extract_trace_links(record):
            by_trace[trace_link].add(index)
    index = _RecordLinkIndex(
        by_resource={key: frozenset(value) for key, value in by_resource.items()},
        by_reference={key: frozenset(value) for key, value in by_reference.items()},
        by_trace={key: frozenset(value) for key, value in by_trace.items()},
    )
    _RECORD_LINK_INDEX = (records, index)
    return index


def build_case_timeline(
    corpus: EvidenceCorpus,
    subject: ResolvedSubject,
    audit_at: str,
    system_activity: Iterable[Mapping[str, str]],
) -> CaseTimeline:
    """Connect subject records, related resource IDs, and events up to cutoff."""
    if parse_timestamp(audit_at) is None:
        raise ValueError(f"Invalid audit_at timestamp: {audit_at}")

    record_index = _record_link_index(corpus.records)
    eligible_record_indexes = frozenset(
        index for index, record in enumerate(corpus.records)
        if timestamp_is_at_or_before(record.available_at, audit_at)
        and timestamp_is_at_or_before(record.observed_at, audit_at)
    )
    eligible_coverage = tuple(
        item for item in corpus.coverage
        if timestamp_is_at_or_before(item.available_at, audit_at)
        and timestamp_is_at_or_before(item.observed_at, audit_at)
    )

    selected: set[int] = set()
    resource_ids: set[str] = set()
    trace_links: set[tuple[str, str, str]] = set()
    relevant_activity_indexes: set[int] = set()
    pending_records: deque[int] = deque()
    pending_resources: deque[str] = deque()
    pending_traces: deque[tuple[str, str, str]] = deque()
    eligible_activities = tuple(
        event for event in system_activity
        if timestamp_is_at_or_before(event.get("event_time", ""), audit_at)
    )
    activity_index: dict[str, set[int]] = defaultdict(set)
    for index, event in enumerate(eligible_activities):
        resource_id = event.get("resource_id", "")
        if resource_id:
            activity_index[resource_id].add(index)

    def add_resource(resource_id: str) -> None:
        if resource_id and resource_id not in resource_ids:
            resource_ids.add(resource_id)
            pending_resources.append(resource_id)

    def add_trace(trace_link: tuple[str, str, str]) -> None:
        if trace_link not in trace_links:
            trace_links.add(trace_link)
            pending_traces.append(trace_link)

    def include_record(index: int) -> None:
        if index not in eligible_record_indexes or index in selected:
            return
        selected.add(index)
        pending_records.append(index)

    def include_activity(index: int) -> None:
        if index in relevant_activity_indexes:
            return
        relevant_activity_indexes.add(index)
        event = eligible_activities[index]
        add_resource(event.get("resource_id", ""))
        for resource_id in RESOURCE_ID_PATTERN.findall(event.get("details", "")):
            add_resource(resource_id)

    for index in sorted(eligible_record_indexes):
        record = corpus.records[index]
        if _subject_matches(record, subject):
            include_record(index)
    for resource_id in subject.linked_resource_ids:
        add_resource(resource_id)

    # Activity events can introduce resources directly or through details that
    # explicitly identify the request subject. Their results remain claims;
    # linked evidence records establish the observed state.
    for index, event in enumerate(eligible_activities):
        if _subject_matches_text(event.get("details", ""), subject):
            include_activity(index)

    while pending_records or pending_resources or pending_traces:
        while pending_records:
            record = corpus.records[pending_records.popleft()]
            add_resource(record.resource_id)
            for reference in _extract_resource_references(record):
                add_resource(reference)
            for trace_link in _extract_trace_links(record):
                add_trace(trace_link)
        while pending_resources:
            resource_id = pending_resources.popleft()
            for index in sorted(record_index.by_resource.get(resource_id, ())):
                include_record(index)
            for index in sorted(record_index.by_reference.get(resource_id, ())):
                include_record(index)
            for index in activity_index.get(resource_id, ()):
                include_activity(index)
        while pending_traces:
            trace_link = pending_traces.popleft()
            for index in sorted(record_index.by_trace.get(trace_link, ())):
                include_record(index)

    relevant_activities = tuple(
        eligible_activities[index]
        for index in sorted(relevant_activity_indexes)
    )

    relevant_records = tuple(sorted(
        (corpus.records[index] for index in selected),
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
    strong = subject.identifiers - subject.name_identifiers
    return any(_contains_identifier(text, identifier) for identifier in strong) or any(
        _contains_identifier(text, identifier) for identifier in subject.weak_identifiers
    )
