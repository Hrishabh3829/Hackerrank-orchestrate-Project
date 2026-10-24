"""Policy rule loading, state assessment, and required-treatment mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from evidence import EvidenceCoverage, EvidenceRecord
from identity_resolution import ResolvedSubject
from timeline import CaseTimeline, parse_timestamp, scope_hint


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class PolicyAssessment:
    system_id: str
    resource_id: str
    data_category: str
    action: str
    state: str
    evidence_id: str
    observed_at: str
    violation_operation: str = ""
    remediation_operation: str = ""
    remediation_state: str = ""
    verification_operation: str = ""
    verification_state: str = ""
    compliant: bool = True


def rules_from_rows(rows: Iterable[Mapping[str, str]]) -> tuple[DeletionRule, ...]:
    """Convert CSV rows into typed policy rules."""
    return tuple(
        DeletionRule(
            rule_id=row["rule_id"],
            data_category=row["data_category"],
            condition=row["condition"],
            required_action=row["required_action"].strip().upper(),
        )
        for row in rows
    )


def rules_for_category(category: str, rules: Iterable[DeletionRule]) -> tuple[DeletionRule, ...]:
    wanted = category.strip().casefold()
    return tuple(rule for rule in rules if rule.data_category.strip().casefold() == wanted)


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "yes", "1", "enabled", "active", "allowed", "open"}:
            return True
        if normalized in {"false", "no", "0", "disabled", "inactive", "blocked", "denied", "closed"}:
            return False
    return None


def _normalized_state(record: EvidenceRecord) -> str:
    fields = record.fields
    text_state = record.text.casefold()
    if record.data_category == "DATA_FLOW":
        enabled = parse_bool(fields.get("enabled", fields.get("active")))
        if enabled is True:
            return "ACTIVE"
        if enabled is False:
            return "DISABLED"
        flow_status = str(fields.get("status", fields.get("result", ""))).strip().upper()
        if flow_status in {"ACTIVE", "ENABLED", "RUNNING"}:
            return "ACTIVE"
        if flow_status in {"DISABLED", "INACTIVE", "STOPPED"}:
            return "DISABLED"
        if any(marker in text_state for marker in ("continuous sync", "continuous import", "enabled", "status healthy", "status: healthy", " active")):
            return "ACTIVE"
        if any(marker in text_state for marker in ("sync disabled", "flow disabled", "connector disabled", "inactive", "stopped")):
            return "DISABLED"
    if record.data_category == "BACKUP_ARCHIVE":
        allowed = parse_bool(fields.get("restore_allowed", fields.get("restore_enabled")))
        if allowed is True:
            return "ACTIVE"
        if allowed is False:
            return "BLOCKED"
        if any(marker in text_state for marker in ("restore allowed", "can still be restored", "restore access enabled", "restorable")):
            return "ACTIVE"
        if any(marker in text_state for marker in ("restore blocked", "restore disabled", "restore access blocked")):
            return "BLOCKED"
    for key in ("result", "state", "status", "record_status", "account_status", "deletion_status", "restore_status"):
        value = fields.get(key)
        if value is None:
            continue
        text = str(value).strip().upper().replace("-", "_").replace(" ", "_")
        if text in {"NOT_FOUND", "ABSENT", "DELETED", "REMOVED", "PURGED", "404", "MISSING"}:
            return "ABSENT"
        if text in {"ANONYMIZED", "ANONYMISED"}:
            return "ANONYMIZED"
        if text in {"REDACTED", "MASKED"}:
            return "REDACTED"
        if text in {"BLOCKED", "RESTORE_BLOCKED"}:
            return "BLOCKED"
        if text in {"DISABLED", "INACTIVE", "STOPPED"}:
            return "DISABLED"
        if text in {"ACTIVE", "ENABLED", "IDENTIFIABLE", "FOUND", "PRESENT", "READY", "AVAILABLE", "SUCCESS", "200"}:
            return "PRESENT"

    for key in ("status_code", "http_status", "response_code"):
        value = fields.get(key)
        try:
            code = int(value)
        except (TypeError, ValueError):
            continue
        if code in {404, 410}:
            return "ABSENT"

    for key in ("exists", "record_exists", "present", "found", "is_deleted"):
        value = parse_bool(fields.get(key))
        if key == "is_deleted" and value is True:
            return "ABSENT"
        if key != "is_deleted" and value is False:
            return "ABSENT"
    if parse_bool(fields.get("deleted")) is True:
        return "ABSENT"

    if record.data_category == "DATA_FLOW":
        enabled = parse_bool(fields.get("enabled", fields.get("active")))
        if enabled is True:
            return "ACTIVE"
        if enabled is False:
            return "DISABLED"
    if record.data_category == "BACKUP_ARCHIVE":
        allowed = parse_bool(fields.get("restore_allowed", fields.get("restore_enabled")))
        if allowed is True:
            return "ACTIVE"
        if allowed is False:
            return "BLOCKED"
    return "PRESENT"


def _contains_identifier(text: str, identifier: str) -> bool:
    value = identifier.strip()
    if not value:
        return False
    if "@" in value or len(value) >= 16 and value.isalnum():
        return value.casefold() in text.casefold()
    digits = re.sub(r"\D", "", value)
    if 7 <= len(digits) <= 15 and not any(char.isalpha() for char in value):
        return digits in re.sub(r"\D", "", text)
    if any(char.isspace() for char in value):
        return " ".join(value.casefold().split()) in " ".join(text.casefold().split())
    return re.search(rf"(?<![\w]){re.escape(value)}(?![\w])", text, re.IGNORECASE) is not None


def _has_direct_identifier(record: EvidenceRecord, subject: ResolvedSubject) -> bool:
    direct_fields = {
        "name", "full_name", "display_name", "email", "owner_email", "customer_email",
        "requester_email", "recipient_email", "email_address", "recipient", "to",
        "phone", "owner_phone", "requester_phone", "email_hash",
        "subject_reference", "customer_reference", "user_id", "user_reference",
        "message", "message_text", "message_excerpt", "document", "profile", "record_json",
    }
    identifiers = tuple(subject.identifiers)
    if record.data_category == "EMAIL_DELIVERY_LOG":
        identifiers = tuple(value for value in identifiers if "@" in value)
    if record.data_category == "ACCOUNT_TOMBSTONE":
        direct_fields -= {"user_id", "user_reference", "customer_reference"}

    needles = identifiers

    def visit(value: Any, parent_key: str = "") -> bool:
        if isinstance(value, Mapping):
            return any(visit(child, str(key).casefold()) for key, child in value.items())
        if isinstance(value, (list, tuple)):
            return any(visit(child, parent_key) for child in value)
        if not isinstance(value, str) or not value.strip():
            return False
        if parent_key and parent_key not in direct_fields and parent_key not in {"text", "details"}:
            return False
        return any(_contains_identifier(value, needle) for needle in needles)

    return visit(record.fields)


def _time(value: str) -> datetime:
    parsed = parse_timestamp(value)
    return parsed or datetime.min.replace(tzinfo=timezone.utc)


def _latest_by_component(
    records: Iterable[EvidenceRecord],
    coverage: Iterable[EvidenceCoverage],
    system_id: str,
    resource_id: str,
    category: str,
) -> list[tuple[EvidenceRecord | EvidenceCoverage, str]]:
    grouped: dict[str, list[EvidenceRecord]] = {}
    for record in records:
        if (record.system_id, record.resource_id, record.data_category) != (system_id, resource_id, category):
            continue
        grouped.setdefault(record.source_component or record.source_kind, []).append(record)

    coverage_by_component: dict[str, list[EvidenceCoverage]] = {}
    for item in coverage:
        if (item.system_id, item.data_category) != (system_id, category):
            continue
        coverage_by_component.setdefault(item.source_component, []).append(item)

    latest: list[tuple[EvidenceRecord | EvidenceCoverage, str]] = []
    for component, component_records in grouped.items():
        current_record = max(component_records, key=lambda record: (_time(record.observed_at), _time(record.available_at)))
        component_coverage = coverage_by_component.get(component, [])
        if not component_coverage:
            # JSON/SQL readers may encode table names in the component while
            # a query result uses only a source label; only exact scopes apply.
            latest.append((current_record, _normalized_state(current_record)))
            continue
        current_scope = max(component_coverage, key=lambda item: (_time(item.observed_at), _time(item.available_at)))
        if _time(current_scope.observed_at) >= _time(current_record.observed_at) and resource_id not in current_scope.present_resource_ids:
            latest.append((current_scope, "ABSENT"))
        else:
            latest.append((current_record, _normalized_state(current_record)))

    # A full snapshot can establish absence even if no row survives in that
    # component; callers supply only resource IDs previously linked to subject.
    for component, component_scopes in coverage_by_component.items():
        if component in grouped:
            continue
        current_scope = max(component_scopes, key=lambda item: (_time(item.observed_at), _time(item.available_at)))
        if resource_id not in current_scope.present_resource_ids:
            latest.append((current_scope, "ABSENT"))

    return latest


def _is_retention_active(record: EvidenceRecord, audit_at: str) -> bool:
    retention_until = str(record.fields.get("retention_until", record.fields.get("retained_until", "")))
    if not retention_until:
        return True
    expiry = parse_timestamp(retention_until)
    cutoff = parse_timestamp(audit_at)
    return bool(expiry and cutoff and expiry >= cutoff)


def _rule_action(category: str, record: EvidenceRecord, rules: tuple[DeletionRule, ...], audit_at: str) -> str:
    matching = rules_for_category(category, rules)
    action = matching[0].required_action if matching else ""
    fields = record.fields
    if category == "DATA_FLOW":
        return "DISABLE_DATA_FLOW"
    if category == "BACKUP_ARCHIVE":
        if _normalized_state(record) == "BLOCKED":
            return "RETAIN"
        can_block = parse_bool(fields.get("can_block_restore", fields.get("restore_access_blockable")))
        return "RETAIN" if can_block is not False else "DELETE"
    if category == "SECURITY_AUDIT_LOG" and not _is_retention_active(record, audit_at):
        return "DELETE"
    if category == "LEGAL_HOLD_RECORD":
        active = parse_bool(fields.get("active", fields.get("hold_active", fields.get("legal_hold_active"))))
        if active is False:
            return "DELETE"
    if category == "SUPPORT_ATTACHMENT":
        shared = parse_bool(fields.get("shared_context", fields.get("shared_with_others")))
        if shared is True:
            return "REDACT"
    if category == "SUPPORT_MESSAGE":
        shared = parse_bool(fields.get("shared_context", fields.get("shared_with_others")))
        if shared is False:
            return "DELETE"
    return action


def assess_timeline(timeline: CaseTimeline, rules: Iterable[DeletionRule]) -> tuple[PolicyAssessment, ...]:
    """Apply policy to the latest evidence state of each linked resource."""
    rule_set = tuple(rules)
    resource_keys = sorted({
        (record.system_id, record.resource_id, record.data_category)
        for record in timeline.evidence_records
        if record.resource_id and record.data_category
    })
    resource_keys.extend(
        (hint[0], resource_id, hint[1])
        for resource_id in timeline.resource_ids
        if (hint := scope_hint(resource_id)) is not None
        and any(item.system_id == hint[0] and item.data_category == hint[1] for item in timeline.coverage)
    )
    resource_keys = sorted(set(resource_keys))

    assessments: list[PolicyAssessment] = []
    for system_id, resource_id, category in resource_keys:
        observations = _latest_by_component(
            timeline.evidence_records, timeline.coverage, system_id, resource_id, category,
        )
        if not observations:
            continue
        action_record = max(
            (item for item, _ in observations),
            key=lambda item: (_time(item.observed_at), _time(item.available_at)),
        )
        if not isinstance(action_record, EvidenceRecord):
            continue
        action = _rule_action(category, action_record, rule_set, timeline.audit_at)
        if not action:
            continue

        present = [(item, state) for item, state in observations if state not in {"ABSENT"}]
        absent = not present
        violation_item: EvidenceRecord | EvidenceCoverage | None = None
        violation_operation = ""
        remediation_operation = ""
        remediation_state = ""
        verification_operation = ""
        verification_state = ""
        compliant = True
        state = "ABSENT" if absent else "PRESENT"

        if action == "DELETE":
            verification_operation, verification_state = "VERIFY_RECORD_ABSENT", "ABSENT"
            if not absent:
                violation_item = max((item for item, _ in present), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
                violation_operation = "REPORT_REMAINING_RECORD"
                remediation_operation, remediation_state = "DELETE_RECORD", "ABSENT"
                compliant, state = False, "PRESENT"
            else:
                item = max((item for item, _ in observations), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
                violation_item = item
        elif action == "REDACT":
            verification_operation, verification_state = "VERIFY_RECORD_REDACTED", "REDACTED"
            exposed = [item for item, _ in present if isinstance(item, EvidenceRecord) and _has_direct_identifier(item, timeline.subject)]
            if exposed:
                violation_item = max(exposed, key=lambda item: (_time(item.observed_at), _time(item.available_at)))
                violation_operation = "REPORT_EXPOSED_PII"
                remediation_operation, remediation_state = "REDACT_RECORD", "REDACTED"
                compliant, state = False, "PRESENT"
            elif present:
                state = "REDACTED"
                violation_item = max((item for item, _ in present), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
            else:
                continue
        elif action == "ANONYMIZE":
            verification_operation, verification_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            attributable = [item for item, _ in present if isinstance(item, EvidenceRecord) and _has_direct_identifier(item, timeline.subject)]
            if attributable:
                violation_item = max(attributable, key=lambda item: (_time(item.observed_at), _time(item.available_at)))
                violation_operation = "REPORT_EXPOSED_PII"
                remediation_operation, remediation_state = "ANONYMIZE_RECORD", "ANONYMIZED"
                compliant, state = False, "PRESENT"
            elif present:
                state = "ANONYMIZED"
                violation_item = max((item for item, _ in present), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
            else:
                continue
        elif action == "RETAIN":
            if category == "BACKUP_ARCHIVE":
                # Backup presence is expected. Only an enabled restore path is
                # actionable, and that is assessed separately below.
                continue
            verification_operation, verification_state = "VERIFY_RECORD_PRESENT", "PRESENT"
            if present:
                state = "PRESENT"
                violation_item = max((item for item, _ in present), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
            else:
                # The allowed output vocabulary has no finding for a missing
                # policy-required retained record; keep it out of the plan.
                continue
        elif action == "DISABLE_DATA_FLOW":
            verification_operation, verification_state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            active = [(item, item_state) for item, item_state in present if item_state == "ACTIVE"]
            if active:
                violation_item = max((item for item, _ in active), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
                violation_operation = "REPORT_ACTIVE_DATA_FLOW"
                remediation_operation, remediation_state = "DISABLE_DATA_FLOW", "DISABLED"
                compliant, state = False, "ACTIVE"
            else:
                disabled = [(item, item_state) for item, item_state in observations if item_state == "DISABLED"]
                if not disabled:
                    continue
                violation_item = max((item for item, _ in observations), key=lambda item: (_time(item.observed_at), _time(item.available_at)))
                state = "DISABLED"
        else:
            continue

        if violation_item is None:
            continue
        assessments.append(PolicyAssessment(
            system_id=system_id,
            resource_id=resource_id,
            data_category=category,
            action=action,
            state=state,
            evidence_id=violation_item.evidence_id,
            observed_at=violation_item.observed_at,
            violation_operation=violation_operation,
            remediation_operation=remediation_operation,
            remediation_state=remediation_state,
            verification_operation=verification_operation,
            verification_state=verification_state,
            compliant=compliant,
        ))

    # A backup archive is retained by policy; only a live restore path is a risk.
    # Its restore_allowed flag is independent of the archive's own presence.
    backup_keys = [
        (record.system_id, record.resource_id, record.data_category)
        for record in timeline.evidence_records
        if record.resource_id and record.data_category == "BACKUP_ARCHIVE"
    ]
    for system_id, resource_id, category in sorted(set(backup_keys)):
        records = [record for record in timeline.evidence_records if (record.system_id, record.resource_id, record.data_category) == (system_id, resource_id, category)]
        latest = max(records, key=lambda record: (_time(record.observed_at), _time(record.available_at)))
        can_block = parse_bool(latest.fields.get("can_block_restore", latest.fields.get("restore_access_blockable")))
        allowed = parse_bool(latest.fields.get("restore_allowed", latest.fields.get("restore_enabled")))
        result = str(latest.fields.get("result", latest.fields.get("status", ""))).upper()
        if can_block is not False and (allowed is True or result in {"ACTIVE", "RESTORE_ALLOWED", "RESTORABLE"}):
            assessments.append(PolicyAssessment(
                system_id=system_id,
                resource_id=resource_id,
                data_category=category,
                action="BLOCK_RESTORE",
                state="ACTIVE",
                evidence_id=latest.evidence_id,
                observed_at=latest.observed_at,
                violation_operation="REPORT_RESTORE_RISK",
                remediation_operation="BLOCK_RESTORE",
                remediation_state="BLOCKED",
                verification_operation="VERIFY_RESTORE_BLOCKED",
                verification_state="BLOCKED",
                compliant=False,
            ))
        elif allowed is False or result in {"BLOCKED", "RESTORE_BLOCKED"}:
            assessments.append(PolicyAssessment(
                system_id=system_id,
                resource_id=resource_id,
                data_category=category,
                action="BLOCK_RESTORE",
                state="BLOCKED",
                evidence_id=latest.evidence_id,
                observed_at=latest.observed_at,
                verification_operation="VERIFY_RESTORE_BLOCKED",
                verification_state="BLOCKED",
                compliant=True,
            ))

    # Keep only the latest assessment per system/resource/category/action.
    by_key: dict[tuple[str, str, str, str], PolicyAssessment] = {}
    for assessment in assessments:
        key = (assessment.system_id, assessment.resource_id, assessment.data_category, assessment.action)
        prior = by_key.get(key)
        if prior is None or _time(assessment.observed_at) >= _time(prior.observed_at):
            by_key[key] = assessment
    return tuple(sorted(by_key.values(), key=lambda item: (item.system_id, item.resource_id, item.action)))
