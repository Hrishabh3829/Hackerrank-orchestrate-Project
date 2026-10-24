"""Policy rule loading, state assessment, and required-treatment mapping."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from evidence import EvidenceCoverage, EvidenceRecord
from identity_resolution import ResolvedSubject
from timeline import CaseTimeline, _contains_identifier, parse_timestamp, scope_hint


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
        eligible = parse_bool(fields.get("eligible"))
        deletion_block = parse_bool(fields.get("deletion_block"))
        if eligible is True and deletion_block is False:
            return "ACTIVE"
        if eligible is False or deletion_block is True:
            return "BLOCKED"
        if any(marker in text_state for marker in ("restore allowed", "can still be restored", "restore access enabled", "restorable")):
            return "ACTIVE"
        if any(marker in text_state for marker in ("restore blocked", "restore disabled", "restore access blocked")):
            return "BLOCKED"
    # Account/deletion status fields describe a workflow or soft-delete label;
    # they do not negate the existence of a row found in a source snapshot.
    # This also keeps deleted-account tombstones eligible for PII checks.
    state_fields = ["result", "state", "status", "record_status", "restore_status"]
    for key in state_fields:
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


def _has_direct_identifier(
    record: EvidenceRecord,
    subject: ResolvedSubject,
    *,
    include_linkage: bool = False,
) -> bool:
    direct_fields = {
        "name", "full_name", "display_name", "email", "owner_email", "customer_email",
        "requester_email", "recipient_email", "email_address", "recipient", "to",
        "phone", "owner_phone", "requester_phone", "email_hash",
        "message", "message_text", "message_excerpt", "document", "profile", "record_json",
    }
    if include_linkage:
        direct_fields.update({"subject_reference", "customer_reference", "user_id", "user_reference"})
    identifiers = tuple(value for value in subject.identifiers if include_linkage or value != subject.user_id)
    if record.data_category == "EMAIL_DELIVERY_LOG":
        identifiers = tuple(value for value in identifiers if "@" in value)
    if record.data_category == "ACCOUNT_TOMBSTONE":
        direct_fields -= {"user_id", "user_reference", "customer_reference"}
        direct_fields.discard("subject_reference")

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

    return visit(record.fields) or any(
        _contains_identifier(record.text, identifier)
        for identifier in needles
    )


def _time(value: str) -> datetime:
    parsed = parse_timestamp(value)
    return parsed or datetime.min.replace(tzinfo=timezone.utc)


def _observation_detail_rank(record: EvidenceRecord) -> tuple[int, int]:
    """Prefer same-time observations that carry an explicit state signal."""
    fields = record.fields
    if record.data_category == "DATA_FLOW":
        state_keys = ("enabled", "active", "status", "state", "result")
    elif record.data_category == "BACKUP_ARCHIVE":
        state_keys = (
            "restore_allowed", "restore_enabled", "eligible", "deletion_block",
            "status", "state", "result",
        )
    else:
        state_keys = (
            "exists", "record_exists", "present", "found", "is_deleted",
            "status_code", "http_status", "result", "state",
        )
    explicit = sum(
        key in fields and fields[key] not in (None, "")
        for key in state_keys
    )
    normalized = _normalized_state(record)
    return explicit, int(normalized not in {"PRESENT", "ACTIVE"})


def _record_observation_key(record: EvidenceRecord) -> tuple[datetime, datetime, int, int]:
    detail_rank = _observation_detail_rank(record)
    return (
        _time(record.observed_at),
        _time(record.available_at),
        detail_rank[0],
        detail_rank[1],
    )


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
        current_record = max(component_records, key=_record_observation_key)
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
        event = str(fields.get("event", fields.get("event_type", ""))).casefold()
        marker_found = parse_bool(fields.get("marker_found"))
        if "deletion_marker" in event and marker_found is False:
            return "DELETE"
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
        # Coverage can be the newest observation and establish that the
        # resource is absent. Keep a real resource row for category-specific
        # policy conditions and use the coverage item as the proof of absence.
        action_records = [
            record for record in timeline.evidence_records
            if (record.system_id, record.resource_id, record.data_category)
            == (system_id, resource_id, category)
        ]
        if not action_records:
            category_rules = rules_for_category(category, rule_set)
            unconditional_deletion = any(
                rule.condition.strip().casefold() == "always"
                and rule.required_action == "DELETE"
                for rule in category_rules
            )
            current_scopes: dict[str, EvidenceCoverage] = {}
            for scope in timeline.coverage:
                if (scope.system_id, scope.data_category) != (system_id, category):
                    continue
                prior = current_scopes.get(scope.source_component)
                if prior is None or (_time(scope.observed_at), _time(scope.available_at)) > (
                    _time(prior.observed_at), _time(prior.available_at),
                ):
                    current_scopes[scope.source_component] = scope
            has_snapshot_absence = bool(current_scopes) and all(
                resource_id not in scope.present_resource_ids
                for scope in current_scopes.values()
            )
            if unconditional_deletion and observations and has_snapshot_absence:
                evidence_item = max(
                    (item for item, state in observations if state == "ABSENT"),
                    key=lambda item: (_time(item.observed_at), _time(item.available_at)),
                    default=None,
                )
                if evidence_item is not None:
                    assessments.append(PolicyAssessment(
                        system_id=system_id,
                        resource_id=resource_id,
                        data_category=category,
                        action="DELETE",
                        state="ABSENT",
                        evidence_id=evidence_item.evidence_id,
                        observed_at=evidence_item.observed_at,
                        verification_operation="VERIFY_RECORD_ABSENT",
                        verification_state="ABSENT",
                        compliant=True,
                    ))
            continue
        action_record = max(
            action_records,
            key=_record_observation_key,
        )
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
            attributable = [
                item for item, _ in present
                if isinstance(item, EvidenceRecord)
                and _has_direct_identifier(item, timeline.subject, include_linkage=True)
            ]
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
        latest = max(records, key=_record_observation_key)
        can_block = parse_bool(latest.fields.get("can_block_restore", latest.fields.get("restore_access_blockable")))
        allowed = parse_bool(latest.fields.get("restore_allowed", latest.fields.get("restore_enabled")))
        result = str(latest.fields.get("result", latest.fields.get("status", ""))).upper()
        if can_block is not False and (
            allowed is True
            or result in {"ACTIVE", "RESTORE_ALLOWED", "RESTORABLE"}
            or _normalized_state(latest) == "ACTIVE"
        ):
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
        elif allowed is False or result in {"BLOCKED", "RESTORE_BLOCKED"} or _normalized_state(latest) == "BLOCKED":
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
