"""Deletion intent, evidence timeline, policy assessment, and case steps."""

from __future__ import annotations

import re
import unicodedata
from typing import Mapping

from data_loading import Dataset
from evidence import EvidenceCorpus
from identity_resolution import ResolvedSubject, resolve_subjects
from output_generation import CasePrediction, Step
from policies import PolicyAssessment, assess_timeline, rules_from_rows
from timeline import CaseTimeline, build_case_timeline


_DELETION_PATTERNS = (
    re.compile(r"\b(delete|deletion|erase|erasure|destroy|purge)\b", re.IGNORECASE),
    re.compile(r"\b(close|remove)\s+(?:my|this|the|associated)\s+account\b", re.IGNORECASE),
    re.compile(r"\b(remove|erase|delete)\b.{0,80}\b(account|personal (?:data|information))\b", re.IGNORECASE),
    re.compile(r"\baccount[- ]deletion\b", re.IGNORECASE),
)
_NON_DELETION_PATTERNS = (
    re.compile(r"\bmarketing (?:lists?|emails?) only\b", re.IGNORECASE),
    re.compile(r"\b(?:stop|unsubscribe|opt[ -]?out)\b.{0,50}\b(?:promotional|marketing|emails?)\b", re.IGNORECASE),
    re.compile(r"\b(?:download|export|copy of|access|tell me what|information do you hold)\b", re.IGNORECASE),
    re.compile(r"\b(?:change|correct|correction|update|misspelled|out of date|reset(?:ting)?)\b", re.IGNORECASE),
    re.compile(r"\b(?:invoice|invoices|billing statement)\b", re.IGNORECASE),
    re.compile(r"\b(?:do not|don't|never)\s+(?:delete|erase|remove)\b", re.IGNORECASE),
)


def _fold_latin(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text.casefold())
    return "".join(char for char in normalized if not unicodedata.combining(char))


def request_authorizes_deletion(request_text: str) -> bool:
    """Detect explicit deletion intent, including supplied languages.

    The dataset includes English, Portuguese, Spanish, French, Japanese, and
    Korean requests. Non-deletion requests are checked first so marketing-only
    removal, access, correction, and export requests remain non-destructive.
    """
    text = request_text.strip()
    if not text:
        return False
    latin = _fold_latin(text)
    if any(pattern.search(latin) for pattern in _NON_DELETION_PATTERNS):
        return False
    if any(pattern.search(latin) for pattern in _DELETION_PATTERNS):
        return True
    # Portuguese, Spanish, and French terms after accent folding.
    if re.search(r"\b(exclusao|eliminacion|supression|suppression)\b", latin):
        return True
    # Japanese and Korean terms used by the supplied request templates.
    return "削除" in text or "삭제" in text


def _resolve_case_subject(request: Mapping[str, str], dataset: Dataset) -> ResolvedSubject:
    subjects = resolve_subjects(
        request.get("email", ""),
        dataset.identities,
        dataset.identity_audit_log,
        request.get("audit_at", ""),
        dataset.system_activity,
    )
    if not subjects:
        # Keep the supplied request identifier searchable if it is not present
        # in the current snapshot or audit history.
        email = request.get("email", "").strip()
        return ResolvedSubject(user_id="", identifiers=frozenset({email}) if email else frozenset())
    if len(subjects) == 1:
        return subjects[0]
    return ResolvedSubject(
        user_id="",
        identifiers=frozenset().union(*(subject.identifiers for subject in subjects)),
        linked_resource_ids=frozenset().union(*(subject.linked_resource_ids for subject in subjects)),
    )


def _step_from_assessment(
    assessment: PolicyAssessment,
    phase: str,
    *,
    include_verification_evidence: bool = False,
) -> Step | None:
    """Create a step while keeping future evidence IDs empty."""

    if phase == "FINDING":
        if not assessment.violation_operation:
            return None

        state = (
            "ACTIVE"
            if assessment.violation_operation
            in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"}
            else "PRESENT"
        )

        return Step(
            phase="FINDING",
            system_id=assessment.system_id,
            resource_id=assessment.resource_id,
            operation=assessment.violation_operation,
            state=state,
            evidence_id=assessment.evidence_id,
        )

    if phase == "REMEDIATION":
        if not assessment.remediation_operation:
            return None

        return Step(
            phase="REMEDIATION",
            system_id=assessment.system_id,
            resource_id=assessment.resource_id,
            operation=assessment.remediation_operation,
            state=assessment.remediation_state,
            evidence_id="",
        )

    if not assessment.verification_operation:
        return None

    evidence_id = (
        assessment.evidence_id
        if include_verification_evidence and assessment.compliant
        else ""
    )

    return Step(
        phase="VERIFICATION",
        system_id=assessment.system_id,
        resource_id=assessment.resource_id,
        operation=assessment.verification_operation,
        state=assessment.verification_state,
        evidence_id=evidence_id,
    )


_OPERATION_ORDER = {
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


def _ordered_steps(steps: list[Step]) -> tuple[Step, ...]:
    """Follow the challenge ordering: phase, operation, then system/resource."""
    return tuple(sorted(
        steps,
        key=lambda step: (
            {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}[step.phase],
            _OPERATION_ORDER[step.operation],
            step.system_id,
            step.resource_id,
        ),
    ))


def _build_prediction(request: Mapping[str, str], timeline: CaseTimeline, dataset: Dataset) -> CasePrediction:
    assessments = assess_timeline(timeline, rules_from_rows(dataset.deletion_rules))
    violations = [assessment for assessment in assessments if not assessment.compliant]
    case_id = request["case_id"]

    if violations:
        findings = [step for assessment in violations if (step := _step_from_assessment(assessment, "FINDING"))]
        remediations = [step for assessment in violations if (step := _step_from_assessment(assessment, "REMEDIATION"))]
        verification_by_resource: dict[tuple[str, str, str], Step] = {}
        for assessment in assessments:
            step = _step_from_assessment(assessment, "VERIFICATION",include_verification_evidence=False)
            if step:
                key = (step.system_id, step.resource_id, step.operation)
                prior = verification_by_resource.get(key)
                if prior is None or (not prior.evidence_id and step.evidence_id):
                    verification_by_resource[key] = step
        steps = _ordered_steps(findings + remediations + list(verification_by_resource.values()))
        return CasePrediction(case_id=case_id, deletion_status="INCOMPLETE", steps=steps)

    verification_by_resource = {}
    for assessment in assessments:
        if not assessment.compliant:
            continue
        step = _step_from_assessment(
    assessment,
    "VERIFICATION",
    include_verification_evidence=True,
)
        if not step:
            continue
        key = (step.system_id, step.resource_id, step.operation)
        prior = verification_by_resource.get(key)
        if prior is None or (not prior.evidence_id and step.evidence_id):
            verification_by_resource[key] = step

    if not verification_by_resource:
        # Without evidence-backed checks, the workflow claim is insufficient
        # to certify completion. No unsupported finding is fabricated.
        return CasePrediction(case_id=case_id, deletion_status="INCOMPLETE", steps=())
    return CasePrediction(
        case_id=case_id,
        deletion_status="COMPLETE",
        steps=_ordered_steps(list(verification_by_resource.values())),
    )


def investigate_case(
    request: Mapping[str, str],
    dataset: Dataset,
    corpus: EvidenceCorpus,
) -> CasePrediction:
    """Investigate one request using only information available by audit_at."""
    case_id = request["case_id"]
    if not request_authorizes_deletion(request.get("request_text", "")):
        return CasePrediction(case_id=case_id, deletion_status="NOT_APPLICABLE", steps=())

    subject = _resolve_case_subject(request, dataset)
    timeline = build_case_timeline(
        corpus,
        subject,
        request.get("audit_at", ""),
        dataset.system_activity,
    )
    return _build_prediction(request, timeline, dataset)
