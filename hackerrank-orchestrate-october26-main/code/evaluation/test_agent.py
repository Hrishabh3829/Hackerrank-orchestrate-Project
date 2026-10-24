"""Independent behavioral checks for the deletion-audit agent."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from evidence import EvidenceCorpus, EvidenceCoverage, EvidenceRecord, _read_json, _read_log, normalize_category  # noqa: E402
from identity_resolution import ResolvedSubject, resolve_subjects  # noqa: E402
from investigation import request_authorizes_deletion  # noqa: E402
from output_generation import CasePrediction, Step, write_output  # noqa: E402
from policies import _has_direct_identifier, assess_timeline, rules_from_rows  # noqa: E402
from timeline import CaseTimeline, _contains_identifier, _extract_resource_references, _subject_matches, build_case_timeline  # noqa: E402


class AgentBehaviorTests(unittest.TestCase):
    def test_intent_separates_deletion_from_marketing_opt_out(self) -> None:
        self.assertTrue(request_authorizes_deletion("Please delete my account and personal data."))
        self.assertTrue(request_authorizes_deletion("I am deleting my account; please delete the old export file too."))
        self.assertTrue(request_authorizes_deletion("Can you verify that my account was deleted?"))
        self.assertTrue(request_authorizes_deletion("Please permanently delete my account and apply the correct treatment to records."))
        self.assertFalse(request_authorizes_deletion("Please stop promotional marketing emails only."))
        self.assertFalse(request_authorizes_deletion("Please export my data for me."))
        self.assertFalse(request_authorizes_deletion("Please update my email address."))
        self.assertTrue(request_authorizes_deletion("Close the account and make sure it can no longer send my data to other systems."))

    def test_historical_email_resolves_identifiers_as_of_cutoff(self) -> None:
        subjects = resolve_subjects(
            "old@example.test",
            identities=(
                {
                    "user_id": "user_007", "name": "Example User",
                    "email": "new@example.test", "phone": "+1 (202) 555-0107",
                    "email_hash": "hash_007", "updated_at": "2026-10-01T00:00:00Z",
                },
            ),
            audit_log=(
                {
                    "audit_id": "audit_1", "user_id": "user_007",
                    "event_time": "2026-09-01T00:00:00Z", "field_name": "email",
                    "old_value": "old@example.test", "new_value": "new@example.test",
                },
                {
                    "audit_id": "audit_2", "user_id": "user_007",
                    "event_time": "2026-09-02T00:00:00Z", "field_name": "phone",
                    "old_value": "+1 202-555-0106", "new_value": "+1 (202) 555-0107",
                },
            ),
            audit_at="2026-09-15T00:00:00Z",
        )
        self.assertEqual(len(subjects), 1)
        self.assertEqual(subjects[0].user_id, "user_007")
        self.assertIn("old@example.test", subjects[0].identifiers)
        self.assertIn("+1 (202) 555-0107", subjects[0].identifiers)

    def test_ambiguous_name_is_not_used_as_a_unique_identity_match(self) -> None:
        subjects = resolve_subjects(
            "one@example.test",
            identities=(
                {"user_id": "user_001", "name": "Shared Name", "email": "one@example.test", "updated_at": "2026-09-01T00:00:00Z"},
                {"user_id": "user_002", "name": "Shared Name", "email": "two@example.test", "updated_at": "2026-09-01T00:00:00Z"},
            ),
            audit_log=(), audit_at="2026-09-20T00:00:00Z",
        )
        record = EvidenceRecord(
            evidence_id="file_1", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="support_platform",
            resource_id="support_101", data_category="SUPPORT_MESSAGE",
            source_component="support_tickets", file_path="fixture.txt", source_kind="text",
            fields={"message_text": "Shared Name"}, text="Shared Name",
        )
        self.assertEqual(len(subjects), 1)
        self.assertFalse(_subject_matches(record, subjects[0]))

    def test_phone_match_requires_a_bounded_number_group(self) -> None:
        self.assertTrue(_contains_identifier("Caller: +1 (202) 555-0107", "+1 202 555 0107"))
        self.assertFalse(_contains_identifier("Unrelated id 1202555010799", "2025550107"))

    def test_name_match_requires_token_boundaries(self) -> None:
        self.assertTrue(_contains_identifier("Profile name: Priya Raman.", "Priya Raman"))
        self.assertFalse(_contains_identifier("Profile name: Priya Ramanathan.", "Priya Raman"))

    def test_email_hash_is_matched_as_an_opaque_identifier(self) -> None:
        digest = "44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e"
        self.assertTrue(_contains_identifier(f"correlation_key={digest}", digest))
        self.assertFalse(_contains_identifier("unrelated phone 442651548578", digest))

    def test_timeline_follows_activity_resource_links_and_obeys_cutoff(self) -> None:
        def record(resource_id: str, observed_at: str) -> EvidenceRecord:
            return EvidenceRecord(
                evidence_id="file_1", available_at="2026-09-10T00:00:00Z",
                observed_at=observed_at, system_id="search_service",
                resource_id=resource_id, data_category="SEARCH_INDEX_ENTRY",
                source_component="search_documents", file_path="fixture.json",
                source_kind="json", fields={"resource_id": resource_id},
                text=resource_id,
            )

        timeline = build_case_timeline(
            EvidenceCorpus(
                records=(
                    record("search_101", "2026-09-10T00:00:00Z"),
                    record("search_102", "2026-10-10T00:00:00Z"),
                ),
                coverage=(),
            ),
            ResolvedSubject("user_007", frozenset({"user_007"})),
            "2026-09-20T00:00:00Z",
            system_activity=(
                {
                    "activity_id": "activity_1", "event_time": "2026-09-15T00:00:00Z",
                    "event_type": "SYNC_RECORD", "source_system": "integration_service",
                    "target_system": "search_service", "resource_id": "data_flow_101",
                    "reported_result": "SUCCESS",
                    "details": "user_007 sync copied downstream resource search_101",
                },
            ),
        )
        self.assertIn("data_flow_101", timeline.resource_ids)
        self.assertIn("search_101", timeline.resource_ids)
        self.assertEqual([item.resource_id for item in timeline.evidence_records], ["search_101"])

    def test_unique_report_time_links_activity_target_to_snapshot_absence(self) -> None:
        request = {"case_id": "case_a", "reported_at": "2026-09-10T00:00:00Z"}
        activity = {
            "activity_id": "activity_delete", "event_time": "2026-09-10T00:02:00Z",
            "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
            "target_system": "account_service", "resource_id": "account_101",
            "reported_result": "SUCCESS", "details": "Deletion operation completed.",
        }
        scope = EvidenceCoverage(
            evidence_id="file_snapshot", available_at="2026-09-11T00:00:00Z",
            observed_at="2026-09-11T00:00:00Z", system_id="account_service",
            data_category="USER_PROFILE", source_component="accounts",
            present_resource_ids=frozenset(), file_path="snapshot.sql",
        )
        timeline = build_case_timeline(
            EvidenceCorpus(records=(), coverage=(scope,)),
            ResolvedSubject("user_007", frozenset({"user_007"})),
            "2026-09-20T00:00:00Z", (activity,),
            request=request, request_pool=(request,),
        )
        self.assertIn("account_101", timeline.resource_ids)
        self.assertEqual(len(timeline.activity_events), 1)
        assessments = assess_timeline(timeline, rules_from_rows(({
            "rule_id": "rule_profile", "data_category": "USER_PROFILE",
            "condition": "Always", "required_action": "DELETE",
        },)))
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].verification_operation, "VERIFY_RECORD_ABSENT")
        self.assertEqual(assessments[0].evidence_id, "file_snapshot")

    def test_report_time_activity_link_is_skipped_for_ambiguous_requests(self) -> None:
        requests = (
            {"case_id": "case_a", "reported_at": "2026-09-10T00:00:00Z"},
            {"case_id": "case_b", "reported_at": "2026-09-10T00:00:00Z"},
        )
        activity = {
            "activity_id": "activity_delete", "event_time": "2026-09-10T00:02:00Z",
            "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
            "target_system": "account_service", "resource_id": "account_101",
            "reported_result": "SUCCESS", "details": "Deletion operation completed.",
        }
        timeline = build_case_timeline(
            EvidenceCorpus(records=(), coverage=()),
            ResolvedSubject("user_007", frozenset({"user_007"})),
            "2026-09-20T00:00:00Z", (activity,),
            request=requests[0], request_pool=requests,
        )
        self.assertNotIn("account_101", timeline.resource_ids)
        self.assertEqual(timeline.activity_events, ())

    def test_report_time_link_uses_only_the_nearest_action_burst(self) -> None:
        request = {"case_id": "case_a", "reported_at": "2026-09-10T00:00:00Z"}
        activities = (
            {
                "activity_id": "activity_account", "event_time": "2026-09-10T00:00:00Z",
                "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
                "target_system": "account_service", "resource_id": "account_101",
                "reported_result": "SUCCESS", "details": "Profile action completed.",
            },
            {
                "activity_id": "activity_export", "event_time": "2026-09-10T00:00:30Z",
                "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
                "target_system": "export_service", "resource_id": "export_101",
                "reported_result": "SUCCESS", "details": "Export action completed.",
            },
            {
                "activity_id": "activity_search", "event_time": "2026-09-10T00:05:00Z",
                "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
                "target_system": "search_service", "resource_id": "search_101",
                "reported_result": "SUCCESS", "details": "Search action completed.",
            },
        )
        timeline = build_case_timeline(
            EvidenceCorpus(records=(), coverage=()),
            ResolvedSubject("user_007", frozenset({"user_007"})),
            "2026-09-20T00:00:00Z", activities,
            request=request, request_pool=(request,),
        )
        self.assertEqual(timeline.resource_ids, frozenset({"account_101", "export_101"}))

    def test_timeline_joins_related_log_rows_by_scoped_trace_id(self) -> None:
        direct = EvidenceRecord(
            evidence_id="file_log", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="unknown_system",
            resource_id="", data_category="", source_component="log", file_path="events.log",
            source_kind="log", fields={"email": "x@example.test", "trace_id": "trace_101"},
            text="x@example.test trace_101",
        )
        flow = EvidenceRecord(
            evidence_id="file_log", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:01Z", system_id="integration_service",
            resource_id="data_flow_101", data_category="DATA_FLOW", source_component="log",
            file_path="events.log", source_kind="log",
            fields={"resource_id": "data_flow_101", "enabled": True, "trace_id": "trace_101"},
            text="data_flow_101 enabled trace_101",
        )
        timeline = build_case_timeline(
            EvidenceCorpus(records=(direct, flow), coverage=()),
            ResolvedSubject("user_007", frozenset({"user_007", "x@example.test"})),
            "2026-09-20T00:00:00Z", system_activity=(),
        )
        self.assertEqual({item.resource_id for item in timeline.evidence_records}, {"", "data_flow_101"})
        self.assertIn("data_flow_101", timeline.resource_ids)

    def test_placeholder_reference_does_not_expand_resource_timeline(self) -> None:
        record = EvidenceRecord(
            evidence_id="file_1", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="support_platform",
            resource_id="support_101", data_category="SUPPORT_MESSAGE",
            source_component="support_conversations", file_path="fixture.json",
            source_kind="json", fields={"resource_id": "support_101", "customer_reference": "null"},
            text="support_101",
        )
        self.assertEqual(_extract_resource_references(record), {"support_101"})

    def test_active_data_flow_produces_risk_and_disable_plan(self) -> None:
        flow = EvidenceRecord(
            evidence_id="file_flow", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="integration_service",
            resource_id="data_flow_101", data_category="DATA_FLOW",
            source_component="connector_subscriptions", file_path="fixture.json",
            source_kind="json", fields={"resource_id": "data_flow_101", "enabled": True},
            text="data_flow_101 enabled",
        )
        timeline = CaseTimeline(
            subject=ResolvedSubject("user_007", frozenset({"user_007"})),
            audit_at="2026-09-20T00:00:00Z", evidence_records=(flow,),
            coverage=(), activity_events=(), resource_ids=frozenset({"data_flow_101"}),
        )
        assessments = assess_timeline(timeline, rules=())
        self.assertTrue(any(item.violation_operation == "REPORT_ACTIVE_DATA_FLOW" for item in assessments))
        self.assertTrue(any(item.remediation_operation == "DISABLE_DATA_FLOW" for item in assessments))

    def test_same_time_flow_observations_prefer_explicit_state(self) -> None:
        observed_at = "2026-09-10T00:00:00Z"
        common = {
            "available_at": observed_at, "observed_at": observed_at,
            "system_id": "integration_service", "resource_id": "data_flow_101",
            "data_category": "DATA_FLOW", "source_component": "connector_log",
            "file_path": "fixture.log", "source_kind": "log",
        }
        start = EvidenceRecord(
            evidence_id="file_start", fields={"event": "connector_config_read_started"},
            text="connector_config_read_started", **common,
        )
        complete = EvidenceRecord(
            evidence_id="file_complete",
            fields={"event": "connector_config_read_completed", "enabled": "true"},
            text="connector_config_read_completed enabled=true", **common,
        )
        timeline = CaseTimeline(
            subject=ResolvedSubject("user_007", frozenset({"user_007"})),
            audit_at="2026-09-20T00:00:00Z", evidence_records=(start, complete),
            coverage=(), activity_events=(), resource_ids=frozenset({"data_flow_101"}),
        )
        assessments = assess_timeline(timeline, rules=())
        flow_assessment = next(item for item in assessments if item.data_category == "DATA_FLOW")
        self.assertEqual(flow_assessment.state, "ACTIVE")
        self.assertEqual(flow_assessment.evidence_id, "file_complete")

    def test_restore_candidate_without_deletion_block_is_a_live_risk(self) -> None:
        backup = EvidenceRecord(
            evidence_id="file_backup", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="backup_service",
            resource_id="backup_101", data_category="BACKUP_ARCHIVE",
            source_component="restore_candidates", file_path="fixture.log",
            source_kind="log", fields={
                "resource_id": "backup_101", "eligible": "true", "deletion_block": "false",
            }, text="backup_101 eligible=true deletion_block=false",
        )
        timeline = CaseTimeline(
            subject=ResolvedSubject("user_007", frozenset({"user_007"})),
            audit_at="2026-09-20T00:00:00Z", evidence_records=(backup,),
            coverage=(), activity_events=(), resource_ids=frozenset({"backup_101"}),
        )
        assessments = assess_timeline(timeline, rules=())
        self.assertTrue(any(item.violation_operation == "REPORT_RESTORE_RISK" for item in assessments))
        self.assertTrue(any(item.remediation_operation == "BLOCK_RESTORE" for item in assessments))

    def test_deleted_account_tombstone_still_requires_redaction(self) -> None:
        tombstone = EvidenceRecord(
            evidence_id="file_tombstone", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="identity_service",
            resource_id="tombstone_101", data_category="ACCOUNT_TOMBSTONE",
            source_component="deleted_customer_references", file_path="fixture.json",
            source_kind="json", fields={
                "resource_id": "tombstone_101", "account_status": "DELETED",
                "subject_reference": "user_007", "email": "old@example.test",
            }, text="tombstone_101 user_007 old@example.test",
        )
        timeline = CaseTimeline(
            subject=ResolvedSubject("user_007", frozenset({"user_007", "old@example.test"})),
            audit_at="2026-09-20T00:00:00Z", evidence_records=(tombstone,),
            coverage=(), activity_events=(), resource_ids=frozenset({"tombstone_101"}),
        )
        assessments = assess_timeline(timeline, rules_from_rows(({
            "rule_id": "rule_tombstone", "data_category": "ACCOUNT_TOMBSTONE",
            "condition": "keep stable reference only", "required_action": "REDACT",
        },)))
        self.assertTrue(any(item.violation_operation == "REPORT_EXPOSED_PII" for item in assessments))
        self.assertTrue(any(item.remediation_operation == "REDACT_RECORD" for item in assessments))

    def test_stable_reference_is_not_direct_pii_for_redaction(self) -> None:
        record = EvidenceRecord(
            evidence_id="file_support", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="support_platform",
            resource_id="support_101", data_category="SUPPORT_MESSAGE",
            source_component="support_tickets", file_path="fixture.json",
            source_kind="json", fields={"resource_id": "support_101", "customer_reference": "user_007"},
            text="support_101 user_007",
        )
        subject = ResolvedSubject("user_007", frozenset({"user_007", "x@example.test"}))
        self.assertFalse(_has_direct_identifier(record, subject))
        self.assertTrue(_has_direct_identifier(record, subject, include_linkage=True))

    def test_support_message_deletion_marker_and_shared_context_are_respected(self) -> None:
        subject = ResolvedSubject("user_007", frozenset({"user_007", "x@example.test"}))
        rules = rules_from_rows(({
            "rule_id": "rule_support", "data_category": "SUPPORT_MESSAGE",
            "condition": "shared context", "required_action": "REDACT",
        },))
        def assessment(shared: bool | None):
            fields = {"resource_id": "support_101", "email": "x@example.test"}
            if shared is not None:
                fields["shared_context"] = shared
            record = EvidenceRecord(
                evidence_id="file_support", available_at="2026-09-10T00:00:00Z",
                observed_at="2026-09-10T00:00:00Z", system_id="support_platform",
                resource_id="support_101", data_category="SUPPORT_MESSAGE",
                source_component="support_tickets", file_path="fixture.json",
                source_kind="json", fields=fields, text="support_101 x@example.test",
            )
            timeline = CaseTimeline(
                subject=subject, audit_at="2026-09-20T00:00:00Z", evidence_records=(record,),
                coverage=(), activity_events=(), resource_ids=frozenset({"support_101"}),
            )
            return assess_timeline(timeline, rules)[0]
        self.assertEqual(assessment(None).remediation_operation, "REDACT_RECORD")
        self.assertEqual(assessment(False).remediation_operation, "DELETE_RECORD")
        fields = {"resource_id": "support_101", "event": "deletion_marker_check", "marker_found": False}
        record = EvidenceRecord(
            evidence_id="file_support", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="support_platform",
            resource_id="support_101", data_category="SUPPORT_MESSAGE",
            source_component="support_tickets", file_path="fixture.json",
            source_kind="log", fields=fields, text="support_101 deletion_marker_check",
        )
        timeline = CaseTimeline(
            subject=subject, audit_at="2026-09-20T00:00:00Z", evidence_records=(record,),
            coverage=(), activity_events=(), resource_ids=frozenset({"support_101"}),
        )
        self.assertEqual(assess_timeline(timeline, rules)[0].remediation_operation, "DELETE_RECORD")
        self.assertEqual(assessment(True).remediation_operation, "REDACT_RECORD")

    def test_unstructured_evidence_text_is_checked_for_direct_identifiers(self) -> None:
        record = EvidenceRecord(
            evidence_id="file_note", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="support_platform",
            resource_id="support_101", data_category="SUPPORT_MESSAGE",
            source_component="support_notes", file_path="fixture.txt", source_kind="text",
            fields={}, text="Contact: x@example.test",
        )
        subject = ResolvedSubject("user_007", frozenset({"user_007", "x@example.test"}))
        self.assertTrue(_has_direct_identifier(record, subject))

    def test_log_resource_prefix_outweighs_incidental_export_wording(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-log-") as temporary_dir:
            log_path = Path(temporary_dir) / "events.log"
            log_path.write_text(
                '2026-09-10T00:00:00Z system=integration_service '
                'resource_id=data_flow_101 message="export pipeline status checked"\n',
                encoding="utf-8",
            )
            records = _read_log("file_log", "2026-09-10T00:00:00Z", str(log_path), log_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].data_category, "DATA_FLOW")

    def test_marketing_consent_log_uses_marketing_deletion_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-log-") as temporary_dir:
            log_path = Path(temporary_dir) / "events.log"
            log_path.write_text(
                '2026-09-10T00:00:00Z service=analytics_platform '
                'resource_id=analytics_101 email_opt_in=true event=contact_lookup_completed\n',
                encoding="utf-8",
            )
            records = _read_log("file_log", "2026-09-10T00:00:00Z", str(log_path), log_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].data_category, "MARKETING_PROFILE")
        self.assertEqual(records[0].system_id, "analytics_platform")

    def test_log_service_instance_is_not_mistaken_for_customer_resource(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-log-") as temporary_dir:
            log_path = Path(temporary_dir) / "events.log"
            log_path.write_text(
                '2026-09-10T00:00:00Z service=account_service '
                'instance=account-2 lookup_key="x@example.test" event=profile_lookup_started\n',
                encoding="utf-8",
            )
            records = _read_log("file_log", "2026-09-10T00:00:00Z", str(log_path), log_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].resource_id, "")

    def test_labeled_resource_inside_log_message_is_still_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-log-") as temporary_dir:
            log_path = Path(temporary_dir) / "events.log"
            log_path.write_text(
                '2026-09-10T00:00:00Z function=account_service '
                'message="resource_id=account_101 event=profile_lookup_completed"\n',
                encoding="utf-8",
            )
            records = _read_log("file_log", "2026-09-10T00:00:00Z", str(log_path), log_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].resource_id, "account_101")

    def test_attachment_semantics_disambiguate_generic_support_resource_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-log-") as temporary_dir:
            log_path = Path(temporary_dir) / "events.log"
            log_path.write_text(
                '2026-09-10T00:00:00Z resource_id=support_101 event=ATTACHMENT_STORED\n',
                encoding="utf-8",
            )
            records = _read_log("file_log", "2026-09-10T00:00:00Z", str(log_path), log_path)
        self.assertEqual(records[0].data_category, "SUPPORT_ATTACHMENT")

    def test_attachment_context_precedes_incidental_delivery_wording(self) -> None:
        self.assertEqual(
            normalize_category("", "delivery_correction_attachment.pdf"),
            "SUPPORT_ATTACHMENT",
        )

    def test_nested_json_collection_outweighs_export_filename(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-json-") as temporary_dir:
            json_path = Path(temporary_dir) / "service_export.json"
            json_path.write_text(
                json.dumps({"service_exports": {"support_platform": {
                    "tickets": [{"resource_id": "support_101", "requester_email": "x@example.test"}]
                }}}),
                encoding="utf-8",
            )
            records, _ = _read_json("file_json", "2026-09-10T00:00:00Z", "service_export.json", json_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].data_category, "SUPPORT_MESSAGE")

    def test_typed_json_resource_disambiguates_generic_profiles_table(self) -> None:
        with tempfile.TemporaryDirectory(prefix="deletion-audit-json-") as temporary_dir:
            json_path = Path(temporary_dir) / "service_export.json"
            json_path.write_text(
                json.dumps({"service_exports": {"account_service": {
                    "profiles": [{"resource_id": "analytics_101", "user_id": "user_007"}]
                }}}),
                encoding="utf-8",
            )
            records, _ = _read_json("file_json", "2026-09-10T00:00:00Z", "service_export.json", json_path)
        self.assertEqual(records[0].data_category, "ANALYTICS_PROFILE")
        self.assertEqual(records[0].system_id, "analytics_platform")

    def test_latest_snapshot_coverage_can_verify_absence(self) -> None:
        record = EvidenceRecord(
            evidence_id="file_row", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="account_service",
            resource_id="account_101", data_category="USER_PROFILE",
            source_component="customer_profiles", file_path="fixture.json",
            source_kind="json", fields={"resource_id": "account_101"}, text="account_101",
        )
        coverage = EvidenceCoverage(
            evidence_id="file_snapshot", available_at="2026-09-15T00:00:00Z",
            observed_at="2026-09-15T00:00:00Z", system_id="account_service",
            data_category="USER_PROFILE", source_component="customer_profiles",
            present_resource_ids=frozenset(), file_path="fixture.json",
        )
        timeline = CaseTimeline(
            subject=ResolvedSubject("user_007", frozenset({"user_007"})),
            audit_at="2026-09-20T00:00:00Z", evidence_records=(record,),
            coverage=(coverage,), activity_events=(), resource_ids=frozenset({"account_101"}),
        )
        assessments = assess_timeline(timeline, rules_from_rows(({
            "rule_id": "rule_profile", "data_category": "USER_PROFILE",
            "condition": "Always", "required_action": "DELETE",
        },)))
        self.assertEqual(len(assessments), 1)
        self.assertTrue(assessments[0].compliant)
        self.assertEqual(assessments[0].evidence_id, "file_snapshot")

    def test_deleted_workflow_label_does_not_hide_stored_profile_row(self) -> None:
        record = EvidenceRecord(
            evidence_id="file_row", available_at="2026-09-10T00:00:00Z",
            observed_at="2026-09-10T00:00:00Z", system_id="account_service",
            resource_id="account_101", data_category="USER_PROFILE",
            source_component="customer_profiles", file_path="fixture.json",
            source_kind="json", fields={"resource_id": "account_101", "account_status": "DELETED"},
            text="account_101",
        )
        timeline = CaseTimeline(
            subject=ResolvedSubject("user_007", frozenset({"user_007"})),
            audit_at="2026-09-20T00:00:00Z", evidence_records=(record,),
            coverage=(), activity_events=(), resource_ids=frozenset({"account_101"}),
        )
        assessments = assess_timeline(timeline, rules_from_rows(({
            "rule_id": "rule_profile", "data_category": "USER_PROFILE",
            "condition": "Always", "required_action": "DELETE",
        },)))
        self.assertEqual(len(assessments), 1)
        self.assertFalse(assessments[0].compliant)
        self.assertEqual(assessments[0].violation_operation, "REPORT_REMAINING_RECORD")

    def test_output_has_sorted_rows_valid_json_and_sequential_steps(self) -> None:
        predictions = (
            CasePrediction("case_b", "NOT_APPLICABLE", ()),
            CasePrediction(
                "case_a", "COMPLETE",
                (Step("VERIFICATION", "account_service", "account_101", "VERIFY_RECORD_ABSENT", "ABSENT", "file_1"),),
            ),
        )
        with tempfile.TemporaryDirectory(prefix="deletion-audit-output-") as temporary_dir:
            output_path = Path(temporary_dir) / "output.csv"
            write_output(output_path, predictions)
            with output_path.open("r", encoding="utf-8", newline="") as source:
                rows = list(csv.DictReader(source))
        self.assertEqual([row["case_id"] for row in rows], ["case_a", "case_b"])
        self.assertEqual(tuple(rows[0].keys()), ("case_id", "deletion_status", "steps_json"))
        steps = json.loads(rows[0]["steps_json"])
        self.assertEqual(steps[0]["step_no"], 1)
        self.assertEqual(json.loads(rows[1]["steps_json"]), [])


if __name__ == "__main__":
    unittest.main()
