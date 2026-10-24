"""Extract searchable evidence records from every manifest-backed format."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from data_loading import Dataset


class EvidenceReadError(RuntimeError):
    """Raised when required evidence cannot be read safely."""


RESOURCE_PATTERN = re.compile(
    r"\b(?:account|search|support|analytics|audit_record|tombstone|data_flow|backup|export|"
    r"marketing|cache|telemetry|email_delivery|secondary_identifier|legal_hold|support_attachment)"
    r"[_-]\d[A-Za-z0-9_-]*\b",
    re.IGNORECASE,
)

CATEGORY_ALIASES = {
    "USER_PROFILE": "USER_PROFILE",
    "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY": "CACHE_ENTRY",
    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY": "PRODUCT_TELEMETRY",
    "USER_EXPORT": "USER_EXPORT",
    "MARKETING_PROFILE": "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
    "DATA_FLOW": "DATA_FLOW",
}


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    available_at: str
    observed_at: str
    system_id: str
    resource_id: str
    data_category: str
    source_component: str
    file_path: str
    source_kind: str
    fields: Mapping[str, Any]
    text: str


@dataclass(frozen=True)
class EvidenceCoverage:
    """A point-in-time snapshot that covers a category/component."""

    evidence_id: str
    available_at: str
    observed_at: str
    system_id: str
    data_category: str
    source_component: str
    present_resource_ids: frozenset[str]
    file_path: str


@dataclass(frozen=True)
class EvidenceCorpus:
    records: tuple[EvidenceRecord, ...]
    coverage: tuple[EvidenceCoverage, ...]


def normalize_category(value: str, fallback: str = "") -> str:
    """Map source collection/table names to challenge policy categories."""
    candidate = value.strip().upper().replace("-", "_").replace(" ", "_")
    if candidate in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[candidate]
    lowered = f"{candidate} {fallback.upper()}"
    if "TOMBSTONE" in lowered or "DELETED_CUSTOMER_REFERENCE" in lowered:
        return "ACCOUNT_TOMBSTONE"
    if "SECURITY" in lowered or "AUDIT_RECORD" in lowered or "AUDIT_EVENT" in lowered:
        return "SECURITY_AUDIT_LOG"
    if "LEGAL_HOLD" in lowered or "RETAINED_ORDER" in lowered:
        return "LEGAL_HOLD_RECORD"
    if "BACKUP" in lowered or "RESTORE" in lowered or "ARCHIVE" in lowered:
        return "BACKUP_ARCHIVE"
    if "CONNECTOR" in lowered or "DATA_FLOW" in lowered or "SUBSCRIPTION" in lowered:
        return "DATA_FLOW"
    if "IMPORT_PIPELINE" in lowered or "SYNC_PIPELINE" in lowered or "DATA_IMPORT" in lowered:
        return "DATA_FLOW"
    if "SEARCH" in lowered or "INDEX" in lowered:
        return "SEARCH_INDEX_ENTRY"
    if "CACHE" in lowered:
        return "CACHE_ENTRY"
    if "ANALYTIC" in lowered:
        return "ANALYTICS_PROFILE"
    if "TELEMETRY" in lowered or "PRODUCT_EVENT" in lowered:
        return "PRODUCT_TELEMETRY"
    if "EXPORT" in lowered:
        return "USER_EXPORT"
    if "MARKETING" in lowered:
        return "MARKETING_PROFILE"
    if "DELIVERY" in lowered or "EMAIL_LOG" in lowered:
        return "EMAIL_DELIVERY_LOG"
    if "ATTACHMENT" in lowered:
        return "SUPPORT_ATTACHMENT"
    if "SUPPORT" in lowered or "TICKET" in lowered or "CONVERSATION" in lowered:
        return "SUPPORT_MESSAGE"
    if "PROFILE" in lowered or "ACCOUNT_PROFILE" in lowered or "ACCOUNT_SERVICE" in lowered:
        return "USER_PROFILE"
    if re.search(r"\baccount[_-]\d+\b", lowered):
        return "USER_PROFILE"
    if "SECONDARY_IDENTIFIER" in lowered:
        return "SECONDARY_IDENTIFIER"
    return ""


def infer_system(value: str, category: str = "", component: str = "") -> str:
    candidate = " ".join((value, component)).casefold()
    if "identity" in candidate or "tombstone" in candidate or category == "ACCOUNT_TOMBSTONE":
        return "identity_service"
    if "account" in candidate or category == "USER_PROFILE":
        return "account_service"
    if "search" in candidate or category == "SEARCH_INDEX_ENTRY":
        return "search_service"
    if "analytics" in candidate or category == "ANALYTICS_PROFILE":
        return "analytics_platform"
    if "support" in candidate or category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:
        return "support_platform"
    if "security" in candidate or category == "SECURITY_AUDIT_LOG":
        return "security_service"
    if "legal" in candidate or category == "LEGAL_HOLD_RECORD":
        return "legal_service"
    if "backup" in candidate or "restore" in candidate or category == "BACKUP_ARCHIVE":
        return "backup_service"
    if "connector" in candidate or "integration" in candidate or category == "DATA_FLOW":
        return "integration_service"
    if "export" in candidate or category == "USER_EXPORT":
        return "export_service"
    if "marketing" in candidate or category == "MARKETING_PROFILE":
        return "marketing_service"
    if "delivery" in candidate or category == "EMAIL_DELIVERY_LOG":
        return "email_delivery_service"
    if "cache" in candidate or category == "CACHE_ENTRY":
        return "cache_service"
    if "telemetry" in candidate or category == "PRODUCT_TELEMETRY":
        return "telemetry_service"
    return value.strip() or "unknown_system"


def _first_text(fields: Mapping[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = fields.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return ""


def _flatten_text(value: Any) -> str:
    if isinstance(value, Mapping):
        return " ".join(f"{key} {_flatten_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(item) for item in value)
    return str(value) if value is not None else ""


def _resource_id(
    fields: Mapping[str, Any],
    text: str = "",
    *,
    allow_unlabelled_text: bool = True,
) -> str:
    value = _first_text(fields, ("resource_id", "_id", "record_id", "tombstone_id", "ticket_id", "archive_id", "export_id", "object_id"))
    if value:
        return value
    if not allow_unlabelled_text:
        # Structured logs also contain service instance names such as
        # ``instance=account-2``. Those identify a host, not a customer record.
        # Accept only a resource token attached to a resource-like field label.
        match = re.search(
            r"\b(?:resource_id|record_id|tombstone_id|ticket_id|archive_id|export_id|object_id)"
            r"\s*[:=]\s*[\"']?"
            r"((?:account|search|support|analytics|audit_record|tombstone|data_flow|backup|export|"
            r"marketing|cache|telemetry|email_delivery|secondary_identifier|legal_hold|support_attachment)"
            r"[_-]\d[A-Za-z0-9_-]*)",
            text,
            re.IGNORECASE,
        )
        return match.group(1) if match else ""
    match = RESOURCE_PATTERN.search(text)
    return match.group(0) if match else ""


def _make_record(
    evidence_id: str,
    available_at: str,
    file_path: str,
    source_kind: str,
    fields: Mapping[str, Any],
    context: Mapping[str, str] | None = None,
    text: str = "",
    observed_at: str = "",
    resource_override: str = "",
    allow_unlabelled_resource_text: bool = True,
) -> EvidenceRecord:
    context = context or {}
    combined = {**context, **fields}
    rendered = text or _flatten_text(fields)
    resource_id = resource_override or _resource_id(
        fields,
        rendered,
        allow_unlabelled_text=allow_unlabelled_resource_text,
    )
    explicit_category = _first_text(fields, ("data_category", "record_type", "category"))
    category = normalize_category(explicit_category)
    # In nested JSON exports, generic table names such as "profiles" can
    # contain records exported from a different service. A typed resource ID
    # is the stronger signal when no explicit category field exists.
    if not category and source_kind == "json":
        category = normalize_category("", resource_id)
    category_value = _first_text(combined, ("collection", "table_name"))
    if not category:
        category = normalize_category(
            category_value,
            " ".join((context.get("service", ""), context.get("data_store", ""), context.get("origin_system", ""))),
        )
    if not category:
        category = normalize_category(
            "",
            " ".join((file_path, context.get("service", ""), context.get("data_store", ""), context.get("origin_system", ""))),
        )
    component = _first_text(combined, ("collection", "table_name", "source_component", "system")) or context.get("collection", "") or context.get("table", "")
    system_value = _first_text(fields, ("system_id", "system", "service_id", "service", "origin_system", "data_store", "source_system"))
    if system_value:
        system_id = infer_system(system_value, category, component)
    elif source_kind == "json" and normalize_category("", resource_id):
        system_id = infer_system("", category, component)
    else:
        system_id = infer_system(context.get("service", "") or context.get("data_store", "") or context.get("origin", ""), category, component)
    timestamp = observed_at or _first_text(combined, ("observed_at", "recorded_at", "event_time", "captured_at", "updated_at", "indexed_at", "created_at", "exported_at")) or available_at
    return EvidenceRecord(
        evidence_id=evidence_id,
        available_at=available_at,
        observed_at=timestamp,
        system_id=system_id,
        resource_id=resource_id,
        data_category=category,
        source_component=component or source_kind,
        file_path=file_path,
        source_kind=source_kind,
        fields=dict(fields),
        text=rendered,
    )


def _looks_like_record(value: Mapping[str, Any]) -> bool:
    return any(key in value for key in ("resource_id", "_id", "record_id", "tombstone_id", "ticket_id", "archive_id", "export_id", "object_id"))


def _read_json(evidence_id: str, available_at: str, file_path: str, path: Path) -> tuple[list[EvidenceRecord], list[EvidenceCoverage]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceReadError(f"Could not parse JSON evidence {file_path}: {exc}") from exc

    records: list[EvidenceRecord] = []
    coverage: list[EvidenceCoverage] = []

    def walk(value: Any, context: dict[str, str], parent_key: str = "") -> None:
        if isinstance(value, list):
            for item in value:
                walk(item, context, parent_key)
            return
        if not isinstance(value, Mapping):
            return

        current = dict(context)
        for key in ("source", "origin", "service", "system", "system_id", "origin_system", "data_store", "collection", "region"):
            field = value.get(key)
            if isinstance(field, str) and field.strip():
                current[key] = field.strip()
        if parent_key and parent_key not in {"records", "snapshots", "service_exports"}:
            # In nested service exports the service name is the parent of the
            # table list. The table (for example, tickets or connectors) is a
            # more precise category signal than the surrounding JSON filename.
            current["collection"] = parent_key

        if "records" in value and isinstance(value["records"], list):
            category = normalize_category(current.get("collection", ""), file_path)
            system = infer_system(current.get("data_store", current.get("service", "")), category, current.get("collection", ""))
            observed = current.get("captured_at", current.get("exported_at", available_at))
            component = current.get("collection", "")
            ids: set[str] = set()
            for item in value["records"]:
                if isinstance(item, Mapping):
                    rid = _resource_id(item, _flatten_text(item))
                    if rid:
                        ids.add(rid)
                    walk(item, current, "records")
            if category:
                coverage.append(EvidenceCoverage(evidence_id, available_at, observed, system, category, component, frozenset(ids), file_path))

        if _looks_like_record(value):
            record_context = dict(current)
            if parent_key and parent_key not in {"records", "snapshots", "service_exports"}:
                record_context.setdefault("collection", parent_key)
            observed = _first_text(value, ("observed_at", "recorded_at", "event_time", "captured_at", "updated_at", "indexed_at", "created_at")) or current.get("captured_at", "")
            records.append(_make_record(evidence_id, available_at, file_path, "json", value, record_context, observed_at=observed))

        for key, child in value.items():
            if key == "records":
                continue
            if key == "service_exports" and isinstance(child, Mapping):
                for service, service_payload in child.items():
                    nested = dict(current)
                    nested["service"] = str(service)
                    walk(service_payload, nested, str(service))
            elif key == "snapshots" and isinstance(child, list):
                for snapshot in child:
                    if not isinstance(snapshot, Mapping):
                        continue
                    snap_context = dict(current)
                    snap_context.update({
                        "data_store": str(snapshot.get("data_store", "")),
                        "collection": str(snapshot.get("collection", "")),
                        "captured_at": str(snapshot.get("captured_at", available_at)),
                    })
                    walk(snapshot, snap_context, "snapshots")
            elif isinstance(child, (Mapping, list)):
                walk(child, current, str(key))

    initial = {key: str(payload[key]) for key in ("source", "origin", "exported_at", "captured_at") if isinstance(payload, Mapping) and isinstance(payload.get(key), str)}
    walk(payload, initial)
    return records, coverage


def _read_sql(evidence_id: str, available_at: str, file_path: str, path: Path) -> tuple[list[EvidenceRecord], list[EvidenceCoverage]]:
    connection: sqlite3.Connection | None = None
    try:
        sql = path.read_text(encoding="utf-8-sig", errors="replace")
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(sql)
    except (OSError, sqlite3.Error) as exc:
        if connection is not None:
            connection.close()
        raise EvidenceReadError(f"Could not read SQL evidence {file_path}: {exc}") from exc

    header_match = re.search(r"Captured at:\s*(\S+)", sql, re.IGNORECASE)
    default_observed = header_match.group(1) if header_match else available_at
    records: list[EvidenceRecord] = []
    coverage: list[EvidenceCoverage] = []
    try:
        table_names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for table in table_names:
            if table == "snapshot_scope":
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            rows = [dict(row) for row in connection.execute(f"SELECT * FROM {quoted}").fetchall()]
            component_categories: dict[tuple[str, str], set[str]] = {}
            component_resources: dict[tuple[str, str], set[str]] = {}
            for row in rows:
                fields: dict[str, Any] = dict(row)
                if isinstance(fields.get("record_json"), str):
                    try:
                        nested = json.loads(fields["record_json"])
                    except json.JSONDecodeError:
                        nested = {}
                    if isinstance(nested, Mapping):
                        fields = {**fields, **nested}
                fallback = str(row.get("collection_name", table))
                category = normalize_category(_first_text(fields, ("data_category", "record_type", "category", "collection_name")), table + " " + fallback)
                if not category:
                    continue
                system_value = _first_text(fields, ("system_id", "system", "service", "origin_system", "source_system"))
                system_id = infer_system(system_value, category, table)
                component = f"{table}:{fallback}" if "collection_name" in row else table
                fields["source_component"] = component
                timestamp = _first_text(fields, ("observed_at", "recorded_at", "event_time", "captured_at", "updated_at", "indexed_at")) or default_observed
                rid = _resource_id(fields, _flatten_text(fields))
                if rid:
                    component_resources.setdefault((system_id, component), set()).add(rid)
                component_categories.setdefault((system_id, component), set()).add(category)
                records.append(_make_record(evidence_id, available_at, file_path, "sql", fields, {"table": table, "collection": fallback}, observed_at=timestamp, resource_override=rid))
            # Empty tables still provide point-in-time coverage for their category.
            if not rows:
                category = normalize_category(table, file_path)
                if category:
                    system_id = infer_system("", category, table)
                    component_categories.setdefault((system_id, table), set()).add(category)
            for (system_id, component), categories in component_categories.items():
                for category in categories:
                    coverage.append(EvidenceCoverage(
                        evidence_id, available_at, default_observed, system_id, category, component,
                        frozenset(component_resources.get((system_id, component), set())), file_path,
                    ))
    finally:
        if connection is not None:
            connection.close()
    return records, coverage


def _parse_key_value_line(line: str) -> tuple[str, dict[str, Any]]:
    timestamp = line.split(maxsplit=1)[0] if line.strip() else ""
    body = line[len(timestamp):].strip() if timestamp else line.strip()
    fields: dict[str, Any] = {}
    if body.startswith("{"):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, Mapping):
                fields = dict(parsed)
        except json.JSONDecodeError:
            pass
    if not fields:
        try:
            tokens = shlex.split(body, posix=True)
        except ValueError:
            tokens = body.split()
        for token in tokens:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            fields[key] = value.strip('"\\')
    fields.setdefault("event_time", timestamp)
    fields.setdefault("message", body)
    return timestamp, fields


def _read_log(evidence_id: str, available_at: str, file_path: str, path: Path) -> list[EvidenceRecord]:
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError as exc:
        raise EvidenceReadError(f"Could not read log evidence {file_path}: {exc}") from exc
    records: list[EvidenceRecord] = []
    for line in lines:
        if not line.strip():
            continue
        observed, fields = _parse_key_value_line(line)
        rid = _resource_id(fields, line, allow_unlabelled_text=False)
        # Prefer explicit category metadata, then the resource identifier, then
        # free-form message text. Log messages often mention exports or restores
        # while describing a different resource, so prose must be the last resort.
        category = normalize_category(_first_text(fields, ("data_category", "record_type", "category", "collection")))
        if not category:
            text_category = normalize_category("", line)
            resource_category = normalize_category("", rid)
            if text_category == "SUPPORT_ATTACHMENT" and resource_category == "SUPPORT_MESSAGE":
                category = text_category
            else:
                category = resource_category or text_category
        if rid or category:
            records.append(_make_record(
                evidence_id,
                available_at,
                file_path,
                "log",
                fields,
                {"collection": category},
                text=line,
                observed_at=observed,
                resource_override=rid,
                allow_unlabelled_resource_text=False,
            ))
    return records


def _read_text(evidence_id: str, available_at: str, file_path: str, path: Path) -> list[EvidenceRecord]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise EvidenceReadError(f"Could not read text evidence {file_path}: {exc}") from exc
    records: list[EvidenceRecord] = []
    for line in text.splitlines():
        stripped = line.strip().lstrip("- ")
        parts = [part.strip() for part in stripped.split("|")]
        if len(parts) >= 6:
            fields = {
                "event_time": parts[0], "system": parts[1], "resource_id": parts[2],
                "record_type": parts[3], "result": parts[4], "subject_reference": parts[5],
            }
            records.append(_make_record(evidence_id, available_at, file_path, "text", fields, text=line, observed_at=parts[0]))
    if not records:
        for resource_id in sorted(set(RESOURCE_PATTERN.findall(text))):
            records.append(_make_record(evidence_id, available_at, file_path, "text", {"resource_id": resource_id, "text": text}, text=text, resource_override=resource_id))
    return records


def _read_pdf(evidence_id: str, available_at: str, file_path: str, path: Path) -> list[EvidenceRecord]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise EvidenceReadError("PDF reading requires pypdf; install the packages in requirements.txt") from exc
    try:
        reader = PdfReader(str(path))
    except Exception as exc:
        raise EvidenceReadError(f"Could not open PDF evidence {file_path}: {exc}") from exc
    records: list[EvidenceRecord] = []
    for page_number, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        if not text.strip():
            continue
        lines = text.splitlines()
        resource_ids = sorted(set(RESOURCE_PATTERN.findall(text)))
        if resource_ids:
            for resource_id in resource_ids:
                index = next((i for i, line in enumerate(lines) if resource_id.casefold() in line.casefold()), 0)
                excerpt = " ".join(lines[max(0, index - 2):index + 4])
                records.append(_make_record(evidence_id, available_at, file_path, "pdf", {"resource_id": resource_id, "page": page_number, "text": excerpt}, text=excerpt, resource_override=resource_id))
        else:
            records.append(_make_record(evidence_id, available_at, file_path, "pdf", {"page": page_number, "text": text}, text=text))
    return records


def _image_category(file_path: str, text: str) -> str:
    lowered = (file_path + " " + text).casefold()
    for marker, category in (
        ("security_audit", "SECURITY_AUDIT_LOG"),
        ("backup", "BACKUP_ARCHIVE"),
        ("connector", "DATA_FLOW"),
        ("search_index", "SEARCH_INDEX_ENTRY"),
        ("analytics", "ANALYTICS_PROFILE"),
        ("marketing", "MARKETING_PROFILE"),
        ("customer_export", "USER_EXPORT"),
        ("object_storage", "SUPPORT_ATTACHMENT"),
        ("support_ticket", "SUPPORT_MESSAGE"),
        ("deleted_account", "ACCOUNT_TOMBSTONE"),
        ("account_admin", "USER_PROFILE"),
    ):
        if marker in lowered:
            return category
    return normalize_category("", lowered)


def _read_image(evidence_id: str, available_at: str, file_path: str, path: Path) -> list[EvidenceRecord]:
    try:
        from PIL import Image
        import pytesseract
    except ImportError as exc:
        raise EvidenceReadError("Screenshot reading requires Pillow and pytesseract; install requirements.txt and Tesseract OCR") from exc
    configured_tesseract = os.environ.get("TESSERACT_CMD", "").strip()
    if configured_tesseract:
        pytesseract.pytesseract.tesseract_cmd = configured_tesseract
    elif shutil.which("tesseract") is None:
        windows_default = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        if windows_default.is_file():
            pytesseract.pytesseract.tesseract_cmd = str(windows_default)
    try:
        with Image.open(path) as image:
            text = pytesseract.image_to_string(image)
    except Exception as exc:
        raise EvidenceReadError(f"Could not OCR image evidence {file_path}: {exc}") from exc
    if not text.strip():
        raise EvidenceReadError(f"OCR returned no readable text for image evidence {file_path}")
    lines = text.splitlines()
    records: list[EvidenceRecord] = []
    category = _image_category(file_path, text)
    for resource_id in sorted(set(RESOURCE_PATTERN.findall(text))):
        index = next((i for i, line in enumerate(lines) if resource_id.casefold() in line.casefold()), 0)
        excerpt = " ".join(lines[max(0, index - 2):index + 4])
        fields = {"resource_id": resource_id, "record_type": category, "text": excerpt}
        records.append(_make_record(evidence_id, available_at, file_path, "image", fields, text=excerpt, resource_override=resource_id))
    return records


def load_evidence(dataset: Dataset) -> EvidenceCorpus:
    """Parse every file listed by the participant-facing evidence manifest."""
    all_records: list[EvidenceRecord] = []
    all_coverage: list[EvidenceCoverage] = []
    for evidence_id, entry in sorted(dataset.evidence_manifest.items()):
        relative_path = entry["file_path"]
        path = dataset.evidence_path(evidence_id)
        extension = Path(relative_path).suffix.casefold()
        if extension == ".json":
            records, coverage = _read_json(evidence_id, entry["captured_at"], relative_path, path)
            all_records.extend(records)
            all_coverage.extend(coverage)
        elif extension == ".sql":
            records, coverage = _read_sql(evidence_id, entry["captured_at"], relative_path, path)
            all_records.extend(records)
            all_coverage.extend(coverage)
        elif extension == ".log":
            all_records.extend(_read_log(evidence_id, entry["captured_at"], relative_path, path))
        elif extension == ".txt":
            all_records.extend(_read_text(evidence_id, entry["captured_at"], relative_path, path))
        elif extension == ".pdf":
            all_records.extend(_read_pdf(evidence_id, entry["captured_at"], relative_path, path))
        elif extension == ".png":
            all_records.extend(_read_image(evidence_id, entry["captured_at"], relative_path, path))
        else:
            raise EvidenceReadError(f"Unsupported evidence type for {relative_path}")
    return EvidenceCorpus(tuple(all_records), tuple(all_coverage))
