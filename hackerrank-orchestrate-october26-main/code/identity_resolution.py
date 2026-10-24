"""Resolve a request email to time-bounded identity history."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping


@dataclass(frozen=True)
class ResolvedSubject:
    """A stable user reference and identifiers known by an audit cutoff."""

    user_id: str
    identifiers: frozenset[str]
    linked_resource_ids: frozenset[str] = frozenset()


def normalize_email(value: str) -> str:
    """Normalize email for case-insensitive matching."""
    return value.strip().casefold()


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _known_by(timestamp: str, cutoff: datetime) -> bool:
    parsed = _parse_time(timestamp)
    return parsed is not None and parsed <= cutoff


def resolve_subjects(
    email: str,
    identities: Iterable[Mapping[str, str]],
    audit_log: Iterable[Mapping[str, str]],
    audit_at: str,
    system_activity: Iterable[Mapping[str, str]] = (),
) -> tuple[ResolvedSubject, ...]:
    """Find users matching current or historical identifiers before cutoff.

    The returned identifier set includes historical field values from the audit
    log and current snapshot values only when that snapshot predates the cutoff.
    Identity-link activity can additionally connect those identifiers to
    resource IDs. Other activity event results are not treated as proof of state.
    """
    cutoff = _parse_time(audit_at)
    if cutoff is None:
        raise ValueError(f"Invalid audit_at timestamp: {audit_at}")
    wanted = normalize_email(email)
    identity_rows = tuple(identities)
    audit_rows = tuple(audit_log)
    activity_rows = tuple(system_activity)

    matching_users: set[str] = set()
    for row in identity_rows:
        if _known_by(row.get("updated_at", ""), cutoff) and normalize_email(row.get("email", "")) == wanted:
            matching_users.add(row.get("user_id", ""))

    for row in audit_rows:
        if not _known_by(row.get("event_time", ""), cutoff):
            continue
        if row.get("field_name", "").casefold() != "email":
            continue
        old_value = normalize_email(row.get("old_value", ""))
        new_value = normalize_email(row.get("new_value", ""))
        if wanted in (old_value, new_value) and row.get("user_id"):
            matching_users.add(row["user_id"])

    identifiers_by_user: dict[str, set[str]] = {user_id: {user_id} for user_id in matching_users if user_id}
    for row in identity_rows:
        user_id = row.get("user_id", "")
        if user_id not in identifiers_by_user or not _known_by(row.get("updated_at", ""), cutoff):
            continue
        identifiers_by_user[user_id].update(
            value.strip()
            for field in ("name", "email", "phone", "email_hash")
            if (value := row.get(field, "").strip())
        )

    for row in audit_rows:
        user_id = row.get("user_id", "")
        if user_id not in identifiers_by_user or not _known_by(row.get("event_time", ""), cutoff):
            continue
        identifiers_by_user[user_id].update(
            value.strip() for value in (row.get("old_value", ""), row.get("new_value", "")) if value.strip()
        )

    linked_by_user: dict[str, set[str]] = {user_id: set() for user_id in identifiers_by_user}
    resource_pattern = re.compile(
        r"\b(?:account|search|support|support_attachment|analytics|audit_record|tombstone|data_flow|backup|export|"
        r"marketing|cache|telemetry|email_delivery|secondary_identifier|legal_hold)_[0-9][A-Za-z0-9_-]*\b",
        re.IGNORECASE,
    )
    for activity in activity_rows:
        if activity.get("event_type", "").upper() != "LINK_RESOURCE_IDENTITY":
            continue
        if not _known_by(activity.get("event_time", ""), cutoff):
            continue
        details = activity.get("details", "")
        for user_id, values in identifiers_by_user.items():
            if not any(_contains_identifier(details, value) for value in values):
                continue
            if activity.get("resource_id"):
                linked_by_user[user_id].add(activity["resource_id"])
            linked_by_user[user_id].update(resource_pattern.findall(details))

    return tuple(
        ResolvedSubject(
            user_id=user_id,
            identifiers=frozenset(values),
            linked_resource_ids=frozenset(linked_by_user.get(user_id, set())),
        )
        for user_id, values in sorted(identifiers_by_user.items())
    )


def _contains_identifier(text: str, identifier: str) -> bool:
    """Match a whole identifier instead of an accidental substring."""
    candidate = identifier.strip()
    if not candidate:
        return False
    if "@" in candidate or len(candidate) >= 12 and candidate.isalnum():
        return candidate.casefold() in text.casefold()
    digits = re.sub(r"\D", "", candidate)
    if len(digits) >= 7 and len(digits) > len(candidate) // 2:
        return digits in re.sub(r"\D", "", text)
    if any(char.isspace() for char in candidate):
        return " ".join(candidate.casefold().split()) in " ".join(text.casefold().split())
    return re.search(rf"(?<![\w]){re.escape(candidate)}(?![\w])", text, re.IGNORECASE) is not None
