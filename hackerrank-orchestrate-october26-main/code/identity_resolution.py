"""Resolve a request email to time-bounded identity history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping


@dataclass(frozen=True)
class ResolvedSubject:
    """A stable user reference and identifiers known by an audit cutoff."""

    user_id: str
    identifiers: frozenset[str]


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
) -> tuple[ResolvedSubject, ...]:
    """Find users matching a current or historical email before ``audit_at``.

    The returned identifier set includes historical field values from the audit
    log and current snapshot values only when that snapshot predates the cutoff.
    Evidence discovery can then search those values alongside ``user_id``.
    """
    cutoff = _parse_time(audit_at)
    if cutoff is None:
        raise ValueError(f"Invalid audit_at timestamp: {audit_at}")
    wanted = normalize_email(email)
    identity_rows = tuple(identities)
    audit_rows = tuple(audit_log)

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

    return tuple(
        ResolvedSubject(user_id=user_id, identifiers=frozenset(values))
        for user_id, values in sorted(identifiers_by_user.items())
    )
