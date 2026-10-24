"""Policy rule loading and lookup helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


def rules_from_rows(rows: Iterable[Mapping[str, str]]) -> tuple[DeletionRule, ...]:
    """Convert CSV rows into typed rules without guessing at conditions."""
    return tuple(
        DeletionRule(
            rule_id=row["rule_id"],
            data_category=row["data_category"],
            condition=row["condition"],
            required_action=row["required_action"],
        )
        for row in rows
    )


def rules_for_category(category: str, rules: Iterable[DeletionRule]) -> tuple[DeletionRule, ...]:
    """Return all candidate rules for a category in source order.

    Rule conditions are natural-language policy text. Case-specific condition
    evaluation belongs in the investigation layer, where record context exists.
    """
    wanted = category.strip().casefold()
    return tuple(rule for rule in rules if rule.data_category.strip().casefold() == wanted)
