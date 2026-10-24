"""Does the SQL still answer the question? A deterministic check of named resources (E4).

The gate sees only SQL, so a model that swaps a forbidden table for another one (asked for loans,
counted transactions) or silently drops a forbidden column passes every SQL check while answering
something else. This module finds which tables and columns the *question* names, using the
reviewed ``question_terms`` of the policy, and reports the ones the role may not read:

* a named forbidden **table** means the query answers a different question: the gate refuses;
* a named forbidden **column** the SQL dropped is reported as withheld, exactly like a display
  column the gate removed, so the user gets a partial answer with a notice.

No model is called and nothing leaves the process. Only resources the question itself names are
reported, so a refusal or notice never reveals a hidden column the user did not mention.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from sqlguard.security.policy import RolePolicy


@dataclass(frozen=True)
class QuestionCoverage:
    forbidden_tables: tuple[str, ...] = ()  # named tables (or columns of tables) the role lacks
    withheld_columns: tuple[str, ...] = ()  # named readable-table columns the role may not read


def named_resources(question: str, policy: RolePolicy) -> frozenset[str]:
    """Tables and ``table.column`` names whose reviewed terms occur in the question."""
    text = unicodedata.normalize("NFC", question).casefold()
    return frozenset(
        resource
        for resource, terms in policy.question_terms.items()
        if any(_mentions(text, term) for term in terms)
    )


def check_question_coverage(
    question: str, policy: RolePolicy, role: str, *, removed: Iterable[str] = ()
) -> QuestionCoverage:
    """Forbidden resources the question names; ``removed`` columns are already withheld."""
    role = role.casefold()
    allowed_tables = policy.allowed_tables(role)
    already = set(removed)
    tables, columns = set(), set()
    for resource in named_resources(question, policy):
        table, _, column = resource.partition(".")
        if table not in allowed_tables:
            tables.add(table)
        elif column and not policy.can_read(role, table, column) and resource not in already:
            columns.add(resource)
    return QuestionCoverage(tuple(sorted(tables)), tuple(sorted(columns)))


def _mentions(text: str, term: str) -> bool:
    # \w is Unicode-aware, so "thẻ" never matches inside a longer word and "card" not in "card_id".
    return re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text) is not None
