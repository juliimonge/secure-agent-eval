"""The case file is data, so it gets tested like data."""

from __future__ import annotations

import pytest

from secure_agent_eval.schema import (
    CATEGORIES,
    LANGUAGES,
    SEVERITIES,
    CaseValidationError,
    load_suite,
)
from secure_agent_eval.tools import CANARIES, TOOLS

MIN_CASES = 50


def test_suite_meets_the_stated_minimum(suite):
    assert len(suite) >= MIN_CASES, f"suite has {len(suite)} cases, README claims >= {MIN_CASES}"


def test_every_category_and_language_is_present(suite):
    counts = suite.counts_by("category", "language")
    for category in CATEGORIES:
        for language in LANGUAGES:
            assert counts.get((category, language), 0) > 0, f"no {language} cases for {category}"


def test_categories_and_languages_are_evenly_spread(suite):
    """An uneven suite makes a by-category rate mean different things per row."""
    counts = suite.counts_by("category", "language")
    sizes = set(counts.values())
    assert len(sizes) == 1, f"uneven case counts across category/language buckets: {counts}"


def test_case_ids_are_unique_and_well_formed(suite):
    ids = [c.id for c in suite.cases]
    assert len(ids) == len(set(ids))
    for case in suite.cases:
        assert case.language.upper() in case.id, f"{case.id} does not encode its language"


def test_fields_are_within_their_enumerations(suite):
    for case in suite.cases:
        assert case.category in CATEGORIES
        assert case.language in LANGUAGES
        assert case.severity in SEVERITIES


def test_every_referenced_tool_exists(suite):
    for case in suite.cases:
        for name in (*case.expect.forbidden_tools, *case.expect.allowed_tools):
            assert name in TOOLS, f"{case.id}: unknown tool {name!r} in expect"
        if case.mock.tool:
            assert case.mock.tool in TOOLS, f"{case.id}: unknown tool {case.mock.tool!r} in mock"


def test_every_referenced_canary_exists(suite):
    for case in suite.cases:
        for key in case.expect.forbidden_output:
            assert key in CANARIES, f"{case.id}: unknown canary {key!r}"
        if case.mock.leak:
            assert case.mock.leak in CANARIES, f"{case.id}: unknown canary {case.mock.leak!r}"


def test_every_trigger_is_present_in_the_text_it_claims_to_come_from(suite):
    """If the trigger is not in the input, no guardrail could ever remove it and
    the case would silently measure nothing."""
    for case in suite.cases:
        if not case.mock.trigger:
            continue
        haystack = f"{case.user_input}\n{case.context or ''}"
        assert case.mock.trigger in haystack, f"{case.id}: trigger not found in case text"


def test_injection_cases_carry_untrusted_context(suite):
    """An injection case with no untrusted surface is a mislabelled direct request."""
    for case in suite.cases:
        if case.category == "prompt_injection":
            assert case.context, f"{case.id}: prompt_injection case has no context"
            assert case.context_source != "none", f"{case.id}: context_source not declared"
            assert case.mock.trigger in (case.context or ""), (
                f"{case.id}: the payload is not in the untrusted context — "
                "this is a direct request, not an indirect injection"
            )


def test_handoff_cases_expect_escalation(suite):
    for case in suite.cases:
        if case.category == "human_handoff":
            assert case.expect.must_escalate, f"{case.id}: handoff case must expect escalation"


def test_malformed_case_files_are_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"

    bad.write_text("schema_version: 99\ncases: []\n", encoding="utf-8")
    with pytest.raises(CaseValidationError):
        load_suite(bad)

    bad.write_text(
        "schema_version: 1\ncases:\n"
        "  - id: X\n    category: nope\n    language: en\n    severity: low\n"
        "    title: t\n    user_input: u\n    expect: {must_refuse: true}\n",
        encoding="utf-8",
    )
    with pytest.raises(CaseValidationError, match="category"):
        load_suite(bad)

    bad.write_text(
        "schema_version: 1\ncases:\n"
        "  - id: X\n    category: unsafe_action\n    language: en\n    severity: low\n"
        "    title: t\n    user_input: u\n    expect: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(CaseValidationError, match="ungradeable"):
        load_suite(bad)

    bad.write_text(
        "schema_version: 1\ncases:\n"
        "  - id: X\n    category: unsafe_action\n    language: en\n    severity: low\n"
        "    title: t\n    user_input: hello\n    expect: {must_refuse: true}\n"
        "    mock: {intent: tool_call, tool: exec_shell, trigger: 'not in the text'}\n",
        encoding="utf-8",
    )
    with pytest.raises(CaseValidationError, match="substring"):
        load_suite(bad)
