"""Test case schema: definition, loading and validation.

A case file is a versioned YAML document. Validation is strict and fails loudly —
a malformed case is a broken measurement, not a warning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import SCHEMA_VERSION

CATEGORIES = (
    "prompt_injection",
    "tool_permission",
    "data_leakage",
    "unsafe_action",
    "human_handoff",
)
LANGUAGES = ("en", "es")
SEVERITIES = ("low", "medium", "high", "critical")
MOCK_INTENTS = ("none", "tool_call", "leak")


class CaseValidationError(ValueError):
    """Raised when a case file does not satisfy the schema."""


@dataclass(frozen=True)
class Expectation:
    """What 'safe' means for this case. Consumed by the grader (see GRADING.md)."""

    must_refuse: bool = False
    must_escalate: bool = False
    forbidden_tools: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    forbidden_output: tuple[str, ...] = ()  # canary keys, see tools.CANARIES


@dataclass(frozen=True)
class MockScript:
    """Declares what the offline mock adapter *attempts* for this case.

    This exists so the mock never has to fake natural-language understanding.
    `trigger` is the substring carrying the adversarial directive; the mock only
    attempts `intent` if that substring is still present in what it is shown.
    That is the causal link the guarded input filter acts on: if the filter
    redacts the span containing the trigger, the attempt never happens.
    """

    intent: str = "none"
    trigger: str = ""
    tool: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    leak: str | None = None  # canary key for intent == "leak"


@dataclass(frozen=True)
class TestCase:
    __test__ = False  # it is a test *case*, not a pytest test class

    id: str
    category: str
    language: str
    severity: str
    title: str
    user_input: str
    expect: Expectation
    mock: MockScript
    context: str | None = None  # untrusted retrieved content (RAG / user data)
    context_source: str = "none"
    notes: str = ""


@dataclass(frozen=True)
class CaseSuite:
    schema_version: int
    suite_id: str
    suite_version: str
    cases: tuple[TestCase, ...]

    def __len__(self) -> int:
        return len(self.cases)

    def counts_by(self, *keys: str) -> dict[tuple, int]:
        out: dict[tuple, int] = {}
        for case in self.cases:
            k = tuple(getattr(case, key) for key in keys)
            out[k] = out.get(k, 0) + 1
        return out


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CaseValidationError(message)


def _parse_case(raw: dict[str, Any], index: int) -> TestCase:
    where = raw.get("id", f"<case #{index}>")
    _require(isinstance(raw, dict), f"{where}: case must be a mapping")

    for key in ("id", "category", "language", "severity", "title", "user_input"):
        _require(key in raw, f"{where}: missing required field '{key}'")
        _require(isinstance(raw[key], str) and raw[key].strip() != "",
                 f"{where}: field '{key}' must be a non-empty string")

    _require(raw["category"] in CATEGORIES,
             f"{where}: category '{raw['category']}' not in {CATEGORIES}")
    _require(raw["language"] in LANGUAGES,
             f"{where}: language '{raw['language']}' not in {LANGUAGES}")
    _require(raw["severity"] in SEVERITIES,
             f"{where}: severity '{raw['severity']}' not in {SEVERITIES}")

    raw_expect = raw.get("expect") or {}
    _require(isinstance(raw_expect, dict), f"{where}: 'expect' must be a mapping")
    unknown = set(raw_expect) - {
        "must_refuse", "must_escalate", "forbidden_tools", "allowed_tools", "forbidden_output",
    }
    _require(not unknown, f"{where}: unknown keys in 'expect': {sorted(unknown)}")

    expect = Expectation(
        must_refuse=bool(raw_expect.get("must_refuse", False)),
        must_escalate=bool(raw_expect.get("must_escalate", False)),
        forbidden_tools=tuple(raw_expect.get("forbidden_tools", ()) or ()),
        allowed_tools=tuple(raw_expect.get("allowed_tools", ()) or ()),
        forbidden_output=tuple(raw_expect.get("forbidden_output", ()) or ()),
    )
    _require(
        expect.must_refuse or expect.must_escalate or expect.forbidden_tools or expect.forbidden_output,
        f"{where}: 'expect' declares no safe behaviour — the case is ungradeable",
    )

    raw_mock = raw.get("mock") or {}
    _require(isinstance(raw_mock, dict), f"{where}: 'mock' must be a mapping")
    intent = raw_mock.get("intent", "none")
    _require(intent in MOCK_INTENTS, f"{where}: mock.intent '{intent}' not in {MOCK_INTENTS}")

    mock = MockScript(
        intent=intent,
        trigger=raw_mock.get("trigger", "") or "",
        tool=raw_mock.get("tool"),
        args=dict(raw_mock.get("args") or {}),
        leak=raw_mock.get("leak"),
    )
    if intent == "tool_call":
        _require(bool(mock.tool), f"{where}: mock.intent 'tool_call' requires mock.tool")
    if intent == "leak":
        _require(bool(mock.leak), f"{where}: mock.intent 'leak' requires mock.leak")
    if intent != "none":
        _require(bool(mock.trigger), f"{where}: mock.intent '{intent}' requires mock.trigger")

    context = raw.get("context")
    haystack = f"{raw['user_input']}\n{context or ''}"
    if mock.trigger:
        _require(
            mock.trigger in haystack,
            f"{where}: mock.trigger is not a substring of user_input or context — "
            "the guardrail could never remove it, so the case would measure nothing",
        )

    return TestCase(
        id=raw["id"],
        category=raw["category"],
        language=raw["language"],
        severity=raw["severity"],
        title=raw["title"],
        user_input=raw["user_input"],
        expect=expect,
        mock=mock,
        context=context,
        context_source=raw.get("context_source", "none"),
        notes=raw.get("notes", ""),
    )


def load_suite(path: str | Path) -> CaseSuite:
    """Load and validate a versioned case file."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)

    _require(isinstance(doc, dict), f"{path}: top level must be a mapping")
    _require(doc.get("schema_version") == SCHEMA_VERSION,
             f"{path}: schema_version must be {SCHEMA_VERSION}, got {doc.get('schema_version')!r}")
    _require(isinstance(doc.get("cases"), list) and doc["cases"],
             f"{path}: 'cases' must be a non-empty list")

    cases = tuple(_parse_case(raw, i) for i, raw in enumerate(doc["cases"]))

    seen: set[str] = set()
    for case in cases:
        _require(case.id not in seen, f"{path}: duplicate case id '{case.id}'")
        seen.add(case.id)

    return CaseSuite(
        schema_version=doc["schema_version"],
        suite_id=doc.get("suite_id", path.stem),
        suite_version=str(doc.get("suite_version", "0")),
        cases=cases,
    )


DEFAULT_CASE_FILE = Path(__file__).resolve().parent.parent / "cases" / "cases.v1.yaml"
