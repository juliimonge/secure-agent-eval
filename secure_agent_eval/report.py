"""Results aggregation, JSON serialisation and the markdown report.

Two rates are reported everywhere, and they answer different questions:

* **unsafe rate** — did a forbidden effect actually reach the world or the user?
  This grades the *system*. Guardrails move it.
* **attempt rate** — did the agent reach for the forbidden thing at all?
  This grades the *agent*. A blocking guardrail does not move it.

Reporting only the first would let a permission layer look like it fixed the
model. Reporting both keeps the claim honest.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .grader import Grade, Verdict
from .harness import CaseRun
from .schema import CATEGORIES, LANGUAGES, CaseSuite

CATEGORY_LABELS = {
    "prompt_injection": "Prompt injection",
    "tool_permission": "Tool permission",
    "data_leakage": "Data leakage",
    "unsafe_action": "Unsafe action",
    "human_handoff": "Human handoff",
}
LANGUAGE_LABELS = {"en": "English", "es": "Spanish"}


@dataclass
class Outcome:
    """One case under one configuration, graded."""

    case_id: str
    config: str
    category: str
    language: str
    severity: str
    verdict: str
    rule: str
    reason: str
    attempted: bool
    executed_tools: list[str]
    blocked_tools: list[str]
    effects: list[str]
    latency_ms: float
    input_tokens: int
    output_tokens: int
    steps: int
    error: str | None = None

    @classmethod
    def build(cls, run: CaseRun, grade: Grade, attempted_flag: bool) -> "Outcome":
        return cls(
            case_id=run.case_id, config=run.config, category=run.category,
            language=run.language, severity=run.severity,
            verdict=grade.verdict.value, rule=grade.rule, reason=grade.reason,
            attempted=attempted_flag,
            executed_tools=run.executed_tools, blocked_tools=run.blocked_tools,
            effects=run.effects, latency_ms=run.latency_ms,
            input_tokens=run.input_tokens, output_tokens=run.output_tokens,
            steps=run.steps, error=run.error,
        )


@dataclass
class Stats:
    n: int = 0
    safe: int = 0
    unsafe: int = 0
    ambiguous: int = 0
    attempts: int = 0

    def add(self, outcome: Outcome) -> None:
        self.n += 1
        setattr(self, outcome.verdict, getattr(self, outcome.verdict) + 1)
        if outcome.attempted:
            self.attempts += 1

    @property
    def unsafe_rate(self) -> float:
        return 0.0 if not self.n else self.unsafe / self.n

    @property
    def safe_rate(self) -> float:
        return 0.0 if not self.n else self.safe / self.n

    @property
    def attempt_rate(self) -> float:
        return 0.0 if not self.n else self.attempts / self.n

    def to_dict(self) -> dict[str, Any]:
        return {"n": self.n, "safe": self.safe, "unsafe": self.unsafe,
                "ambiguous": self.ambiguous, "attempts": self.attempts,
                "unsafe_rate": round(self.unsafe_rate, 4),
                "safe_rate": round(self.safe_rate, 4),
                "attempt_rate": round(self.attempt_rate, 4)}


@dataclass
class RunReport:
    run_id: str
    started_at: str
    suite_id: str
    suite_version: str
    schema_version: int
    adapter: dict[str, Any]
    configs: list[str]
    outcomes: list[Outcome] = field(default_factory=list)

    # ---------------- aggregation ----------------
    def _select(self, config: str, **filters: str) -> list[Outcome]:
        return [o for o in self.outcomes
                if o.config == config and all(getattr(o, k) == v for k, v in filters.items())]

    def stats(self, config: str, **filters: str) -> Stats:
        s = Stats()
        for outcome in self._select(config, **filters):
            s.add(outcome)
        return s

    def latency_summary(self, config: str) -> dict[str, float]:
        values = [o.latency_ms for o in self.outcomes if o.config == config]
        if not values:
            return {"mean_ms": 0.0, "p50_ms": 0.0, "max_ms": 0.0, "total_ms": 0.0}
        return {
            "mean_ms": round(statistics.fmean(values), 3),
            "p50_ms": round(statistics.median(values), 3),
            "max_ms": round(max(values), 3),
            "total_ms": round(sum(values), 3),
        }

    def token_summary(self, config: str) -> dict[str, int]:
        rows = [o for o in self.outcomes if o.config == config]
        return {
            "input_tokens": sum(o.input_tokens for o in rows),
            "output_tokens": sum(o.output_tokens for o in rows),
            "total_tokens": sum(o.input_tokens + o.output_tokens for o in rows),
            "mean_total_per_case": round(
                sum(o.input_tokens + o.output_tokens for o in rows) / len(rows)) if rows else 0,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "suite": {"id": self.suite_id, "version": self.suite_version,
                      "schema_version": self.schema_version},
            "adapter": self.adapter,
            "configs": self.configs,
            "totals": {c: self.stats(c).to_dict() for c in self.configs},
            "by_category": {
                c: {cat: self.stats(c, category=cat).to_dict() for cat in CATEGORIES}
                for c in self.configs
            },
            "by_language": {
                c: {lang: self.stats(c, language=lang).to_dict() for lang in LANGUAGES}
                for c in self.configs
            },
            "by_category_language": {
                c: {f"{cat}|{lang}": self.stats(c, category=cat, language=lang).to_dict()
                    for cat in CATEGORIES for lang in LANGUAGES}
                for c in self.configs
            },
            "latency": {c: self.latency_summary(c) for c in self.configs},
            "tokens": {c: self.token_summary(c) for c in self.configs},
            "outcomes": [asdict(o) for o in self.outcomes],
        }

    def write_json(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def write_markdown(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(self), encoding="utf-8")
        return path


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------


def _pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def _delta(baseline: float, guarded: float) -> str:
    diff = (guarded - baseline) * 100
    if abs(diff) < 0.5:
        return "0"
    return f"{diff:+.0f} pp"


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def render_markdown(report: RunReport) -> str:
    base, guard = "baseline", "guarded"
    have_both = base in report.configs and guard in report.configs

    lines: list[str] = [
        "# secure-agent-eval — results",
        "",
        f"- **Run id**: `{report.run_id}`",
        f"- **Started**: {report.started_at}",
        f"- **Suite**: `{report.suite_id}` v{report.suite_version} "
        f"(schema v{report.schema_version}), {report.stats(report.configs[0]).n} cases",
        f"- **Adapter**: `{json.dumps(report.adapter, sort_keys=True)}`",
        "",
        "`unsafe rate` = a forbidden effect reached the world or the user (grades the system). ",
        "`attempt rate` = the agent reached for the forbidden thing, blocked or not (grades the agent).",
        "",
        "## Headline",
        "",
    ]

    if have_both:
        b, g = report.stats(base), report.stats(guard)
        lines.append(_table(
            ["Metric", "Baseline", "Guarded", "Delta"],
            [
                ["Unsafe", f"{b.unsafe}/{b.n} ({_pct(b.unsafe_rate)})",
                 f"{g.unsafe}/{g.n} ({_pct(g.unsafe_rate)})", _delta(b.unsafe_rate, g.unsafe_rate)],
                ["Safe", f"{b.safe}/{b.n} ({_pct(b.safe_rate)})",
                 f"{g.safe}/{g.n} ({_pct(g.safe_rate)})", _delta(b.safe_rate, g.safe_rate)],
                ["Ambiguous", str(b.ambiguous), str(g.ambiguous), ""],
                ["Attempted", f"{b.attempts}/{b.n} ({_pct(b.attempt_rate)})",
                 f"{g.attempts}/{g.n} ({_pct(g.attempt_rate)})",
                 _delta(b.attempt_rate, g.attempt_rate)],
            ],
        ))
    else:
        for config in report.configs:
            s = report.stats(config)
            lines.append(f"- **{config}**: unsafe {s.unsafe}/{s.n} ({_pct(s.unsafe_rate)}), "
                         f"attempts {s.attempts}/{s.n} ({_pct(s.attempt_rate)})")

    # ---- by category ----
    lines += ["", "## Unsafe rate by category", ""]
    rows = []
    for cat in CATEGORIES:
        row = [CATEGORY_LABELS[cat]]
        for config in report.configs:
            s = report.stats(config, category=cat)
            row.append(f"{s.unsafe}/{s.n} ({_pct(s.unsafe_rate)})")
        if have_both:
            row.append(_delta(report.stats(base, category=cat).unsafe_rate,
                              report.stats(guard, category=cat).unsafe_rate))
        rows.append(row)
    headers = ["Category", *report.configs] + (["Delta"] if have_both else [])
    lines.append(_table(headers, rows))

    # ---- by language ----
    lines += ["", "## Unsafe rate by language", ""]
    rows = []
    for lang in LANGUAGES:
        row = [LANGUAGE_LABELS[lang]]
        for config in report.configs:
            s = report.stats(config, language=lang)
            row.append(f"{s.unsafe}/{s.n} ({_pct(s.unsafe_rate)})")
        if have_both:
            row.append(_delta(report.stats(base, language=lang).unsafe_rate,
                              report.stats(guard, language=lang).unsafe_rate))
        rows.append(row)
    lines.append(_table(["Language", *report.configs] + (["Delta"] if have_both else []), rows))

    # ---- the cross-tab: this is the interesting one ----
    lines += ["", "## Guarded unsafe rate by category and language", "",
              "The bilingual split. A gap here means a guardrail is carrying less "
              "weight in one language than the other.", ""]
    rows = []
    for cat in CATEGORIES:
        en = report.stats(guard if have_both else report.configs[-1], category=cat, language="en")
        es = report.stats(guard if have_both else report.configs[-1], category=cat, language="es")
        ben = report.stats(base, category=cat, language="en") if have_both else en
        bes = report.stats(base, category=cat, language="es") if have_both else es
        rows.append([
            CATEGORY_LABELS[cat],
            f"{ben.unsafe}/{ben.n}", f"{en.unsafe}/{en.n}",
            f"{bes.unsafe}/{bes.n}", f"{es.unsafe}/{es.n}",
            _delta(en.unsafe_rate, es.unsafe_rate),
        ])
    lines.append(_table(
        ["Category", "EN baseline", "EN guarded", "ES baseline", "ES guarded", "ES − EN (guarded)"],
        rows,
    ))

    # ---- the same cross-tab on attempts ----
    if have_both:
        lines += ["", "## Guarded attempt rate by category and language", "",
                  "Where the unsafe rate says whether harm landed, this says whether the "
                  "agent still reached for it. A category that is 0% unsafe but non-zero "
                  "here is being held up by a blocking guardrail, not by the agent.", ""]
        rows = []
        for cat in CATEGORIES:
            en = report.stats(guard, category=cat, language="en")
            es = report.stats(guard, category=cat, language="es")
            rows.append([
                CATEGORY_LABELS[cat],
                f"{en.attempts}/{en.n} ({_pct(en.attempt_rate)})",
                f"{es.attempts}/{es.n} ({_pct(es.attempt_rate)})",
                _delta(en.attempt_rate, es.attempt_rate),
            ])
        lines.append(_table(["Category", "EN guarded", "ES guarded", "ES − EN"], rows))

    # ---- cost / latency ----
    lines += ["", "## Latency and tokens per run", ""]
    rows = []
    for config in report.configs:
        lat = report.latency_summary(config)
        tok = report.token_summary(config)
        rows.append([config, f"{lat['mean_ms']:.2f}", f"{lat['p50_ms']:.2f}",
                     f"{lat['max_ms']:.2f}", f"{lat['total_ms']:.1f}",
                     f"{tok['input_tokens']:,}", f"{tok['output_tokens']:,}",
                     f"{tok['mean_total_per_case']:,}"])
    lines.append(_table(
        ["Config", "Mean ms", "p50 ms", "Max ms", "Total ms",
         "Input tok", "Output tok", "Mean tok/case"],
        rows,
    ))
    if not report.adapter.get("is_live", True):
        lines += ["", "> Token counts from the offline mock are a deterministic "
                  "`len(text)//4` estimate, not a real tokenizer. They are here so the "
                  "column is wired end to end; only live-adapter counts are meaningful."]

    # ---- failures worth reading ----
    lines += ["", "## Cases still unsafe under the guarded configuration", ""]
    remaining = [o for o in report.outcomes
                 if o.config == (guard if have_both else report.configs[-1])
                 and o.verdict == Verdict.UNSAFE.value]
    if not remaining:
        lines.append("_None._")
    else:
        lines.append(_table(
            ["Case", "Lang", "Category", "Severity", "Rule", "Why"],
            [[o.case_id, o.language, CATEGORY_LABELS[o.category], o.severity, o.rule, o.reason]
             for o in sorted(remaining, key=lambda o: (o.category, o.language, o.case_id))],
        ))

    ambiguous = [o for o in report.outcomes
                 if o.config == (guard if have_both else report.configs[-1])
                 and o.verdict == Verdict.AMBIGUOUS.value]
    lines += ["", "## Ambiguous under the guarded configuration", ""]
    if not ambiguous:
        lines.append("_None._")
    else:
        lines.append(
            "Ambiguous is a real verdict, not a rounding error: no forbidden effect was "
            "observed, but the behaviour was not clearly correct either.\n")
        lines.append(_table(
            ["Case", "Lang", "Category", "Rule", "Why"],
            [[o.case_id, o.language, CATEGORY_LABELS[o.category], o.rule, o.reason]
             for o in sorted(ambiguous, key=lambda o: (o.category, o.language, o.case_id))],
        ))

    lines += ["", "---", "",
              "Generated by `python -m secure_agent_eval.run`. "
              "Every number here is reproducible from the audit log in the same results directory."]
    return "\n".join(lines) + "\n"


def new_report(suite: CaseSuite, adapter_info: dict[str, Any], configs: list[str],
               run_id: str) -> RunReport:
    return RunReport(
        run_id=run_id,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        schema_version=suite.schema_version,
        adapter=adapter_info,
        configs=configs,
    )
