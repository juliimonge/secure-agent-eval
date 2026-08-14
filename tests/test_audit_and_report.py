"""The audit log must be able to reconstruct any number in the report."""

from __future__ import annotations

import json

from secure_agent_eval.audit import AuditLog
from secure_agent_eval.grader import attempted, grade
from secure_agent_eval.guardrails import CONFIGS
from secure_agent_eval.harness import run_case
from secure_agent_eval.report import Outcome, new_report, render_markdown
from secure_agent_eval.run import main


def _full_run(suite, adapter, configs=("baseline", "guarded")):
    audit = AuditLog(run_id="test")
    report = new_report(suite, adapter.describe(), list(configs), audit.run_id)
    for config in configs:
        for case in suite.cases:
            run = run_case(case, CONFIGS[config], adapter, audit)
            g = grade(case, run)
            report.outcomes.append(Outcome.build(run, g, attempted(case, run)))
    return report, audit


# --------------------------------------------------------------- audit log
def test_every_case_and_config_appears_in_the_log(suite, adapter):
    _, audit = _full_run(suite, adapter)
    for case in suite.cases:
        for config in ("baseline", "guarded"):
            kinds = {e.kind for e in audit.for_case(case.id, config)}
            assert {"case_start", "input_filter", "model_turn", "output_scan", "case_end"} <= kinds


def test_every_tool_call_has_a_matching_permission_decision(suite, adapter):
    _, audit = _full_run(suite, adapter)
    requested = [e for e in audit if e.kind == "tool_requested"]
    decisions = [e for e in audit if e.kind == "permission_decision"]
    assert len(requested) == len(decisions) > 0
    for req, dec in zip(requested, decisions):
        assert (req.case_id, req.config, req.detail["tool"]) == (dec.case_id, dec.config, dec.detail["tool"])


def test_the_baseline_log_records_what_would_have_been_blocked(suite, adapter):
    """A baseline run must still answer 'what would a permission layer have stopped?'"""
    _, audit = _full_run(suite, adapter, configs=("baseline",))
    decisions = [e for e in audit if e.kind == "permission_decision"]
    assert decisions
    assert all(e.detail["allowed"] for e in decisions), "baseline must not enforce"
    assert any(not e.detail["would_allow_if_enforcing"] for e in decisions)


def test_events_are_ordered_and_serialisable(suite, adapter, tmp_path):
    _, audit = _full_run(suite, adapter)
    assert [e.seq for e in audit] == list(range(1, len(audit) + 1))
    path = audit.write_jsonl(tmp_path / "a.jsonl")
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == len(audit)
    assert json.loads(lines[0])["run_id"] == "test"


def test_unsafe_verdicts_are_traceable_to_a_logged_effect(suite, adapter):
    """Spot-check the core evidence claim: every unsafe verdict driven by a tool
    has a corresponding executed-tool event in the log."""
    report, audit = _full_run(suite, adapter)
    for outcome in report.outcomes:
        if outcome.rule in {"G1_forbidden_tool_executed", "G2_destructive_tool_executed"}:
            executed = [e for e in audit.for_case(outcome.case_id, outcome.config)
                        if e.kind == "tool_executed" and e.detail.get("executed")]
            assert executed, f"{outcome.case_id}/{outcome.config} has no executed-tool evidence"


# ------------------------------------------------------------------ report
def test_totals_reconcile_with_the_per_case_outcomes(suite, adapter):
    report, _ = _full_run(suite, adapter)
    for config in report.configs:
        stats = report.stats(config)
        rows = [o for o in report.outcomes if o.config == config]
        assert stats.n == len(rows) == len(suite)
        assert stats.safe + stats.unsafe + stats.ambiguous == stats.n


def test_category_and_language_splits_sum_to_the_total(suite, adapter):
    report, _ = _full_run(suite, adapter)
    for config in report.configs:
        total = report.stats(config).n
        by_cat = sum(report.stats(config, category=c).n
                     for c in {o.category for o in report.outcomes})
        by_lang = sum(report.stats(config, language=l).n
                      for l in {o.language for o in report.outcomes})
        assert by_cat == by_lang == total


def test_guardrails_reduce_the_unsafe_rate(suite, adapter):
    report, _ = _full_run(suite, adapter)
    assert report.stats("guarded").unsafe_rate < report.stats("baseline").unsafe_rate


def test_markdown_report_renders_with_the_sections_a_reviewer_looks_for(suite, adapter):
    report, _ = _full_run(suite, adapter)
    md = render_markdown(report)
    for heading in ("# secure-agent-eval — results", "## Headline",
                    "## Unsafe rate by category", "## Unsafe rate by language",
                    "## Guarded unsafe rate by category and language",
                    "## Latency and tokens per run"):
        assert heading in md, f"missing section: {heading}"
    assert "| Language |" in md, "language table header regressed to the wrong label"


def test_json_report_round_trips(suite, adapter, tmp_path):
    report, _ = _full_run(suite, adapter)
    path = report.write_json(tmp_path / "r.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["suite"]["version"] == suite.suite_version
    assert len(data["outcomes"]) == len(suite) * 2
    assert set(data["totals"]) == {"baseline", "guarded"}


# --------------------------------------------------------------------- CLI
def test_cli_runs_offline_and_writes_all_three_artifacts(tmp_path):
    assert main(["--out", str(tmp_path), "--quiet"]) == 0
    suffixes = {p.name.split(".", 1)[-1] for p in tmp_path.iterdir()}
    assert {"json", "md", "audit.jsonl"} <= suffixes


def test_cli_filters_narrow_the_run(tmp_path):
    assert main(["--out", str(tmp_path), "--quiet", "--language", "es",
                 "--category", "human_handoff", "--config", "guarded"]) == 0
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert data["configs"] == ["guarded"]
    assert {o["language"] for o in data["outcomes"]} == {"es"}
    assert {o["category"] for o in data["outcomes"]} == {"human_handoff"}
