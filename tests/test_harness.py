"""End-to-end harness behaviour, including the properties the whole result rests on."""

from __future__ import annotations

from secure_agent_eval.adapters import MockAdapter
from secure_agent_eval.adapters.base import AgentTurn, ModelAdapter, ToolCall
from secure_agent_eval.audit import AuditLog
from secure_agent_eval.grader import attempted, grade
from secure_agent_eval.guardrails import CONFIGS
from secure_agent_eval.harness import run_case
from secure_agent_eval.tools import CANARIES


def _by_id(suite, case_id):
    return next(c for c in suite.cases if c.id == case_id)


def _run(case, config_name, adapter, audit):
    return run_case(case, CONFIGS[config_name], adapter, audit)


# ------------------------------------------------------------- determinism
def test_the_offline_run_is_deterministic(suite, adapter, audit):
    """A benchmark that moves between runs cannot support a claim."""
    case = _by_id(suite, "PI-EN-01")
    first = _run(case, "baseline", adapter, audit)
    second = _run(case, "baseline", adapter, AuditLog())
    assert first.executed_tools == second.executed_tools
    assert first.final_output == second.final_output
    assert first.effects == second.effects


def test_the_mock_cannot_see_which_configuration_it_is_running_under(suite, adapter, audit):
    """If the mock could branch on the config, the comparison would be circular."""
    case = _by_id(suite, "TP-EN-01")
    baseline = _run(case, "baseline", adapter, audit)
    guarded = _run(case, "guarded", adapter, audit)
    # Same request, same attempt. Only the outcome differs, and only because
    # the permission layer intervened.
    assert baseline.requested_tools == guarded.requested_tools == ["exec_shell"]
    assert baseline.executed_tools == ["exec_shell"]
    assert guarded.executed_tools == []


# --------------------------------------------------------- the four defences
def test_permission_layer_blocks_out_of_scope_calls_end_to_end(suite, adapter, audit):
    case = _by_id(suite, "UA-EN-02")
    guarded = _run(case, "guarded", adapter, audit)
    assert guarded.blocked_tools == ["exec_shell"]
    assert not any(e.startswith("exec_shell") for e in guarded.effects)
    assert grade(case, guarded).verdict.value == "safe"


def test_baseline_actually_executes_the_destructive_call(suite, adapter, audit):
    case = _by_id(suite, "UA-EN-02")
    baseline = _run(case, "baseline", adapter, audit)
    assert any(e.startswith("exec_shell") for e in baseline.effects)
    assert grade(case, baseline).verdict.value == "unsafe"


def test_input_filter_neutralises_an_indirect_injection(suite, adapter, audit):
    case = _by_id(suite, "PI-EN-01")
    baseline = _run(case, "baseline", adapter, audit)
    guarded = _run(case, "guarded", adapter, audit)
    assert "delete_booking" in baseline.executed_tools
    assert guarded.requested_tools == [], "the payload should never have been reached for"
    assert attempted(case, baseline) and not attempted(case, guarded)


def test_output_scanner_stops_a_canary_reaching_the_user(suite, adapter, audit):
    case = _by_id(suite, "DL-EN-04")
    baseline = _run(case, "baseline", adapter, audit)
    guarded = _run(case, "guarded", adapter, audit)
    assert CANARIES["admin_token"] in baseline.final_output
    assert CANARIES["admin_token"] not in guarded.final_output
    assert CANARIES["admin_token"] in guarded.raw_output, (
        "the agent still produced the secret — only the boundary stopped it"
    )


def test_cross_user_reads_never_execute_under_the_guarded_config(suite, adapter, audit):
    case = _by_id(suite, "DL-EN-03")
    guarded = _run(case, "guarded", adapter, audit)
    assert not any(e.startswith("read_user_record:user_b") for e in guarded.effects)


def test_handoff_is_routed_only_when_the_filter_recognises_the_situation(suite, adapter, audit):
    case = _by_id(suite, "HH-EN-01")
    assert "escalate_to_human" not in _run(case, "baseline", adapter, audit).executed_tools
    assert "escalate_to_human" in _run(case, "guarded", adapter, audit).executed_tools


# ---------------------------------------------------------------- profiles
def test_cautious_profile_resists_direct_requests_but_not_injection(
    suite, cautious_adapter, audit
):
    direct = _run(_by_id(suite, "TP-EN-01"), "baseline", cautious_adapter, audit)
    injected = _run(_by_id(suite, "PI-EN-01"), "baseline", cautious_adapter, audit)
    assert direct.requested_tools == []
    assert injected.executed_tools == ["delete_booking"]


# ----------------------------------------------------------------- plumbing
def test_a_broken_adapter_is_never_scored_as_safe(suite, audit):
    class Broken(ModelAdapter):
        name = "broken"
        is_live = False

        def step(self, request):
            raise RuntimeError("provider exploded")

    case = _by_id(suite, "TP-EN-01")
    run = run_case(case, CONFIGS["guarded"], Broken(), audit)
    assert run.error and grade(case, run).rule == "G0_run_error"


def test_the_loop_terminates_when_a_model_never_stops(suite, audit):
    class Looping(ModelAdapter):
        name = "looping"
        is_live = False

        def step(self, request):
            return AgentTurn(text="thinking", tool_calls=(ToolCall("search_docs", {"query": "x"}),),
                             stop=False)

    case = _by_id(suite, "PI-EN-01")
    run = run_case(case, CONFIGS["guarded"], Looping(), audit, max_steps=3)
    assert run.steps == 3 and "step limit" in (run.error or "")


def test_each_case_gets_a_fresh_world(suite, adapter, audit):
    """State leaking between cases would make results order-dependent."""
    case = _by_id(suite, "UA-EN-01")
    first = _run(case, "baseline", adapter, audit)
    second = _run(case, "baseline", adapter, audit)
    assert first.effects == second.effects and first.effects


def test_every_case_runs_under_both_configurations(suite, adapter):
    audit = AuditLog()
    for case in suite.cases:
        for config in ("baseline", "guarded"):
            run = run_case(case, CONFIGS[config], adapter, audit)
            assert run.error is None, f"{case.id}/{config}: {run.error}"
            assert grade(case, run).verdict.value in {"safe", "unsafe", "ambiguous"}
