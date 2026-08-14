"""The agent harness: one case, one configuration, one bounded loop.

Order of operations per case — this *is* the guarded pipeline:

    input filter  ->  model turn  ->  permission check  ->  tool execution
                          ^                                       |
                          +---------------- results --------------+
                                        (max_steps)
                                          |
                                     output scan  ->  grader

Under the baseline configuration the same pipeline runs with each guardrail's
`enabled`/`enforcing` flag off. The guardrails still *evaluate* and still log
their would-be decisions, so a baseline run answers "what would have been
stopped?" without changing what actually happened.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .adapters.base import ModelAdapter, ToolCall, ToolResult, TurnRequest
from .audit import AuditLog
from .guardrails import GuardrailConfig, InputFilter, OutputScanner
from .schema import TestCase
from .tools import SYSTEM_PROMPT, TOOLS, PermissionLayer, World, visible_tool_specs

MAX_STEPS = 4


@dataclass
class ExecutedCall:
    name: str
    args: dict[str, Any]
    allowed: bool
    rule: str
    detail: str
    result: str
    step: int


@dataclass
class CaseRun:
    """Everything observed for one (case, configuration) pair."""

    case_id: str
    config: str
    language: str
    category: str
    severity: str
    final_output: str
    raw_output: str                       # before the output scanner
    calls: list[ExecutedCall] = field(default_factory=list)
    effects: list[str] = field(default_factory=list)
    input_findings: list[dict[str, str]] = field(default_factory=list)
    output_findings: list[dict[str, str]] = field(default_factory=list)
    steps: int = 0
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None

    @property
    def executed_tools(self) -> list[str]:
        return [c.name for c in self.calls if c.allowed]

    @property
    def requested_tools(self) -> list[str]:
        return [c.name for c in self.calls]

    @property
    def blocked_tools(self) -> list[str]:
        return [c.name for c in self.calls if not c.allowed]


def run_case(case: TestCase, config: GuardrailConfig, adapter: ModelAdapter,
             audit: AuditLog, max_steps: int = MAX_STEPS) -> CaseRun:
    world = World()
    input_filter = InputFilter(enabled=config.input_filter)
    scanner = OutputScanner(enabled=config.output_scanning)
    permissions = PermissionLayer(enforcing=config.permission_enforcement)

    audit.record(case.id, config.name, "case_start",
                 category=case.category, language=case.language, severity=case.severity,
                 title=case.title, context_source=case.context_source)

    started = time.perf_counter()
    filtered = input_filter.apply(case.user_input, case.context)
    audit.record(
        case.id, config.name, "input_filter",
        enabled=config.input_filter,
        findings=[{"rule": f.rule, "where": f.where, "matched": f.matched, "action": f.action}
                  for f in filtered.findings],
        redactions=filtered.redactions,
        notices=filtered.policy_notices,
    )

    run = CaseRun(
        case_id=case.id, config=config.name, language=case.language,
        category=case.category, severity=case.severity,
        final_output="", raw_output="",
        input_findings=[{"rule": f.rule, "where": f.where, "action": f.action}
                        for f in filtered.findings],
    )

    specs = tuple(visible_tool_specs())
    pending: tuple[ToolResult, ...] = ()
    final_text = ""

    try:
        for step in range(1, max_steps + 1):
            request = TurnRequest(
                system_prompt=SYSTEM_PROMPT,
                user_input=filtered.user_input,
                context=filtered.context,
                policy_notices=tuple(filtered.policy_notices),
                tool_specs=specs,
                tool_results=pending,
                case_id=case.id,
                language=case.language,
            )
            turn = adapter.step(request)
            run.steps = step
            run.input_tokens += turn.input_tokens
            run.output_tokens += turn.output_tokens
            if turn.text:
                final_text = turn.text

            audit.record(case.id, config.name, "model_turn", step=step,
                         text_preview=turn.text[:280], stop=turn.stop,
                         tool_calls=[c.name for c in turn.tool_calls],
                         input_tokens=turn.input_tokens, output_tokens=turn.output_tokens,
                         raw=turn.raw)

            if not turn.tool_calls:
                break

            pending = _execute(turn.tool_calls, permissions, world, run,
                               audit, case.id, config.name, step)

            if turn.stop:
                break
        else:
            run.error = f"step limit reached ({max_steps})"
    except Exception as exc:  # a broken adapter must not silently score as safe
        run.error = f"{type(exc).__name__}: {exc}"
        audit.record(case.id, config.name, "model_turn", step=run.steps, error=run.error)

    run.raw_output = final_text
    scan = scanner.scan(final_text)
    run.final_output = scan.text
    run.output_findings = [{"rule": f.rule, "where": f.where, "action": f.action}
                           for f in scan.findings]
    audit.record(case.id, config.name, "output_scan", enabled=config.output_scanning,
                 findings=run.output_findings, redactions=scan.redactions,
                 output_preview=run.final_output[:280])

    run.effects = list(world.effects)
    run.latency_ms = round((time.perf_counter() - started) * 1000, 3)
    audit.record(case.id, config.name, "case_end", steps=run.steps,
                 latency_ms=run.latency_ms, executed_tools=run.executed_tools,
                 blocked_tools=run.blocked_tools, effects=run.effects, error=run.error)
    return run


def _execute(calls: tuple[ToolCall, ...], permissions: PermissionLayer, world: World,
             run: CaseRun, audit: AuditLog, case_id: str, config_name: str,
             step: int) -> tuple[ToolResult, ...]:
    results: list[ToolResult] = []
    for call in calls:
        audit.record(case_id, config_name, "tool_requested", step=step,
                     tool=call.name, args=call.args)

        decision = permissions.check(call.name, call.args)
        would_be = permissions.evaluate(call.name, call.args)
        audit.record(case_id, config_name, "permission_decision", step=step,
                     tool=call.name, allowed=decision.allowed, rule=decision.rule,
                     detail=decision.detail, enforcing=permissions.enforcing,
                     would_allow_if_enforcing=would_be.allowed, would_be_rule=would_be.rule)

        if not decision.allowed:
            content = f"Blocked by permission layer ({decision.rule}): {decision.detail}"
            results.append(ToolResult(call.call_id, call.name, content, is_error=True))
            run.calls.append(ExecutedCall(call.name, dict(call.args), False,
                                          decision.rule, decision.detail, content, step))
            audit.record(case_id, config_name, "tool_executed", step=step,
                         tool=call.name, executed=False, reason=decision.rule)
            continue

        tool = TOOLS.get(call.name)
        if tool is None:  # unenforced baseline can reach here for an unknown name
            content = f"No tool named {call.name!r}."
            results.append(ToolResult(call.call_id, call.name, content, is_error=True))
            run.calls.append(ExecutedCall(call.name, dict(call.args), False,
                                          "P0_unknown_tool", content, content, step))
            continue

        try:
            content = tool.handler(world, dict(call.args))
            is_error = False
        except Exception as exc:
            content = f"Tool raised {type(exc).__name__}: {exc}"
            is_error = True

        results.append(ToolResult(call.call_id, call.name, content, is_error=is_error))
        run.calls.append(ExecutedCall(call.name, dict(call.args), True,
                                      decision.rule, decision.detail, content, step))
        audit.record(case_id, config_name, "tool_executed", step=step, tool=call.name,
                     executed=True, destructive=tool.destructive,
                     result_preview=content[:200])
    return tuple(results)
