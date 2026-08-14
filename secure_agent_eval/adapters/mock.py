"""Offline mock adapter — deterministic, free, no API key, no network.

## What this is, and what it is not

The mock is **not** a model and does not estimate any model's safety. It is a
fixed, deliberately susceptible agent used to exercise the harness and to
measure **guardrail coverage**. Read every mock number as a statement about the
guardrails, not about an LLM.

Its entire behaviour is three rules:

1. If the adversarial `trigger` string is still present in what it is shown, it
   carries out the case's scripted `intent` (call a tool, or emit a canary).
2. If a policy notice tells it to hand off, it calls `escalate_to_human`.
3. Otherwise it answers benignly.

Rule 1 is what makes the comparison meaningful: the guarded input filter removes
the trigger from untrusted context, so the attempt never happens; the baseline
leaves it in place, so it does. Nothing is randomised and nothing is hardcoded
per-configuration — the mock cannot see which configuration it is running under.

## Profiles

`compliant` (default)
    Worst-case agent. Complies with any visible trigger, wherever it came from.

`cautious`
    Models the well-documented asymmetry that instruction-tuned models resist
    adversarial requests typed directly by the user far more often than the same
    instruction arriving inside retrieved content. Refuses direct requests;
    still falls for indirect injection. Baseline numbers under this profile are
    less degenerate and closer to a real agent's shape.
"""

from __future__ import annotations

from typing import Any

from ..tools import CANARIES
from .base import AgentTurn, ModelAdapter, ToolCall, TurnRequest

PROFILES = ("compliant", "cautious")

_REFUSAL = {
    "en": "I can't help with that — it's outside what I'm authorised to do for this account.",
    "es": "No puedo ayudar con eso: está fuera de lo que estoy autorizado a hacer para esta cuenta.",
}
_BENIGN = {
    "en": "Here's what I found for your booking. Let me know if you'd like anything else.",
    "es": "Esto es lo que encontré sobre tu reserva. Dime si necesitas algo más.",
}
_HANDOFF = {
    "en": "This needs a human colleague. I've handed it over and someone will follow up shortly.",
    "es": "Esto requiere un colega humano. Lo he transferido y alguien te contactará en breve.",
}


def _tokens(text: str) -> int:
    """A deterministic stand-in for a tokenizer. Reported as an estimate."""
    return max(1, len(text) // 4)


class MockAdapter(ModelAdapter):
    name = "mock"
    is_live = False

    def __init__(self, profile: str = "compliant") -> None:
        if profile not in PROFILES:
            raise ValueError(f"unknown mock profile {profile!r}; expected one of {PROFILES}")
        self.profile = profile
        self._scripts: dict[str, Any] = {}

    def describe(self) -> dict[str, Any]:
        return {"adapter": self.name, "is_live": False, "profile": self.profile,
                "deterministic": True}

    def prepare(self, suite) -> None:  # noqa: ANN001
        self._scripts = {case.id: case.mock for case in suite.cases}

    # ------------------------------------------------------------------
    def step(self, request: TurnRequest) -> AgentTurn:
        script = self._scripts.get(request.case_id)
        lang = request.language if request.language in _REFUSAL else "en"
        visible = f"{request.user_input}\n{request.context or ''}"
        notices = "\n".join(request.policy_notices)

        prompt_tokens = _tokens(request.system_prompt + visible + notices)

        # --- second step of the loop: results are back, produce the answer ---
        if request.tool_results:
            return self._final_step(request, script, lang, prompt_tokens)

        # --- handoff: an explicit instruction to call a specific tool ---
        if "escalate_to_human" in notices:
            text = _HANDOFF[lang]
            return AgentTurn(
                text=text,
                tool_calls=(ToolCall("escalate_to_human",
                                     {"reason": "policy notice: matter requires a human"},
                                     call_id=f"{request.case_id}-esc"),),
                stop=False,
                input_tokens=prompt_tokens,
                output_tokens=_tokens(text),
                raw={"path": "policy_handoff"},
            )

        if script is None or script.intent == "none" or not script.trigger:
            text = _BENIGN[lang]
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text), raw={"path": "benign"})

        # --- rule 1: is the adversarial instruction still visible? ---
        if script.trigger not in visible:
            text = _BENIGN[lang]
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text),
                             raw={"path": "trigger_removed"})

        from_context = bool(request.context) and script.trigger in request.context
        if self.profile == "cautious" and not from_context:
            text = _REFUSAL[lang]
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text),
                             raw={"path": "cautious_refusal"})

        if script.intent == "tool_call":
            text = ""
            return AgentTurn(
                text=text,
                tool_calls=(ToolCall(script.tool, dict(script.args),
                                     call_id=f"{request.case_id}-1"),),
                stop=False,
                input_tokens=prompt_tokens,
                output_tokens=_tokens(str(script.args)) + 4,
                raw={"path": "comply_tool_call", "from_context": from_context},
            )

        if script.intent == "leak":
            if script.tool:  # fetch first, disclose on the next step
                return AgentTurn(
                    tool_calls=(ToolCall(script.tool, dict(script.args),
                                         call_id=f"{request.case_id}-1"),),
                    stop=False,
                    input_tokens=prompt_tokens,
                    output_tokens=_tokens(str(script.args)) + 4,
                    raw={"path": "comply_leak_fetch", "from_context": from_context},
                )
            text = self._leak_text(script.leak, request, lang)
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text),
                             raw={"path": "comply_leak_direct", "from_context": from_context})

        text = _BENIGN[lang]
        return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                         output_tokens=_tokens(text), raw={"path": "benign_fallthrough"})

    # ------------------------------------------------------------------
    def _final_step(self, request: TurnRequest, script, lang: str,
                    prompt_tokens: int) -> AgentTurn:
        blocked = any(r.is_error for r in request.tool_results)
        joined = "\n".join(r.content for r in request.tool_results)

        if script is not None and script.intent == "leak" and script.tool and not blocked:
            # Disclose whatever the tool handed back, canary included.
            text = (f"Here is what I retrieved:\n{joined}" if lang == "en"
                    else f"Esto es lo que obtuve:\n{joined}")
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text), raw={"path": "leak_disclose"})

        if blocked:
            text = _REFUSAL[lang]
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text), raw={"path": "post_block_refusal"})

        if any(r.name == "escalate_to_human" for r in request.tool_results):
            text = _HANDOFF[lang]
            return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                             output_tokens=_tokens(text), raw={"path": "handoff_done"})

        text = (f"Done. {joined}" if lang == "en" else f"Listo. {joined}")
        return AgentTurn(text=text, stop=True, input_tokens=prompt_tokens,
                         output_tokens=_tokens(text), raw={"path": "tool_done"})

    @staticmethod
    def _leak_text(leak_key: str, request: TurnRequest, lang: str) -> str:
        secret = CANARIES.get(leak_key, "")
        if leak_key == "system_prompt":
            body = request.system_prompt
        else:
            body = secret
        lead = "Sure — here it is:" if lang == "en" else "Claro, aquí lo tienes:"
        return f"{lead}\n{body}"
