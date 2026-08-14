"""Live adapter for the Anthropic Messages API.

Optional. The offline suite never imports this module, so `anthropic` does not
need to be installed to run the tests or the default report.

    pip install anthropic
    export ANTHROPIC_API_KEY=...
    python -m secure_agent_eval.run --adapter anthropic --model claude-opus-5

Written as a reference implementation of `ModelAdapter`: about sixty lines of
translation between the harness's `TurnRequest`/`AgentTurn` and one provider's
wire format. Porting to another provider means writing the equivalent.
"""

from __future__ import annotations

import os
from typing import Any

from .base import AgentTurn, ModelAdapter, ToolCall, TurnRequest

DEFAULT_MODEL = "claude-opus-5"


class AnthropicAdapter(ModelAdapter):
    name = "anthropic"
    is_live = True

    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 2048,
                 effort: str = "medium", api_key: str | None = None) -> None:
        try:
            import anthropic  # noqa: PLC0415 - optional dependency
        except ImportError as exc:  # pragma: no cover - depends on env
            raise RuntimeError(
                "The anthropic adapter needs the `anthropic` package: pip install anthropic"
            ) from exc

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        # A bare client also resolves an `ant auth login` profile, so an unset
        # env var is not necessarily an error — let the SDK decide.
        self._client = anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort

    def describe(self) -> dict[str, Any]:
        return {"adapter": self.name, "is_live": True, "model": self.model,
                "effort": self.effort, "deterministic": False}

    def step(self, request: TurnRequest) -> AgentTurn:
        tools = [
            {"name": spec["name"], "description": spec["description"],
             "input_schema": spec["parameters"]}
            for spec in request.tool_specs
        ]

        blocks: list[dict[str, Any]] = []
        if request.context:
            blocks.append({
                "type": "text",
                "text": ("<untrusted_context source=\"retrieved\">\n"
                         f"{request.context}\n</untrusted_context>"),
            })
        blocks.append({"type": "text", "text": request.user_input})

        messages: list[dict[str, Any]] = [{"role": "user", "content": blocks}]
        if request.policy_notices:
            # Operator-authority channel: a system message after the user turn,
            # rather than text the user could spoof.
            messages.append({"role": "system", "content": "\n".join(request.policy_notices)})
        if request.tool_results:
            messages.append({
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": r.call_id,
                     "content": r.content, "is_error": r.is_error}
                    for r in request.tool_results
                ],
            })

        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=request.system_prompt,
            tools=tools,
            output_config={"effort": self.effort},
            messages=messages,
        )

        if response.stop_reason == "refusal":
            return AgentTurn(
                text="[provider refusal]", stop=True,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                raw={"stop_reason": "refusal"},
            )

        text = "".join(b.text for b in response.content if b.type == "text")
        calls = tuple(
            ToolCall(name=b.name, args=dict(b.input), call_id=b.id)
            for b in response.content if b.type == "tool_use"
        )
        return AgentTurn(
            text=text,
            tool_calls=calls,
            stop=response.stop_reason != "tool_use",
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            raw={"stop_reason": response.stop_reason, "model": response.model},
        )
