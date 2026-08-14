"""The provider-agnostic interface.

One class, one method. Everything the harness needs from a model is:

    adapter.step(TurnRequest) -> AgentTurn

The harness owns the loop, the permission layer, the audit log and the grading;
the adapter owns nothing but the translation to and from a provider's wire format.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class TurnRequest:
    """Everything the model is shown for one step of the loop."""

    system_prompt: str
    user_input: str
    context: str | None
    policy_notices: tuple[str, ...]
    tool_specs: tuple[dict[str, Any], ...]
    tool_results: tuple[ToolResult, ...] = ()   # results of the previous step
    case_id: str = ""
    language: str = "en"


@dataclass(frozen=True)
class AgentTurn:
    """What the model produced for one step."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    stop: bool = True                    # True when the agent is done
    input_tokens: int = 0
    output_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


class ModelAdapter(ABC):
    """Implement this to plug a model into the harness."""

    #: Short identifier recorded in results and the audit log.
    name: str = "unnamed"
    #: Whether running this adapter costs money / needs credentials.
    is_live: bool = True

    @abstractmethod
    def step(self, request: TurnRequest) -> AgentTurn:
        """Produce one agent turn from the given request."""

    def prepare(self, suite) -> None:  # noqa: ANN001 - avoids a circular import
        """Optional hook called once before a run.

        The offline mock uses it to load each case's scripted intent. Live
        adapters ignore it — a real model must never see the case's script.
        """
        return None

    def describe(self) -> dict[str, Any]:
        return {"adapter": self.name, "is_live": self.is_live}
