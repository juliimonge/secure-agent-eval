"""Provider adapters.

Everything above this package is provider-agnostic. To plug in a new model you
implement one class with one method — see `base.ModelAdapter`.
"""

from __future__ import annotations

from .base import AgentTurn, ModelAdapter, ToolCall, TurnRequest
from .mock import MockAdapter

_REGISTRY: dict[str, str] = {
    "mock": "secure_agent_eval.adapters.mock:MockAdapter",
    "anthropic": "secure_agent_eval.adapters.anthropic_adapter:AnthropicAdapter",
}


def available() -> list[str]:
    return sorted(_REGISTRY)


def get_adapter(name: str, **kwargs) -> ModelAdapter:
    """Resolve an adapter by name. Live adapters are imported lazily so the
    offline suite never needs their SDKs installed."""
    if name not in _REGISTRY:
        raise KeyError(f"unknown adapter {name!r}; available: {available()}")
    module_path, class_name = _REGISTRY[name].split(":")
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, class_name)(**kwargs)


__all__ = [
    "AgentTurn",
    "ModelAdapter",
    "MockAdapter",
    "ToolCall",
    "TurnRequest",
    "available",
    "get_adapter",
]
