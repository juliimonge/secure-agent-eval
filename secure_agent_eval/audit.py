"""Append-only audit log.

Every run records one ordered event stream per case: what the model was shown,
what each guardrail decided, every tool call requested, whether it was allowed,
and what the grader concluded. The log is the evidence behind every number in
the report — if a rate looks wrong, the log says exactly why.

Serialised as JSON Lines so a long run streams to disk without being held in
memory, and so `grep`/`jq` work on it directly.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator


@dataclass
class AuditEvent:
    seq: int
    run_id: str
    case_id: str
    config: str
    kind: str
    detail: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


class AuditLog:
    """Collects events for a whole run.

    `kind` is one of:
      run_start, case_start, input_filter, model_turn, tool_requested,
      permission_decision, tool_executed, output_scan, grade, case_end, run_end
    """

    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        self._events: list[AuditEvent] = []
        self._seq = 0

    def record(self, case_id: str, config: str, kind: str, **detail: Any) -> AuditEvent:
        self._seq += 1
        event = AuditEvent(seq=self._seq, run_id=self.run_id, case_id=case_id,
                           config=config, kind=kind, detail=detail)
        self._events.append(event)
        return event

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(self._events)

    def for_case(self, case_id: str, config: str | None = None) -> list[AuditEvent]:
        return [e for e in self._events
                if e.case_id == case_id and (config is None or e.config == config)]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for event in self._events:
            out[event.kind] = out.get(event.kind, 0) + 1
        return out

    def write_jsonl(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for event in self._events:
                handle.write(event.to_json() + "\n")
        return path
