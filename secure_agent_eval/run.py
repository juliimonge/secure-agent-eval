"""CLI entry point.

    python -m secure_agent_eval.run                      # offline, both configs
    python -m secure_agent_eval.run --mock-profile cautious
    python -m secure_agent_eval.run --adapter anthropic --model claude-opus-5

The default run needs no API key, no network and no money.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters import available, get_adapter
from .audit import AuditLog
from .grader import attempted, grade
from .guardrails import CONFIGS
from .harness import MAX_STEPS, run_case
from .report import Outcome, new_report
from .schema import CATEGORIES, DEFAULT_CASE_FILE, LANGUAGES, load_suite

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "results"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secure-agent-eval",
        description="Evaluate LLM agent behaviour under adversarial conditions, EN/ES.",
    )
    p.add_argument("--cases", type=Path, default=DEFAULT_CASE_FILE,
                   help=f"case file (default: {DEFAULT_CASE_FILE.name})")
    p.add_argument("--adapter", default="mock", choices=available(),
                   help="model adapter (default: mock — offline, free, deterministic)")
    p.add_argument("--model", default=None, help="model id, for live adapters")
    p.add_argument("--mock-profile", default="compliant", choices=("compliant", "cautious"),
                   help="mock agent susceptibility profile (default: compliant)")
    p.add_argument("--config", action="append", choices=sorted(CONFIGS),
                   help="configuration(s) to run; repeatable (default: baseline and guarded)")
    p.add_argument("--category", action="append", choices=CATEGORIES,
                   help="restrict to categories; repeatable")
    p.add_argument("--language", action="append", choices=LANGUAGES,
                   help="restrict to languages; repeatable")
    p.add_argument("--max-steps", type=int, default=MAX_STEPS,
                   help=f"tool-loop step limit per case (default: {MAX_STEPS})")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT,
                   help=f"output directory (default: {DEFAULT_OUT.name}/)")
    p.add_argument("--run-id", default=None,
                   help="fixed run id, for reproducible artifact filenames")
    p.add_argument("--quiet", action="store_true", help="suppress the console summary")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    suite = load_suite(args.cases)
    cases = [
        c for c in suite.cases
        if (not args.category or c.category in args.category)
        and (not args.language or c.language in args.language)
    ]
    if not cases:
        print("No cases matched the given filters.", file=sys.stderr)
        return 2

    adapter_kwargs = {}
    if args.adapter == "mock":
        adapter_kwargs["profile"] = args.mock_profile
    elif args.model:
        adapter_kwargs["model"] = args.model
    adapter = get_adapter(args.adapter, **adapter_kwargs)
    adapter.prepare(suite)

    config_names = args.config or ["baseline", "guarded"]
    audit = AuditLog(run_id=args.run_id)
    report = new_report(suite, adapter.describe(), config_names, audit.run_id)

    audit.record("-", "-", "run_start", adapter=adapter.describe(),
                 configs=config_names, n_cases=len(cases),
                 suite=f"{suite.suite_id}@{suite.suite_version}", max_steps=args.max_steps)

    for config_name in config_names:
        config = CONFIGS[config_name]
        for case in cases:
            run = run_case(case, config, adapter, audit, max_steps=args.max_steps)
            verdict = grade(case, run)
            outcome = Outcome.build(run, verdict, attempted(case, run))
            report.outcomes.append(outcome)
            audit.record(case.id, config_name, "grade", verdict=verdict.verdict.value,
                         rule=verdict.rule, reason=verdict.reason, attempted=outcome.attempted)

    audit.record("-", "-", "run_end", outcomes=len(report.outcomes), events=len(audit))

    out = Path(args.out)
    json_path = report.write_json(out / f"{audit.run_id}.json")
    md_path = report.write_markdown(out / f"{audit.run_id}.md")
    log_path = audit.write_jsonl(out / f"{audit.run_id}.audit.jsonl")

    if not args.quiet:
        _print_summary(report, config_names)
        print(f"\nresults : {json_path}")
        print(f"report  : {md_path}")
        print(f"audit   : {log_path}  ({len(audit)} events)")
    return 0


def _print_summary(report, config_names: list[str]) -> None:
    print(f"\nsecure-agent-eval — {report.suite_id} v{report.suite_version} "
          f"| adapter: {report.adapter.get('adapter')}"
          f"{' (' + report.adapter['profile'] + ')' if 'profile' in report.adapter else ''}")
    width = max(len(c) for c in config_names)
    for config in config_names:
        s = report.stats(config)
        en = report.stats(config, language="en")
        es = report.stats(config, language="es")
        print(f"  {config:<{width}}  unsafe {s.unsafe:>3}/{s.n:<3} "
              f"({s.unsafe_rate * 100:5.1f}%)   attempts {s.attempts:>3}/{s.n:<3}"
              f"   |  EN {en.unsafe}/{en.n}  ES {es.unsafe}/{es.n}")


if __name__ == "__main__":
    raise SystemExit(main())
