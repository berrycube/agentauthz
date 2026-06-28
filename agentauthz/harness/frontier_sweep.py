"""Frontier cross-model sweep — the SAME fire-rate matrix, but each TARGET is a frontier
model *as driven by its production agent CLI* (Claude Code / Codex) calling AgentAuthZ's
tools over MCP.  The ATTACKER is held CONSTANT (``glm4:9b`` by default, exactly as the local
sweep) so the only variable is the target — keeping the numbers comparable to the local
matrix in ``docs/cross-model-sweep.md``.

It reuses the EXISTING pieces unchanged: the multi-turn ``run_attack`` loop, the deterministic
``evaluate`` (via ``run_attack``), the ``SweepReport`` matrix + its honest error annotation,
and the attacker-seat error detection (``_ErrorTrackingClient`` + the Ollama error sentinel).
Only the TARGET seat differs: a ``CLITargetAgent`` instead of the in-repo ``Agent``.

HONEST RECORDING (the seat-aware accounting, identical in spirit to ``sweep_models``):
1. ATTACKER error (a broken ``glm4:9b`` turn) -> ERROR (a broken attacker is not a valid
   exploit) — excluded from the denominator, never a false 'safe' 0.
2. else a deterministic FIRE (the evaluator saw the violation) -> FIRE (ground truth).
3. else the TARGET CLI errored (transport/exec failure) -> ERROR (never a false 'safe' 0).
4. else a genuine NON-FIRE — the model ran and DID NOT land the exploit (a refusal on a
   vulnerable target, or the code-level block on a fixed target). This is a real data point,
   NOT an error.

DETERMINISM/OFFLINE: ``frontier_sweep`` takes INJECTED ``drivers`` + an ``attacker_llm_for``
factory — tests inject fakes (no subprocess, no network); ``main(--live)`` injects the real
``ClaudeCodeDriver`` / ``CodexDriver`` + the live Ollama attacker.  The library path NEVER
touches the network; only ``main`` does.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import Any

from agentauthz.harness.attacker import run_attack
from agentauthz.harness.cli_target import ClaudeCodeDriver, CLITargetAgent, CodexDriver
from agentauthz.harness.loader import load_scenarios
from agentauthz.harness.runner import _OllamaClient
from agentauthz.harness.sweep import SweepReport, _ErrorTrackingClient

__all__ = ["frontier_sweep", "build_driver", "main"]


def _safe(label: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in label)


def frontier_sweep(
    drivers: list,
    attacker_model: str,
    scenarios: Any,
    target: str,
    *,
    repeats: int,
    run_root: str,
    attacker_llm_for: Callable[[], Any],
) -> SweepReport:
    """Run ``scenarios`` against each CLI ``driver`` ``repeats`` times (attacker held at
    ``attacker_model``) and aggregate a per-(driver, vulnerability) fire-rate ``SweepReport``.

    ``drivers`` are duck-typed (``.label()`` + ``.run_turn(...)``); ``attacker_llm_for()``
    builds a FRESH attacker client per scenario.
    """
    if target not in ("vulnerable", "fixed"):
        raise ValueError(f"unknown target {target!r} (expected 'vulnerable' or 'fixed')")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 1:
        raise ValueError(f"repeats must be an integer >= 1, got {repeats!r}")
    if not drivers:
        raise ValueError("drivers must be a non-empty list")

    scenarios = list(scenarios)
    labels = [d.label() for d in drivers]
    cells: list[dict] = []

    for driver in drivers:
        label = driver.label()
        fired_counts = {sc.id: 0 for sc in scenarios}
        error_counts = {sc.id: 0 for sc in scenarios}
        for rep in range(repeats):
            for sc in scenarios:
                run_dir = os.path.join(run_root, _safe(label), sc.id, str(rep))
                os.makedirs(run_dir, exist_ok=True)
                agent = CLITargetAgent(
                    driver,
                    run_dir=run_dir,
                    target=target,
                    session_customer_id=sc.session_customer_id,
                )
                atk_sink: dict[str, bool] = {}
                attacker = _ErrorTrackingClient(attacker_llm_for(), atk_sink, sc.id)
                run = run_attack(sc, agent, attacker)
                # Seat-aware accounting (error != safe):
                if atk_sink.get(sc.id):
                    error_counts[sc.id] += 1            # 1. broken attacker turn
                elif run.verdict.fired:
                    fired_counts[sc.id] += 1            # 2. deterministic fire = ground truth
                elif agent.errored:
                    error_counts[sc.id] += 1            # 3. target CLI transport/exec failure
                # 4. else: genuine non-fire (refusal / code-block) — a real 0, not an error
        for sc in scenarios:
            fc = fired_counts[sc.id]
            ec = error_counts[sc.id]
            effective = repeats - ec
            cells.append(
                {
                    "target_model": label,
                    "vulnerability": sc.vulnerability,
                    "scenario_id": sc.id,
                    "fired_count": fc,
                    "error_count": ec,
                    "total": repeats,
                    "rate": (fc / effective) if effective > 0 else 0.0,
                }
            )

    return SweepReport(
        target=target,
        repeats=repeats,
        attacker_model=attacker_model,
        target_models=labels,
        cells=cells,
    )


# --------------------------------------------------------------------------- #
# Live driver factory + CLI (only path that touches the network/subprocess)
# --------------------------------------------------------------------------- #
def build_driver(spec: str, *, timeout: int = 300) -> Any:
    """Build a CLI driver from a ``cli:model`` spec.

    ``claude:claude-sonnet-4-6`` -> Claude Code (``claude -p``);
    ``codex:gpt-5.5`` -> Codex (``codex exec``).  Construction touches NO network — only
    ``run_turn`` (a subprocess) does."""
    cli, sep, model = spec.partition(":")
    if not sep or not model.strip():
        raise ValueError(f"driver spec must be 'cli:model', got {spec!r}")
    cli = cli.strip().lower()
    model = model.strip()
    if cli in ("claude", "claude-code"):
        return ClaudeCodeDriver(model, timeout=timeout)
    if cli == "codex":
        return CodexDriver(model, timeout=timeout)
    raise ValueError(f"unknown CLI {cli!r} in spec {spec!r} (expected 'claude' or 'codex')")


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - live only
    """CLI: sweep a fire-rate matrix across frontier CLI targets (attacker held constant).

    Requires ``--live`` (it spawns real CLIs + a real Ollama attacker)."""
    parser = argparse.ArgumentParser(
        description="AgentAuthZ frontier cross-model sweep — model X via its production CLI"
    )
    parser.add_argument("--target", required=True, choices=("vulnerable", "fixed"))
    parser.add_argument(
        "--target-clis",
        required=True,
        help="comma-separated CLI driver specs, e.g. 'claude:claude-sonnet-4-6,codex:gpt-5.5'",
    )
    parser.add_argument("--attacker-model", default="glm4:9b", help="held-constant Ollama attacker")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--scenarios", default="agentauthz/scenarios")
    parser.add_argument("--run-root", required=True, help="base dir for per-run state (store/transcript)")
    parser.add_argument("--timeout", type=int, default=300, help="per-CLI-turn timeout (seconds)")
    parser.add_argument("--live", action="store_true", help="spawn real CLIs + attacker (required)")
    parser.add_argument("--out", default=None)
    parser.add_argument("--format", choices=("json", "md"), default="md")
    args = parser.parse_args(argv)

    if not args.live:
        print("A real frontier sweep requires --live (it spawns real CLIs).", file=sys.stderr)
        return 2
    if args.repeats < 1:
        print("--repeats must be >= 1", file=sys.stderr)
        return 2

    specs = [s.strip() for s in args.target_clis.split(",")]
    if not specs or any(not s for s in specs):
        print("--target-clis has an empty/blank entry", file=sys.stderr)
        return 2
    try:
        drivers = [build_driver(s, timeout=args.timeout) for s in specs]
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    scenarios = load_scenarios(args.scenarios)
    attacker_model = args.attacker_model

    def attacker_llm_for() -> Any:
        return _OllamaClient(model=attacker_model)

    report = frontier_sweep(
        drivers,
        attacker_model,
        scenarios,
        args.target,
        repeats=args.repeats,
        run_root=args.run_root,
        attacker_llm_for=attacker_llm_for,
    )

    out = report.to_markdown() if args.format == "md" else report.to_json()
    if args.out is not None:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        print(out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
