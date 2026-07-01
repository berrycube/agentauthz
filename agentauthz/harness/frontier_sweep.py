"""Frontier cross-model sweep — the SAME fire-rate matrix, but each TARGET is a frontier
model *as driven by its production agent CLI* (Claude Code / Codex) calling AgentAuthZ's
tools over MCP.  The ATTACKER is the deterministic per-scenario script (``attacker_script``),
held perfectly constant, so the only variable is the target — keeping the numbers comparable to
the local matrix in ``docs/cross-model-sweep.md``.

It reuses the EXISTING pieces unchanged: the ``run_attack`` scripted loop, the deterministic
``evaluate`` (via ``run_attack``), and the ``SweepReport`` matrix + its honest error annotation.
Only the TARGET seat differs: a ``CLITargetAgent`` instead of the in-repo ``Agent``.

HONEST RECORDING (error != safe): a deterministic FIRE (the evaluator saw the violation) is
ground truth; else a TARGET CLI transport/exec failure (``agent.errored``) is an ERROR (excluded
from the denominator, never a false 'safe' 0); else a genuine NON-FIRE — the model ran and did
not land the exploit (a refusal on a vulnerable target, or the code-level block on a fixed one).
There is no attacker error class: the scripted attacker cannot error.

DETERMINISM/OFFLINE: ``frontier_sweep`` takes INJECTED ``drivers`` — tests inject fakes (no
subprocess, no network); ``main(--live)`` injects the real ``ClaudeCodeDriver`` / ``CodexDriver``.
The library path NEVER touches the network; only ``main`` does.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from agentauthz.harness.attacker import run_attack
from agentauthz.harness.cli_target import ClaudeCodeDriver, CLITargetAgent, CodexDriver
from agentauthz.harness.loader import load_scenarios
from agentauthz.harness.sweep import _SCRIPTED_ATTACKER, SweepReport

__all__ = ["frontier_sweep", "build_driver", "main"]


def _safe(label: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in label)


def frontier_sweep(
    drivers: list,
    scenarios: Any,
    target: str,
    *,
    repeats: int,
    run_root: str,
) -> SweepReport:
    """Run ``scenarios`` against each CLI ``driver`` ``repeats`` times — the attacker is the
    deterministic per-scenario script (held perfectly constant) so the only variable is the
    target — and aggregate a per-(driver, vulnerability) fire-rate ``SweepReport``.

    ``drivers`` are duck-typed (``.label()`` + ``.run_turn(...)``).
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
                run = run_attack(sc, agent)
                # error != safe: a deterministic FIRE is ground truth; a target CLI
                # transport/exec failure is an ERROR (excluded from the denominator, never a
                # safe 0); else a genuine non-fire (a refusal or the code-level block).
                if run.verdict.fired:
                    fired_counts[sc.id] += 1
                elif agent.errored:
                    error_counts[sc.id] += 1
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
        attacker=_SCRIPTED_ATTACKER,
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
    """CLI: sweep a fire-rate matrix across frontier CLI targets.

    The attacker is the deterministic per-scenario script (no model). Requires ``--live`` (it
    spawns the real CLIs)."""
    parser = argparse.ArgumentParser(
        description="AgentAuthZ frontier cross-model sweep — model X via its production CLI"
    )
    parser.add_argument("--target", required=True, choices=("vulnerable", "fixed"))
    parser.add_argument(
        "--target-clis",
        required=True,
        help="comma-separated CLI driver specs, e.g. 'claude:claude-sonnet-4-6,codex:gpt-5.5'",
    )
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--scenarios", default="agentauthz/scenarios")
    parser.add_argument("--run-root", required=True, help="base dir for per-run state (store/transcript)")
    parser.add_argument("--timeout", type=int, default=300, help="per-CLI-turn timeout (seconds)")
    parser.add_argument("--live", action="store_true", help="spawn real CLIs (required)")
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

    report = frontier_sweep(
        drivers,
        scenarios,
        args.target,
        repeats=args.repeats,
        run_root=args.run_root,
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
