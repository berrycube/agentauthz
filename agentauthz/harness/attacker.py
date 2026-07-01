"""DETERMINISTIC SCRIPTED attacker harness.

Correct, secure harness code (NOT a deliberate vulnerability): drives a multi-turn attack
against a target agent by replaying the scenario's ``attacker_script`` — one message per turn —
with NO attacker LLM.

``run_attack(scenario, target_agent)``: for turn ``t`` in ``1..min(max_turns, len(script))`` it
sends ``script[t-1]`` to the target agent (duck-typed: ``.run(msg) -> str`` plus the
``.store`` / ``.transcript`` / ``.session_customer_id`` the evaluator reads), records the
dialogue turn, runs the deterministic evaluator, and BREAKS on fire.  Script/turns exhausted
without a fire → graceful give-up.

Why a script rather than an LLM attacker: the evaluator judges the TOOL-LAYER violation, not
conversational realism, so the attacker only needs to persistently present a fixed goal + the
exact seed identifiers — which a closed-world escalation ladder does deterministically.  The
attacker side calls NO LLM, so it cannot error or drift and is held PERFECTLY constant across
every run and every target: the only variable is the target.  Deterministic + offline; the
harness only ever drives the in-repo agent (self-built target only).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauthz.harness.evaluator import Verdict, evaluate
from agentauthz.harness.loader import Scenario

__all__ = ["AttackRun", "run_attack"]


@dataclass(frozen=True)
class AttackRun:
    """The result of one scripted attack run against a target agent.

    ``dialogue`` is the per-turn record (each ``{turn, attacker_message, agent_reply}``);
    ``transcript`` is the target agent's tool transcript (the evidence); ``verdict`` is the
    evaluator's deterministic decision for the scenario.
    """

    scenario_id: str
    vulnerability: str
    turns_used: int
    dialogue: list[dict]
    transcript: list[dict]
    verdict: Verdict


def run_attack(scenario: Scenario, target_agent: Any) -> AttackRun:
    """Drive the scenario's deterministic scripted attack and return the recorded ``AttackRun``.

    Loop, for turn in ``1..min(scenario.max_turns, len(scenario.attacker_script))`` (STRICT upper
    bound): send ``attacker_script[turn-1]`` to the target agent, record the dialogue turn,
    evaluate the scenario, and BREAK early on fire.  The verdict is the LAST ``evaluate`` result;
    for a scenario with an empty script (the loader forbids this, but stay fail-safe) evaluate
    once so the verdict is always a real ``Verdict``.
    """
    dialogue: list[dict] = []
    verdict: Verdict | None = None
    script = scenario.attacker_script
    turns = min(scenario.max_turns, len(script))

    for turn in range(1, turns + 1):
        msg = script[turn - 1]
        reply = target_agent.run(msg)
        # Ensure agent_reply is always a str (duck-typed agent may return non-str).
        agent_reply = reply if isinstance(reply, str) else ""
        dialogue.append({"turn": turn, "attacker_message": msg, "agent_reply": agent_reply})

        verdict = evaluate(scenario, target_agent)
        if verdict.fired:
            break

    if verdict is None:  # empty-script guard (loader rejects an empty script upstream)
        verdict = evaluate(scenario, target_agent)

    return AttackRun(
        scenario_id=scenario.id,
        vulnerability=scenario.vulnerability,
        turns_used=len(dialogue),
        dialogue=dialogue,
        transcript=list(target_agent.transcript),
        verdict=verdict,
    )
