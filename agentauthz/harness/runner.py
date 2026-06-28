"""Benchmark RUNNER (``--target vulnerable|fixed``) + CLI.

Correct, secure harness code (NOT a deliberate vulnerability): ties the v1 harness
together.  ``run_benchmark`` loads nothing itself — it takes already-loaded scenarios
plus per-seat LLM factories, and for each scenario builds the target agent
(the deliberately-vulnerable ``Agent`` OR the remediated ``FixedAgent``, selected by
``target``), drives the multi-turn attacker, reads the deterministic evaluator
``Verdict`` off each ``AttackRun``, and aggregates everything into a structured
``Report`` (``report.py``).

``--target vulnerable`` must auto-discover all three planted vulnerabilities with
transcript evidence; ``--target fixed`` must yield zero findings.  Determinism + offline
come from INJECTING the per-seat LLM factories:
tests inject scripted ``FakeLLM`` seats; the CLI ``main`` wires real Ollama clients
ONLY under ``--live`` (never in the test suite).  The runner only ever drives the
in-repo agent.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from typing import Any

from agentauthz.agent import Agent
from agentauthz.config import get_model
from agentauthz.fixed.agent_fixed import FixedAgent
from agentauthz.harness.attacker import run_attack
from agentauthz.harness.loader import load_scenarios
from agentauthz.harness.report import Report
from agentauthz.store import seed_store

__all__ = ["run_benchmark", "main"]


# ---------------------------------------------------------------------------
# Graceful-exhaustion wrapper for injected LLM clients
# ---------------------------------------------------------------------------


class _ExhaustionSafeLLM:
    """Thin wrapper that turns a script-exhausted ``FakeLLM`` into a graceful
    empty response, WITHOUT swallowing any other failure.

    This lets the attacker loop in ``run_attack`` treat script exhaustion as a
    graceful give-up (``content=None`` → ``not isinstance(msg, str)`` → ``break``)
    rather than crashing.  The ``FakeLLM`` design raises ``AssertionError`` on
    exhaustion to catch bugs in the AGENT loop (too many turns requested); here
    the ATTACKER seat may have fewer scripted turns than ``scenario.max_turns`` —
    for the fixed target where no scenario fires, the attacker can only contribute
    one message before the script is spent.

    REPORT-FIDELITY: we MUST NOT catch a bare ``AssertionError`` — that would also
    swallow the attacker LLM's own internal assertions, the test's offline/network
    guard, and any message-shape validation, masking a real harness/invariant
    failure as a benign "attack not triggered" (a silent ``fired=False``).  So
    instead of catching exhaustion AFTER the fact, we DETECT it BEFORE delegating:
    a ``FakeLLM`` exposes the scripted turns it has left (``_responses``/``_index``),
    so we can recognise "no turns remain" precisely and return the give-up sentinel
    only for that exact condition.  Every real call is delegated verbatim and any
    exception it raises propagates untouched.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def complete(self, messages: Any, tools: Any) -> Any:
        if self._is_exhausted_fake():
            # The scripted fake has no turns left: signal give-up to run_attack
            # WITHOUT letting (or relying on) any exception be swallowed.
            return LLMResponse([], None)
        return self._inner.complete(messages, tools)

    def _is_exhausted_fake(self) -> bool:
        """True iff ``inner`` is a scripted fake (duck-typed: integer ``_index`` +
        sized ``_responses``) whose script is spent.  Anything that does not expose
        BOTH a script cursor and a sized script (e.g. the real ``_OllamaClient``, or
        any non-fake client) is never treated as exhausted — its ``complete`` is
        always called and its errors always surface."""
        index = getattr(self._inner, "_index", None)
        responses = getattr(self._inner, "_responses", None)
        if not isinstance(index, int) or isinstance(index, bool):
            return False
        try:
            remaining = len(responses)
        except TypeError:
            return False
        return index >= remaining


# ---------------------------------------------------------------------------
# Fail-closed Ollama client (used ONLY by main() under --live; never in tests)
# ---------------------------------------------------------------------------
# The client connects to a local Ollama server via HTTP POST to
# /api/chat (native tool-calling format).  Any HTTP or parse error returns a
# final LLMResponse([], '[ollama-client error]') so the agent loop ends
# fail-closed — it NEVER raises.

from agentauthz.agent import LLMResponse, ToolCall  # noqa: E402


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    """Wrap AgentAuthZ's flat ``{name, description, parameters}`` tool schemas into the nested
    ``{"type":"function","function":{...}}`` form that Ollama's /api/chat AND OpenAI-
    compatible APIs (DeepSeek, ...) require.

    This wrapping is REQUIRED, not cosmetic: sending the FLAT form to Ollama yields
    ``tool_calls`` with an EMPTY ``name`` (the arguments survive but the name is lost), so
    the agent dispatches a nameless tool that the toolbox rejects — the attack silently
    no-ops and the run reports a false ``fired=False``.  Already-nested entries pass
    through; an entry without a string ``name`` is dropped (fail-closed)."""
    out: list[dict] = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        if t.get("type") == "function" and isinstance(t.get("function"), dict):
            out.append(t)
            continue
        name = t.get("name")
        if not isinstance(name, str):
            continue
        out.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
        )
    return out


class _OllamaClient:
    """Fail-closed HTTP client for a local Ollama server (/api/chat).

    Constructs one ``LLMResponse`` per call from the Ollama native response
    format.  On ANY error (connection refused, timeout, JSON parse error, missing
    field) returns ``LLMResponse([], '[ollama-client error]')`` so the caller
    (the agent loop) always gets a well-typed response and terminates cleanly.
    """

    def __init__(self, model: str, base_url: str = "http://localhost:11434") -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")

    def complete(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        """POST to /api/chat and parse the response; fail-closed on any error."""
        import http.client
        import urllib.parse

        _FALLBACK = LLMResponse([], "[ollama-client error]")
        try:
            payload = json.dumps(
                {
                    "model": self._model,
                    "messages": messages,
                    "tools": _to_openai_tools(tools),
                    "stream": False,
                },
                default=str,
            ).encode("utf-8")
            parsed = urllib.parse.urlparse(self._base_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 11434
            conn = http.client.HTTPConnection(host, port, timeout=60)
            try:
                conn.request(
                    "POST",
                    "/api/chat",
                    body=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp = conn.getresponse()
                # Fail-closed on a non-2xx status BEFORE consuming the body: a
                # degraded server/proxy can return parseable, chat-shaped JSON on a
                # 4xx/5xx error; without this check that error page would be used as
                # a valid LLMResponse and produce a misleading report.  (close runs
                # in `finally` so the error path never leaks the socket.)
                if not (200 <= resp.status < 300):
                    return _FALLBACK
                raw = resp.read().decode("utf-8")
            finally:
                conn.close()
        except Exception:  # noqa: BLE001
            return _FALLBACK

        try:
            data = json.loads(raw)
        except Exception:  # noqa: BLE001
            return _FALLBACK

        try:
            msg = data.get("message") or {}
            if not isinstance(msg, dict):
                return _FALLBACK
            content: str | None = msg.get("content") or None
            # Parse tool_calls from the Ollama native format
            raw_calls = msg.get("tool_calls") or []
            tool_calls: list[ToolCall] = []
            if isinstance(raw_calls, list):
                for tc in raw_calls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or {}
                    if not isinstance(fn, dict):
                        continue
                    name = fn.get("name")
                    # Read arguments RAW: do NOT coerce a malformed/falsey value with
                    # `or {}` (that masks a bad payload as an empty-args call). Require an
                    # actual dict and DROP the call otherwise. A blank name (Ollama emits ""
                    # for a mis-shaped schema) is never a real tool — drop it too, so it
                    # cannot become a ToolCall("") that silently no-ops the whole attack.
                    args_raw = fn.get("arguments")
                    if (
                        not isinstance(name, str)
                        or not name.strip()
                        or not isinstance(args_raw, dict)
                    ):
                        continue
                    tool_calls.append(ToolCall(name, args_raw))
            # A well-formed 200 that yields NOTHING usable (no tool call AND no nonblank
            # text) — e.g. `{}` or `{"message":{"content":null,"tool_calls":[]}}` from a
            # degraded server/proxy — is a failure, NOT a model refusal: return the error
            # sentinel so a sweep counts it as an error, not a false 'safe' non-fire.
            if not tool_calls and not (isinstance(content, str) and content.strip()):
                return _FALLBACK
            return LLMResponse(tool_calls, content)
        except Exception:  # noqa: BLE001
            return _FALLBACK


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_benchmark(
    scenarios: Any,
    target: str,
    *,
    target_llm_for: Callable[[Any], Any],
    attacker_llm_for: Callable[[Any], Any],
) -> Report:
    """Run all ``scenarios`` against ``target`` and return a structured ``Report``.

    ``target`` must be ``'vulnerable'`` or ``'fixed'`` — any other value raises
    ``ValueError`` (fail-closed; unknown target must not silently produce an empty run).

    For each scenario:
    - ``seed_store()`` builds a FRESH independent store (mutation isolation).
    - ``target_llm_for(sc)`` builds a FRESH target-seat LLM (stateful fakes must
      reset between scenarios).
    - ``attacker_llm_for(sc)`` builds a FRESH attacker-seat LLM.
    - The target agent (``Agent`` or ``FixedAgent``) is constructed over the store.
    - ``run_attack`` drives the multi-turn loop and returns an ``AttackRun``.
    - The ``AttackRun``'s ``verdict`` is recorded; fired scenarios append a ``finding``
      (with transcript + evidence) and increment the ``by_vulnerability`` counter.
    """
    # Fail-closed: unknown target is a hard error, not a silent empty run.
    if target not in ("vulnerable", "fixed"):
        raise ValueError(f"unknown target {target!r}")

    results: list[dict] = []
    findings: list[dict] = []
    by_vulnerability: dict[str, int] = {}

    for sc in scenarios:
        # Fresh store per scenario — prevents cross-scenario state leakage.
        store = seed_store()
        llm = target_llm_for(sc)
        attacker_llm = attacker_llm_for(sc)

        if target == "vulnerable":
            agent = Agent(llm, store, sc.session_customer_id)
        else:
            agent = FixedAgent(llm, store, sc.session_customer_id)

        # Wrap attacker LLM so script exhaustion is a graceful give-up, not a crash.
        safe_attacker_llm = _ExhaustionSafeLLM(attacker_llm)
        run = run_attack(sc, agent, safe_attacker_llm)
        v = run.verdict

        results.append(
            {
                "scenario_id": sc.id,
                "vulnerability": sc.vulnerability,
                "fired": v.fired,
                "turns_used": run.turns_used,
                "detail": v.detail,
            }
        )

        if v.fired:
            findings.append(
                {
                    "scenario_id": sc.id,
                    "vulnerability": sc.vulnerability,
                    "evidence": v.evidence,
                    "transcript": run.transcript,
                    "dialogue": run.dialogue,
                    "detail": v.detail,
                }
            )
            by_vulnerability[sc.vulnerability] = (
                by_vulnerability.get(sc.vulnerability, 0) + 1
            )

    summary = {
        "total": len(scenarios) if not hasattr(scenarios, "__len__") else len(scenarios),
        "fired_count": len(findings),
        "by_vulnerability": by_vulnerability,
    }

    return Report(target=target, results=results, findings=findings, summary=summary)


def main(argv: list[str] | None = None) -> int:
    """Parse CLI args, load scenarios, and run the benchmark.

    Requires ``--live`` to contact the real Ollama server — WITHOUT ``--live`` the
    CLI prints a refusal to stderr and returns 2 (fail-closed; no network access).
    Tests use ``run_benchmark()`` directly with injected fakes.
    """
    parser = argparse.ArgumentParser(
        description="AgentAuthZ benchmark runner — evaluate vulnerable vs fixed agent"
    )
    parser.add_argument(
        "--target",
        required=True,
        choices=("vulnerable", "fixed"),
        help="Which agent variant to benchmark.",
    )
    parser.add_argument(
        "--scenarios",
        default="agentauthz/scenarios",
        help="Directory containing scenario YAML files (default: agentauthz/scenarios).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Contact the real Ollama server. Without this flag the runner refuses.",
    )
    parser.add_argument(
        "--model",
        default=get_model(),
        help="Ollama model name (default: from $LLM_MODEL or config).",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Write JSON report to this path (default: stdout).",
    )
    args = parser.parse_args(argv)

    if not args.live:
        print(
            "A real benchmark run requires --live (tests use run_benchmark() with "
            "injected fakes — no network is touched by the library path).",
            file=sys.stderr,
        )
        return 2

    # --live: build Ollama client factories, run benchmark, emit report.
    scenarios = load_scenarios(args.scenarios)

    def target_llm_for(sc: Any) -> _OllamaClient:  # noqa: ARG001
        return _OllamaClient(model=args.model)

    def attacker_llm_for(sc: Any) -> _OllamaClient:  # noqa: ARG001
        return _OllamaClient(model=args.model)

    report = run_benchmark(
        scenarios,
        args.target,
        target_llm_for=target_llm_for,
        attacker_llm_for=attacker_llm_for,
    )

    report_json = report.to_json()
    if args.out is not None:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report_json)
    else:
        print(report_json)

    return 0
