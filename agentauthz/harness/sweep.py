"""Cross-model SWEEP — run the declare->attack->evaluate benchmark across many brains.

The v1 runner answers "does this vulnerability reproduce against ONE model?".
The sweep answers the productizable question: *does it reproduce across DIFFERENT
brains, or was a single "the model refused" run just one model's judgement on one day?*

``sweep_models`` runs the existing ``run_benchmark`` ``repeats`` times per TARGET
model — holding ONE attacker model CONSTANT — and aggregates a per-(model, vulnerability)
FIRE RATE (``fired_count / repeats``) into a ``SweepReport`` matrix.  Holding the attacker
constant and varying only the target isolates the TARGET model as the single variable: a
low fire rate then means "this target resisted", not "the attacker was too weak to land
the attack" (a model that is merely bad at tool-calling fails in BOTH seats, which would
otherwise read a weak model as a falsely "safe" one).

DETERMINISM + OFFLINE: ``sweep_models`` takes
an INJECTED ``client_for(model_spec, seat)`` factory — tests inject scripted fakes; the
``--live`` CLI injects real clients (local Ollama via the ``_OllamaClient``, and any
OpenAI-compatible endpoint such as DeepSeek via ``OpenAICompatClient``).  The library path
NEVER touches the network; only ``main(--live)`` does.  The runner only ever drives the
in-repo agent.

Reproducibility: the CLI emits real model IDs (so a reader re-runs the exact sweep); API
keys are read from the environment (``DEEPSEEK_API_KEY`` / ``OPENAI_API_KEY``) and NEVER
stored in the repo.

KNOWN LIMITATION (cloud endpoints, multi-turn tool protocol): fixed-target verification
over an OpenAI-compatible endpoint (DeepSeek/OpenAI) is INCOMPLETE — see
``OpenAICompatClient`` for the full account.  The fire-rate matrix (which model fires which
vulnerability) is decided on the FIRST tool turn and is UNAFFECTED; the gap only touches
cells that need a SECOND model turn after a tool runs, and such a cell is recorded as a
fail-closed ERROR (excluded from the denominator), NEVER a false 'safe' 0/N.  Verify
``fixed -> 0`` via the local Ollama path.  Tracked as a follow-up story (give the multi-turn
protocol OpenAI ``tool_call_id`` linkage).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentauthz.agent import LLMResponse, ToolCall
from agentauthz.harness.loader import load_scenarios
from agentauthz.harness.runner import _OllamaClient, _to_openai_tools, run_benchmark

__all__ = ["SweepReport", "sweep_models", "main"]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
@dataclass
class SweepReport:
    """A cross-model sweep result: the fixed attacker + repeat count, the target models
    swept, and one ``cell`` per (target_model, vulnerability) carrying its fire rate.

    Each cell: ``{target_model, vulnerability, scenario_id, fired_count, total, rate}``
    where ``rate == fired_count / total`` and ``total == repeats``.
    """

    target: str
    repeats: int
    attacker_model: str
    target_models: list
    cells: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "repeats": self.repeats,
            "attacker_model": self.attacker_model,
            "target_models": list(self.target_models),
            "cells": [dict(c) for c in self.cells],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def to_markdown(self) -> str:
        """Render the sweep as a matrix: vulnerabilities (rows) x target models (columns),
        each cell ``fired/total``; the constant attacker + repeat count are disclosed."""
        lines: list[str] = [
            f"# Cross-model vulnerability sweep — target: `{self.target}`",
            "",
            f"**Attacker model (held constant):** `{self.attacker_model}`  ·  "
            f"**Repeats per cell:** {self.repeats}",
            "",
        ]

        models = list(self.target_models)
        # vulnerability rows in first-seen order; remember one scenario id per vuln (label).
        vulns: list[str] = []
        scenario_of: dict[str, str] = {}
        cell_by: dict[tuple, dict] = {}
        for c in self.cells:
            v = c.get("vulnerability")
            m = c.get("target_model")
            if v not in scenario_of:
                vulns.append(v)
                scenario_of[v] = c.get("scenario_id", "")
            cell_by[(m, v)] = c

        lines.append("| Vulnerability | " + " | ".join(f"`{m}`" for m in models) + " |")
        lines.append("|---|" + "---|" * len(models))
        any_errors = False
        for v in vulns:
            sid = scenario_of.get(v) or ""
            label = f"{v} (`{sid}`)" if sid else f"{v}"
            row = [label]
            for m in models:
                c = cell_by.get((m, v))
                if not c:
                    row.append("—")
                    continue
                ec = c.get("error_count", 0)
                fc, total = c["fired_count"], c["total"]
                if ec:
                    any_errors = True
                    # show the EFFECTIVE denominator (errored runs excluded) + the error count.
                    row.append(f"{fc}/{total - ec} ({ec} err)")
                else:
                    row.append(f"{fc}/{total}")
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        if any_errors:
            lines.append(
                "> `(N err)` = N repeats were LIVE-CLIENT ERRORS (transport/auth/parse), "
                "EXCLUDED from the fire-rate denominator — an unreachable endpoint is NOT a "
                "'safe' result."
            )
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestration (pure / offline — drives run_benchmark with the injected client_for)
# ---------------------------------------------------------------------------
# The live clients are fail-closed: on a transport/auth/parse failure they return an
# LLMResponse with one of these SENTINEL contents and NO tool calls.  The sweep must NOT
# count such a run as a "safe" non-fire (an unreachable endpoint / 401 is not a safe
# model) — it tracks them as ERRORS and excludes them from the fire-rate denominator.
_LIVE_ERROR_SENTINELS = ("[ollama-client error]", "[openai-compat-client error]")


class _ErrorTrackingClient:
    """Wrap a (live) client so the sweep can tell a real refusal from a client ERROR.
    Records ``sink[key] = True`` whenever the wrapped client returns a fail-closed error
    sentinel; otherwise delegates verbatim (no behaviour change)."""

    def __init__(self, inner: Any, sink: dict, key: str) -> None:
        self._inner = inner
        self._sink = sink
        self._key = key

    def complete(self, messages: Any, tools: Any) -> Any:
        resp = self._inner.complete(messages, tools)
        content = getattr(resp, "content", None)
        if isinstance(content, str) and content in _LIVE_ERROR_SENTINELS:
            self._sink[self._key] = True
        return resp

    def __getattr__(self, name: str) -> Any:
        # Transparently proxy any other attribute to the wrapped client so duck-typed
        # introspection still works THROUGH the wrapper — notably run_attack's
        # _ExhaustionSafeLLM, which reads a scripted fake's `_index`/`_responses` to detect
        # graceful give-up.  (Real live clients lack those attrs -> AttributeError -> the
        # caller's getattr default applies, exactly as without the wrapper.)
        if name == "_inner":  # not yet set (partial construction) -> avoid infinite recursion
            raise AttributeError(name)
        return getattr(self._inner, name)


def _validate_inputs(target_models: Any, attacker_model: Any, target: Any, repeats: Any) -> None:
    """Fail-closed on every malformed input (never silently produce an empty/garbage sweep)."""
    if target not in ("vulnerable", "fixed"):
        raise ValueError(f"unknown target {target!r} (expected 'vulnerable' or 'fixed')")
    # bool is a subclass of int — exclude it so repeats=True is not read as 1.
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 1:
        raise ValueError(f"repeats must be an integer >= 1, got {repeats!r}")
    if not isinstance(target_models, (list, tuple)) or len(target_models) == 0:
        raise ValueError("target_models must be a non-empty list of model specs")
    for m in target_models:
        if not isinstance(m, str) or not m.strip():
            raise ValueError(f"each target model must be a non-empty string, got {m!r}")
    if not isinstance(attacker_model, str) or not attacker_model.strip():
        raise ValueError(f"attacker_model must be a non-empty string, got {attacker_model!r}")


def sweep_models(
    target_models: list,
    attacker_model: str,
    scenarios: Any,
    target: str,
    *,
    repeats: int,
    client_for: Callable[[str, str], Any],
) -> SweepReport:
    """Run ``scenarios`` against each target model ``repeats`` times (attacker held at
    ``attacker_model``) and aggregate a per-(model, vulnerability) fire-rate ``SweepReport``.

    ``client_for(model_spec, seat)`` builds a FRESH LLM client for ``seat`` in
    ``{"target", "attacker"}`` — fresh because scripted fakes (and stateful live clients)
    must not be reused across scenarios/repeats.
    """
    _validate_inputs(target_models, attacker_model, target, repeats)
    scenarios = list(scenarios)

    cells: list[dict] = []
    for tm in target_models:
        fired_counts: dict[str, int] = {sc.id: 0 for sc in scenarios}
        error_counts: dict[str, int] = {sc.id: 0 for sc in scenarios}
        for _ in range(repeats):
            # Per-run error sinks, kept SEPARATE BY SEAT: a live client that returns a
            # fail-closed error sentinel sets its seat's sink for that scenario.
            tgt_errored: dict[str, bool] = {}
            atk_errored: dict[str, bool] = {}
            report = run_benchmark(
                scenarios,
                target,
                # _tm / _sink default-bind the loop+run state (no late-binding closure bug);
                # the attacker factory closes over the CONSTANT attacker_model.
                target_llm_for=lambda sc, _tm=tm, _sink=tgt_errored: _ErrorTrackingClient(
                    client_for(_tm, "target"), _sink, sc.id
                ),
                attacker_llm_for=lambda sc, _sink=atk_errored: _ErrorTrackingClient(
                    client_for(attacker_model, "attacker"), _sink, sc.id
                ),
            )
            for res in report.results:
                sid = res["scenario_id"]
                # Seat-aware accounting:
                # 1. ATTACKER error -> the attack never really ran (a broken attacker
                #    endpoint must NOT look like a valid exploit) -> ERROR, even if the
                #    scripted/garbage message happened to make the target fire.
                # 2. else a deterministic FIRE is ground truth (the evaluator saw the
                #    violation) -> a TARGET error LATER in the run cannot erase it -> FIRE.
                # 3. else a TARGET error on a non-fired run -> untrustworthy non-fire -> ERROR.
                if atk_errored.get(sid):
                    error_counts[sid] += 1
                elif res.get("fired"):
                    fired_counts[sid] += 1
                elif tgt_errored.get(sid):
                    error_counts[sid] += 1
        for sc in scenarios:
            fc = fired_counts[sc.id]
            ec = error_counts[sc.id]
            # exclude errored runs from the denominator (an errored run is neither a fire
            # nor a trustworthy non-fire); if EVERY run errored, rate is 0.0 and
            # error_count == total makes the cell unusable-but-honest.
            effective = repeats - ec
            cells.append(
                {
                    "target_model": tm,
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
        target_models=list(target_models),
        cells=cells,
    )


# ---------------------------------------------------------------------------
# OpenAI-compatible live client (DeepSeek etc.) — used ONLY under --live, never in tests.
# Its PURE helpers (_to_openai_tools / _parse_openai_choice) ARE unit-tested offline.
# ---------------------------------------------------------------------------
def _parse_openai_choice(data: Any) -> LLMResponse:
    """Parse an OpenAI/DeepSeek chat-completion response into an ``LLMResponse``.

    Tool-call ``arguments`` arrive as a JSON *string* (confirmed live against DeepSeek) —
    decode it to a dict.  Any malformed call (bad JSON, non-object args, non-string name)
    is DROPPED, never coerced; any malformed payload returns an empty response.  Never
    raises (fail-closed)."""
    fallback = LLMResponse([], None)
    try:
        if not isinstance(data, dict):
            return fallback
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            return fallback
        first = choices[0]
        msg = first.get("message") if isinstance(first, dict) else None
        if not isinstance(msg, dict):
            return fallback

        content = msg.get("content") or None
        if content is not None and not isinstance(content, str):
            content = None

        tool_calls: list[ToolCall] = []
        raw_calls = msg.get("tool_calls") or []
        if isinstance(raw_calls, list):
            for tc in raw_calls:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") or {}
                if not isinstance(fn, dict):
                    continue
                name = fn.get("name")
                # Drop a blank/whitespace name (mirrors the Ollama guard): a "" name is
                # never a real tool — keeping it hands the agent a nameless call that
                # no-ops through the toolbox and silently distorts the run.
                if not isinstance(name, str) or not name.strip():
                    continue
                args_raw = fn.get("arguments")
                if isinstance(args_raw, dict):
                    args = args_raw
                elif isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw)
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(args, dict):
                        continue
                else:
                    continue
                tool_calls.append(ToolCall(name, args))
        return LLMResponse(tool_calls, content)
    except Exception:  # noqa: BLE001  (a malformed payload must never crash the run)
        return fallback


def _live_openai_response(data: Any) -> LLMResponse:
    """Map a decoded OpenAI-compatible payload to an ``LLMResponse`` for the LIVE sweep.

    A genuine assistant turn (a tool call, OR a refusal/answer carrying text) parses
    normally.  But a 200-status body that is NOT a well-formed chat completion — a
    200-wrapped ``{"error": ...}`` object, a missing/empty ``choices``, a missing
    ``message``, or a well-formed envelope that yields NOTHING usable (no tool call AND no
    text) — is a provider/transport failure, NOT a model refusal: it returns the fail-closed
    ERROR sentinel so the sweep counts it as an error (excluded from the fire-rate
    denominator) instead of a false 'safe' non-fire."""
    sentinel = LLMResponse([], "[openai-compat-client error]")
    if not isinstance(data, dict) or "error" in data:
        return sentinel
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return sentinel
    if not isinstance(choices[0].get("message"), dict):
        return sentinel
    parsed = _parse_openai_choice(data)
    if not parsed.tool_calls and not (isinstance(parsed.content, str) and parsed.content.strip()):
        return sentinel
    return parsed


class OpenAICompatClient:
    """Fail-closed client for any OpenAI-compatible ``/chat/completions`` endpoint
    (DeepSeek, OpenAI, ...).  On ANY error (connection/timeout/non-2xx/parse) returns
    ``LLMResponse([], '[openai-compat-client error]')`` so the agent loop ends cleanly.

    KNOWN LIMITATION — multi-turn tool protocol (tracked as a follow-up story).  The in-repo
    ``Agent`` (agentauthz/agent.py) feeds tool results back to the model WITHOUT the OpenAI
    ``tool_call_id`` linkage (and without re-emitting the assistant ``tool_calls`` turn).  A
    LOCAL Ollama server accepts this lax history; a strict OpenAI-compatible endpoint
    (DeepSeek/OpenAI) REJECTS the follow-up request, which this client maps to the fail-closed
    error sentinel.  CONSEQUENCE for the sweep: a cell that needs a SECOND model turn after a
    tool executes — chiefly a FIXED target that lets the model call a tool and then BLOCKS it —
    is recorded as an ERROR (excluded from the fire-rate denominator), NOT as a false 'safe'
    0/N.  This never inflates a fire rate and never reports a failure as safe (fail-closed); it
    DOES make fixed-target verification over a cloud endpoint incomplete.  So: verify
    ``fixed -> 0`` with the LOCAL Ollama path, and use OpenAI-compatible targets for FIRE-RATE
    (decided on the first tool turn, hence unaffected).  Full fix = give the multi-turn
    protocol OpenAI-compatible ``tool_call_id`` linkage (separate story)."""

    def __init__(self, model: str, *, base_url: str, api_key: str, timeout: int = 120) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def complete(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        import http.client
        import urllib.parse

        fallback = LLMResponse([], "[openai-compat-client error]")
        try:
            payload: dict[str, Any] = {
                "model": self._model,
                "messages": messages,
                "stream": False,
            }
            otools = _to_openai_tools(tools)
            if otools:  # attacker seat passes [] -> omit tools entirely
                payload["tools"] = otools
                payload["tool_choice"] = "auto"
            body = json.dumps(payload, default=str).encode("utf-8")

            parsed = urllib.parse.urlparse(self._base_url)
            host = parsed.hostname
            if not host:
                return fallback
            is_https = parsed.scheme != "http"  # default to TLS
            port = parsed.port or (443 if is_https else 80)
            path = parsed.path.rstrip("/") + "/chat/completions"
            ConnCls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
            conn = ConnCls(host, port, timeout=self._timeout)
            try:
                conn.request(
                    "POST",
                    path,
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self._api_key}",
                    },
                )
                resp = conn.getresponse()
                if not (200 <= resp.status < 300):
                    return fallback
                raw = resp.read().decode("utf-8")
            finally:
                conn.close()
        except Exception:  # noqa: BLE001
            return fallback

        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return fallback
        return _live_openai_response(data)


# ---------------------------------------------------------------------------
# Live provider factory + CLI (only path that touches the network)
# ---------------------------------------------------------------------------
def _build_live_client(model_spec: str, seat: str) -> Any:  # noqa: ARG001  (seat unused: a model client is seat-agnostic)
    """Build a real LLM client from a ``provider:model`` spec.

    ``ollama:llama3.2`` / ``llama3.2`` (default provider) -> local Ollama;
    ``deepseek:deepseek-v4-pro`` -> DeepSeek (``DEEPSEEK_API_KEY``);
    ``openai:<model>`` -> OpenAI / any OpenAI-compatible base (``OPENAI_API_KEY`` +
    optional ``OPENAI_BASE_URL``).  Missing key -> ValueError (fail-closed; a live sweep
    must not silently read 'guarded' because a key was unset).  Construction touches NO
    network — only ``.complete()`` does."""
    provider, sep, name = model_spec.partition(":")
    if not sep:
        provider, name = "ollama", model_spec
    provider = provider.strip().lower()
    name = name.strip()
    if not name:
        raise ValueError(f"empty model name in spec {model_spec!r}")

    if provider == "ollama":
        return _OllamaClient(model=name)
    if provider == "deepseek":
        key = os.environ.get("DEEPSEEK_API_KEY")
        if not key:
            raise ValueError("DEEPSEEK_API_KEY is not set (required for a deepseek:* model under --live)")
        return OpenAICompatClient(name, base_url="https://api.deepseek.com", api_key=key)
    if provider in ("openai", "openai-compat"):
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError("OPENAI_API_KEY is not set (required for an openai:* model under --live)")
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        return OpenAICompatClient(name, base_url=base, api_key=key)
    raise ValueError(f"unknown model provider {provider!r} in spec {model_spec!r}")


def main(argv: list[str] | None = None) -> int:
    """CLI: sweep a fire-rate matrix across target models (attacker held constant).

    Requires ``--live`` to contact real models — WITHOUT it the CLI refuses and returns 2
    (no network in the library path; tests call ``sweep_models()`` with injected fakes)."""
    parser = argparse.ArgumentParser(
        description="AgentAuthZ cross-model sweep — fire-rate matrix across target models"
    )
    parser.add_argument("--target", required=True, choices=("vulnerable", "fixed"))
    parser.add_argument(
        "--target-models",
        required=True,
        help="comma-separated model specs, e.g. 'ollama:llama3.2,deepseek:deepseek-v4-pro'",
    )
    parser.add_argument(
        "--attacker-model",
        required=True,
        help="the single attacker model spec, held CONSTANT across the sweep",
    )
    parser.add_argument("--repeats", type=int, default=5, help="runs per (model, scenario) cell")
    parser.add_argument("--scenarios", default="agentauthz/scenarios")
    parser.add_argument(
        "--live",
        action="store_true",
        help="contact real models. Without this flag the sweep refuses (no network).",
    )
    parser.add_argument("--out", default=None, help="write the report here (default: stdout)")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    args = parser.parse_args(argv)

    if not args.live:
        print(
            "A real sweep requires --live (it contacts real models). Tests call "
            "sweep_models() with injected fakes — no network in the library path.",
            file=sys.stderr,
        )
        return 2

    # Fail-closed: a non-positive --repeats is a usage error (exit 2), not an uncaught
    # ValueError from deep inside sweep_models.
    if args.repeats < 1:
        print("--repeats must be an integer >= 1", file=sys.stderr)
        return 2

    # Fail-closed: reject an empty/blank entry (a stray or trailing comma) rather than
    # silently dropping it and publishing an incomplete matrix that hides the bad input.
    target_models = [m.strip() for m in args.target_models.split(",")]
    if not target_models or any(not m for m in target_models):
        print(
            "--target-models has an empty/blank entry (check for stray or trailing commas)",
            file=sys.stderr,
        )
        return 2

    # Fail-closed UPFRONT: validate every spec (incl. its API key) BEFORE spending any
    # model calls.  Construction is network-free, so this is a pure credential/spec check.
    try:
        for spec in target_models:
            _build_live_client(spec, "target")
        _build_live_client(args.attacker_model, "attacker")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    scenarios = load_scenarios(args.scenarios)
    report = sweep_models(
        target_models=target_models,
        attacker_model=args.attacker_model,
        scenarios=scenarios,
        target=args.target,
        repeats=args.repeats,
        client_for=_build_live_client,
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
