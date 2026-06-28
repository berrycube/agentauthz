"""OpenTelemetry instrumentation of the vulnerable agent.

The instrumented classes wrap each tool call in an ``execute_tool`` span carrying
``gen_ai.operation.name`` / ``gen_ai.tool.name`` / ``agentauthz.tool.arguments`` /
``agentauthz.tool.result``. Behavior otherwise stays IDENTICAL to the base classes — the
deliberate V1/V2/V3 vulnerabilities live in ``tools.py`` and are NOT touched here. The
exporter feeds ``observation_from_spans``, which reconstructs a standard ``Observation``
from the captured trace.

OTel API used: ``opentelemetry.sdk.trace.TracerProvider`` +
``opentelemetry.sdk.trace.export.SimpleSpanProcessor`` +
``opentelemetry.sdk.trace.export.in_memory_span_exporter.InMemorySpanExporter``; a span via
``with tracer.start_as_current_span('execute_tool') as span: span.set_attribute(k, v)``.
"""

from __future__ import annotations

import json
from typing import Any

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agentauthz.agent import Agent
from agentauthz.harness.observation import TOOL_SPAN_NAME
from agentauthz.store import Store
from agentauthz.tools import RefundLedger, Toolbox

__all__ = [
    "TOOL_SPAN_NAME",
    "InstrumentedToolbox",
    "InstrumentedAgent",
    "setup_in_memory_tracer",
]

# Sentinel stored in agentauthz.tool.arguments / agentauthz.tool.result when the value cannot be
# JSON-encoded. It is itself valid JSON that decodes to a *string scalar* (NOT a dict), so
# the adapter (observation_from_spans) keeps the span but falls back to empty arguments —
# it can never fabricate a V1/V2/V3 finding (those need specific dict fields). This keeps
# instrumentation behavior-neutral: a span attribute is best-effort and must NEVER change
# the call's outcome.
_UNSERIALIZABLE_ATTR = json.dumps("<unserializable>")


def _json_attr(value: Any) -> str:
    """JSON-encode a span-attribute value, fail-closed to a sentinel on ANY encode failure.

    ``json.dumps(value, default=str, sort_keys=True)`` can raise on adversarial/degenerate
    input that ``Toolbox.call`` already handled safely upstream — and it can raise in MORE
    ways than the obvious encoder errors:

    * ``TypeError``      — a dict with mixed-type (e.g. non-string) keys breaks ``sort_keys``;
    * ``ValueError``     — a circular reference, or an int whose digit count exceeds CPython's
                           ``int_max_str_digits`` cap;
    * ``OverflowError``  — defensive: any encoder path that overflows;
    * ``RecursionError`` — a deeply-nested structure exhausts the recursion limit;
    * ANY OTHER ``Exception`` — because ``default=str`` calls ``str(obj)`` on an unencodable
                           value, an adversarial argument whose ``__str__`` raises an arbitrary
                           exception (``KeyError``, ``RuntimeError``, a custom error, ...) would
                           propagate AFTER ``Toolbox.call`` already returned its structured
                           result. A span attribute is best-effort metadata; it must NEVER be
                           able to change the call's outcome.

    Catching the full ``Exception`` (still NOT ``BaseException`` — ``KeyboardInterrupt`` /
    ``SystemExit`` must propagate) and returning a sentinel guarantees the surrounding ``call``
    always reaches ``return result`` with the EXACT ``super().call()`` value — instrumentation
    only adds a span, it never changes behavior.
    """
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except Exception:  # noqa: BLE001 — best-effort span metadata, must never abort the call
        return _UNSERIALIZABLE_ATTR


class InstrumentedToolbox(Toolbox):
    """A ``Toolbox`` that wraps every tool call in an ``execute_tool`` OTel span.

    Behavior is otherwise IDENTICAL to the base ``Toolbox`` — the deliberate V1/V2/V3 flaws are
    inherited unchanged. Takes a ``tracer`` (the in-memory tracer from
    ``setup_in_memory_tracer``); the span carries the tool name + JSON-encoded
    arguments/result as attributes the adapter reads back.
    """

    def __init__(
        self,
        store: Store,
        session_customer_id: str,
        tracer: Any,
        refund_ledger: RefundLedger | None = None,
    ):
        super().__init__(store, session_customer_id, refund_ledger=refund_ledger)
        self._tracer = tracer

    def call(self, name: str, arguments: Any) -> Any:
        """Wrap the parent ``Toolbox.call`` in an ``execute_tool`` OTel span.

        The span carries:
        * ``gen_ai.operation.name`` — fixed ``"execute_tool"`` (matches the span name);
        * ``gen_ai.tool.name``      — the validated tool name (or ``"unknown"`` if not str);
        * ``agentauthz.tool.arguments``   — JSON-encoded arguments (sentinel if it cannot encode);
        * ``agentauthz.tool.result``      — JSON-encoded result (sentinel if it cannot encode).

        The underlying ``super().call()`` is unchanged — all deliberate V1/V2/V3
        vulnerabilities (in ``Toolbox``) are inherited and NOT touched here. Crucially, span
        attributes are best-effort: the base ``Toolbox`` already returns a *structured error*
        for adversarial arguments (e.g. a dict with non-string keys), and encoding such
        arguments via ``json.dumps(..., sort_keys=True)`` would raise AFTER the base handled
        the call. Two layers keep this wrapper behavior-preserving: ``_json_attr`` never
        raises on a degenerate/adversarial value (incl. one whose ``__str__`` blows up), and
        the whole attribute-tagging block is wrapped so that even an unexpected OTel failure
        cannot stop the wrapper from returning the EXACT ``super().call()`` result. The span is
        added as a side effect; it can never abort or alter the call.
        """
        with self._tracer.start_as_current_span(TOOL_SPAN_NAME) as span:
            result = super().call(name, arguments)
            try:
                span.set_attribute("gen_ai.operation.name", "execute_tool")
                span.set_attribute(
                    "gen_ai.tool.name", name if isinstance(name, str) else "unknown"
                )
                span.set_attribute("agentauthz.tool.arguments", _json_attr(arguments))
                span.set_attribute("agentauthz.tool.result", _json_attr(result))
            except Exception:  # noqa: BLE001 — span tagging is best-effort, never alters call
                pass
            return result


class InstrumentedAgent(Agent):
    """An ``Agent`` whose toolbox is an :class:`InstrumentedToolbox` (OTel-instrumented).

    Same constructor surface as ``Agent`` plus a required ``tracer``. After delegating to
    ``Agent.__init__`` it REPLACES ``self.toolbox`` with an ``InstrumentedToolbox`` bound to
    the SAME refund ledger the base agent built (so refund accounting is preserved), leaving
    every inherited behavior — including the deliberate vulnerabilities — unchanged.
    """

    def __init__(
        self,
        llm_client: Any,
        store: Store,
        session_customer_id: str,
        tracer: Any,
        system_prompt: str | None = None,
        max_steps: int = 8,
        max_tool_calls: int = 32,
        refund_ledger: RefundLedger | None = None,
    ):
        super().__init__(
            llm_client,
            store,
            session_customer_id,
            system_prompt=system_prompt,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            refund_ledger=refund_ledger,
        )
        # Re-bind the toolbox to the instrumented one, reusing the base agent's refund ledger
        # so cumulative refund accounting is identical to the uninstrumented agent.
        self.toolbox = InstrumentedToolbox(
            store, session_customer_id, tracer, refund_ledger=self.toolbox.refunds
        )


def setup_in_memory_tracer() -> tuple[Any, InMemorySpanExporter]:
    """Build a FRESH, isolated in-memory tracer + exporter (no global provider touched).

    Returns ``(tracer, exporter)``: a brand-new ``TracerProvider`` with a
    ``SimpleSpanProcessor`` feeding an ``InMemorySpanExporter``, so each call captures
    spans into its OWN exporter — deterministic and offline, with zero network and no
    interference with any process-global OpenTelemetry configuration. Read finished spans
    via ``exporter.get_finished_spans()``.
    """
    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agentauthz.targets.otel_instrumentation")
    return tracer, exporter
