"""The framework-agnostic OBSERVATION + the OpenTelemetry adapter.

``observation_from_spans`` parses the ``execute_tool`` spans, ORDERS them by
``.start_time``, decodes the JSON attrs into transcript rows, and fails closed on any
malformed span.

Design contract (why this exists): ``evaluate`` reads EXACTLY three attributes of
a finished run — ``.store`` / ``.transcript`` / ``.session_customer_id``. ``Observation`` is a
framework-agnostic view that exposes those three and NOTHING agent-specific, so ``evaluate``
runs UNCHANGED on it — decoupling the evaluator from THIS agent's concrete shape.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Real
from typing import Any

__all__ = ["TOOL_SPAN_NAME", "Observation", "observation_from_spans"]

# The OTel span name emitted once per tool call (also the gen_ai.operation.name value).
TOOL_SPAN_NAME = "execute_tool"


@dataclass
class Observation:
    """A framework-agnostic view of a finished agent run.

    Exposes EXACTLY the three attributes the deterministic evaluator reads, so
    ``agentauthz.harness.evaluator.evaluate(scenario, observation)`` runs UNCHANGED — the same
    duck-type the live ``Agent`` (and any ``FixedAgent``) already satisfies:

    * ``session_customer_id`` — the authenticated customer the run acted as (V1/V2 read it);
    * ``transcript``          — the ordered list of executed tool calls, each a
                                ``{'tool', 'arguments', 'result'}`` dict (V2/V3 scan it);
    * ``store``               — the datastore snapshot AFTER the run (V1 compares a field).
    """

    session_customer_id: str
    transcript: list[dict]
    store: Any


def observation_from_spans(
    spans: Any, store: Any, session_customer_id: str
) -> Observation:
    """Build an ``Observation`` from a finished OpenTelemetry trace + a state snapshot.

    Collects all spans whose ``.name`` is ``TOOL_SPAN_NAME`` (``"execute_tool"``), orders
    them by ``.start_time`` (ascending), then decodes each span's attributes into a
    transcript row. A span is SKIPPED (fail-closed — never raise, never fabricate a step)
    when it is malformed in ANY of these ways:

    * its ``.attributes`` is absent or is not a ``Mapping``;
    * ``gen_ai.tool.name`` is missing or not a ``str``;
    * either ``agentauthz.tool.arguments`` or ``agentauthz.tool.result`` is MISSING (an incomplete span
      must not be defaulted into a transcript row — every span THIS harness emits always sets
      both, so a missing payload attribute marks a foreign/corrupted span);
    * either payload attribute is not a string or is unparseable JSON;
    * the decoded ``arguments`` is not a ``dict`` (a non-dict arguments payload is corrupt —
      it is SKIPPED, never coerced to ``{}``, so a malformed span can never be promoted into a
      trusted evaluator step).

    Every span touch — selection (reading ``.name``), ordering (reading ``.start_time``), and
    attribute access (``attrs.get(...)``, which on a hostile ``Mapping`` subclass could itself
    raise) — is wrapped so ANY ``Exception`` (never ``BaseException`` — ``KeyboardInterrupt`` /
    ``SystemExit`` still propagate) skips just that one span. A single corrupt/foreign span can
    therefore never abort the whole observation or prevent the evaluator from reaching a
    verdict. Ordering is additionally crash-proof: a non-numeric ``start_time`` collapses to
    ``0`` instead of a mixed-type comparison inside ``sorted``.

    Returns an ``Observation`` whose ``.store`` is the caller-supplied state snapshot
    (the post-run store — NOT a fresh seed) and whose ``.transcript`` is ordered by
    ``start_time``.
    """

    def _is_tool_span(span: Any) -> bool:
        # Reading `.name` can itself raise on a pathological accessor — treat that as "not a
        # tool span" rather than letting it abort selection.
        try:
            return getattr(span, "name", None) == TOOL_SPAN_NAME
        except Exception:  # noqa: BLE001 — malformed span is skipped, never crashes selection
            return False

    def _sort_key(span: Any) -> float:
        # Read start_time AND convert it defensively, honoring only a finite real number.
        # Anything else (missing, str, non-comparable, an accessor that raises, or a Real
        # subclass whose __float__ raises / yields NaN/inf) collapses to 0.0 — so `sorted`
        # never raises on a mixed-type key, a hostile property, or a hostile __float__.
        try:
            st = getattr(span, "start_time", 0)
            if isinstance(st, bool) or not isinstance(st, Real):
                return 0.0
            val = float(st)
        except Exception:  # noqa: BLE001 — hostile accessor/conversion -> 0.0, never crash
            return 0.0
        return val if math.isfinite(val) else 0.0

    tool_spans = sorted((s for s in spans if _is_tool_span(s)), key=_sort_key)
    transcript: list[dict] = []
    for span in tool_spans:
        # Belt-and-suspenders: even a pathological span object (one whose attribute access, or
        # a hostile Mapping subclass whose `.get` raises a non-Type/ValueError) is skipped
        # fail-closed instead of aborting the whole run. Caught as Exception (NOT BaseException).
        try:
            attrs = getattr(span, "attributes", None)
            # A ReadableSpan's attributes is a Mapping; anything else (None, or a non-mapping
            # on a malformed/foreign span) is skipped rather than risking a raising `.get`.
            if not isinstance(attrs, Mapping):
                continue
            name = attrs.get("gen_ai.tool.name")
            if not isinstance(name, str):
                continue
            raw_args = attrs.get("agentauthz.tool.arguments")
            raw_result = attrs.get("agentauthz.tool.result")
            # Both payload attributes must be PRESENT and string-typed — never default a span
            # that is missing them into a fabricated step.
            if not isinstance(raw_args, str) or not isinstance(raw_result, str):
                continue
            args = json.loads(raw_args)
            result = json.loads(raw_result)
        except Exception:  # noqa: BLE001 — any malformed-span failure skips just this span
            continue
        # A corrupt non-dict arguments payload is SKIPPED, not coerced to {} — coercion would
        # let a malformed span be promoted into a trusted transcript row the evaluator reads.
        if not isinstance(args, dict):
            continue
        transcript.append({
            "tool": name,
            "arguments": args,
            "result": result,
        })
    return Observation(session_customer_id, transcript, store)
