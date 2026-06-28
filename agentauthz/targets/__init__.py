"""AgentAuthZ agent TARGETS — framework-specific instrumentations of the vulnerable agent.

A *target* is a concrete way to RUN and OBSERVE the deliberately-vulnerable agent so
the framework-agnostic ``agentauthz.harness.evaluator`` can judge it. The first one is
``otel_instrumentation`` — an OpenTelemetry-instrumented ``Toolbox`` / ``Agent`` that
emits one ``execute_tool`` span per tool call, plus an in-memory tracer for deterministic,
offline capture. The adapter ``agentauthz.harness.observation.observation_from_spans`` then
reconstructs a standard ``Observation`` from that trace, decoupling the evaluator from
this agent's concrete in-memory shape.

The deliberate vulnerabilities are NOT re-implemented here: the instrumented classes
inherit the base ``Toolbox`` / ``Agent`` behavior unchanged (the flaws stay in ``tools.py``);
this package only wraps each tool call in a span.
"""

from __future__ import annotations
