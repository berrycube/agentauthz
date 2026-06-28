"""A LangGraph target over the SAME deliberately-vulnerable Toolbox.

The same V1/V2/V3 business-logic invariants are reproduced on a second agent
framework (LangGraph), proving the findings are a pattern, not an artifact of the
hand-written loop.  The LangGraph wiring DELEGATES every tool call to an
:class:`~agentauthz.targets.otel_instrumentation.InstrumentedToolbox` — so the deliberate
V1/V2/V3 authorization flaws (in ``tools.py``) AND the ``execute_tool`` OTel span are
both inherited unchanged.  The LangGraph wiring adds NO authorization logic of
its own; it only routes the scripted tool calls into the unchanged ``Toolbox``.

``build_ollama_model`` is the --live escape hatch (local Ollama via ``langchain_ollama``).
It is imported lazily so the test suite (which never calls it) has zero network dependency.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition

from agentauthz.store import Store
from agentauthz.targets.otel_instrumentation import InstrumentedToolbox

__all__ = ["build_langgraph_target", "build_ollama_model"]


class _AgentAuthZState(MessagesState):
    """LangGraph state that extends MessagesState with per-invocation execution counters.

    ``step_count`` tracks LLM agent turns; ``executed_tool_count`` tracks total tool
    executions across ALL turns in a single ``app.invoke`` call; ``budget_exhausted``
    signals that ``max_tool_calls`` was reached so the ``tools`` node routes to ``END``
    instead of back to ``agent`` — mirroring the hand-written Agent's immediate-return on
    budget exhaustion.  All three default to 0/False via ``.get(..., default)`` in the nodes,
    so callers that pass only ``{"messages": [...]}`` work unchanged.
    """

    step_count: int
    executed_tool_count: int
    budget_exhausted: bool


def build_langgraph_target(
    store: Store,
    session_customer_id: str,
    tracer: Any,
    model: Any,
    max_steps: int = 8,
    max_tool_calls: int = 32,
) -> Any:
    """Build a compiled LangGraph app over the SAME deliberately-vulnerable Toolbox.

    The app's tools node runs the three vulnerable tools (``update_recovery_email`` /
    ``get_order`` / ``issue_refund``) by DELEGATING each to an
    :class:`~agentauthz.targets.otel_instrumentation.InstrumentedToolbox` bound to ``store`` and
    ``session_customer_id`` — which emits the ``execute_tool`` OTel span the
    ``observation_from_spans`` adapter reads back.  The ``model`` (a
    ``FakeMessagesListChatModel`` in tests; a ``ChatOllama`` under ``--live``) drives the
    agent node.

    RAW DELEGATION (faithful cross-target consistency): the tools node forwards the
    LLM's ``tool_call`` ``name`` and ``args`` dict INTO ``InstrumentedToolbox.call``
    BYTE-FOR-BYTE — no typed ``StructuredTool`` wrapper sits in the path.  This matters: a
    typed wrapper builds a pydantic args schema from a ``(order_id: str, amount: float)``
    signature, so ``ToolNode`` would COERCE / DROP adversarial arguments before the toolbox
    ever sees them (``amount=True`` silently becomes ``1.0``; ``amount="642.50"`` becomes
    ``642.5``; an unexpected key is dropped).  That would make the LangGraph path silently
    "fix" arg shapes that the hand-written ``InstrumentedAgent`` forwards UNCHANGED, producing
    DIVERGENT evaluator verdicts for the same scenario.  Forwarding the raw ``args`` dict
    instead routes every adversarial shape through the SAME fail-closed validation in the
    unchanged ``Toolbox`` (which already rejects a non-number ``amount``, an unexpected key, a
    non-dict args object, a non-string key, an unknown tool — returning a structured error,
    never crashing), so the two targets reach IDENTICAL results.  The tools node never
    validates or coerces ``args`` itself — the deliberately-vulnerable, already-hardened
    ``Toolbox`` is the single authority on argument handling.

    EXECUTION BUDGET (cross-target consistency — matches ``Agent.max_steps=8`` and
    ``Agent.max_tool_calls=32``): the LangGraph nodes enforce the SAME two-axis budget as the
    hand-written ``Agent``:

    *  ``agent_node`` tracks a ``step_count`` per-invocation in the graph state.  When
       ``step_count >= max_steps``, it terminates by returning a final ``AIMessage(content="")``
       without calling the model — matching the hand-written loop's bounded-termination at
       ``max_steps`` exhaustion.

    *  ``tools_node`` tracks ``executed_tool_count`` in per-invocation state.  On the FIRST
       call that exceeds the ``max_tool_calls`` budget, it emits exactly ONE structured error
       ToolMessage ("tool-call budget exhausted"), skips ALL remaining tool_calls in the batch
       (no side effects), and sets ``budget_exhausted=True`` — mirroring ``Agent.run``'s
       immediate ``return ""`` on the first over-budget call.  A conditional edge routes the
       ``tools`` node to ``END`` when ``budget_exhausted`` is set, so no further model turn
       runs — the loop terminates immediately, exactly as the hand-written target would.

    All three counters live in the per-``invoke`` graph state (NOT in a shared closure), so
    reusing the same compiled ``app`` across multiple ``invoke`` calls does NOT bleed budget
    from one run into the next.

    Each tool result is returned as ``json.dumps(result, default=str)`` ``ToolMessage``
    content so LangGraph receives a string; the actual dict result is independently captured
    inside :class:`~agentauthz.targets.otel_instrumentation.InstrumentedToolbox` via the OTel span
    attribute, so the evaluator always sees the raw dict regardless of the string content.
    """
    itb = InstrumentedToolbox(store, session_customer_id, tracer)

    def agent_node(state: _AgentAuthZState) -> dict:
        """Run the model for one LLM turn; enforce the max_steps bound.

        Reads ``step_count`` from state (defaults to 0 if absent).  When the budget is
        exhausted, returns a final ``AIMessage(content="")`` without calling the model —
        matching the hand-written Agent's bounded-termination at ``max_steps``.
        """
        step = state.get("step_count", 0)
        if step >= max_steps:
            # max_steps exhausted: return a terminal empty message, no model call.
            return {"messages": [AIMessage(content="")], "step_count": step + 1}
        response = model.invoke(state["messages"])
        return {"messages": [response], "step_count": step + 1}

    def tools_node(state: _AgentAuthZState) -> dict:
        """Forward each pending ``tool_call`` to the toolbox with its RAW name + args dict.

        Reads the pending tool calls off the last message and delegates each to
        ``InstrumentedToolbox.call`` with the LLM-emitted ``name`` and ``args`` UNCHANGED — no
        pydantic schema, no coercion, no key filtering.  Envelope fields (``name`` / ``args`` /
        ``id``) are read with ``.get`` so a malformed ``tool_call`` cannot crash the node: a
        missing ``args`` forwards ``None``, which the toolbox rejects with a structured
        ``arguments must be an object`` error exactly as the hand-written loop would — the
        toolbox owns ALL argument validation, fail-closed.

        On the FIRST over-budget call (``executed_tool_count >= max_tool_calls``): emits
        exactly ONE "tool-call budget exhausted" ToolMessage, skips ALL remaining tool_calls,
        and sets ``budget_exhausted=True``.  The conditional edge on ``tools`` routes to
        ``END`` when this flag is set — terminating the graph immediately, mirroring the
        hand-written Agent's immediate ``return ""`` on the first over-budget call.
        """
        last = state["messages"][-1]
        tool_calls = getattr(last, "tool_calls", None) or []
        executed = state.get("executed_tool_count", 0)
        out = []
        exhausted = False
        for tc in tool_calls:
            if executed >= max_tool_calls:
                # Budget exhausted: emit exactly ONE error ToolMessage, skip the rest.
                budget_result: dict = {
                    "status": "error",
                    "reason": "tool-call budget exhausted",
                }
                out.append(
                    ToolMessage(
                        content=json.dumps(budget_result, default=str),
                        name=str(tc.get("name")),
                        tool_call_id=str(tc.get("id")),
                    )
                )
                exhausted = True
                break  # Mirror Agent.run: stop on the FIRST over-budget call, not the rest.
            result = itb.call(tc.get("name"), tc.get("args"))
            executed += 1
            out.append(
                ToolMessage(
                    content=json.dumps(result, default=str),
                    name=str(tc.get("name")),
                    tool_call_id=str(tc.get("id")),
                )
            )
        return {"messages": out, "executed_tool_count": executed, "budget_exhausted": exhausted}

    def _tools_route(state: _AgentAuthZState) -> str:
        """Route to END when the tool-call budget is exhausted; otherwise back to agent."""
        return END if state.get("budget_exhausted", False) else "agent"

    g = StateGraph(_AgentAuthZState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tools_node)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", tools_condition)
    g.add_conditional_edges("tools", _tools_route)
    return g.compile()


def build_ollama_model(model_name: str = "llama3.2") -> Any:
    """Build a local ``ChatOllama`` for the ``--live`` path (NOT used by the test suite).

    The deterministic/offline suite drives the agent node with a scripted
    ``FakeMessagesListChatModel`` and captures the trace with an in-memory OTel exporter,
    so it never touches the network.  ``build_ollama_model`` is the escape hatch a human
    uses to run the SAME LangGraph target against a real local model — exercising the live
    LLM only outside pytest.

    ``langchain_ollama`` is imported lazily here so the test suite (which never calls this
    function) has zero import-time dependency on the Ollama library.
    """
    from langchain_ollama import ChatOllama  # noqa: PLC0415 — lazy: --live only

    return ChatOllama(model=model_name)
