"""The agent: a tool-calling loop holding an authenticated-customer session,
driven by an INJECTABLE LLM client.

Tests use a deterministic, offline scripted fake LLM — no network, no real LLM in the
suite. A real LLM is used only in exploit ``--live`` mode, never here.
"""

from __future__ import annotations

import socket

from agentauthz import config
from agentauthz.agent import Agent, LLMResponse, ToolCall
from agentauthz.fakes import FakeLLM
from agentauthz.store import seed_store


def _script(*responses: LLMResponse) -> FakeLLM:
    return FakeLLM(list(responses))


def test_agent_runs_tool_calling_loop_with_fake_llm():
    store = seed_store()
    fake = _script(
        LLMResponse(tool_calls=[ToolCall("get_order", {"order_id": "ORD-2001"})], content=None),
        LLMResponse(tool_calls=[], content="Your order ORD-2001 is on its way."),
    )
    agent = Agent(fake, store, session_customer_id="bob")
    result = agent.run("where is my order ORD-2001?")
    assert result == "Your order ORD-2001 is on its way."
    # the loop actually executed the emitted tool call (recorded in the transcript)
    assert any(step["tool"] == "get_order" for step in agent.transcript)


def test_agent_exposes_session_customer_context():
    store = seed_store()
    agent = Agent(_script(LLMResponse([], "hi")), store, session_customer_id="alice")
    assert agent.session_customer_id == "alice"
    # the tools act AS this authenticated session (the substrate the authz vulns are about)
    assert agent.toolbox.session_customer_id == "alice"


def test_agent_executes_tool_calls_emitted_by_fake_llm():
    # the agent really invokes the tool the fake emits — observable store side effect
    store = seed_store()
    fake = _script(
        LLMResponse(
            [ToolCall("update_recovery_email", {"account_id": "alice", "new_email": "x@y.z"})],
            None,
        ),
        LLMResponse([], "done"),
    )
    agent = Agent(fake, store, session_customer_id="bob")
    agent.run("please change it")
    assert store.get_customer_by_id("alice").recovery_email == "x@y.z"


def test_fake_llm_is_deterministic_and_offline(monkeypatch):
    # OFFLINE: any socket creation during the run is a hard failure (the invariant).
    def _no_network(*args, **kwargs):
        raise AssertionError("network access attempted — the test suite must be offline")

    monkeypatch.setattr(socket, "socket", _no_network)
    script = (
        LLMResponse([ToolCall("get_order", {"order_id": "ORD-1001"})], None),
        LLMResponse([], "ok"),
    )
    # DETERMINISTIC: identical scripts -> identical output sequences
    a = FakeLLM(list(script))
    b = FakeLLM(list(script))
    assert [a.complete([], []) for _ in script] == [b.complete([], []) for _ in script]
    # and the whole agent loop runs to completion with no network at all
    agent = Agent(FakeLLM(list(script)), seed_store(), session_customer_id="bob")
    assert agent.run("hi") == "ok"


def test_config_reads_model_from_env_with_default(monkeypatch):
    monkeypatch.delenv(config.LLM_MODEL_ENV, raising=False)
    assert config.get_model() == config.DEFAULT_LLM_MODEL
    monkeypatch.setenv(config.LLM_MODEL_ENV, "my-custom-model")
    assert config.get_model() == "my-custom-model"


# ---- orthogonal hardening (the agent itself ships no vulnerability) ---- #


def test_agent_loop_is_bounded_against_a_runaway_llm():
    # an LLM that ONLY ever emits tool calls must not loop forever — bounded by max_steps.
    store = seed_store()

    class _Runaway:
        def complete(self, messages, tools):
            return LLMResponse([ToolCall("get_order", {"order_id": "ORD-1001"})], None)

    agent = Agent(_Runaway(), store, session_customer_id="alice", max_steps=3)
    result = agent.run("loop forever")
    assert len(agent.transcript) <= 3, "the loop ran away past max_steps"
    assert isinstance(result, str)  # bounded termination returns a string, never hangs


def test_agent_caps_total_tool_executions_in_one_turn():
    # Under the threat model the LLM controls how many tool calls a SINGLE turn emits.
    # max_steps bounds turns, not executions, so a flooded turn must still be capped by a
    # per-run tool-call budget — else hundreds of calls run before the loop guard re-checks.
    store = seed_store()
    flood = [ToolCall("get_order", {"order_id": "ORD-2001"}) for _ in range(100)]
    fake = _script(LLMResponse(flood, None), LLMResponse([], "done"))
    agent = Agent(fake, store, session_customer_id="bob", max_tool_calls=5)
    agent.run("flood the tools")
    executed = [s for s in agent.transcript if s.get("tool") == "get_order"]
    assert 0 < len(executed) <= 5, f"tool executions must be capped at 5, got {len(executed)}"


def test_agent_feeds_tool_errors_back_without_crashing():
    # a malformed tool call from the LLM must NOT crash the loop; the structured tool
    # error is fed back and the agent can still finish.
    store = seed_store()
    fake = _script(
        LLMResponse([ToolCall("get_order", {})], None),  # missing required arg -> tool error
        LLMResponse([], "handled"),
    )
    agent = Agent(fake, store, session_customer_id="bob")
    assert agent.run("oops") == "handled"
    assert any(
        isinstance(step["result"], dict) and step["result"].get("status") == "error"
        for step in agent.transcript
    )


def test_agent_feeds_string_content_back_to_a_strict_llm():
    # A strict chat client requires STRING message content. The agent must serialize tool
    # results (successes AND structured errors) to strings before feeding them back, and
    # still take a follow-up turn — proving the fail-closed feedback path for a REAL client,
    # not relying on FakeLLM ignoring messages. Covers unknown-tool + missing-arg calls.
    store = seed_store()

    class _StrictSpy:
        def __init__(self):
            self.turns = 0

        def complete(self, messages, tools):
            for m in messages:
                assert isinstance(m["content"], str), f"non-string content fed to LLM: {m!r}"
            self.turns += 1
            if self.turns == 1:
                return LLMResponse([ToolCall("no_such_tool", {}), ToolCall("get_order", {})], None)
            return LLMResponse([], "recovered")

    spy = _StrictSpy()
    agent = Agent(spy, store, session_customer_id="bob")
    assert agent.run("strict client") == "recovered"
    assert spy.turns == 2  # the error feedback produced a real second turn, no crash
