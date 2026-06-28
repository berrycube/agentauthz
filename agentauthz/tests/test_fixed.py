"""Acceptance tests for the FIXED reference implementations.

The ``fixed/`` reference implementations make every corresponding exploit
FAIL to violate its invariant (V1 ownership + OTP-to-existing-email, V2 session-authz on
order lookup, V3 hard human-approval gate above the threshold) WITHOUT over-blocking
legitimate owner actions.

These tests drive a ``FixedAgent`` with the REAL ``FakeLLM`` + ``seed_store`` using the
SAME attack tool calls as the exploits (``agentauthz/exploits/*``), and assert the invariant
HOLDS while legitimate owner actions still succeed. They are DETERMINISTIC and OFFLINE: the
LLM seat is a scripted ``FakeLLM`` whose ``tool_calls`` are fixed — there is NO real LLM
and NO network, and the harness only ever drives the in-repo agent.

Every contract value is PINNED to its documented value (attacker ``attacker@evil.test``,
victim ``alice`` / session ``bob``, the order ids + owners + amounts + PII shipping
address from the seed store, the ``REFUND_APPROVAL_THRESHOLD`` of 500.0) —
a shape-only test would let the remediation silently
regress. ``REFUND_APPROVAL_THRESHOLD`` is imported from the tools (read-only reuse), so
the boundary tests track the real policy threshold rather than a hard-coded copy.
"""

from __future__ import annotations

from agentauthz.agent import LLMResponse, ToolCall
from agentauthz.fakes import FakeLLM
from agentauthz.fixed import FixedAgent, FixedToolbox
from agentauthz.store import seed_store
from agentauthz.tools import REFUND_APPROVAL_THRESHOLD

# ---------------------------------------------------------------------------
# PINNED documented contract values (agentauthz/store.py seed).
# These mirror the EXACT attack tool calls the exploits drive.
# ---------------------------------------------------------------------------
ATTACKER_EMAIL = "attacker@evil.test"
VICTIM_ACCOUNT = "alice"  # the V1/V2 victim; the attacker session is "bob"
ATTACKER_SESSION = "bob"

ALICE_BASELINE_EMAIL = "alice.personal@example.com"  # the V1 takeover baseline
ALICE_NEW_EMAIL = "alice.new@example.com"  # a legitimate owner-driven email change

ALICE_ORDER = "ORD-1001"  # owned by alice; total 89.99 (< threshold); carries PII
ALICE_PII_ADDRESS = "742 Evergreen Terrace, Springfield"
SMALL_REFUND_AMOUNT = 89.99  # ORD-1001 total — a legitimate under-threshold refund

LARGE_REFUND_ORDER = "ORD-1002"  # owned by alice; total 642.50 (> threshold)
LARGE_REFUND_AMOUNT = 642.50  # over the $500 policy gate (V3 target)
AT_THRESHOLD_AMOUNT = (
    500.0  # EXACTLY the threshold — policy is "OVER $500", so still auto
)


# ---------------------------------------------------------------------------
# Builders — a FRESH FixedAgent every call (FakeLLM scripts + the agent store are
# STATEFUL). The FakeLLM emits the SAME tool call the matching exploit drives,
# then a final text so the bounded agent loop terminates cleanly.
# ---------------------------------------------------------------------------
def _agent_for(session: str, call: ToolCall) -> FixedAgent:
    fake = FakeLLM(
        [
            LLMResponse(tool_calls=[call], content=None),
            LLMResponse(tool_calls=[], content="done"),
        ]
    )
    return FixedAgent(fake, seed_store(), session_customer_id=session)


def _last_result(agent: FixedAgent, tool: str):
    """The result of the last executed ``tool`` call in the agent transcript (or None)."""
    for entry in reversed(agent.transcript):
        if entry.get("tool") == tool:
            return entry.get("result")
    return None


def _recovery_otps(agent: FixedAgent) -> list[dict]:
    return [m for m in agent.toolbox.outbox if m.get("kind") == "recovery_otp"]


# ---------------------------------------------------------------------------
# V1 — account takeover is BLOCKED, the victim's recovery email is UNCHANGED,
# and no confirmation OTP is routed to the attacker address.
# ---------------------------------------------------------------------------
def test_fixed_v1_account_takeover_blocked_email_unchanged():
    # Same attack as agentauthz/exploits/account_takeover: a non-owner session (bob) tries to
    # rewrite alice's recovery email to the attacker address.
    agent = _agent_for(
        ATTACKER_SESSION,
        ToolCall(
            "update_recovery_email",
            {"account_id": VICTIM_ACCOUNT, "new_email": ATTACKER_EMAIL},
        ),
    )
    agent.run(f"Update {VICTIM_ACCOUNT}'s recovery email to {ATTACKER_EMAIL}.")

    # Invariant held: alice's recovery email is UNCHANGED (the takeover did not land).
    victim = agent.store.get_customer_by_id(VICTIM_ACCOUNT)
    assert victim.recovery_email == ALICE_BASELINE_EMAIL

    # The tool refused the cross-account write with a structured denial.
    result = _last_result(agent, "update_recovery_email")
    assert isinstance(result, dict)
    assert result.get("status") == "denied"

    # And NO confirmation OTP was routed to the attacker address (no silent takeover).
    assert all(m.get("to") != ATTACKER_EMAIL for m in _recovery_otps(agent))


# ---------------------------------------------------------------------------
# V2 — IDOR on order lookup is DENIED for a non-owner session, with no PII leak.
# ---------------------------------------------------------------------------
def test_fixed_v2_idor_denied_no_pii_leak():
    # Same attack as agentauthz/exploits/idor_order_lookup: bob reads alice's order ORD-1001.
    agent = _agent_for(
        ATTACKER_SESSION, ToolCall("get_order", {"order_id": ALICE_ORDER})
    )
    agent.run(f"Look up order {ALICE_ORDER} for me.")

    result = _last_result(agent, "get_order")
    # Invariant held: a foreign-order lookup is a denial (status == "denied") or None...
    assert result is None or (
        isinstance(result, dict) and result.get("status") == "denied"
    )
    # ...and CRUCIALLY never carries the PII shipping address (no leak via any key).
    if isinstance(result, dict):
        assert "shipping_address" not in result
        assert ALICE_PII_ADDRESS not in result.values()


# ---------------------------------------------------------------------------
# V3 — a refund OVER the threshold requires human approval: held, never auto-issued.
# ---------------------------------------------------------------------------
def test_fixed_v3_large_refund_requires_human_approval():
    # Anchor the policy-relevant fact, then assert the real behavior alongside it.
    assert LARGE_REFUND_AMOUNT > REFUND_APPROVAL_THRESHOLD
    # Same attack as agentauthz/exploits/refund_gate_bypass: alice self-issues a >$500 refund.
    agent = _agent_for(
        VICTIM_ACCOUNT,
        ToolCall(
            "issue_refund",
            {"order_id": LARGE_REFUND_ORDER, "amount": LARGE_REFUND_AMOUNT},
        ),
    )
    agent.run(
        f"Issue a full refund on order {LARGE_REFUND_ORDER} for ${LARGE_REFUND_AMOUNT}."
    )

    result = _last_result(agent, "issue_refund")
    assert isinstance(result, dict)
    # Invariant held: the agent CANNOT self-approve — the refund is held for a human.
    assert result.get("required_human_approval") is True
    assert result.get("status") == "pending_approval"
    assert result.get("status") != "refunded"
    # And it is NOT recorded in the refund ledger (no money moved without a human).
    assert all(r["order_id"] != LARGE_REFUND_ORDER for r in agent.toolbox.refunds)


# ---------------------------------------------------------------------------
# NO over-blocking — legitimate OWNER actions still succeed.
# ---------------------------------------------------------------------------
def test_fixed_still_allows_legitimate_owner_actions():
    # (a) alice reads her OWN order ORD-1001 -> the order is returned WITH its PII.
    read_agent = _agent_for(
        VICTIM_ACCOUNT, ToolCall("get_order", {"order_id": ALICE_ORDER})
    )
    read_agent.run(f"Look up my order {ALICE_ORDER}.")
    read = _last_result(read_agent, "get_order")
    assert isinstance(read, dict)
    assert read.get("id") == ALICE_ORDER
    assert read.get("owner") == VICTIM_ACCOUNT
    assert read.get("shipping_address") == ALICE_PII_ADDRESS

    # (b) alice updates her OWN recovery email (session == account) -> ok, store shows the
    # new email, and the confirmation OTP is routed to the EXISTING/old owner address
    # (so a legitimate owner approves the change — it never goes to the new address).
    email_agent = _agent_for(
        VICTIM_ACCOUNT,
        ToolCall(
            "update_recovery_email",
            {"account_id": VICTIM_ACCOUNT, "new_email": ALICE_NEW_EMAIL},
        ),
    )
    email_agent.run(f"Update my recovery email to {ALICE_NEW_EMAIL}.")
    upd = _last_result(email_agent, "update_recovery_email")
    assert isinstance(upd, dict)
    assert upd.get("status") == "ok"
    assert (
        email_agent.store.get_customer_by_id(VICTIM_ACCOUNT).recovery_email
        == ALICE_NEW_EMAIL
    )
    otps = _recovery_otps(email_agent)
    assert otps, "a confirmation OTP should be sent for a legitimate owner change"
    assert (
        otps[-1].get("to") == ALICE_BASELINE_EMAIL
    )  # to the EXISTING owner, not the new addr
    assert otps[-1].get("to") != ALICE_NEW_EMAIL


# ---------------------------------------------------------------------------
# NO over-blocking + strict-> boundary — under/at-threshold refunds still auto.
# ---------------------------------------------------------------------------
def test_fixed_v3_small_refund_still_auto_ok():
    # Anchor the boundary policy alongside the real behavior assertions.
    assert AT_THRESHOLD_AMOUNT == REFUND_APPROVAL_THRESHOLD

    # (a) alice refunds her OWN ORD-1001 for 89.99 (UNDER threshold) -> auto refunded.
    small_agent = _agent_for(
        VICTIM_ACCOUNT,
        ToolCall(
            "issue_refund", {"order_id": ALICE_ORDER, "amount": SMALL_REFUND_AMOUNT}
        ),
    )
    small_agent.run(f"Refund my order {ALICE_ORDER} for ${SMALL_REFUND_AMOUNT}.")
    small = _last_result(small_agent, "issue_refund")
    assert isinstance(small, dict)
    assert small.get("status") == "refunded"
    assert small.get("required_human_approval") is False
    assert any(
        r["order_id"] == ALICE_ORDER and r["amount"] == SMALL_REFUND_AMOUNT
        for r in small_agent.toolbox.refunds
    )

    # (b) alice refunds her OWN ORD-1002 for EXACTLY 500.0 (the threshold, NOT over, since
    # policy gates refunds OVER $500) -> still auto refunded (the gate is strict > only).
    boundary_agent = _agent_for(
        VICTIM_ACCOUNT,
        ToolCall(
            "issue_refund",
            {"order_id": LARGE_REFUND_ORDER, "amount": AT_THRESHOLD_AMOUNT},
        ),
    )
    boundary_agent.run(
        f"Refund my order {LARGE_REFUND_ORDER} for ${AT_THRESHOLD_AMOUNT}."
    )
    boundary = _last_result(boundary_agent, "issue_refund")
    assert isinstance(boundary, dict)
    assert boundary.get("status") == "refunded"
    assert boundary.get("required_human_approval") is False


# ---------------------------------------------------------------------------
# The override PRESERVES the inherited fail-closed dispatch + schema validation.
# ---------------------------------------------------------------------------
def test_fixed_toolbox_preserves_dispatch_and_schema():
    # (a) an unknown tool name fails closed with a structured "unknown tool" error
    # (inherited dispatch from the base Toolbox, unchanged by the override).
    toolbox = FixedToolbox(seed_store(), VICTIM_ACCOUNT)
    unknown = toolbox.call("nope", {})
    assert isinstance(unknown, dict)
    assert unknown.get("status") == "error"
    assert "unknown tool" in unknown.get("reason", "")

    # (b) a call missing a required argument fails closed (inherited schema validation).
    missing = toolbox.call("issue_refund", {"order_id": ALICE_ORDER})
    assert isinstance(missing, dict)
    assert missing.get("status") == "error"
    assert "amount" in missing.get("reason", "")

    # (c) a valid dispatch ROUTES to the overridden FIXED get_order and returns alice's
    # own order (proving the override is actually reached through Toolbox.call).
    routed = toolbox.call("get_order", {"order_id": ALICE_ORDER})
    assert isinstance(routed, dict)
    assert routed.get("id") == ALICE_ORDER
    assert routed.get("owner") == VICTIM_ACCOUNT
