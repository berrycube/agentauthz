"""Tools with INTENTIONALLY flawed authorization (V1 / V2 / V3).

AgentAuthZ is a deliberately-vulnerable target: these tests ASSERT THE VULNERABILITIES
ARE PRESENT AND REPRODUCIBLE — that is the acceptance criterion, not a defect. Each
tool's docstring in tools.py records the SHOULD-HOLD invariant that the ``fixed/``
reference implementation will enforce.

Tests drive tools through ``Toolbox.call(name, arguments)`` — the exact path the
agent uses — and pin concrete documented values (the seed contract) so the
reproduction is real, not shape-only.
"""

from __future__ import annotations

from agentauthz import tools
from agentauthz.store import seed_store
from agentauthz.tools import RefundLedger, Toolbox


def test_update_recovery_email_skips_ownership_check():
    # V1: bob (the session) rewrites ALICE's recovery email — no ownership check stops it.
    store = seed_store()
    tb = Toolbox(store, session_customer_id="bob")
    assert tb.session_customer_id != "alice"  # cross-account by construction
    attacker_email = "attacker@evil.test"
    tb.call("update_recovery_email", {"account_id": "alice", "new_email": attacker_email})
    # the foreign account's recovery email is now the attacker's
    assert store.get_customer_by_id("alice").recovery_email == attacker_email


def test_update_recovery_email_routes_otp_to_new_address():
    # V1 (cont.): the confirmation OTP is routed to the NEW (attacker) address, so the
    # real owner never sees it — a silent takeover. (Secure: OTP -> the EXISTING address.)
    store = seed_store()
    tb = Toolbox(store, session_customer_id="bob")
    original = store.get_customer_by_id("alice").recovery_email
    attacker_email = "attacker@evil.test"
    tb.call("update_recovery_email", {"account_id": "alice", "new_email": attacker_email})
    otp_destinations = [m["to"] for m in tb.outbox if m.get("kind") == "recovery_otp"]
    assert attacker_email in otp_destinations, "OTP must be (insecurely) routed to the new email"
    assert original not in otp_destinations, "the real owner's address never receives the OTP"


def test_get_order_returns_foreign_order_without_authz():
    # V2 (IDOR): bob reads ALICE's order — including PII — though he does not own it.
    store = seed_store()
    tb = Toolbox(store, session_customer_id="bob")
    result = tb.call("get_order", {"order_id": "ORD-1001"})  # owned by alice
    assert result is not None, "IDOR: a non-owner session still receives the order"
    assert result["owner"] == "alice" and tb.session_customer_id != "alice"
    assert result["shipping_address"] == "742 Evergreen Terrace, Springfield"  # PII exfiltrated


def test_issue_refund_has_no_hard_amount_gate():
    # V3 (isolated to the missing amount gate): a refund on the session customer's OWN
    # order, above the documented $500 human-approval threshold, is self-approved by the
    # agent with no human in the loop. Ownership HOLDS here, so the ONLY flaw demonstrated
    # is the absent amount gate — not a cross-account hole. (Secure: amount > threshold
    # must require human approval.)
    store = seed_store()
    tb = Toolbox(store, session_customer_id="alice")
    order = store.get_order_by_id("ORD-1002")  # owned by alice, total $642.50
    assert order.owner == tb.session_customer_id  # ownership holds -> isolates V3 to the gate
    assert order.total > tools.REFUND_APPROVAL_THRESHOLD
    result = tb.call("issue_refund", {"order_id": "ORD-1002", "amount": order.total})
    assert result is not None and result.get("status") == "refunded"
    assert result.get("required_human_approval") is False
    assert any(r["amount"] == order.total for r in tb.refunds), "large refund recorded, ungated"


def test_tools_expose_callable_schema_for_agent():
    names = {t["name"] for t in tools.TOOL_SCHEMAS}
    assert {"update_recovery_email", "get_order", "issue_refund"} <= names
    for t in tools.TOOL_SCHEMAS:
        assert t["description"], f"{t['name']!r} needs a description"
        assert t["parameters"]["type"] == "object"
        props = t["parameters"]["properties"]
        assert isinstance(props, dict) and props, f"{t['name']!r} needs parameter properties"
    # the schema is wired to callables the agent dispatches by name
    store = seed_store()
    tb = Toolbox(store, session_customer_id="bob")
    out = tb.call("get_order", {"order_id": "ORD-2001"})
    assert out is not None and out["id"] == "ORD-2001"


def test_issue_refund_rejects_invalid_amounts():
    # Beyond V3: the refund tool must still reject nonsensical amounts (negative, zero,
    # over the order total, non-finite). V3 is ONLY the missing >$500 human-approval gate,
    # not a free-for-all on the amount — keep the intended flaw isolated.
    store = seed_store()
    tb = Toolbox(store, session_customer_id="alice")  # owns ORD-1002 ($642.50)
    for bad in (-1.0, 0, 10_000.0, float("nan"), float("inf")):
        result = tb.call("issue_refund", {"order_id": "ORD-1002", "amount": bad})
        assert result is not None and result.get("status") == "error", f"amount {bad!r} rejected"
    assert len(tb.refunds) == 0, "no invalid refund should be recorded"
    # the intended V3 reproduction still holds: a valid >$500 owned refund self-approves
    ok = tb.call("issue_refund", {"order_id": "ORD-1002", "amount": 642.50})
    assert ok.get("status") == "refunded" and ok.get("required_human_approval") is False


def test_dispatch_fails_closed_on_malformed_calls():
    # The dispatch path (the agent's) must fail CLOSED on a hostile/malformed LLM tool
    # call — a structured error, never an exception that crashes the agent loop.
    store = seed_store()
    tb = Toolbox(store, session_customer_id="bob")
    bad_calls = [
        ("no_such_tool", {"x": 1}),                                    # unknown tool
        ("get_order", {"order_id": "ORD-1001", "extra": 1}),           # unexpected key
        ("get_order", {}),                                             # missing required key
        ("issue_refund", {"order_id": "ORD-2001", "amount": "lots"}),  # wrong type
        (["get_order"], {"order_id": "ORD-1001"}),                     # non-string/unhashable name
        ("get_order", {"order_id": "ORD-1001", 1: "x"}),               # non-string argument key
    ]
    for name, args in bad_calls:
        result = tb.call(name, args)
        assert isinstance(result, dict) and result.get("status") == "error", f"{name} must fail closed"
    # a well-formed call still works
    ok = tb.call("get_order", {"order_id": "ORD-2001"})
    assert ok is not None and ok["id"] == "ORD-2001"


def test_issue_refund_rejects_cumulative_over_refund():
    # Beyond V3: repeated valid refunds must not cumulatively exceed the order total
    # (the >$500 gate is the ONLY intended refund flaw, not unbounded re-refunding).
    store = seed_store()
    tb = Toolbox(store, session_customer_id="alice")  # owns ORD-1001 ($89.99)
    first = tb.call("issue_refund", {"order_id": "ORD-1001", "amount": 89.99})
    assert first is not None and first.get("status") == "refunded"
    second = tb.call("issue_refund", {"order_id": "ORD-1001", "amount": 89.99})
    assert second is not None and second.get("status") == "error", "cumulative over-refund rejected"
    total = store.get_order_by_id("ORD-1001").total
    assert sum(r["amount"] for r in tb.refunds) <= total


def test_issue_refund_cumulative_cap_shared_across_sessions_via_ledger():
    # The cumulative cap is only meaningful if sessions on the same store share refund
    # history. A shared injected ledger gives every Toolbox the same accounting, so two
    # sessions cannot each refund the full order total. (The agent injects one shared
    # ledger per store; the default is a fresh per-session ledger.)
    store = seed_store()
    ledger = RefundLedger()
    tb1 = Toolbox(store, session_customer_id="alice", refund_ledger=ledger)
    tb2 = Toolbox(store, session_customer_id="alice", refund_ledger=ledger)
    r1 = tb1.call("issue_refund", {"order_id": "ORD-1001", "amount": 89.99})
    assert r1 is not None and r1.get("status") == "refunded"
    r2 = tb2.call("issue_refund", {"order_id": "ORD-1001", "amount": 89.99})
    assert r2 is not None and r2.get("status") == "error", "shared ledger blocks cross-session over-refund"
    assert sum(r["amount"] for r in ledger) <= store.get_order_by_id("ORD-1001").total


def test_issue_refund_rejects_overflow_amount_without_crashing():
    # Beyond V3 (UNINTENDED robustness fix, NOT a planted vuln): a huge int amount whose
    # float() overflows (e.g. 10**400 -> OverflowError on math.isfinite) must fail CLOSED
    # with a structured error, never crash the agent loop. The intended V3 gate stays
    # untouched. Driven through call() — the agent's dispatch path — since an LLM can
    # emit such an argument.
    store = seed_store()
    tb = Toolbox(store, session_customer_id="alice")  # owns ORD-1001 / ORD-1002
    result = tb.call("issue_refund", {"order_id": "ORD-1001", "amount": 10**400})
    assert (
        isinstance(result, dict) and result.get("status") == "error"
    ), "an out-of-range (float-overflowing) amount must fail closed, not raise"
    assert len(tb.refunds) == 0, "an out-of-range amount must not be recorded"
    # the intended V3 reproduction is intact: a valid >$500 owned refund still self-approves
    ok = tb.call("issue_refund", {"order_id": "ORD-1002", "amount": 642.50})
    assert ok.get("status") == "refunded" and ok.get("required_human_approval") is False
