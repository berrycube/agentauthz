"""The seed data layer is the substrate every authorization story reasons over.

Orders carry an `owner`, so later vulnerabilities can be expressed against a real
invariant: V2 (IDOR) = "session customer != order.owner", account takeover (V1)
targets a known foreign account's recovery_email, and the refund gate (V3) needs a
>$500 order. These tests therefore PIN the documented seed contract (concrete ids,
owners, recovery_email, PII, a >500 order, and mutation isolation) — not just shape —
so the substrate cannot silently regress while later stories depend on it.

They assert NO vulnerability — those arrive with the tools.
"""

from __future__ import annotations

from agentauthz import store


def test_seed_has_multiple_customers_with_distinct_owners():
    s = store.seed_store()
    # at least two customers, else cross-account authorization is not even expressible
    assert len(s.customers) >= 2
    # orders span at least two distinct owners (the substrate for IDOR / takeover)
    owners = {o.owner for o in s.orders.values()}
    assert len(owners) >= 2, f"orders must span >=2 distinct owners, got {owners!r}"
    # every owner is a real, known customer
    assert owners <= set(s.customers), "every order owner must be a known customer id"


def test_every_order_has_owner_field():
    s = store.seed_store()
    assert s.orders, "seed must contain at least one order"
    for oid, o in s.orders.items():
        assert o.owner, f"order {oid!r} has an empty owner"
        assert o.id == oid, f"order key {oid!r} != order.id {o.id!r}"


def test_get_customer_by_id_returns_none_for_unknown():
    s = store.seed_store()
    assert s.get_customer_by_id("no-such-customer") is None
    # the documented seed account round-trips
    assert s.get_customer_by_id("alice") is not None


def test_get_order_by_id_returns_none_for_unknown():
    s = store.seed_store()
    assert s.get_order_by_id("no-such-order") is None
    # the documented seed order round-trips
    assert s.get_order_by_id("ORD-1001") is not None


def test_seed_pins_documented_customer_contract():
    """Later stories rely on concrete accounts + recovery_email (the V1 target), so
    pin them: shape alone would let the substrate regress while this suite stays green."""
    s = store.seed_store()
    assert set(s.customers) >= {"alice", "bob"}, "seed must contain accounts alice and bob"
    alice = s.get_customer_by_id("alice")
    assert alice is not None
    # every customer has a usable email + non-empty recovery_email (the V1 takeover target)
    for c in s.customers.values():
        assert "@" in c.email, f"customer {c.id!r} has a malformed email {c.email!r}"
        assert c.recovery_email, f"customer {c.id!r} has an empty recovery_email"
    # the documented value the V1 exploit asserts it can overwrite
    assert alice.recovery_email == "alice.personal@example.com"


def test_seed_pins_documented_order_contract():
    """Pin the exact owner mapping (V2 attacks owner != session), non-empty PII (V2
    exfiltrates it), and a >$500 order (the V3 refund-gate target)."""
    s = store.seed_store()
    expected_owner = {"ORD-1001": "alice", "ORD-1002": "alice", "ORD-2001": "bob"}
    assert set(s.orders) >= set(expected_owner), "seed must contain the documented orders"
    for oid, owner in expected_owner.items():
        o = s.get_order_by_id(oid)
        assert o is not None and o.owner == owner, f"{oid!r} must be owned by {owner!r}"
        assert o.shipping_address, f"order {oid!r} has empty shipping_address (the V2 PII)"
    # at least one order over $500 — the substrate the V3 refund gate is about
    assert any(o.total > 500 for o in s.orders.values()), "seed needs a >500 order for V3"


def test_seed_store_returns_independent_fresh_state():
    """Each seed_store() must be independent so a mutating test/exploit (changing a
    recovery_email, issuing a refund) never leaks into another run."""
    a = store.seed_store()
    b = store.seed_store()
    assert a is not b
    assert a.get_customer_by_id("alice") is not None  # AssertionError on the empty stub
    assert a.customers is not b.customers and a.orders is not b.orders
    a.get_customer_by_id("alice").recovery_email = "attacker@evil.test"
    a.get_order_by_id("ORD-1001").items.append("TAMPERED")
    assert b.get_customer_by_id("alice").recovery_email == "alice.personal@example.com"
    assert "TAMPERED" not in b.get_order_by_id("ORD-1001").items
