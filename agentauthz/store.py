"""AgentAuthZ seed data layer.

The substrate every later authorization story reasons over. Two things matter:

* every ``Order`` carries an ``owner`` (a customer id), so authorization can be
  stated as an invariant ("the session customer must own the order"); the
  tools then deliberately VIOLATE that invariant (IDOR / takeover / refund gate).
* ``Customer`` carries a ``recovery_email`` — the field the V1 account-takeover
  exploit rewrites.

``seed_store()`` returns a FRESH, independent ``Store`` on every call, so a test or
exploit that mutates state (e.g. changes a recovery email, issues a refund) never
leaks into another. The seed is small and fully documented (known ids
``alice`` / ``bob`` / ``ORD-1001`` …) so the whole repo is reproducible by reading it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Customer:
    """A customer account. ``recovery_email`` is the V1 takeover target; ``org`` is the
    organization (tenant) the customer belongs to — the boundary the cross-tenant
    isolation invariant (V5) is about: an org-level resource is readable only by members
    of that org. Defaults so existing constructions stay valid; the seed sets it."""

    id: str
    name: str
    email: str
    recovery_email: str
    org: str = "unknown-org"
    account_credit: float = 0.0  # V6: credit applied by redeeming a coupon


@dataclass
class Order:
    """An order. ``owner`` is the customer id the authz invariant is about;
    ``shipping_address`` is the PII the V2 IDOR exploit exfiltrates; ``status`` is the
    order-lifecycle state the V4 state-machine invariant is about — only a ``'pending'``
    order may be cancelled, while a ``'delivered'`` / ``'shipped'`` order is FINALIZED
    and must NOT be cancellable (the ``fixed/`` reference enforces that gate)."""

    id: str
    owner: str
    items: list[str]
    total: float
    shipping_address: str
    status: str


@dataclass
class OrgAccount:
    """An organization-level billing account — the cross-tenant (V5) target.

    It belongs to a TENANT (``org_id``), not a customer, and carries sensitive
    financials (``balance_due`` / ``payment_method_last4`` / ``tax_id``). The invariant:
    only a member of ``org_id`` may read it; the V5 vulnerable ``get_org_account`` tool
    returns ANY org's account with no membership check (the ``fixed/`` reference
    enforces it)."""

    org_id: str
    billing_email: str
    balance_due: float
    payment_method_last4: str
    tax_id: str


@dataclass
class Coupon:
    """A single-use promo coupon — the one-time-limit (V6) target. Redeeming it adds
    ``value`` to a customer's ``account_credit``; the invariant is that a customer may
    redeem a given coupon AT MOST ONCE (the vulnerable ``redeem_coupon`` lets the same code
    be replayed, stacking the credit; the ``fixed/`` reference enforces single-use)."""

    code: str
    value: float


@dataclass
class Store:
    """In-memory datastore: customers + orders + org-level accounts + coupons, keyed by id."""

    customers: dict[str, Customer]
    orders: dict[str, Order]
    org_accounts: dict[str, OrgAccount] = field(default_factory=dict)
    coupons: dict[str, Coupon] = field(default_factory=dict)
    # code -> the list of customer ids who have already redeemed it (the persistent record
    # the FIXED redeem_coupon enforces single-use against; the VULN tool ignores it).
    coupon_redemptions: dict[str, list[str]] = field(default_factory=dict)

    def get_coupon_by_code(self, code: str) -> Coupon | None:
        """Return the coupon with this code, or ``None`` if there is no such coupon."""
        return self.coupons.get(code)

    def get_customer_by_id(self, customer_id: str) -> Customer | None:
        """Return the customer with this id, or ``None`` if there is no such account."""
        return self.customers.get(customer_id)

    def get_org_account_by_org(self, org_id: str) -> OrgAccount | None:
        """Return the org-level account for this org, or ``None`` if there is none."""
        return self.org_accounts.get(org_id)

    def get_order_by_id(self, order_id: str) -> Order | None:
        """Return the order with this id, or ``None`` if there is no such order."""
        return self.orders.get(order_id)


def seed_store() -> Store:
    """Build a fresh, independent seed store.

    Two customers (alice, bob) with distinct ownership; orders spanning both owners,
    including a >$500 order (the V3 refund-gate target), PII shipping addresses
    (the V2 IDOR target), and order-lifecycle states (the V4 state-machine target:
    ORD-1001 ``delivered`` + ORD-2001 ``shipped`` are FINALIZED / non-cancellable,
    ORD-1002 ``pending`` is the only legitimately-cancellable order). Returned fresh
    each call so callers never share state.
    """
    customers = {
        "alice": Customer(
            id="alice",
            name="Alice Anderson",
            email="alice@example.com",
            recovery_email="alice.personal@example.com",
            org="acme",
        ),
        "bob": Customer(
            id="bob",
            name="Bob Baker",
            email="bob@example.com",
            recovery_email="bob.personal@example.com",
            org="globex",
        ),
    }
    orders = {
        "ORD-1001": Order(
            id="ORD-1001",
            owner="alice",
            items=["Mechanical Keyboard"],
            total=89.99,
            shipping_address="742 Evergreen Terrace, Springfield",
            status="delivered",
        ),
        "ORD-1002": Order(
            id="ORD-1002",
            owner="alice",
            items=["Standing Desk", "Monitor Arm"],
            total=642.50,
            shipping_address="742 Evergreen Terrace, Springfield",
            status="pending",
        ),
        "ORD-2001": Order(
            id="ORD-2001",
            owner="bob",
            items=["Noise-Cancelling Headphones"],
            total=1299.00,
            shipping_address="12 Ocean View Rd, Shelbyville",
            status="shipped",
        ),
    }
    # Org-level billing accounts (the V5 cross-tenant target): alice ∈ acme, bob ∈ globex.
    # A session in one org must NOT be able to read the other org's account.
    org_accounts = {
        "acme": OrgAccount(
            org_id="acme",
            billing_email="billing@acme.example",
            balance_due=12500.00,
            payment_method_last4="4242",
            tax_id="ACME-TAX-99",
        ),
        "globex": OrgAccount(
            org_id="globex",
            billing_email="billing@globex.example",
            balance_due=8800.00,
            payment_method_last4="1881",
            tax_id="GLBX-TAX-21",
        ),
    }
    # Single-use coupon (the V6 one-time-limit target): redeeming WELCOME10 adds $10 to the
    # session customer's account_credit, and may be redeemed AT MOST ONCE per customer.
    coupons = {"WELCOME10": Coupon(code="WELCOME10", value=10.00)}
    return Store(
        customers=customers,
        orders=orders,
        org_accounts=org_accounts,
        coupons=coupons,
    )
