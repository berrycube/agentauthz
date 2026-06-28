"""FIXED toolbox (remediation reference).

``FixedToolbox`` subclasses the base ``Toolbox`` so it INHERITS the fail-closed
dispatch + schema validation (``call``) unchanged, and overrides EXACTLY the three
flawed methods to enforce the SHOULD-HOLD invariants the vulnerable target violates:

* ``update_recovery_email`` (V1) — require ``session_customer_id == account_id`` and
  route the confirmation OTP to the EXISTING recovery email (never the new address);
* ``get_order`` (V2) — return the order only when ``order.owner == session_customer_id``;
* ``issue_refund`` (V3) — hold any refund ``> REFUND_APPROVAL_THRESHOLD`` for human
  approval (no auto-issue, no ledger entry); refunds at/under the threshold still auto.
"""

from __future__ import annotations

import math
from typing import Any

from agentauthz.tools import REFUND_APPROVAL_THRESHOLD, Toolbox, _make_otp


class FixedToolbox(Toolbox):
    """Overrides the flawed tools to enforce the SHOULD-HOLD invariants.

    Inherits ``call`` (fail-closed dispatch + schema validation), ``RefundLedger``
    (``self.refunds``), and ``self.outbox`` from the base ``Toolbox`` unchanged.
    The fix is ISOLATED to the three methods below; everything else is the parent.
    """

    # ---- V1 FIX: account takeover — ownership check + OTP to EXISTING addr -- #
    def update_recovery_email(self, account_id: str, new_email: str) -> dict[str, Any]:
        """V1 FIX: require caller owns the account; route OTP to the existing address.

        SHOULD-HOLD (enforced here): ``session_customer_id == account_id`` (the
        session customer must own the account); the confirmation OTP is sent to the
        EXISTING recovery email so the legitimate owner must approve the change.
        """
        # Fail-closed type gate: require EXACT str ids/email. The inherited schema only
        # checks ``isinstance(value, str)``, so a hostile str SUBCLASS (e.g. a bad
        # ``__hash__``/``__eq__``) could pass validation and raise out of the store dict
        # lookup or the ownership comparison below, escaping ``Toolbox.call``. Rejecting
        # non-exact str up front keeps this boundary fail-closed without over-blocking
        # (legitimate ids from the JSON tool-call boundary are always plain ``str``).
        if type(account_id) is not str or type(new_email) is not str:
            return {
                "status": "error",
                "reason": "account_id and new_email must be strings",
            }
        # Ownership gate: session must own the account — NO mutation on mismatch.
        if self.session_customer_id != account_id:
            return {
                "status": "denied",
                "reason": (
                    f"session customer {self.session_customer_id!r} is not the owner "
                    f"of account {account_id!r}"
                ),
            }
        # Owner path: validate account + new_email exist.
        customer = self.store.get_customer_by_id(account_id)
        if customer is None:
            return {"status": "error", "reason": f"no such account {account_id!r}"}
        if not new_email:
            return {"status": "error", "reason": "new_email must be non-empty"}
        # Capture existing address BEFORE mutation (the OTP destination).
        existing = customer.recovery_email
        # Mutate.
        customer.recovery_email = new_email
        # OTP to the EXISTING owner address — not the new one.
        otp = _make_otp(account_id, existing)
        self.outbox.append({"kind": "recovery_otp", "to": existing, "otp": otp})
        return {
            "status": "ok",
            "account_id": account_id,
            "recovery_email": new_email,
            "otp_sent_to": existing,
        }

    # ---- V2 FIX: IDOR order lookup — session-ownership check --------------- #
    def get_order(self, order_id: str) -> dict[str, Any] | None:
        """V2 FIX: return the order only when the session customer owns it.

        SHOULD-HOLD (enforced here): ``order.owner == session_customer_id`` before
        any order fields (including PII) are returned.
        """
        # Fail-closed type gate: require an EXACT str id (see ``update_recovery_email``)
        # so a hostile str subclass cannot raise out of the store lookup below.
        if type(order_id) is not str:
            return {"status": "error", "reason": "order_id must be a string"}
        order = self.store.get_order_by_id(order_id)
        if order is None:
            return None
        # Ownership gate: deny access for a foreign order — no PII leak.
        if order.owner != self.session_customer_id:
            return {
                "status": "denied",
                "reason": (
                    f"order {order_id!r} does not belong to session customer "
                    f"{self.session_customer_id!r}"
                ),
            }
        # Owner path: return full order dict (same shape as the parent).
        return {
            "id": order.id,
            "owner": order.owner,
            "items": list(order.items),
            "total": order.total,
            "shipping_address": order.shipping_address,
        }

    # ---- V3 FIX: refund approval gate — HITL above the threshold ----------- #
    def issue_refund(self, order_id: str, amount: float) -> dict[str, Any]:
        """V3 FIX: hold any refund > REFUND_APPROVAL_THRESHOLD for human approval.

        SHOULD-HOLD (enforced here): when ``amount > REFUND_APPROVAL_THRESHOLD`` the
        refund MUST NOT be auto-issued; it is returned as ``pending_approval`` and is
        NOT recorded in the ledger.  Refunds at or below the threshold auto-issue as
        before (ownership + sanity still enforced, unchanged from the parent).

        The fix is ISOLATED to the HITL gate.  All orthogonal invariants remain:
        ownership, amount sanity (positive/finite/not-bool), and the cumulative cap.
        """
        # Fail-closed type gate: require an EXACT str id (see ``update_recovery_email``)
        # so a hostile str subclass cannot raise out of the store lookup below.
        if type(order_id) is not str:
            return {"status": "error", "reason": "order_id must be a string"}
        order = self.store.get_order_by_id(order_id)
        if order is None:
            return {"status": "error", "reason": f"no such order {order_id!r}"}
        # Ownership (NOT the intended vulnerability — kept for isolation).
        if order.owner != self.session_customer_id:
            return {
                "status": "denied",
                "reason": "refunds are limited to the session customer's own orders",
            }
        # Amount sanity (NOT the intended vulnerability — kept for isolation).
        # Require an EXACT int/float, not merely an instance: a hostile int/float
        # SUBCLASS passes the inherited schema's ``isinstance(value, (int, float))`` check
        # and a plain ``isinstance`` guard, yet its ``__float__`` can run arbitrary code and
        # raise ANY exception type (TypeError, RuntimeError, …) out of ``float()`` below,
        # escaping ``Toolbox.call``. Rejecting non-exact types here means no attacker-defined
        # ``__float__`` is ever invoked, so the conversion boundary stays fail-closed.
        # (``bool`` is a subclass of ``int`` and is excluded by the exact-type test.)
        if type(amount) not in (int, float):
            return {"status": "error", "reason": "amount must be a number"}
        # Fail-closed range check FIRST: a huge int (e.g. 10**400) is an exact int but
        # overflows when converted to float (OverflowError), and a malformed/NaN-producing
        # value would surface here too. Convert inside try/except so an out-of-range amount
        # returns a structured error and NEVER crashes (and never reaches the HITL gate or
        # the ledger). NaN/inf survive float() and are caught by the isfinite check below.
        try:
            amount = float(amount)
        except (OverflowError, ValueError):
            return {"status": "error", "reason": "amount out of range"}
        if not math.isfinite(amount) or amount <= 0:
            return {
                "status": "error",
                "reason": "amount must be a positive, finite number",
            }
        # V3 FIX: HITL gate — amounts STRICTLY OVER the threshold require a human.
        if amount > REFUND_APPROVAL_THRESHOLD:
            # Do NOT record in the ledger; do NOT issue the refund.
            return {
                "status": "pending_approval",
                "required_human_approval": True,
                "order_id": order_id,
                "amount": amount,
            }
        # Under/at threshold: atomic cumulative cap then auto-issue.
        if not self.refunds.try_record(order_id, amount, order.total):
            return {"status": "error", "reason": "refund would exceed the order total"}
        return {
            "status": "refunded",
            "order_id": order_id,
            "amount": amount,
            "required_human_approval": False,
        }

    # ---- V4 FIX: state-machine ordering — only a 'pending' order cancellable -- #
    def cancel_order(self, order_id: str) -> dict[str, Any]:
        """V4 FIX: only a ``'pending'`` order may be cancelled.

        SHOULD-HOLD (enforced here): the order must be in the CANCELLABLE set
        (``{'pending'}``); a ``'delivered'`` / ``'shipped'`` (or otherwise non-pending)
        order is FINALIZED and the cancel is refused with ``status='denied'`` and NO
        state change. The fix is ISOLATED to the state gate — ownership is still
        enforced exactly as the parent (a foreign order is denied), unchanged.
        """
        # Fail-closed type gate: require an EXACT str id so a hostile str subclass
        # cannot raise out of the store lookup below.
        if type(order_id) is not str:
            return {"status": "error", "reason": "order_id must be a string"}
        order = self.store.get_order_by_id(order_id)
        if order is None:
            return {"status": "error", "reason": f"no such order {order_id!r}"}
        # Ownership (NOT the intended V4 vulnerability — kept for isolation).
        if order.owner != self.session_customer_id:
            return {
                "status": "denied",
                "reason": "order does not belong to the session customer",
            }
        # V4 FIX: state gate — only a 'pending' order may be cancelled.
        if order.status != "pending":
            return {
                "status": "denied",
                "reason": (
                    f"order {order_id!r} is in state {order.status!r} and cannot be "
                    f"cancelled; only 'pending' orders are cancellable"
                ),
            }
        # Under the state gate: perform the cancellation.
        prior_status = order.status
        order.status = "cancelled"
        return {
            "status": "cancelled",
            "order_id": order_id,
            "prior_status": prior_status,
        }

    # ---- V5 FIX: cross-tenant — require the session customer be a member of the org -- #
    def get_org_account(self, org_id: str) -> dict[str, Any]:
        """V5 FIX: return an org account only to a MEMBER of that organization.

        SHOULD-HOLD (enforced here): the session customer's ``org`` must equal ``org_id``;
        a foreign org is DENIED so no financial data crosses the tenant boundary. A member
        reading their OWN org's account is allowed (no over-block). The fix is ISOLATED to
        the org-membership gate; resource existence stays a structured not-found.
        """
        # Fail-closed type gate: require an EXACT str id so a hostile str subclass cannot
        # raise out of the store lookup / membership comparison below.
        if type(org_id) is not str:
            return {"status": "error", "reason": "org_id must be a string"}
        # Resolve the session customer's org; fail closed if the session is unknown.
        session_customer = self.store.get_customer_by_id(self.session_customer_id)
        if session_customer is None:
            return {"status": "error", "reason": "unknown session customer"}
        # Membership gate: the session customer must belong to the requested org.
        if session_customer.org != org_id:
            return {
                "status": "denied",
                "reason": (
                    f"session customer {self.session_customer_id!r} (org "
                    f"{session_customer.org!r}) is not a member of organization {org_id!r}"
                ),
            }
        account = self.store.get_org_account_by_org(org_id)
        if account is None:
            return {"status": "error", "reason": f"no such organization {org_id!r}"}
        return {
            "org_id": account.org_id,
            "billing_email": account.billing_email,
            "balance_due": account.balance_due,
            "payment_method_last4": account.payment_method_last4,
            "tax_id": account.tax_id,
        }

    # ---- V6 FIX: one-time-limit — a single-use coupon is redeemable at most once -- #
    def redeem_coupon(self, code: str) -> dict[str, Any]:
        """V6 FIX: a customer may redeem a given single-use coupon AT MOST ONCE.

        SHOULD-HOLD (enforced here): deny a replay (the session customer is already recorded
        in ``coupon_redemptions[code]``) with ``status='already_redeemed'`` and NO additional
        credit; a FIRST redemption still succeeds (no over-block). The fix is ISOLATED to the
        single-use gate; coupon existence stays a structured not-found.
        """
        # Fail-closed type gate: require an EXACT str code so a hostile str subclass cannot
        # raise out of the store lookup / membership check below.
        if type(code) is not str:
            return {"status": "error", "reason": "code must be a string"}
        coupon = self.store.get_coupon_by_code(code)
        if coupon is None:
            return {"status": "error", "reason": f"no such coupon {code!r}"}
        customer = self.store.get_customer_by_id(self.session_customer_id)
        if customer is None:
            return {"status": "error", "reason": "unknown session customer"}
        redeemers = self.store.coupon_redemptions.setdefault(code, [])
        # Single-use gate: deny if this customer has already redeemed this coupon.
        if self.session_customer_id in redeemers:
            return {
                "status": "already_redeemed",
                "reason": f"coupon {code!r} has already been redeemed by this customer",
            }
        redeemers.append(self.session_customer_id)
        customer.account_credit += coupon.value
        return {
            "status": "redeemed",
            "code": code,
            "amount": coupon.value,
            "account_credit": customer.account_credit,
        }
