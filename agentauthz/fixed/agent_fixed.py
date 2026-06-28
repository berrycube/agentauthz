"""FIXED agent (remediation reference).

``FixedAgent`` subclasses the base ``Agent`` and, after the parent constructor builds the
session, swaps ``self.toolbox`` for a ``FixedToolbox`` over the SAME store, session
customer, and refund ledger — so the agent loop is identical to the base loop but every
tool call now flows through the hardened, invariant-enforcing toolbox (see
``tools_fixed``). The SAME attacks driven against this agent FAIL to violate the
invariants, while legitimate owner actions still succeed.
"""

from __future__ import annotations

from typing import Any

from agentauthz.agent import Agent
from agentauthz.fixed.tools_fixed import FixedToolbox
from agentauthz.store import Store
from agentauthz.tools import RefundLedger


class FixedAgent(Agent):
    """Same tool-calling loop as the base ``Agent``, but routes every tool call
    through a ``FixedToolbox`` (over the same store / session / ledger) instead of the
    deliberately-vulnerable ``Toolbox``."""

    def __init__(
        self,
        llm_client: Any,
        store: Store,
        session_customer_id: str,
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
        # Swap the deliberately-vulnerable toolbox for the hardened one, preserving
        # the same store, session, and (shared) refund ledger the parent just bound.
        self.toolbox = FixedToolbox(
            store,
            session_customer_id,
            refund_ledger=self.toolbox.refunds,
        )
