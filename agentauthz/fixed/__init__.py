"""AgentAuthZ v1 FIXED reference implementations.

The remediation counterpart to the deliberately-vulnerable target. Correct,
SECURE code (NOT a planted vulnerability): it overrides exactly the three flawed
tool methods to ENFORCE the SHOULD-HOLD invariants the vulnerable target violates,
WITHOUT over-blocking legitimate owner actions.

* ``tools_fixed.FixedToolbox`` — subclasses the base ``Toolbox`` (inheriting its
  fail-closed dispatch + schema validation) and overrides ``update_recovery_email``
  (V1: ownership + OTP-to-existing-email), ``get_order`` (V2: session-ownership on
  lookup), and ``issue_refund`` (V3: hard human-approval gate above the threshold).
* ``agent_fixed.FixedAgent`` — subclasses the base ``Agent`` and swaps in a
  ``FixedToolbox`` over the same store / session / refund ledger.

The SAME exploits driven against ``FixedAgent`` must FAIL to violate the
invariant, while legitimate owner actions still succeed.
"""

from __future__ import annotations

from agentauthz.fixed.agent_fixed import FixedAgent
from agentauthz.fixed.tools_fixed import FixedToolbox

__all__ = ["FixedAgent", "FixedToolbox"]
