"""AgentAuthZ v1 red-team harness.

Correct, secure harness code (NOT a deliberate vulnerability) that drives the
deliberately-vulnerable agent against declarative scenarios:

* ``loader``    — parse human-declared scenario YAML into typed ``Scenario`` objects,
                  failing CLOSED on any malformed / under-specified scenario.

The harness also provides ``evaluator``, ``attacker``, and ``runner`` / ``report``.
"""

from __future__ import annotations
