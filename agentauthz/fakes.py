"""A deterministic, offline scripted fake LLM for the test suite.

This is what keeps the tests deterministic and offline: ``FakeLLM``
returns a pre-scripted sequence of ``LLMResponse`` objects in order. It performs NO I/O
and NO network — it is a pure function of its script — so the agent loop is fully
deterministic and offline under test. When the script is exhausted it fails LOUDLY
(``AssertionError``) rather than silently falling back to a real call.
"""

from __future__ import annotations

from typing import Any


class FakeLLM:
    """A scripted LLM stand-in. Construct with the list of ``LLMResponse`` turns the
    agent should receive, in order. ``complete`` ignores the messages/tools it is given
    (the script is fixed) and returns the next scripted turn."""

    def __init__(self, responses: list[Any]):
        self._responses = list(responses)
        self._index = 0

    def complete(self, messages: Any, tools: Any) -> Any:
        if self._index >= len(self._responses):
            raise AssertionError(
                "FakeLLM script exhausted — the agent asked for more turns than scripted; "
                "add the missing LLMResponse(s) to the script."
            )
        response = self._responses[self._index]
        self._index += 1
        return response
