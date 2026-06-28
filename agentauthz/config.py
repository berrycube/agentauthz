"""LLM configuration + the injection point.

``get_model()`` is the single source of the model name (``$LLM_MODEL`` when set, else a
default). The agent takes an INJECTABLE LLM client (its constructor's first argument) —
that is the injection point — so the deterministic test suite passes a ``FakeLLM`` and
never touches a real model. The real Ollama ``--live`` client is built by the exploit
``--live`` path, which reads ``get_model()`` for the model name; it never runs inside the
test suite.
"""

from __future__ import annotations

import os

DEFAULT_LLM_MODEL = "llama3.2"
LLM_MODEL_ENV = "LLM_MODEL"


def get_model() -> str:
    """The configured model name: ``$LLM_MODEL`` when set and non-blank, else the default."""
    value = os.environ.get(LLM_MODEL_ENV)
    return value if value and value.strip() else DEFAULT_LLM_MODEL
