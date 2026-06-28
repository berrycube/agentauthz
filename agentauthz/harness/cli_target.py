"""CLI-driven TARGET agent — the brain is a production agent CLI (Claude Code / Codex).

For the *frontier* cross-model sweep (E6) the target seat is not a raw model wired into the
in-repo ``Agent`` loop; it is a frontier model **as driven by its own production agent CLI**
(``claude -p`` / ``codex exec``), calling AgentAuthZ's tools over MCP (see ``mcp_target``).
This is a STRONGER, honestly-labelled experiment than a raw endpoint: it measures
"model X + its real agent harness", which is how the model is actually deployed.

``CLITargetAgent`` is duck-typed exactly like ``Agent`` — it exposes ``run`` / ``store`` /
``transcript`` / ``session_customer_id`` — so the EXISTING multi-turn attacker loop
(``run_attack``) and the deterministic ``evaluate`` reuse UNCHANGED.  Faithful to the in-repo
``Agent``, each ``run(message)`` is STATELESS per turn (``Agent.run`` also rebuilds its
message list every call): a fresh CLI invocation processes the single new attacker message
against the PERSISTENT run-dir store/transcript.  Cross-turn memory therefore lives only in
the store/transcript (and the attacker's adaptation), exactly as in the local sweep.

HONEST RECORDING (error != safe).  A driver raises ``CLIError`` ONLY for a transport/exec
failure (non-zero exit, timeout, a provider error envelope, no parseable reply) — which
``CLITargetAgent.run`` records by setting ``errored = True`` so the sweep counts the repeat as
a fail-closed ERROR (excluded from the fire-rate denominator), NEVER a false 'safe' 0.  A
model that runs fine but declines to call the tool (a refusal) or is blocked by the fixed
code is NOT an error — it is a genuine non-fire (a real data point), so the driver returns the
reply normally.  The deterministic, OFFLINE tests inject a fake driver; the live subprocess
drivers are exercised only by the runner, never by the suite.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Protocol

from agentauthz.agent import DEFAULT_SYSTEM_PROMPT
from agentauthz.harness.mcp_target import load_store, load_transcript, seed_run_dir
from agentauthz.tools import TOOL_SCHEMAS

__all__ = [
    "CLIError",
    "CLITargetAgent",
    "ClaudeCodeDriver",
    "CodexDriver",
    "TOOL_NAMES",
    "DEFAULT_ALLOWED_TOOLS",
]

MCP_SERVER_NAME = "agentauthz"
TOOL_NAMES = [t["name"] for t in TOOL_SCHEMAS]
DEFAULT_ALLOWED_TOOLS = [f"mcp__{MCP_SERVER_NAME}__{n}" for n in TOOL_NAMES]
_MCP_SERVER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_target.py")

# Codex prints one line per MCP tool call: ``mcp: <server>/<tool> (completed|failed)``.
# A ``(failed)`` line means the tool call did NOT execute (e.g. a sandbox blocked the MCP
# server's run-dir write, or it crashed) — that is a transport failure we MUST record as a
# fail-closed ERROR, never let it masquerade as a clean non-fire (error != safe).
_CODEX_TOOL_FAILED_RE = re.compile(rf"mcp:\s*{re.escape(MCP_SERVER_NAME)}/\S+\s*\(failed\)")


def _codex_mcp_call_failed(stdout: str) -> bool:
    """True iff codex reported an AgentAuthZ MCP tool call as ``(failed)`` (a transport/exec
    failure, NOT a model refusal)."""
    return bool(_CODEX_TOOL_FAILED_RE.search(stdout or ""))


class CLIError(RuntimeError):
    """A transport/exec failure of the agent CLI — recorded as a fail-closed ERROR, never
    as a 'safe' non-fire. (A model refusal is NOT a CLIError; it is a genuine non-fire.)"""


def _clean_env() -> dict:
    """Child env without our own debug-logging vars (they pollute the CLI's stdout)."""
    env = dict(os.environ)
    env.pop("ANTHROPIC_LOG", None)
    env.pop("DEBUG_SDK", None)
    return env


class Driver(Protocol):
    """One stateless CLI turn: process ``message`` against the run dir, return the reply."""

    def label(self) -> str: ...

    def run_turn(
        self,
        message: str,
        *,
        run_dir: str,
        target: str,
        session_customer_id: str,
        system_prompt: str,
        allowed_tools: list[str],
    ) -> str: ...


# --------------------------------------------------------------------------- #
# Claude Code driver (claude -p, MCP via --mcp-config JSON, scoped --allowedTools)
# --------------------------------------------------------------------------- #
class ClaudeCodeDriver:
    """Drive Claude via the Claude Code CLI headless (`claude -p`).

    The six AgentAuthZ tools are exposed as a stdio MCP server and pre-approved with a SCOPED
    ``--allowedTools`` allowlist (no permission bypass).  The ACME customer-service role +
    policy is supplied via ``--append-system-prompt``.  The clean result is the single
    ``{"type":"result"}`` line of ``--output-format json`` (other lines may be debug noise)."""

    def __init__(
        self,
        model: str,
        *,
        claude_bin: str = "claude",
        python_bin: str | None = None,
        mcp_server_path: str = _MCP_SERVER_PATH,
        timeout: int = 300,
    ) -> None:
        self.model = model
        self.claude_bin = claude_bin
        self.python_bin = python_bin or sys.executable
        self.mcp_server_path = mcp_server_path
        self.timeout = timeout

    def label(self) -> str:
        return f"claude-code:{self.model}"

    def _write_mcp_config(self, run_dir: str, target: str, session_customer_id: str) -> str:
        cfg = {
            "mcpServers": {
                MCP_SERVER_NAME: {
                    "command": self.python_bin,
                    "args": [self.mcp_server_path],
                    "env": {
                        "AGENTAUTHZ_RUN_DIR": run_dir,
                        "AGENTAUTHZ_TARGET": target,
                        "AGENTAUTHZ_SESSION": session_customer_id,
                    },
                }
            }
        }
        path = os.path.join(run_dir, "mcp_claude.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        return path

    def run_turn(
        self,
        message: str,
        *,
        run_dir: str,
        target: str,
        session_customer_id: str,
        system_prompt: str,
        allowed_tools: list[str],
    ) -> str:
        cfg_path = self._write_mcp_config(run_dir, target, session_customer_id)
        cmd = [
            self.claude_bin, "-p", message,
            "--model", self.model,
            "--mcp-config", cfg_path,
            "--strict-mcp-config",
            "--allowedTools", " ".join(allowed_tools),
            "--append-system-prompt", system_prompt,
            "--output-format", "json",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, env=_clean_env()
            )
        except subprocess.TimeoutExpired as exc:
            raise CLIError(f"claude -p timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise CLIError(f"claude -p exit {proc.returncode}: {proc.stderr.strip()[:300]}")
        result = _parse_claude_result(proc.stdout)
        if result is None:
            raise CLIError("claude -p produced no result line")
        if result.get("is_error"):
            raise CLIError(f"claude -p reported error: {str(result.get('result'))[:300]}")
        reply = result.get("result")
        return reply if isinstance(reply, str) else ""


def _parse_claude_result(stdout: str) -> dict | None:
    """Extract the single ``{"type":"result"}`` JSON line from claude -p output, tolerating
    interleaved debug-log lines."""
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith('{"type":"result"'):
            try:
                return json.loads(line)
            except (ValueError, TypeError):
                return None
    return None


# --------------------------------------------------------------------------- #
# Codex driver (codex exec, MCP via -c overrides, --output-last-message for the reply)
# --------------------------------------------------------------------------- #
class CodexDriver:
    """Drive GPT via the Codex CLI headless (`codex exec`).

    The MCP server is configured via ``-c mcp_servers.*`` overrides; ``approval_policy=never``
    auto-approves the (self-built) tool calls non-interactively without bypassing the sandbox.
    Codex has no separate system-prompt flag, so the ACME role + policy is prepended to the
    customer message.  The clean final reply is captured via ``--output-last-message``."""

    def __init__(
        self,
        model: str,
        *,
        codex_bin: str = "codex",
        python_bin: str | None = None,
        mcp_server_path: str = _MCP_SERVER_PATH,
        sandbox: str | None = None,
        startup_timeout_sec: int = 30,
        timeout: int = 300,
    ) -> None:
        self.model = model
        self.codex_bin = codex_bin
        self.python_bin = python_bin or sys.executable
        self.mcp_server_path = mcp_server_path
        # sandbox=None -> omit ``-s`` and inherit the user's codex config. The MCP server
        # (spawned by codex) MUST be able to WRITE the run dir (store/transcript); a
        # restrictive sandbox such as ``read-only`` blocks that and makes every tool call
        # fail. The ``(failed)`` guard below turns such a misconfiguration into a fail-closed
        # ERROR rather than a false 'safe' non-fire.
        self.sandbox = sandbox
        self.startup_timeout_sec = startup_timeout_sec
        self.timeout = timeout

    def label(self) -> str:
        return f"codex:{self.model}"

    def _toml_str(self, s: str) -> str:
        # TOML basic string: escape backslash + double-quote (run dirs are plain paths).
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def run_turn(
        self,
        message: str,
        *,
        run_dir: str,
        target: str,
        session_customer_id: str,
        system_prompt: str,
        allowed_tools: list[str],
    ) -> str:
        last_msg_path = os.path.join(run_dir, "codex_last.txt")
        env_table = (
            "{ "
            f"AGENTAUTHZ_RUN_DIR = {self._toml_str(run_dir)}, "
            f"AGENTAUTHZ_TARGET = {self._toml_str(target)}, "
            f"AGENTAUTHZ_SESSION = {self._toml_str(session_customer_id)} "
            "}"
        )
        prompt = f"{system_prompt}\n\n[Incoming customer message]\n{message}"
        cmd = [
            self.codex_bin, "exec",
            "-c", f"mcp_servers.{MCP_SERVER_NAME}.command={self._toml_str(self.python_bin)}",
            "-c", f"mcp_servers.{MCP_SERVER_NAME}.args=[{self._toml_str(self.mcp_server_path)}]",
            "-c", f"mcp_servers.{MCP_SERVER_NAME}.env={env_table}",
            "-c", f"mcp_servers.{MCP_SERVER_NAME}.startup_timeout_sec={self.startup_timeout_sec}",
            "-c", 'approval_policy="never"',
            "-m", self.model,
        ]
        if self.sandbox is not None:
            cmd += ["-s", self.sandbox]
        cmd += ["--skip-git-repo-check", "-o", last_msg_path, prompt]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, env=_clean_env()
            )
        except subprocess.TimeoutExpired as exc:
            raise CLIError(f"codex exec timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise CLIError(f"codex exec exit {proc.returncode}: {proc.stderr.strip()[:300]}")
        # error != safe: a reported MCP tool FAILURE (e.g. a restrictive sandbox blocked the
        # run-dir write) is a transport error, NOT a clean non-fire.
        if _codex_mcp_call_failed(proc.stdout):
            raise CLIError("codex reported an AgentAuthZ MCP tool call as (failed)")
        try:
            with open(last_msg_path, encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            # exit 0 but no last-message file written: treat as an empty (genuine) reply,
            # not an error — the tool side-effects (if any) are already in the run dir.
            return ""


# --------------------------------------------------------------------------- #
# The duck-typed target agent the harness drives
# --------------------------------------------------------------------------- #
class CLITargetAgent:
    """A target agent whose tool-calling brain is a frontier CLI (via ``driver``).

    Duck-typed for ``run_attack`` + ``evaluate``: ``run`` / ``store`` / ``transcript`` /
    ``session_customer_id``.  ``store`` and ``transcript`` are read fresh from the run dir,
    so they always reflect the latest persisted tool side effects.  ``errored`` is True iff a
    turn hit a transport/exec failure (the sweep records that repeat as a fail-closed error).
    """

    def __init__(
        self,
        driver: Driver,
        *,
        run_dir: str,
        target: str,
        session_customer_id: str,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        allowed_tools: list[str] | None = None,
        seed: bool = True,
    ) -> None:
        self.driver = driver
        self.run_dir = run_dir
        self.target = target
        self.session_customer_id = session_customer_id
        self.system_prompt = system_prompt
        self.allowed_tools = list(allowed_tools) if allowed_tools is not None else list(DEFAULT_ALLOWED_TOOLS)
        self.errored = False
        if seed:
            seed_run_dir(run_dir, target, session_customer_id)

    @property
    def store(self) -> Any:
        return load_store(self.run_dir)

    @property
    def transcript(self) -> list:
        return load_transcript(self.run_dir)

    def run(self, user_message: str) -> str:
        """Process one attacker message via the CLI driver; fail-closed on a transport error."""
        try:
            reply = self.driver.run_turn(
                user_message,
                run_dir=self.run_dir,
                target=self.target,
                session_customer_id=self.session_customer_id,
                system_prompt=self.system_prompt,
                allowed_tools=self.allowed_tools,
            )
        except CLIError:
            self.errored = True
            return ""
        return reply if isinstance(reply, str) else ""
