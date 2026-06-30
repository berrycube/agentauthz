"""Stdio MCP target server — exposes AgentAuthZ's six tools to a frontier CLI.

This is the bridge for the *frontier* cross-model sweep (story E6): instead of driving a
raw model through the in-repo ``Agent`` loop, we let a production agent CLI (Claude Code
``claude -p`` / Codex ``codex exec``) BE the tool-calling brain and call AgentAuthZ's tools
over the Model Context Protocol.  The server exposes either the deliberately-flawed
``Toolbox`` (``target="vulnerable"``) or the remediated ``FixedToolbox``
(``target="fixed"``), bound to a seeded ``Store`` + a fixed authenticated session — exactly
the substrate the authz vulnerabilities target.

Why hand-rolled (stdlib only, no ``mcp`` dependency): the rest of the harness deliberately
talks raw HTTP via ``http.client`` rather than pulling SDKs, and the protocol surface we
need is tiny (``initialize`` / ``tools/list`` / ``tools/call`` + notifications).  Crucially,
the PURE protocol + binding logic in ``MCPTargetServer.handle`` is unit-tested OFFLINE
(``test_mcp_target.py`` drives ``handle`` with request dicts) — the live CLI subprocess
driving lives ONLY in the runner, never in the deterministic suite (epic invariant
``E1.INV.deterministic-offline-tests``).

CROSS-INVOCATION STATE.  Each attacker turn is a SEPARATE CLI invocation, so each spawns a
fresh server process.  The authoritative state therefore lives in the RUN DIR on disk:
``store.json`` (the serialized ``Store`` — carries every mutation: a rewritten recovery
email, a stacked coupon credit, a cancelled order, the single-use ledger) and
``transcript.json`` (the append-only tool-call record — the evidence the evaluator binds).
A server LOADS both on startup, mutates the in-memory store per call, and SAVES both after
every call, so the next turn's process continues seamlessly and the evaluator sees the full
multi-turn transcript.  The cumulative-refund ``RefundLedger`` is intentionally per-process
(fresh each invocation): it is orthogonal hardening, never a fire condition, and a fresh
ledger can only ever be MORE permissive — it cannot fabricate or suppress a finding.

FAIL-CLOSED.  A malformed run-dir file raises (an unreadable target is an ERROR the runner
records as fail-closed, never a false 'safe'); a malformed/hostile tool call is rejected by
``Toolbox.call`` into a structured error (never crashes the loop); a malformed JSON-RPC line
is skipped.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
from typing import Any

from agentauthz.fixed.tools_fixed import FixedToolbox
from agentauthz.store import Coupon, Customer, Order, OrgAccount, Store, seed_store
from agentauthz.tools import TOOL_SCHEMAS, Toolbox

__all__ = [
    "PROTOCOL_VERSION",
    "MCPTargetServer",
    "seed_run_dir",
    "load_store",
    "load_transcript",
    "store_to_dict",
    "store_from_dict",
    "mcp_tool_schemas",
    "main",
]

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "agentauthz-target", "version": "0.1.0"}

_STORE_FILE = "store.json"
_TRANSCRIPT_FILE = "transcript.json"
_META_FILE = "meta.json"

_VALID_TARGETS = ("vulnerable", "fixed")


# --------------------------------------------------------------------------- #
# Store (de)serialization — fail-closed (never silently coerce a malformed shape)
# --------------------------------------------------------------------------- #
def store_to_dict(store: Store) -> dict:
    """Serialize a ``Store`` to a JSON-safe dict (dataclasses -> plain dict)."""
    return dataclasses.asdict(store)


def _require_dict(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"malformed store: {label!r} must be an object, got {type(value).__name__}")
    return value


def _require_list(value: Any, label: str) -> list:
    # NOT list(value): that silently mis-coerces a str ("bob" -> ['b','o','b']) — fail closed.
    if not isinstance(value, list):
        raise ValueError(f"malformed store: {label!r} must be a list, got {type(value).__name__}")
    return value


def store_from_dict(data: Any) -> Store:
    """Rebuild a ``Store`` from ``store_to_dict`` output.

    Fail-closed: every section must be the expected shape; a malformed payload RAISES
    (the runner records the run as a fail-closed error) rather than silently yielding a
    partial/garbage store that could fabricate or suppress a finding.
    """
    data = _require_dict(data, "store")
    customers = _require_dict(data.get("customers", {}), "customers")
    orders = _require_dict(data.get("orders", {}), "orders")
    org_accounts = _require_dict(data.get("org_accounts", {}), "org_accounts")
    coupons = _require_dict(data.get("coupons", {}), "coupons")
    redemptions = _require_dict(data.get("coupon_redemptions", {}), "coupon_redemptions")
    return Store(
        customers={k: Customer(**_require_dict(v, f"customers[{k}]")) for k, v in customers.items()},
        orders={k: Order(**_require_dict(v, f"orders[{k}]")) for k, v in orders.items()},
        org_accounts={
            k: OrgAccount(**_require_dict(v, f"org_accounts[{k}]")) for k, v in org_accounts.items()
        },
        coupons={k: Coupon(**_require_dict(v, f"coupons[{k}]")) for k, v in coupons.items()},
        coupon_redemptions={
            k: list(_require_list(v, f"coupon_redemptions[{k}]")) for k, v in redemptions.items()
        },
    )


# --------------------------------------------------------------------------- #
# MCP tool schemas (AgentAuthZ flat {name, description, parameters} -> MCP inputSchema)
# --------------------------------------------------------------------------- #
def mcp_tool_schemas() -> list[dict]:
    """The six tools in MCP ``tools/list`` shape (``inputSchema`` = the JSON schema)."""
    return [
        {
            "name": t["name"],
            "description": t.get("description", ""),
            "inputSchema": t["parameters"],
        }
        for t in TOOL_SCHEMAS
    ]


# --------------------------------------------------------------------------- #
# Run-dir persistence
# --------------------------------------------------------------------------- #
def _path(run_dir: str, name: str) -> str:
    return os.path.join(run_dir, name)


def _write_json(path: str, obj: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, default=str, sort_keys=True)
    os.replace(tmp, path)  # atomic swap so a reader never sees a half-written file


def _read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def seed_run_dir(
    run_dir: str, target: str, session_customer_id: str, store: Store | None = None
) -> None:
    """Initialize a run dir: a FRESH seeded ``Store`` + an empty transcript + meta.

    ``target`` must be 'vulnerable' or 'fixed' (fail-closed on anything else)."""
    if target not in _VALID_TARGETS:
        raise ValueError(f"unknown target {target!r} (expected one of {_VALID_TARGETS})")
    if not isinstance(session_customer_id, str) or not session_customer_id.strip():
        raise ValueError("session_customer_id must be a non-empty string")
    os.makedirs(run_dir, exist_ok=True)
    _write_json(_path(run_dir, _STORE_FILE), store_to_dict(store if store is not None else seed_store()))
    _write_json(_path(run_dir, _TRANSCRIPT_FILE), [])
    _write_json(_path(run_dir, _META_FILE), {"target": target, "session_customer_id": session_customer_id})


def load_store(run_dir: str) -> Store:
    """Load the persisted ``Store`` (fail-closed on a malformed file)."""
    return store_from_dict(_read_json(_path(run_dir, _STORE_FILE)))


def load_transcript(run_dir: str) -> list:
    """Load the persisted tool-call transcript (the evaluator's evidence)."""
    tr = _read_json(_path(run_dir, _TRANSCRIPT_FILE))
    if not isinstance(tr, list):
        raise ValueError("malformed transcript: expected a JSON list")
    return tr


def load_meta(run_dir: str) -> dict:
    return _read_json(_path(run_dir, _META_FILE))


# --------------------------------------------------------------------------- #
# The server
# --------------------------------------------------------------------------- #
class MCPTargetServer:
    """One stdio MCP session bound to a run dir + target variant + session customer.

    Loads store + transcript from the run dir on construction; each ``tools/call`` runs the
    bound ``Toolbox``/``FixedToolbox``, appends ``{tool, arguments, result}`` to the
    transcript, and persists both — so the next turn's process continues the same run.
    """

    def __init__(self, run_dir: str, target: str, session_customer_id: str) -> None:
        if target not in _VALID_TARGETS:
            raise ValueError(f"unknown target {target!r} (expected one of {_VALID_TARGETS})")
        self.run_dir = run_dir
        self.target = target
        self.session_customer_id = session_customer_id
        self._store = load_store(run_dir)
        self._transcript = load_transcript(run_dir)
        toolbox_cls = Toolbox if target == "vulnerable" else FixedToolbox
        self._toolbox = toolbox_cls(self._store, session_customer_id)

    # -- JSON-RPC dispatch ------------------------------------------------- #
    def handle(self, request: Any) -> dict | None:
        """Handle one JSON-RPC request; returns the response dict, or ``None`` for a
        notification (no id / ``notifications/*``)."""
        if not isinstance(request, dict):
            return None
        mid = request.get("id")
        method = request.get("method")

        if method == "initialize":
            return self._ok(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        if method == "tools/list":
            return self._ok(mid, {"tools": mcp_tool_schemas()})
        if method == "tools/call":
            return self._ok(mid, self._call_tool(request.get("params") or {}))
        if isinstance(method, str) and method.startswith("notifications/"):
            return None
        if mid is None:
            return None  # an unknown NOTIFICATION gets no response
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method!r}"},
        }

    # -- tools/call: bind to the (vulnerable|fixed) toolbox + record + persist --- #
    def _call_tool(self, params: Any) -> dict:
        # Fail-closed: a non-object ``params`` (e.g. ``"params": "bad"`` or a list) must NOT crash
        # the server with an AttributeError out of ``params.get(...)`` — return a structured tool
        # error and record NO transcript step (a malformed envelope is not a real tool call).
        if not isinstance(params, dict):
            return {
                "content": [{"type": "text", "text": json.dumps(
                    {"status": "error", "reason": "params must be an object"}, sort_keys=True)}],
                "isError": True,
            }
        name = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        # Toolbox.call validates name/arguments and returns a STRUCTURED error for anything
        # malformed — it never raises — so a hostile tool call cannot crash the session.
        result = self._toolbox.call(name, arguments)
        self._transcript.append({"tool": name, "arguments": arguments, "result": result})
        self._persist()
        return {
            "content": [{"type": "text", "text": json.dumps(result, default=str, sort_keys=True)}],
            "isError": False,
        }

    def _persist(self) -> None:
        _write_json(_path(self.run_dir, _STORE_FILE), store_to_dict(self._store))
        _write_json(_path(self.run_dir, _TRANSCRIPT_FILE), self._transcript)

    @staticmethod
    def _ok(mid: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "result": result}


# --------------------------------------------------------------------------- #
# Stdio entrypoint (LIVE only — driven by the CLI; never imported by the test suite)
# --------------------------------------------------------------------------- #
def main() -> int:  # pragma: no cover - exercised live by the CLI, not in pytest
    """Run the stdio MCP server, reading config from the environment.

    ``AGENTAUTHZ_RUN_DIR`` (required) + ``AGENTAUTHZ_TARGET`` / ``AGENTAUTHZ_SESSION``
    (fall back to the run dir's ``meta.json``).  Newline-delimited JSON-RPC over
    stdin/stdout.  Fail-closed: a malformed line is skipped, never crashes the loop."""
    run_dir = os.environ.get("AGENTAUTHZ_RUN_DIR")
    if not run_dir:
        sys.stderr.write("AGENTAUTHZ_RUN_DIR is required\n")
        return 2
    meta = {}
    try:
        meta = load_meta(run_dir)
    except Exception:  # noqa: BLE001 - meta is optional; env can supply target/session
        meta = {}
    target = os.environ.get("AGENTAUTHZ_TARGET") or meta.get("target")
    session = os.environ.get("AGENTAUTHZ_SESSION") or meta.get("session_customer_id")
    if target not in _VALID_TARGETS or not session:
        sys.stderr.write("target (vulnerable|fixed) and session must be set via env or meta.json\n")
        return 2

    server = MCPTargetServer(run_dir, target, session)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except (ValueError, TypeError):
            continue  # skip a malformed line; never crash the session
        response = server.handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
