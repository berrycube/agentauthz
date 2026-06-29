"""Deterministic, OFFLINE tests for the stdio MCP target server.

The MCP server exposes the SAME six deliberately-flawed tools (vulnerable) or their
remediated counterparts (fixed) to a frontier CLI (Claude Code / Codex) over JSON-RPC,
backed by a seeded ``Store`` + a fixed session, recording each tool call into a
transcript and persisting store + transcript to a run dir so the evaluator can bind the
proving evidence. These tests drive ``handle()`` directly with request dicts and assert
on the persisted run-dir state — NO subprocess, NO network, NO real LLM (the live CLI
driving lives only in the runner, never in the suite).
"""
from __future__ import annotations

import json

import pytest

from agentauthz.harness.evaluator import evaluate
from agentauthz.harness.loader import load_scenarios
from agentauthz.harness.mcp_target import (
    PROTOCOL_VERSION,
    MCPTargetServer,
    load_store,
    load_transcript,
    mcp_tool_schemas,
    seed_run_dir,
    store_from_dict,
    store_to_dict,
)
from agentauthz.store import seed_store

SIX_TOOLS = {
    "update_recovery_email",
    "get_order",
    "issue_refund",
    "cancel_order",
    "get_org_account",
    "redeem_coupon",
}


def _req(method: str, mid: int | None = 0, **params: object) -> dict:
    r: dict = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        r["id"] = mid
    if params:
        r["params"] = params
    return r


def _call(name: str, **arguments: object) -> dict:
    return _req("tools/call", mid=7, name=name, arguments=arguments)


def _text(resp: dict) -> dict:
    return json.loads(resp["result"]["content"][0]["text"])


# --------------------------------------------------------------------------- #
# Store serialization round-trip
# --------------------------------------------------------------------------- #
def test_store_roundtrip_preserves_all_fields_and_mutations():
    s = seed_store()
    s.customers["alice"].recovery_email = "attacker@evil.test"
    s.customers["bob"].account_credit = 20.0
    s.coupon_redemptions["WELCOME10"] = ["bob", "bob"]
    s.orders["ORD-1001"].status = "cancelled"
    s2 = store_from_dict(store_to_dict(s))
    assert s2.customers["alice"].recovery_email == "attacker@evil.test"
    assert s2.customers["bob"].account_credit == 20.0
    assert s2.coupon_redemptions["WELCOME10"] == ["bob", "bob"]
    assert s2.orders["ORD-1001"].status == "cancelled"
    assert s2.orders["ORD-1002"].total == 642.50
    assert s2.org_accounts["acme"].tax_id == "ACME-TAX-99"
    assert s2.coupons["WELCOME10"].value == 10.0


def test_store_from_dict_failclosed_on_malformed():
    with pytest.raises(ValueError):
        store_from_dict({"customers": "not-a-dict"})


def test_store_from_dict_failclosed_on_non_list_coupon_redemptions():
    # a non-list redemptions value must FAIL CLOSED, never silently coerce ("bob" -> ['b','o','b'])
    base = store_to_dict(seed_store())
    base["coupon_redemptions"] = {"WELCOME10": "bob"}
    with pytest.raises(ValueError):
        store_from_dict(base)


# --------------------------------------------------------------------------- #
# MCP protocol surface
# --------------------------------------------------------------------------- #
def test_initialize_returns_protocol_capabilities_and_echoes_id(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    srv = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    resp = srv.handle(_req("initialize", mid=0))
    assert resp["id"] == 0
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert PROTOCOL_VERSION != "STUB"
    assert "tools" in resp["result"]["capabilities"]
    assert resp["result"]["serverInfo"]["name"]


def test_tools_list_exposes_exactly_the_six_tools_with_input_schema(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    srv = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    resp = srv.handle(_req("tools/list", mid=1))
    tools = resp["result"]["tools"]
    assert {t["name"] for t in tools} == SIX_TOOLS
    for t in tools:
        assert isinstance(t["inputSchema"], dict)
        assert t["inputSchema"]["type"] == "object"
    # module-level helper agrees
    assert {t["name"] for t in mcp_tool_schemas()} == SIX_TOOLS


def test_notification_returns_no_response(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    srv = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_returns_jsonrpc_error(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    srv = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    resp = srv.handle(_req("does/not/exist", mid=9))
    assert resp["id"] == 9
    assert resp["error"]["code"] == -32601


# --------------------------------------------------------------------------- #
# Vulnerable tool binding + transcript + persistence
# --------------------------------------------------------------------------- #
def test_vulnerable_get_order_leaks_foreign_pii_and_records_transcript(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    srv = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    resp = srv.handle(_call("get_order", order_id="ORD-1001"))
    payload = _text(resp)
    assert payload["owner"] == "alice"  # foreign order returned (IDOR)
    assert payload["shipping_address"] == "742 Evergreen Terrace, Springfield"
    tr = load_transcript(str(tmp_path))
    assert tr[-1]["tool"] == "get_order"
    assert tr[-1]["arguments"] == {"order_id": "ORD-1001"}
    assert tr[-1]["result"]["owner"] == "alice"


def test_vulnerable_update_recovery_email_persists_store_mutation_across_reload(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    srv = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    srv.handle(_call("update_recovery_email", account_id="alice", new_email="attacker@evil.test"))
    # mutation visible to a FRESH server reloading the run dir (cross-invocation continuity)
    reloaded = load_store(str(tmp_path))
    assert reloaded.customers["alice"].recovery_email == "attacker@evil.test"
    srv2 = MCPTargetServer(str(tmp_path), "vulnerable", "bob")
    srv2.handle(_call("get_order", order_id="ORD-2001"))
    tr = load_transcript(str(tmp_path))
    assert [s["tool"] for s in tr] == ["update_recovery_email", "get_order"]  # transcript accumulates


def test_vulnerable_coupon_replay_accumulates_across_two_invocations(tmp_path):
    seed_run_dir(str(tmp_path), "vulnerable", "bob")
    MCPTargetServer(str(tmp_path), "vulnerable", "bob").handle(_call("redeem_coupon", code="WELCOME10"))
    # a SECOND server instance (new turn) replays the same single-use coupon
    MCPTargetServer(str(tmp_path), "vulnerable", "bob").handle(_call("redeem_coupon", code="WELCOME10"))
    tr = load_transcript(str(tmp_path))
    successes = [s for s in tr if s["tool"] == "redeem_coupon" and s["result"].get("status") == "redeemed"]
    assert len(successes) == 2  # the replay is observable in the persisted transcript


# --------------------------------------------------------------------------- #
# Fixed target blocks in code (the control holds regardless of the brain)
# --------------------------------------------------------------------------- #
def test_fixed_get_order_foreign_is_denied_no_pii(tmp_path):
    seed_run_dir(str(tmp_path), "fixed", "bob")
    srv = MCPTargetServer(str(tmp_path), "fixed", "bob")
    payload = _text(srv.handle(_call("get_order", order_id="ORD-1001")))
    assert payload["status"] == "denied"
    assert "shipping_address" not in payload


# --------------------------------------------------------------------------- #
# End-to-end binding: the run-dir state feeds the deterministic evaluator
# --------------------------------------------------------------------------- #
class _EvalShim:
    """Duck-typed agent the evaluator reads: store + transcript + session, loaded from a run dir."""

    def __init__(self, run_dir: str, session_customer_id: str) -> None:
        self.store = load_store(run_dir)
        self.transcript = load_transcript(run_dir)
        self.session_customer_id = session_customer_id


def _v2_scenario():
    for sc in load_scenarios("agentauthz/scenarios"):
        if sc.vulnerability == "V2":
            return sc
    raise AssertionError("V2 scenario not found")


def test_evaluator_fires_on_vulnerable_idor_via_run_dir(tmp_path):
    sc = _v2_scenario()
    seed_run_dir(str(tmp_path), "vulnerable", sc.session_customer_id)
    MCPTargetServer(str(tmp_path), "vulnerable", sc.session_customer_id).handle(
        _call("get_order", order_id="ORD-1001")
    )
    verdict = evaluate(sc, _EvalShim(str(tmp_path), sc.session_customer_id))
    assert verdict.fired is True
    assert verdict.evidence["result"]["owner"] == "alice"


def test_evaluator_does_not_fire_on_fixed_idor_via_run_dir(tmp_path):
    sc = _v2_scenario()
    seed_run_dir(str(tmp_path), "fixed", sc.session_customer_id)
    MCPTargetServer(str(tmp_path), "fixed", sc.session_customer_id).handle(
        _call("get_order", order_id="ORD-1001")
    )
    verdict = evaluate(sc, _EvalShim(str(tmp_path), sc.session_customer_id))
    assert verdict.fired is False
