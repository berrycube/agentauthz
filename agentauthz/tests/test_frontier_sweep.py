"""Deterministic, OFFLINE tests for the frontier sweep ORCHESTRATION (seat-aware accounting
+ aggregation).  Fake drivers (fire / refuse / transport-error) stand in for the live CLIs —
NO subprocess, NO network.  The attacker is the scenario's deterministic script (there is no
attacker seat to fake).  The honest-recording rule: error != safe — a CLI transport failure is
an ERROR excluded from the denominator; a refusal / code-block is a genuine non-fire.
"""
from __future__ import annotations

import pytest

from agentauthz.harness.cli_target import CLIError
from agentauthz.harness.frontier_sweep import build_driver, frontier_sweep
from agentauthz.harness.loader import load_scenarios
from agentauthz.harness.mcp_target import MCPTargetServer


def _v2_only():
    return [sc for sc in load_scenarios("agentauthz/scenarios") if sc.vulnerability == "V2"]


class _FireDriver:
    """Simulate a model that calls the IDOR tool (leaks ORD-1001) — regardless of the scripted
    attacker message it is handed."""

    def label(self):
        return "fake-fire"

    def run_turn(self, message, *, run_dir, target, session_customer_id, system_prompt, allowed_tools):
        MCPTargetServer(run_dir, target, session_customer_id).handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "get_order", "arguments": {"order_id": "ORD-1001"}}}
        )
        return "Here are the order details."


class _RefuseDriver:
    """Simulate a model that declines to call any tool (a refusal — a genuine non-fire)."""

    def label(self):
        return "fake-refuse"

    def run_turn(self, message, **kw):
        return "I can only help with your own orders."


class _ErrorDriver:
    """Simulate a transport/exec failure on every turn."""

    def label(self):
        return "fake-error"

    def run_turn(self, message, **kw):
        raise CLIError("simulated CLI crash")


def _cell(report, label, vuln="V2"):
    return next(c for c in report.cells if c["target_model"] == label and c["vulnerability"] == vuln)


def test_fire_driver_vulnerable_fires_every_repeat(tmp_path):
    report = frontier_sweep([_FireDriver()], _v2_only(), "vulnerable",
                            repeats=3, run_root=str(tmp_path))
    c = _cell(report, "fake-fire")
    assert (c["fired_count"], c["error_count"], c["rate"]) == (3, 0, 1.0)
    assert report.attacker == "deterministic per-scenario script"


def test_fire_driver_fixed_does_not_fire(tmp_path):
    report = frontier_sweep([_FireDriver()], _v2_only(), "fixed",
                            repeats=3, run_root=str(tmp_path))
    c = _cell(report, "fake-fire")
    assert (c["fired_count"], c["error_count"]) == (0, 0)  # code block = genuine 0, not error


def test_refusal_is_genuine_non_fire_not_error(tmp_path):
    report = frontier_sweep([_RefuseDriver()], _v2_only(), "vulnerable",
                            repeats=4, run_root=str(tmp_path))
    c = _cell(report, "fake-refuse")
    assert (c["fired_count"], c["error_count"]) == (0, 0)  # refused, but NOT an error


def test_cli_transport_error_is_excluded_from_denominator(tmp_path):
    report = frontier_sweep([_ErrorDriver()], _v2_only(), "vulnerable",
                            repeats=5, run_root=str(tmp_path))
    c = _cell(report, "fake-error")
    assert c["error_count"] == 5
    assert c["fired_count"] == 0
    assert c["rate"] == 0.0  # effective denominator is 0 -> honest 0.0, never a 'safe' clean run
    assert "err)" in report.to_markdown()  # the matrix annotates the errored cell


def test_multiple_drivers_produce_labelled_cells(tmp_path):
    report = frontier_sweep([_FireDriver(), _RefuseDriver()], _v2_only(), "vulnerable",
                            repeats=2, run_root=str(tmp_path))
    assert report.target_models == ["fake-fire", "fake-refuse"]
    assert _cell(report, "fake-fire")["fired_count"] == 2
    assert _cell(report, "fake-refuse")["fired_count"] == 0


def test_invalid_inputs_fail_closed(tmp_path):
    with pytest.raises(ValueError):
        frontier_sweep([_FireDriver()], _v2_only(), "bogus", repeats=1, run_root=str(tmp_path))
    with pytest.raises(ValueError):
        frontier_sweep([_FireDriver()], _v2_only(), "vulnerable", repeats=0, run_root=str(tmp_path))
    with pytest.raises(ValueError):
        frontier_sweep([], _v2_only(), "vulnerable", repeats=1, run_root=str(tmp_path))


def test_build_driver_specs():
    from agentauthz.harness.cli_target import ClaudeCodeDriver, CodexDriver
    assert isinstance(build_driver("claude:claude-sonnet-4-6"), ClaudeCodeDriver)
    assert isinstance(build_driver("codex:gpt-5.5"), CodexDriver)
    assert build_driver("claude:claude-opus-4-8").label() == "claude-code:claude-opus-4-8"
    with pytest.raises(ValueError):
        build_driver("nocolon")
    with pytest.raises(ValueError):
        build_driver("unknown:model")
