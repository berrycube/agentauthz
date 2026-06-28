"""Structured benchmark REPORT.

Correct, secure harness code (NOT a deliberate vulnerability): a ``Report`` aggregates
the runner's per-scenario verdicts into a structured artifact — a per-scenario results
list, the subset of fired ``findings`` (each with its transcript evidence), and a
``summary`` (total / fired_count / by_vulnerability) — serializable to dict / JSON /
Markdown for a human or a downstream consumer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Report:
    """The structured result of one benchmark run against a target.

    ``results`` is the per-scenario verdict summary; ``findings`` is the subset that
    fired (each carrying the proving transcript + evidence); ``summary`` aggregates
    counts (``total`` / ``fired_count`` / ``by_vulnerability``).
    """

    target: str
    results: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return the full {target, results, findings, summary} dict."""
        return {
            "target": self.target,
            "results": self.results,
            "findings": self.findings,
            "summary": self.summary,
        }

    def to_json(self, indent: int = 2) -> str:
        """Return ``json.dumps(self.to_dict(), ...)`` (round-trips to_dict)."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def to_markdown(self) -> str:
        """Return a non-empty human-readable report naming every fired vulnerability."""
        lines: list[str] = []

        # Header
        lines.append(f"# Benchmark Report — target: `{self.target}`")
        lines.append("")

        # Summary line
        total = self.summary.get("total", 0)
        fired = self.summary.get("fired_count", 0)
        lines.append(f"**Summary:** {fired}/{total} scenarios fired a vulnerability.")
        lines.append("")

        # Results table
        lines.append("## Results")
        lines.append("")
        lines.append("| Scenario | Vulnerability | Fired | Turns |")
        lines.append("|---|---|---|---|")
        for r in self.results:
            fired_str = "YES" if r.get("fired") else "no"
            lines.append(
                f"| {r.get('scenario_id', '')} "
                f"| {r.get('vulnerability', '')} "
                f"| {fired_str} "
                f"| {r.get('turns_used', 0)} |"
            )
        lines.append("")

        # Per-finding evidence blocks
        if self.findings:
            lines.append("## Findings")
            lines.append("")
            for f in self.findings:
                vuln = f.get("vulnerability", "")
                sid = f.get("scenario_id", "")
                detail = f.get("detail", "")
                lines.append(f"### {vuln} — {sid}")
                lines.append("")
                if detail:
                    lines.append(f"**Detail:** {detail}")
                    lines.append("")
                evidence = f.get("evidence")
                if evidence:
                    lines.append("**Evidence:**")
                    lines.append("")
                    lines.append("```json")
                    lines.append(json.dumps(evidence, indent=2, default=str))
                    lines.append("```")
                    lines.append("")
                transcript = f.get("transcript", [])
                if transcript:
                    lines.append(f"**Transcript ({len(transcript)} step(s)):**")
                    lines.append("")
                    lines.append("```json")
                    lines.append(json.dumps(transcript, indent=2, default=str))
                    lines.append("```")
                    lines.append("")

        # by_vulnerability summary
        by_vuln = self.summary.get("by_vulnerability", {})
        if by_vuln:
            lines.append("## By Vulnerability")
            lines.append("")
            for vuln in sorted(by_vuln):
                count = by_vuln[vuln]
                lines.append(f"- **{vuln}**: {count} finding(s)")
            lines.append("")

        return "\n".join(lines)
