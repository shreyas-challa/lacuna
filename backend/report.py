"""Penetration test report generation.

Two paths feed the report:
  * `ReportBuilder` — sections the Operator explicitly appends via the
    `append_report` tool (optional, narrative colour).
  * `build_state_report` — a DETERMINISTIC report synthesized from the
    structured state + attack graph at the end of the engagement. The report
    is the deliverable, so it must never depend on the model remembering to
    narrate it; everything actionable already lives in StateManager/GraphManager.
"""

from __future__ import annotations


class ReportBuilder:
    """Accumulates markdown sections into a penetration test report."""

    def __init__(self, target: str):
        self.target = target
        self.sections: list[str] = [
            f"# Penetration Test Report: {target}\n",
        ]

    def append(self, markdown: str):
        """Append a section to the report."""
        self.sections.append(markdown)

    @property
    def has_content(self) -> bool:
        """True once anything beyond the title heading has been appended."""
        return len(self.sections) > 1

    def get_markdown(self) -> str:
        """Return the full report as markdown."""
        return '\n\n'.join(self.sections)


# ── Deterministic report synthesis ───────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _outcome(state) -> tuple[str, str]:
    """Return (headline, emoji) describing how far the engagement got."""
    if any(a.level == "root" for a in state.accesses):
        return "Full compromise — **root** access obtained", "🩸"
    if state.accesses:
        return "Foothold obtained — **user** access", "🚩"
    if state.credentials:
        return "Credentials recovered — no shell established", "🔑"
    return "No access obtained", "—"


def build_state_report(target: str, state, graph=None, meta: dict | None = None,
                       extra_sections: list[str] | None = None) -> str:
    """Synthesize a complete markdown report from structured state + graph.

    Deterministic: identical state always yields the same report. `meta` may
    carry engagement stats (model, iterations, tool_calls, cost, duration_s).
    `extra_sections` are appended Operator narrative sections, if any.
    """
    meta = meta or {}
    out: list[str] = [f"# Penetration Test Report: {target}"]

    # ── Executive summary ────────────────────────────────────────────
    headline, emoji = _outcome(state)
    out.append("## Executive Summary")
    summary = [f"{emoji} **Result:** {headline} on `{target}`."]
    if state.loot:
        flags = [f"`{name}` = `{value}`" for name, value in state.loot.items()]
        summary.append("**Flags captured:** " + "; ".join(flags) + ".")
    summary.append(
        f"Discovered {len(state.services)} service(s), "
        f"{len(state.credentials)} credential(s), "
        f"and {len(state.findings)} finding(s)."
    )
    out.append("\n\n".join(summary))

    # ── Engagement details ───────────────────────────────────────────
    if meta:
        rows = []
        if meta.get("model"):
            rows.append(f"| Model | {meta['model']} |")
        if meta.get("iterations") is not None:
            rows.append(f"| Iterations | {meta['iterations']} |")
        if meta.get("tool_calls") is not None:
            rows.append(f"| Tool calls | {meta['tool_calls']} |")
        if meta.get("planner_calls") is not None:
            rows.append(f"| Planner calls | {meta['planner_calls']} |")
        if meta.get("duration_s") is not None:
            rows.append(f"| Duration | {meta['duration_s']:.0f}s |")
        if meta.get("cost") is not None:
            rows.append(f"| Estimated cost | ${meta['cost']:.4f} |")
        if rows:
            out.append("## Engagement Details\n\n| Metric | Value |\n| --- | --- |\n" + "\n".join(rows))

    # ── Attack chain ─────────────────────────────────────────────────
    chain = _render_attack_chain(target, state, graph)
    if chain:
        out.append("## Attack Chain\n\n" + chain)

    # ── Services ─────────────────────────────────────────────────────
    if state.services:
        lines = ["## Services", "", "| Port | Proto | Service | Version | Info |", "| --- | --- | --- | --- | --- |"]
        for svc in sorted(state.services.values(), key=lambda s: s.port):
            info = (svc.info or "").replace("|", "\\|")[:80]
            lines.append(f"| {svc.port} | {svc.protocol} | {svc.name or '?'} | {svc.version or '-'} | {info or '-'} |")
        out.append("\n".join(lines))

    # ── Credentials ──────────────────────────────────────────────────
    if state.credentials:
        lines = ["## Credentials", ""]
        for cred in state.credentials.values():
            status = ""
            if cred.verified_for:
                status = f" — verified for {', '.join(cred.verified_for)}"
            lines.append(f"- `{cred.username}:{cred.password}` (source: {cred.source}){status}")
        out.append("\n".join(lines))

    # ── Access ───────────────────────────────────────────────────────
    if state.accesses:
        lines = ["## Access Obtained", ""]
        for a in state.accesses:
            cred = f" using `{a.credential.username}:{a.credential.password}`" if a.credential else ""
            lines.append(f"- **{a.user}** ({a.level}) on `{a.host}` via {a.method}{cred}")
        out.append("\n".join(lines))

    # ── Findings ─────────────────────────────────────────────────────
    if state.findings:
        lines = ["## Findings", ""]
        for f in sorted(state.findings, key=lambda x: _SEV_ORDER.get(x.severity, 5)):
            cve = f" ({f.cve})" if f.cve else ""
            lines.append(f"- **[{f.severity.upper()}]** {f.title}{cve} — `{f.service}`")
            if f.description:
                lines.append(f"  - {f.description}")
            if f.evidence:
                lines.append(f"  - Evidence: {f.evidence}")
        out.append("\n".join(lines))

    # ── Loot ─────────────────────────────────────────────────────────
    if state.loot:
        lines = ["## Loot", ""]
        for name, value in state.loot.items():
            lines.append(f"- **{name}**: `{value}`")
        out.append("\n".join(lines))

    # ── Notable observations ─────────────────────────────────────────
    if state.notes:
        lines = ["## Notable Observations", ""]
        for note in state.notes[:15]:
            lines.append(f"- {note}")
        out.append("\n".join(lines))

    # ── Operator narrative (optional) ────────────────────────────────
    if extra_sections:
        out.append("## Operator Notes\n\n" + "\n\n".join(extra_sections))

    return "\n\n".join(out)


def _render_attack_chain(target: str, state, graph) -> str:
    """Render the attack chain as an ordered list.

    Prefers a graph walk (machine → … → root) so provenance is shown; falls
    back to a state-derived narrative when the graph is sparse.
    """
    steps: list[str] = []

    # Services that gave the initial surface.
    surface = sorted(state.services.values(), key=lambda s: s.port)
    if surface:
        names = ", ".join(f"{s.name or '?'}/{s.port}" for s in surface)
        steps.append(f"**Enumeration** — exposed services: {names}.")

    # Credential acquisition (with provenance from cred.source).
    for cred in state.credentials.values():
        steps.append(
            f"**Credential access** — recovered `{cred.username}:{cred.password}` "
            f"from {cred.source}."
        )

    # Footholds / privesc, in the order they were achieved.
    for a in state.accesses:
        if a.level == "root":
            steps.append(f"**Privilege escalation** — escalated to **root** on `{a.host}` via {a.method}.")
        else:
            steps.append(f"**Foothold** — gained **{a.user}** ({a.level}) on `{a.host}` via {a.method}.")

    # Pull in any privesc-relevant edges/labels from the graph for colour.
    if graph is not None and getattr(graph, "edges", None):
        notable = [e for e in graph.edges if e.get("label") in ("capability", "privesc", "sqli", "wp-vuln")]
        for e in notable:
            node = graph.nodes.get(e["target"], {})
            label = node.get("label", e["target"])
            steps.append(f"**Vector** — {label} ({e['label']}).")

    if not steps:
        return ""

    # De-dup while preserving order.
    seen = set()
    ordered = []
    for s in steps:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return "\n".join(f"{i}. {s}" for i, s in enumerate(ordered, 1))
