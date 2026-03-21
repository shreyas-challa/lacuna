"""Structured state management for the agent's working memory.

Tracks credentials, access levels, services, and findings so the LLM
always has actionable context without re-reading old tool output.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Credential:
    username: str
    password: str
    source: str  # "pcap", "file", "brute", "config", "hash"
    verified_for: list[str] = field(default_factory=list)  # ["ssh", "ftp"]
    failed_for: list[str] = field(default_factory=list)   # ["web"]

    @property
    def key(self) -> str:
        return f"{self.username}:{self.password}"


@dataclass
class Access:
    host: str
    user: str
    level: str  # "user", "root"
    method: str  # "ssh", "reverse_shell", "web_shell", "meterpreter"
    credential: Credential | None = None


@dataclass
class Service:
    host: str
    port: int
    protocol: str  # "tcp", "udp"
    name: str      # "ssh", "http", "ftp", "smb"
    version: str = ""
    info: str = ""  # extra info from nmap scripts, headers, etc.


@dataclass
class Finding:
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    service: str   # e.g. "10.10.10.1:80"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve: str = ""


class StateManager:
    """The agent's structured working memory.

    Everything actionable gets stored here and is injected into every
    LLM prompt, so the model never loses track of discoveries.
    """

    def __init__(self):
        self.credentials: dict[str, Credential] = {}  # key -> Credential
        self.accesses: list[Access] = []
        self.services: dict[str, Service] = {}  # "host:port" -> Service
        self.findings: list[Finding] = []
        self.loot: dict[str, str] = {}  # "user_flag" -> hash, "root_flag" -> hash
        self.notes: list[str] = []  # free-form observations

    # ── Credentials ──────────────────────────────────────────────

    def add_credential(self, username: str, password: str, source: str = "unknown") -> Credential:
        """Add or update a credential pair."""
        key = f"{username}:{password}"
        if key in self.credentials:
            return self.credentials[key]
        cred = Credential(username=username, password=password, source=source)
        self.credentials[key] = cred
        return cred

    def mark_credential_verified(self, username: str, password: str, service: str):
        """Mark a credential as verified for a service (e.g. 'ssh')."""
        key = f"{username}:{password}"
        if key in self.credentials:
            if service not in self.credentials[key].verified_for:
                self.credentials[key].verified_for.append(service)

    def mark_credential_failed(self, username: str, password: str, service: str):
        """Mark a credential as failed for a service."""
        key = f"{username}:{password}"
        if key in self.credentials:
            if service not in self.credentials[key].failed_for:
                self.credentials[key].failed_for.append(service)

    def get_untested_pairs(self) -> list[tuple[Credential, list[str]]]:
        """Return credentials with services they haven't been tested against."""
        all_service_types = set()
        for svc in self.services.values():
            if svc.name in ('ssh', 'ftp', 'smb', 'mysql', 'rdp'):
                all_service_types.add(svc.name)

        result = []
        for cred in self.credentials.values():
            tested = set(cred.verified_for + cred.failed_for)
            untested = list(all_service_types - tested)
            if untested:
                result.append((cred, untested))
        return result

    # ── Access ───────────────────────────────────────────────────

    def add_access(self, host: str, user: str, level: str = "user",
                   method: str = "ssh", credential: Credential | None = None):
        """Record that we have a shell on a host."""
        for a in self.accesses:
            if a.host == host and a.user == user:
                if level == "root":
                    a.level = "root"
                return
        self.accesses.append(Access(host=host, user=user, level=level,
                                    method=method, credential=credential))

    def has_access(self, host: str, level: str = "user") -> bool:
        for a in self.accesses:
            if a.host == host:
                if level == "user" or a.level == "root":
                    return True
        return False

    def has_root(self, host: str) -> bool:
        return any(a.host == host and a.level == "root" for a in self.accesses)

    # ── Services ─────────────────────────────────────────────────

    def add_service(self, host: str, port: int, protocol: str = "tcp",
                    name: str = "", version: str = "", info: str = "") -> Service:
        key = f"{host}:{port}"
        if key in self.services:
            svc = self.services[key]
            if version and not svc.version:
                svc.version = version
            if info:
                svc.info = info
            return svc
        svc = Service(host=host, port=port, protocol=protocol,
                      name=name, version=version, info=info)
        self.services[key] = svc
        return svc

    # ── Findings ─────────────────────────────────────────────────

    def add_finding(self, title: str, severity: str, service: str,
                    description: str = "", evidence: str = "",
                    cve: str = "") -> Finding:
        for f in self.findings:
            if f.title == title and f.service == service:
                return f
        finding = Finding(title=title, severity=severity, service=service,
                          description=description, evidence=evidence, cve=cve)
        self.findings.append(finding)
        return finding

    # ── Loot ─────────────────────────────────────────────────────

    def add_loot(self, name: str, value: str):
        """Store flags, hashes, or other extracted values."""
        self.loot[name] = value

    # ── Prompt Generation ────────────────────────────────────────

    def get_prompt_summary(self) -> str:
        """Generate a focused summary for the LLM system prompt.

        This is the critical function — everything here is always visible
        to the model, so it never loses track of what it knows.
        """
        sections = []

        # Credentials
        if self.credentials:
            lines = ["## Discovered Credentials"]
            for cred in self.credentials.values():
                status = ""
                if cred.verified_for:
                    status = f" [VERIFIED: {', '.join(cred.verified_for)}]"
                if cred.failed_for:
                    status += f" [FAILED: {', '.join(cred.failed_for)}]"
                lines.append(f"  - {cred.username} : {cred.password} (from {cred.source}){status}")

            # Untested pairs
            untested = self.get_untested_pairs()
            if untested:
                lines.append("  **UNTESTED — try these next:**")
                for cred, services in untested:
                    lines.append(f"    - {cred.username}:{cred.password} → try on {', '.join(services)}")
            sections.append('\n'.join(lines))

        # Access levels
        if self.accesses:
            lines = ["## Current Access"]
            for a in self.accesses:
                cred_note = ""
                if a.credential:
                    cred_note = f" (cred: {a.credential.username}:{a.credential.password})"
                lines.append(f"  - {a.host} as **{a.user}** [{a.level}] via {a.method}{cred_note}")
            sections.append('\n'.join(lines))

        # Services
        if self.services:
            lines = ["## Discovered Services"]
            for svc in sorted(self.services.values(), key=lambda s: s.port):
                ver = f" ({svc.version})" if svc.version else ""
                info = f" — {svc.info}" if svc.info else ""
                lines.append(f"  - {svc.host}:{svc.port}/{svc.protocol} {svc.name}{ver}{info}")
            sections.append('\n'.join(lines))

        # Loot
        if self.loot:
            lines = ["## Loot"]
            for name, value in self.loot.items():
                lines.append(f"  - {name}: {value}")
            sections.append('\n'.join(lines))

        # Findings
        if self.findings:
            lines = ["## Findings"]
            for f in sorted(self.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)):
                cve = f" ({f.cve})" if f.cve else ""
                lines.append(f"  - [{f.severity.upper()}] {f.title}{cve} on {f.service}")
            sections.append('\n'.join(lines))

        if not sections:
            return "## Agent State\nNo discoveries yet."

        return '\n\n'.join(sections)
