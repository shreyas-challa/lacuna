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


@dataclass
class WebSession:
    name: str
    base_url: str = ""
    last_url: str = ""
    last_status: int = 0
    last_content_type: str = ""
    authenticated: bool = False
    cookies: list[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    key: str
    description: str
    status: str = "active"  # active, validated, rejected
    evidence: str = ""


class StateManager:
    """The agent's structured working memory.

    Everything actionable gets stored here and is injected into every
    LLM prompt, so the model never loses track of discoveries.
    """

    # Generic libraries to skip when tracking web assets — these are never security-relevant
    _SKIP_ASSETS = {
        # JS frameworks & UI libraries
        'jquery', 'bootstrap', 'popper', 'modernizr', 'angular', 'react', 'vue',
        'backbone', 'ember', 'lodash', 'underscore', 'moment', 'handlebars',
        # CSS/icon libraries
        'font-awesome', 'fontawesome', 'material-icons', 'ionicons', 'glyphicons',
        # Navigation/menu plugins
        'metismenu', 'metis-menu', 'slimscroll', 'nicescroll', 'perfect-scrollbar',
        # Carousel/slider plugins
        'owl.carousel', 'owl-carousel', 'slick', 'swiper', 'flexslider', 'lightbox',
        # Chart/visualization libraries
        'chart.js', 'chartjs', 'd3.js', 'highcharts', 'morris', 'raphael', 'flot',
        'line-chart', 'pie-chart', 'bar-chart', 'sparkline', 'peity', 'knob',
        # Animation/effects
        'animate', 'wow.js', 'wow.min', 'waypoint', 'scrollreveal', 'aos',
        # Polyfills/utilities
        'html5shiv', 'respond', 'polyfill', 'pace', 'nprogress',
        # Analytics/tracking
        'google-analytics', 'gtag', 'analytics', 'hotjar', 'mixpanel',
        # Form/validation
        'validate', 'parsley', 'select2', 'chosen', 'datepicker', 'colorpicker',
        # Misc common
        'toastr', 'sweetalert', 'swal', 'notify', 'socket.io',
    }
    _MAX_ASSETS_PER_CATEGORY = 20

    def __init__(self):
        self.credentials: dict[str, Credential] = {}  # key -> Credential
        self.accesses: list[Access] = []
        self.services: dict[str, Service] = {}  # "host:port" -> Service
        self.findings: list[Finding] = []
        self.loot: dict[str, str] = {}  # "user_flag" -> hash, "root_flag" -> hash
        self.notes: list[str] = []  # free-form observations
        self.web_sessions: dict[str, WebSession] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.workflow_markers: dict[str, bool] = {}
        self.web_assets: dict[str, set[str]] = {
            'scripts': set(),        # JS files found in HTML
            'stylesheets': set(),    # CSS files
            'forms': set(),          # form action URLs
            'api_endpoints': set(),  # /api/v1/... paths from JS/HTML
        }

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

    def add_note(self, note: str):
        """Store a short free-form observation once."""
        note = (note or '').strip()
        if note and note not in self.notes:
            self.notes.append(note)

    def set_workflow_marker(self, key: str, value: bool = True):
        """Track completion of app-workflow milestones."""
        if key:
            self.workflow_markers[key] = value

    def upsert_web_session(self, name: str, **kwargs):
        """Create or update a web session summary."""
        if not name:
            return
        session = self.web_sessions.get(name)
        if not session:
            session = WebSession(name=name)
            self.web_sessions[name] = session

        for key, value in kwargs.items():
            if value is None:
                continue
            if key == 'cookies' and value:
                for cookie in value:
                    if cookie and cookie not in session.cookies:
                        session.cookies.append(cookie)
            elif hasattr(session, key) and value != "":
                setattr(session, key, value)

    def upsert_hypothesis(self, key: str, description: str, status: str = "active", evidence: str = ""):
        """Track the current dominant reasoning branches explicitly."""
        if not key or not description:
            return
        existing = self.hypotheses.get(key)
        if existing:
            existing.description = description
            existing.status = status or existing.status
            if evidence:
                existing.evidence = evidence
            return
        self.hypotheses[key] = Hypothesis(
            key=key,
            description=description,
            status=status or "active",
            evidence=evidence,
        )

    # ── Web Assets ────────────────────────────────────────────────

    def add_web_asset(self, category: str, url: str) -> bool:
        """Add a discovered web asset. Returns True if newly added."""
        if category not in self.web_assets:
            return False
        url_clean = url.split('?')[0].strip()
        if not url_clean or url_clean == '#':
            return False
        # Skip generic third-party libraries
        basename = url_clean.rsplit('/', 1)[-1].lower()
        if any(skip in basename for skip in self._SKIP_ASSETS):
            return False
        # Skip full external URLs (CDNs, etc.)
        if url_clean.startswith('http') and '://' in url_clean:
            return False
        # Cap per category
        if len(self.web_assets[category]) >= self._MAX_ASSETS_PER_CATEGORY:
            return False
        if url_clean in self.web_assets[category]:
            return False
        self.web_assets[category].add(url_clean)
        return True

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

        # Web Assets
        all_assets = sum(len(v) for v in self.web_assets.values())
        if all_assets:
            lines = ["## Discovered Web Assets"]
            for cat, items in self.web_assets.items():
                if items:
                    lines.append(f"  **{cat}**: {', '.join(sorted(items))}")
            lines.append("  *Fetch unfamiliar files with curl_request or download_and_analyze.*")
            sections.append('\n'.join(lines))

        # Web Sessions
        if self.web_sessions:
            lines = ["## Web Sessions"]
            for session in self.web_sessions.values():
                cookies = ', '.join(session.cookies[:6]) if session.cookies else 'none'
                auth = 'yes' if session.authenticated else 'no'
                lines.append(
                    f"  - {session.name}: status={session.last_status or 'unknown'}, auth={auth}, "
                    f"cookies={cookies}, last_url={session.last_url or session.base_url or 'n/a'}"
                )
            sections.append('\n'.join(lines))

        if self.workflow_markers:
            lines = ["## Workflow Markers"]
            for key in sorted(k for k, v in self.workflow_markers.items() if v):
                lines.append(f"  - {key}")
            if len(lines) > 1:
                sections.append('\n'.join(lines))

        # Loot
        if self.loot:
            lines = ["## Loot"]
            for name, value in self.loot.items():
                lines.append(f"  - {name}: {value}")
            sections.append('\n'.join(lines))

        # Notes
        if self.notes:
            lines = ["## Notes"]
            for note in self.notes[:8]:
                lines.append(f"  - {note}")
            sections.append('\n'.join(lines))

        # Hypotheses
        active_hypotheses = [h for h in self.hypotheses.values() if h.status in ('active', 'validated')]
        if active_hypotheses:
            lines = ["## Hypotheses"]
            for hyp in active_hypotheses[:6]:
                evidence = f" — {hyp.evidence}" if hyp.evidence else ""
                lines.append(f"  - [{hyp.status.upper()}] {hyp.description}{evidence}")
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

    def to_snapshot(self) -> dict:
        """Return a JSON-serializable structured state snapshot for planning."""
        return {
            'credentials': [
                {
                    'username': cred.username,
                    'password': cred.password,
                    'source': cred.source,
                    'verified_for': list(cred.verified_for),
                    'failed_for': list(cred.failed_for),
                }
                for cred in self.credentials.values()
            ],
            'accesses': [
                {
                    'host': access.host,
                    'user': access.user,
                    'level': access.level,
                    'method': access.method,
                }
                for access in self.accesses
            ],
            'services': [
                {
                    'host': svc.host,
                    'port': svc.port,
                    'protocol': svc.protocol,
                    'name': svc.name,
                    'version': svc.version,
                    'info': svc.info,
                }
                for svc in sorted(self.services.values(), key=lambda item: item.port)
            ],
            'findings': [
                {
                    'title': finding.title,
                    'severity': finding.severity,
                    'service': finding.service,
                    'description': finding.description,
                    'evidence': finding.evidence,
                    'cve': finding.cve,
                }
                for finding in self.findings
            ],
            'loot': dict(self.loot),
            'notes': list(self.notes),
            'workflow_markers': sorted(key for key, value in self.workflow_markers.items() if value),
            'web_sessions': [
                {
                    'name': session.name,
                    'base_url': session.base_url,
                    'last_url': session.last_url,
                    'last_status': session.last_status,
                    'last_content_type': session.last_content_type,
                    'authenticated': session.authenticated,
                    'cookies': list(session.cookies),
                }
                for session in self.web_sessions.values()
            ],
            'web_assets': {key: sorted(values) for key, values in self.web_assets.items()},
            'hypotheses': [
                {
                    'key': hyp.key,
                    'description': hyp.description,
                    'status': hyp.status,
                    'evidence': hyp.evidence,
                }
                for hyp in self.hypotheses.values()
            ],
        }
