"""Lacuna Agent — core autonomous penetration testing loop.

Architecture:
  - StateManager tracks all structured findings (creds, services, access, loot)
  - ContextManager compresses old messages to prevent token bloat
  - Knowledge base provides instant exploit recognition
  - Graph + frontend provide real-time visualization
  - Adaptive strategy engine auto-advances phases based on state
  - Planning/reflection prompts force structured reasoning
"""

import json
import os
import re
import shutil
import subprocess
import time
import inspect
from pathlib import Path
from datetime import datetime

from backend.llm import get_client, chat_completion, extract_usage, get_active_model, get_active_backend
from backend.graph import GraphManager
from backend.report import ReportBuilder
from backend.ws_manager import WSManager
from backend.state import StateManager
from backend.context import build_messages
from backend.knowledge import match_service_to_exploits, get_privesc_advice, REVERSE_SHELLS
from backend.tools import TOOL_REGISTRY, get_tools_for_phase
from backend.tools.exploitation import set_lhost
from backend.parsers import TOOL_PARSERS, STATE_EXTRACTORS

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"

PHASES = ['enumeration', 'exploitation', 'privesc']
MAX_ITERATIONS_PER_PHASE = 40
MAX_TOTAL_ITERATIONS = 150

# ── Terminal colors ──────────────────────────────────────────────
C_RESET = '\033[0m'
C_BOLD = '\033[1m'
C_DIM = '\033[2m'
C_BLUE = '\033[94m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_RED = '\033[91m'
C_CYAN = '\033[96m'
C_MAGENTA = '\033[95m'

# ── Argument normalization ───────────────────────────────────────
ARG_ALIASES = {
    'host': 'target', 'ip': 'target', 'hostname': 'target',
    'address': 'target', 'rhost': 'target',
    'options': 'flags', 'args': 'flags', 'arguments': 'flags',
    'params': 'flags', 'nmap_flags': 'flags', 'scan_flags': 'flags',
    'dictionary': 'wordlist', 'wordlist_path': 'wordlist', 'list': 'wordlist',
    'search': 'query', 'term': 'query', 'search_query': 'query',
    'cmd': 'command', 'shell_command': 'command', 'exec': 'command',
    'target_url': 'url', 'site': 'url',
    'content': 'markdown', 'text': 'markdown', 'body': 'markdown',
    'file': 'filename', 'name': 'filename', 'output': 'filename',
    'file_name': 'filename',
}

# ── Tools that must never be cached (stateful / side-effects) ───
_NO_CACHE = frozenset({
    'transition_phase', 'append_report', 'update_graph',
    'msfconsole_run', 'send_payload', 'setup_listener',
    'run_linpeas', 'check_sudo', 'check_suid', 'check_cron',
})

# ── Meta tools (always available) ───────────────────────────────
META_TOOLS = [
    {
        'type': 'function',
        'function': {
            'name': 'transition_phase',
            'description': (
                'Move to the next phase. You can skip phases (e.g. enum → exploitation if you found creds). '
                'Call with next_phase="complete" when you have root and the root flag.'
            ),
            'parameters': {
                'type': 'object',
                'properties': {
                    'next_phase': {
                        'type': 'string',
                        'enum': ['exploitation', 'privesc', 'complete'],
                        'description': 'The phase to transition to',
                    },
                    'reason': {'type': 'string', 'description': 'Why you are transitioning'},
                },
                'required': ['next_phase', 'reason'],
            },
        },
    },
    {
        'type': 'function',
        'function': {
            'name': 'append_report',
            'description': 'Append a markdown section to the penetration test report.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'markdown': {'type': 'string', 'description': 'Markdown content to append'},
                },
                'required': ['markdown'],
            },
        },
    },
]

# ── Tool-specific error hints ────────────────────────────────────
TOOL_HINTS = {
    'nmap_scan': 'HINT: Check the target IP is correct and reachable. Try fewer ports (-p 80,443) or a lighter scan (-sT) instead of a full scan.',
    'gobuster_dir': 'HINT: Verify the URL scheme (http vs https) and that the web server is running. Try a smaller wordlist or different URL path.',
    'ffuf_fuzz': 'HINT: Ensure the URL contains the FUZZ keyword. Check the target is responding. Try filtering by response size (-fs) or status code (-fc).',
    'whatweb_scan': 'HINT: Verify the target URL/IP is correct. Try using http:// or https:// explicitly.',
    'curl_request': 'HINT: Check the URL is well-formed and the service is up. Try adding -v for verbose output or -k to skip TLS verification.',
    'download_and_analyze': 'HINT: Verify the download URL is correct and the file exists. Check HTTP response code. Try curl_request first to confirm the URL works.',
    'execute_command': 'HINT: Check command syntax. If running remote commands via SSH, verify credentials and connectivity first.',
    'nuclei_scan': 'HINT: Ensure the target URL is correct. Try with specific templates (-t) instead of full scan. Check if nuclei templates are installed.',
    'searchsploit': 'HINT: Simplify the search query — use just the software name and version (e.g. "Apache 2.4.49"). Avoid special characters.',
    'nikto_scan': 'HINT: Verify the target URL is correct and the web server is responding. Try with -ssl flag if HTTPS.',
    'msfconsole_run': 'HINT: Check module path and options. Ensure RHOSTS/RHOST, LHOST, LPORT are set. Use semicolons between commands.',
    'setup_listener': 'HINT: Ensure the port is not already in use. Try a different port.',
    'send_payload': 'HINT: Verify the delivery command syntax and target endpoint. Ensure listener is set up before sending.',
    'run_linpeas': 'HINT: Ensure you have shell access on the target first. You MUST wrap with sshpass for remote execution.',
    'check_sudo': 'HINT: You MUST provide a full sshpass SSH command. Use: sshpass -p \'PASS\' ssh -o StrictHostKeyChecking=no USER@TARGET \'sudo -l\'',
    'check_suid': 'HINT: You MUST provide a full sshpass SSH command to run this remotely on the target.',
    'check_cron': 'HINT: You MUST provide a full sshpass SSH command to run this remotely on the target.',
    'sqlmap_scan': 'HINT: Ensure the target URL has a parameter to test (e.g. ?id=1). Try with --level=3 --risk=2 for deeper testing.',
    'hydra_brute': 'HINT: Verify the service is running and accessible. Try fewer credentials or a different protocol.',
    'wpscan': 'HINT: Ensure the target is running WordPress. Check the URL (usually /wp-login.php exists).',
}


def load_prompt(filename: str) -> str:
    path = PROMPTS_DIR / filename
    return path.read_text() if path.exists() else ""


class SessionLogger:
    def __init__(self, target: str):
        LOGS_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('.', '_').replace(':', '_')
        self.log_path = LOGS_DIR / f'{timestamp}_{safe_target}.log'
        self.log_file = open(self.log_path, 'w')

    def log(self, msg: str):
        timestamp = time.strftime('%H:%M:%S')
        print(f"{C_DIM}[{timestamp}]{C_RESET} {msg}")
        plain = re.sub(r'\033\[[0-9;]*m', '', f'[{timestamp}] {msg}')
        self.log_file.write(plain + '\n')
        self.log_file.flush()

    def header(self, msg: str):
        print(msg)
        plain = re.sub(r'\033\[[0-9;]*m', '', msg)
        self.log_file.write(plain + '\n')
        self.log_file.flush()

    def close(self):
        self.log_file.close()


def normalize_args(name: str, args: dict) -> dict:
    normalized = {}
    for key, value in args.items():
        canonical = ARG_ALIASES.get(key, key)
        normalized[canonical] = value
    if name == 'append_report' and 'title' in args:
        title = args.get('title', '')
        md = normalized.get('markdown', '')
        if title and md:
            normalized['markdown'] = f"## {title}\n\n{md}"
        elif title and not md:
            normalized['markdown'] = f"## {title}"
    return normalized


def _add_tool_hint(name: str, args: dict, error_msg: str) -> str:
    hint = TOOL_HINTS.get(name, 'HINT: Try a different approach or tool. Do not repeat the same call.')
    if 'TIMEOUT' in error_msg:
        hint = f'HINT: Command timed out. Try a faster/lighter variant or reduce scope. {hint.replace("HINT: ", "Also: ")}'
    return f"{error_msg} {hint}"


def _find_terminal() -> str | None:
    """Find an available terminal emulator for spawning shell sessions."""
    for term in ['gnome-terminal', 'konsole', 'xfce4-terminal', 'kitty', 'alacritty', 'xterm']:
        if shutil.which(term):
            return term
    return None


def _spawn_terminal_ssh(host: str, user: str, password: str, terminal: str):
    """Spawn a new terminal window with an SSH session to the target."""
    ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{host}"
    title = f"Lacuna Shell — {user}@{host}"

    try:
        if terminal == 'gnome-terminal':
            subprocess.Popen([
                'gnome-terminal', '--title', title, '--',
                'bash', '-c', f'{ssh_cmd}; echo "--- Session ended. Press Enter to close ---"; read'
            ], start_new_session=True)
        elif terminal == 'konsole':
            subprocess.Popen([
                'konsole', '--title', title, '-e',
                'bash', '-c', f'{ssh_cmd}; echo "--- Session ended. Press Enter to close ---"; read'
            ], start_new_session=True)
        elif terminal == 'xfce4-terminal':
            subprocess.Popen([
                'xfce4-terminal', '--title', title, '-e',
                f'bash -c \'{ssh_cmd}; echo "--- Session ended. Press Enter to close ---"; read\''
            ], start_new_session=True)
        elif terminal == 'kitty':
            subprocess.Popen([
                'kitty', '--title', title,
                'bash', '-c', f'{ssh_cmd}; echo "--- Session ended. Press Enter to close ---"; read'
            ], start_new_session=True)
        elif terminal == 'alacritty':
            subprocess.Popen([
                'alacritty', '--title', title, '-e',
                'bash', '-c', f'{ssh_cmd}; echo "--- Session ended. Press Enter to close ---"; read'
            ], start_new_session=True)
        elif terminal == 'xterm':
            subprocess.Popen([
                'xterm', '-title', title, '-e',
                f'bash -c \'{ssh_cmd}; echo "--- Session ended. Press Enter to close ---"; read\''
            ], start_new_session=True)
        return True
    except Exception:
        return False


class Agent:
    def __init__(self, target: str, manager: WSManager, lhost: str = ''):
        self.target = target
        self.lhost = lhost
        self.manager = manager
        self.graph = GraphManager()
        self.report = ReportBuilder(target)
        self.state = StateManager()
        self.client = get_client()
        self.phase = 'enumeration'
        self.messages: list[dict] = []
        self.total_iterations = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.logger = SessionLogger(target)
        self._done = False
        self._tool_cache: dict[str, str] = {}
        self._tool_call_count = 0
        self._phase_entry_iteration = 0
        self._phase_entry_node_count = 0
        self._last_nudge_iteration = -99
        self._knowledge_injected: set[str] = set()
        self.total_cost = 0.0
        self.total_cached_tokens = 0
        self._tool_failures: dict[str, int] = {}
        # Reasoning layer tracking
        self._plan_injected_for_phase: set[str] = set()
        self._phase_failure_count: int = 0
        self._reflection_injected_at: int = -99
        self._current_strategy: str = ''
        # Consecutive wasted iteration tracker (blocked/warned/cached/no-op tool calls)
        self._consecutive_waste: int = 0
        # Same-file repetition tracker: "/tmp/filename" -> count of commands with empty results
        self._file_analysis_count: dict[str, int] = {}
        # Iteration counter for context windowing
        self._iteration_counter: int = 0
        # Shell session tracking
        self._spawned_sessions: set[str] = set()  # "user@host" keys
        self._terminal = _find_terminal()
        # Track previous access count for detecting new access
        self._prev_access_count: int = 0
        # Track hostnames added to /etc/hosts
        self._hosts_added: set = set()

    # ── System prompt construction ───────────────────────────────
    def _build_system_prompt(self) -> str:
        # STATIC PREFIX
        system = load_prompt("system.md")
        lhost = f"\nLHOST: {self.lhost}" if self.lhost else ""
        static = f"{system}\n\nTarget: {self.target}{lhost}"

        # SEMI-STATIC — changes on phase transition
        phase_prompt = load_prompt(f"{self.phase}.md")
        semi_static = f"\n\n## Phase: {self.phase}\n{phase_prompt}"

        # DYNAMIC — changes every iteration
        dynamic_parts = []

        state_summary = self.state.get_prompt_summary()
        if state_summary:
            dynamic_parts.append(state_summary)

        knowledge = self._get_knowledge_hints()
        if knowledge:
            dynamic_parts.append(knowledge)

        # Tool suggestions based on current state
        suggestions = self._get_tool_suggestions()
        if suggestions:
            dynamic_parts.append(suggestions)

        graph_brief = self.graph.get_brief_summary()
        if graph_brief:
            dynamic_parts.append(graph_brief)

        budget_total = MAX_TOTAL_ITERATIONS
        remaining = max(0, budget_total - self._tool_call_count)
        dynamic_parts.append(f"Budget: {remaining}/{budget_total} calls left")

        return static + semi_static + '\n\n' + '\n\n'.join(dynamic_parts)

    def _get_knowledge_hints(self) -> str:
        """Match discovered services against exploit knowledge base."""
        hints = []
        for svc in self.state.services.values():
            svc_key = f"{svc.name}:{svc.version}"
            if svc_key in self._knowledge_injected:
                continue
            matches = match_service_to_exploits(svc.name, svc.version)
            for exploit in matches:
                if exploit.get('severity') not in ('critical', 'high'):
                    continue  # Only auto-inject critical/high matches
                cve = f" ({exploit['cve']})" if exploit.get('cve') else ""
                hints.append(
                    f"- **{svc.name} {svc.version}** on port {svc.port}: "
                    f"{exploit['description']}{cve}\n"
                    f"  Exploit: `{exploit['exploit']}`"
                )
                self._knowledge_injected.add(svc_key)
        if hints:
            return "## Known Exploits Detected\n" + '\n'.join(hints)
        return ""

    def _get_tool_suggestions(self) -> str:
        """Generate brief tool hints based on current state patterns."""
        suggestions = []

        # Web service found but not scanned
        web_ports = [svc for svc in self.state.services.values()
                     if svc.name in ('http', 'https', 'http-proxy')]
        if web_ports and self._tool_call_count < 5:
            for svc in web_ports:
                suggestions.append(
                    f"Web service on port {svc.port} — consider gobuster_dir or curl_request"
                )

        # Untested credentials exist
        untested = self.state.get_untested_pairs()
        if untested:
            for cred, services in untested[:2]:
                suggestions.append(
                    f"UNTESTED CRED: {cred.username}:{cred.password} — try on {', '.join(services)}"
                )

        # Have user access but no root — suggest privesc tools
        has_user = any(a.level == 'user' for a in self.state.accesses)
        has_root = self.state.has_root(self.target)
        if has_user and not has_root and self.phase == 'privesc':
            suggestions.append(
                "User shell obtained — run check_sudo, check_suid, check_cron"
            )

        # Credentials found but still in enumeration
        if self.state.credentials and self.phase == 'enumeration':
            suggestions.append(
                "Credentials discovered — consider transitioning to exploitation"
            )

        if suggestions:
            return "## Suggested Actions\n" + '\n'.join(f"- {s}" for s in suggestions[:4])
        return ""

    def _get_tools(self) -> list[dict]:
        phase_tools = get_tools_for_phase(self.phase)
        # Circuit breaker: exclude tools that have failed 2+ times consecutively
        blocked = {name for name, count in self._tool_failures.items() if count >= 2}
        if blocked:
            phase_tools = [t for t in phase_tools if t['function']['name'] not in blocked]
        return META_TOOLS + phase_tools

    # ── Planning & Reflection (Reasoning Layer) ──────────────────

    def _inject_planning_prompt(self) -> str:
        """Force the agent to strategize before acting in a new phase."""
        return (
            f"[SYSTEM] You have entered the **{self.phase}** phase. Before taking any action, "
            f"analyze your current position:\n"
            f"1. What do you know so far? (services, credentials, access levels, vulnerabilities)\n"
            f"2. What is your hypothesis for the attack path?\n"
            f"3. What are your next 3 specific actions, in priority order?\n\n"
            f"Respond with your analysis ONLY — do NOT call any tools in this response. "
            f"Execute your plan on the next turn."
        )

    def _inject_reflection_prompt(self, failures: int) -> str:
        """Force the agent to reflect after repeated failures."""
        return (
            f"[SYSTEM] You have had {failures} tool failures in the current phase. "
            f"Stop and reflect:\n"
            f"1. Why did these tools fail? What assumption is wrong?\n"
            f"2. What is a fundamentally different approach you haven't tried?\n"
            f"3. Should you transition to a different phase instead?\n\n"
            f"Respond with your analysis ONLY — do NOT call any tools in this response. "
            f"Then take a different approach on the next turn."
        )

    def _is_planning_response(self) -> bool:
        """Check if the previous message was a [SYSTEM] planning/reflection prompt."""
        if len(self.messages) < 2:
            return False
        prev = self.messages[-2]
        return (prev.get('role') == 'user' and
                isinstance(prev.get('content', ''), str) and
                prev['content'].startswith('[SYSTEM]'))

    # ── Adaptive Strategy Engine ─────────────────────────────────

    async def _evaluate_strategy(self):
        """Evaluate current state and auto-advance phases if warranted."""
        L = self.logger
        old_phase = self.phase

        # Root + flag → complete immediately
        if self.state.has_root(self.target) and 'root_flag' in self.state.loot:
            L.log(f"{C_GREEN}{C_BOLD}STRATEGY: Root + flag detected — completing{C_RESET}")
            self.phase = 'complete'
            self._done = True
            await self.manager.broadcast('phase_change', {'phase': 'complete'})
            return

        # User access + no root → jump to privesc
        has_user = any(a.level == 'user' and a.host == self.target for a in self.state.accesses)
        has_root = self.state.has_root(self.target)
        if has_user and not has_root and self.phase in ('enumeration',):
            L.log(f"{C_MAGENTA}{C_BOLD}STRATEGY: User access detected — jumping to privesc{C_RESET}")
            self.phase = 'privesc'
            self._phase_entry_iteration = self.total_iterations
            self._phase_entry_node_count = len(self.graph.nodes)
            await self.manager.broadcast('phase_change', {'phase': self.phase})
            return

        # Verified creds + no access → jump to exploitation
        verified_creds = [c for c in self.state.credentials.values() if c.verified_for]
        unverified_creds = [c for c in self.state.credentials.values()
                           if not c.verified_for and not c.failed_for]
        if (verified_creds or unverified_creds) and not has_user and self.phase == 'enumeration':
            L.log(f"{C_MAGENTA}{C_BOLD}STRATEGY: Credentials found — jumping to exploitation{C_RESET}")
            self.phase = 'exploitation'
            self._phase_entry_iteration = self.total_iterations
            self._phase_entry_node_count = len(self.graph.nodes)
            await self.manager.broadcast('phase_change', {'phase': self.phase})
            return

        # Critical KB exploit match during enumeration → jump to exploitation
        if self.phase == 'enumeration':
            for svc in self.state.services.values():
                matches = match_service_to_exploits(svc.name, svc.version)
                critical_matches = [m for m in matches if m.get('severity') == 'critical']
                if critical_matches:
                    L.log(f"{C_MAGENTA}{C_BOLD}STRATEGY: Critical exploit match for {svc.name} — jumping to exploitation{C_RESET}")
                    self.phase = 'exploitation'
                    self._phase_entry_iteration = self.total_iterations
                    self._phase_entry_node_count = len(self.graph.nodes)
                    await self.manager.broadcast('phase_change', {'phase': self.phase})
                    return

        if self.phase != old_phase:
            await self._broadcast_budget()

    # ── Shell Session Management ─────────────────────────────────

    async def _check_new_access(self):
        """Check if new shell access was gained and handle it."""
        L = self.logger
        current_count = len(self.state.accesses)
        if current_count <= self._prev_access_count:
            return

        # New access detected
        for access in self.state.accesses[self._prev_access_count:]:
            session_key = f"{access.user}@{access.host}"
            if session_key in self._spawned_sessions:
                continue

            level_str = "ROOT" if access.level == "root" else "USER"
            L.log(f"{C_GREEN}{C_BOLD}SHELL ACCESS: {level_str} shell as {access.user}@{access.host} via {access.method}{C_RESET}")

            # Find credentials for this access
            ssh_cmd = ""
            password = ""
            for cred in self.state.credentials.values():
                if cred.username == access.user and ('ssh' in cred.verified_for or cred.verified_for):
                    password = cred.password
                    ssh_cmd = f"sshpass -p '{cred.password}' ssh -o StrictHostKeyChecking=no {cred.username}@{access.host}"
                    break
            if not ssh_cmd and access.credential:
                password = access.credential.password
                ssh_cmd = f"sshpass -p '{access.credential.password}' ssh -o StrictHostKeyChecking=no {access.credential.username}@{access.host}"
            if not ssh_cmd:
                # Try any credential with matching username
                for cred in self.state.credentials.values():
                    if cred.username == access.user:
                        password = cred.password
                        ssh_cmd = f"sshpass -p '{cred.password}' ssh -o StrictHostKeyChecking=no {cred.username}@{access.host}"
                        break

            # Broadcast shell access to frontend
            await self.manager.broadcast('shell_access', {
                'host': access.host,
                'user': access.user,
                'level': access.level,
                'method': access.method,
                'ssh_command': ssh_cmd,
                'timestamp': time.strftime('%H:%M:%S'),
            })

            # Attempt to spawn a local terminal
            if ssh_cmd and self._terminal and password:
                spawned = _spawn_terminal_ssh(access.host, access.user, password, self._terminal)
                if spawned:
                    L.log(f"{C_CYAN}Spawned {self._terminal} with SSH session for {session_key}{C_RESET}")
                    self._spawned_sessions.add(session_key)
                else:
                    L.log(f"{C_YELLOW}Failed to spawn terminal for {session_key}{C_RESET}")
            elif not self._terminal:
                L.log(f"{C_YELLOW}No terminal emulator found — shell info sent to dashboard{C_RESET}")

            self._spawned_sessions.add(session_key)

        self._prev_access_count = current_count

    # ── Auto /etc/hosts management ─────────────────────────────

    async def _auto_add_hosts(self, output: str):
        """Detect hostnames in tool output and add them to /etc/hosts."""
        L = self.logger
        # Match patterns like "redirect to http://hostname.tld" or "Did not follow redirect to http://hostname.htb"
        hostnames = set()
        for m in re.finditer(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', output):
            hostname = m.group(1).lower()
            # Skip common non-target hostnames
            if any(hostname.endswith(skip) for skip in ('.com', '.org', '.net', '.io', '.dev', '.gov')):
                continue
            hostnames.add(hostname)

        for hostname in hostnames:
            if hostname in self._hosts_added:
                continue
            # Check if already in /etc/hosts
            try:
                with open('/etc/hosts', 'r') as f:
                    hosts_content = f.read()
                if hostname in hosts_content:
                    self._hosts_added.add(hostname)
                    continue
            except Exception:
                continue

            # Add to /etc/hosts
            try:
                proc = await asyncio.create_subprocess_shell(
                    f'echo "{self.target} {hostname}" | sudo tee -a /etc/hosts',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                if proc.returncode == 0:
                    self._hosts_added.add(hostname)
                    L.log(f"{C_CYAN}Auto-added to /etc/hosts: {self.target} {hostname}{C_RESET}")
            except Exception:
                pass

    # ── Auto web asset extraction ────────────────────────────────

    def _auto_extract_web_assets(self, result: str):
        """Extract web asset references from HTML/JS tool output into state."""
        L = self.logger
        added = 0

        # Script tags: <script src="...">
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', result, re.IGNORECASE):
            if self.state.add_web_asset('scripts', m.group(1)):
                added += 1

        # Link tags (CSS/JS): <link ... href="...">
        for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', result, re.IGNORECASE):
            href = m.group(1)
            if href.endswith(('.css', '.js')):
                cat = 'stylesheets' if href.endswith('.css') else 'scripts'
                if self.state.add_web_asset(cat, href):
                    added += 1

        # Form actions: <form ... action="...">
        for m in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', result, re.IGNORECASE):
            action = m.group(1)
            if action and action != '#':
                if self.state.add_web_asset('forms', action):
                    added += 1

        # API endpoints in JS/HTML: paths like /api/...
        for m in re.finditer(r'["\'](/api/[^"\'?\s]{3,})["\']', result):
            if self.state.add_web_asset('api_endpoints', m.group(1)):
                added += 1

        # fetch/ajax/post/get URL patterns
        for m in re.finditer(r'(?:fetch|ajax|post|get|put|delete)\s*\(\s*["\'](/[^"\'?\s]{3,})["\']', result, re.IGNORECASE):
            if self.state.add_web_asset('api_endpoints', m.group(1)):
                added += 1

        if added:
            L.log(f"{C_CYAN}Auto-extracted {added} web asset(s) into state{C_RESET}")

    # ── IDOR pattern detection ──────────────────────────────────

    def _check_idor_pattern(self, url: str, result: str):
        """Detect numeric ID patterns in URLs and suggest trying other IDs (especially 0)."""
        L = self.logger
        # Match URLs like /data/1, /download/2, /user/3, /api/items/5, etc.
        m = re.search(r'(https?://[^/]+)?(/[^?#\s]*?/)(\d+)(?:[?#\s]|$)', url)
        if not m:
            return
        base_path = m.group(2)
        current_id = int(m.group(3))

        # Only fire once per base path
        idor_key = f"_idor_nudge_{base_path}"
        if hasattr(self, idor_key):
            return
        setattr(self, idor_key, True)

        # Build suggestion list: always try 0, and try adjacent IDs
        try_ids = set()
        if current_id != 0:
            try_ids.add(0)
        if current_id > 1:
            try_ids.add(current_id - 1)
        try_ids.add(current_id + 1)
        try_ids.discard(current_id)

        if try_ids:
            id_suggestions = ', '.join(str(i) for i in sorted(try_ids))
            host_prefix = m.group(1) or ''
            nudge = (
                f"[SYSTEM] The URL {url} contains a numeric ID ({current_id}). "
                f"This is a potential IDOR (Insecure Direct Object Reference). "
                f"Try accessing other IDs — especially: {', '.join(f'{host_prefix}{base_path}{i}' for i in sorted(try_ids))}. "
                f"ID 0 often contains pre-existing data (captures, profiles, records) from other users."
            )
            self.messages.append({'role': 'user', 'content': nudge, '_iteration': self._iteration_counter})
            L.log(f"{C_CYAN}IDOR pattern detected: {base_path}{current_id} → suggesting IDs: {id_suggestions}{C_RESET}")

    # ── Budget broadcasting ──────────────────────────────────────

    async def _broadcast_budget(self):
        budget_total = MAX_TOTAL_ITERATIONS
        remaining = max(0, budget_total - self._tool_call_count)
        await self.manager.broadcast('budget_update', {
            'remaining': remaining,
            'total': budget_total,
            'used': self._tool_call_count,
        })

    # ── Main agent loop ──────────────────────────────────────────

    async def run(self):
        L = self.logger

        if self.lhost:
            set_lhost(self.lhost)

        L.header(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  LACUNA — Security Research Agent{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Target: {self.target}{C_RESET}")
        if self.lhost:
            L.header(f"{C_BOLD}{C_BLUE}  LHOST: {self.lhost}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Log: {L.log_path}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}{'='*60}{C_RESET}\n")

        self.graph.add_node(self.target, self.target, 'machine')
        await self._broadcast_graph()
        await self.manager.broadcast('phase_change', {'phase': self.phase})
        await self._broadcast_budget()

        self.messages.append({
            'role': 'user',
            'content': f'Begin the authorized penetration test against target {self.target}. Start with enumeration.',
        })

        L.log(f"{C_MAGENTA}Phase: ENUMERATION{C_RESET}")
        self._phase_entry_iteration = 0
        self._phase_entry_node_count = len(self.graph.nodes)

        while self.phase != 'complete' and self.total_iterations < MAX_TOTAL_ITERATIONS and not self._done:
            phase_iterations = 0
            consecutive_stops = 0
            self._phase_failure_count = 0

            # ── Planning injection at phase entry ─────────────
            if self.phase not in self._plan_injected_for_phase and self.total_iterations > 0:
                planning_msg = self._inject_planning_prompt()
                self.messages.append({'role': 'user', 'content': planning_msg, '_iteration': self._iteration_counter})
                self._plan_injected_for_phase.add(self.phase)
                L.log(f"{C_CYAN}Injected planning prompt for {self.phase}{C_RESET}")

            while phase_iterations < MAX_ITERATIONS_PER_PHASE and self.total_iterations < MAX_TOTAL_ITERATIONS:
                self.total_iterations += 1
                self._iteration_counter += 1
                phase_iterations += 1

                # ── Stagnation detection ─────────────────────────
                iters_in_phase = self.total_iterations - self._phase_entry_iteration
                new_nodes = len(self.graph.nodes) - self._phase_entry_node_count
                iterations_since_nudge = self.total_iterations - self._last_nudge_iteration

                # Hard stagnation: in exploitation/privesc without access for too long → complete
                if iters_in_phase > 15 and self.phase in ('exploitation', 'privesc'):
                    has_access = bool(self.state.accesses)
                    has_creds = bool(self.state.credentials)
                    if not has_access and not has_creds:
                        L.log(f"{C_RED}Hard stagnation: {self.phase} for {iters_in_phase} iters without access/creds — completing{C_RESET}")
                        self.phase = 'complete'
                        self._done = True
                        break

                # Hard stagnation: enumeration spinning without progress → force transition
                if iters_in_phase > 25 and self.phase == 'enumeration' and new_nodes == 0:
                    has_creds = bool(self.state.credentials)
                    has_access = bool(self.state.accesses)
                    if not has_creds and not has_access:
                        L.log(f"{C_RED}Hard stagnation: enumeration for {iters_in_phase} iters with 0 new nodes — completing{C_RESET}")
                        self.phase = 'complete'
                        self._done = True
                        break

                if iters_in_phase > 8 and new_nodes == 0 and iterations_since_nudge >= 5:
                    nudge = (
                        f"[SYSTEM] You have been in the '{self.phase}' phase for {iters_in_phase} iterations "
                        f"without discovering new information. You MUST take action NOW:\n"
                        f"- Call a tool with a DIFFERENT approach than previous attempts\n"
                        f"- Do NOT just analyze or summarize — execute a concrete action\n"
                        f"- If truly stuck, call transition_phase to move on"
                    )
                    self.messages.append({'role': 'user', 'content': nudge, '_iteration': self._iteration_counter})
                    self._last_nudge_iteration = self.total_iterations
                    L.log(f"{C_YELLOW}Stagnation nudge (iter {iters_in_phase}, 0 new nodes){C_RESET}")

                # ── Reflection injection after failures ──────────
                if (self._phase_failure_count >= 2 and
                        self.total_iterations - self._reflection_injected_at > 3):
                    reflection_msg = self._inject_reflection_prompt(self._phase_failure_count)
                    self.messages.append({'role': 'user', 'content': reflection_msg, '_iteration': self._iteration_counter})
                    self._reflection_injected_at = self.total_iterations
                    self._phase_failure_count = 0
                    L.log(f"{C_YELLOW}Injected reflection prompt after {self._phase_failure_count} failures{C_RESET}")

                # ── Auto-complete if root flag found ─────────────
                if self.state.has_root(self.target) and 'root_flag' in self.state.loot:
                    L.log(f"{C_GREEN}{C_BOLD}ROOT + FLAG DETECTED — auto-completing{C_RESET}")
                    self.phase = 'complete'
                    self._done = True
                    break

                L.log(f"{C_DIM}--- Iteration {self.total_iterations}/{MAX_TOTAL_ITERATIONS} (phase: {phase_iterations}/{MAX_ITERATIONS_PER_PHASE}) ---{C_RESET}")

                # ── Build context-managed message list ───────────
                system_prompt = self._build_system_prompt()
                messages = build_messages(system_prompt, self.messages, self._iteration_counter)
                tools = self._get_tools()

                L.log(f"{C_CYAN}Calling LLM ({len(messages)} messages, {len(tools)} tools)...{C_RESET}")
                llm_start = time.time()

                try:
                    response = await chat_completion(self.client, messages, tools)
                except Exception as e:
                    L.log(f"{C_RED}LLM ERROR: {e}{C_RESET}")
                    await self.manager.broadcast('error', {'message': f"LLM error: {str(e)}"})
                    L.close()
                    return

                llm_time = time.time() - llm_start
                usage_info = extract_usage(response)
                self.total_input_tokens += usage_info['input']
                self.total_output_tokens += usage_info['output']
                self.total_cached_tokens += usage_info['cached']
                self.total_cost += usage_info['cost']
                if usage_info['input']:
                    cached_pct = f" ({usage_info['cached']} cached)" if usage_info['cached'] else ""
                    L.log(f"{C_DIM}LLM: {llm_time:.1f}s | {usage_info['input']}{cached_pct}/{usage_info['output']} tokens | ${usage_info['cost']:.4f} (total: ${self.total_cost:.4f}){C_RESET}")

                choice = response.choices[0]
                message = choice.message

                if message.content:
                    text = message.content[:200] + ('...' if len(message.content) > 200 else '')
                    L.log(f"{C_YELLOW}Thinking: {text}{C_RESET}")
                    await self.manager.broadcast('agent_thinking', {'text': message.content})

                    # If this was a response to a planning/reflection prompt, broadcast as strategy
                    if self._is_planning_response():
                        self._current_strategy = message.content
                        await self.manager.broadcast('strategy_update', {
                            'strategy': message.content,
                            'phase': self.phase,
                        })
                        L.log(f"{C_CYAN}Strategy update broadcast{C_RESET}")

                assistant_msg = {'role': 'assistant', 'content': message.content or '', '_iteration': self._iteration_counter}
                if message.tool_calls:
                    assistant_msg['tool_calls'] = [
                        {
                            'id': tc.id,
                            'type': 'function',
                            'function': {
                                'name': tc.function.name,
                                'arguments': tc.function.arguments,
                            },
                        }
                        for tc in message.tool_calls
                    ]
                self.messages.append(assistant_msg)

                # ── No tool calls → model is done with phase ─────
                if not message.tool_calls:
                    consecutive_stops += 1
                    L.log(f"{C_DIM}No tool calls (stop #{consecutive_stops}){C_RESET}")

                    if consecutive_stops >= 2:
                        current_idx = PHASES.index(self.phase) if self.phase in PHASES else len(PHASES) - 1
                        # Don't auto-advance to exploitation/privesc without actionable intel
                        has_creds = bool(self.state.credentials)
                        has_access = bool(self.state.accesses)
                        has_vulns = bool(self.state.findings)

                        if current_idx == 0 and not has_creds and not has_access and not has_vulns:
                            # Still in enumeration with nothing — inject a nudge instead of advancing
                            nudge = (
                                "[SYSTEM] You are stuck in enumeration without findings. "
                                "Focus on actionable steps:\n"
                                "1. Add discovered hostnames to /etc/hosts if needed\n"
                                "2. Try registering an account on any web app\n"
                                "3. Try API endpoint fuzzing with ffuf_fuzz\n"
                                "4. Try default credentials with hydra_brute\n"
                                "5. Look for invite codes, registration forms, or API docs\n"
                                "Do NOT just analyze — take a concrete action with a tool call."
                            )
                            self.messages.append({'role': 'user', 'content': nudge, '_iteration': self._iteration_counter})
                            L.log(f"{C_YELLOW}Enum stuck nudge — redirecting instead of advancing{C_RESET}")
                            consecutive_stops = 0
                            continue

                        if current_idx < len(PHASES) - 1:
                            self.phase = PHASES[current_idx + 1]
                            self._phase_entry_iteration = self.total_iterations
                            self._phase_entry_node_count = len(self.graph.nodes)
                            L.log(f"{C_MAGENTA}Auto-advancing to {self.phase.upper()}{C_RESET}")
                            await self.manager.broadcast('phase_change', {'phase': self.phase})
                        else:
                            self.phase = 'complete'
                            self._done = True
                        break
                    continue

                consecutive_stops = 0

                # ── Process tool calls ───────────────────────────
                should_break = False
                for tc in message.tool_calls:
                    name = tc.function.name
                    try:
                        raw_args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        raw_args = {}

                    args = normalize_args(name, raw_args)
                    if args != raw_args:
                        L.log(f"{C_YELLOW}Args normalized: {json.dumps(raw_args)[:100]} -> {json.dumps(args)[:100]}{C_RESET}")

                    call_id = tc.id
                    args_short = json.dumps(args)
                    if len(args_short) > 150:
                        args_short = args_short[:150] + '...'
                    L.log(f"{C_GREEN}Tool: {C_BOLD}{name}{C_RESET}{C_GREEN} | {args_short}{C_RESET}")
                    await self.manager.broadcast('tool_call', {'id': call_id, 'name': name, 'args': args})

                    # ── Cache check ──────────────────────────────
                    cache_key = f"{name}|{json.dumps(args, sort_keys=True)}"
                    if cache_key in self._tool_cache:
                        result = f"[CACHED - identical call already executed] {self._tool_cache[cache_key][:3000]}"
                        tool_time = 0.0
                        L.log(f"{C_YELLOW}Cache hit: {name}{C_RESET}")
                    else:
                        self._tool_call_count += 1
                        await self._broadcast_budget()
                        tool_start = time.time()
                        result = await self._execute_tool(name, args)
                        tool_time = time.time() - tool_start
                        if name not in _NO_CACHE:
                            self._tool_cache[cache_key] = result

                    result_lines = result.count('\n') + 1
                    L.log(f"{C_GREEN}Done: {name} | {tool_time:.1f}s | {len(result)} chars, {result_lines} lines{C_RESET}")

                    # Circuit breaker: track consecutive failures per tool
                    if result.startswith('[ERROR]') or result.startswith('[TIMEOUT'):
                        self._tool_failures[name] = self._tool_failures.get(name, 0) + 1
                        self._phase_failure_count += 1
                        if self._tool_failures[name] >= 2:
                            L.log(f"{C_RED}Circuit breaker: {name} failed {self._tool_failures[name]}x — temporarily disabled{C_RESET}")
                    else:
                        self._tool_failures.pop(name, None)

                    # ── Waste tracking ────────────────────────────
                    _is_waste = (
                        result.startswith('[ERROR]') or
                        result.startswith('[WARNING]') or
                        result.startswith('[CACHED') or
                        (name == 'execute_command' and len(result.strip()) == 0)
                    )
                    if _is_waste:
                        self._consecutive_waste += 1
                        if self._consecutive_waste >= 5:
                            waste_nudge = (
                                "[SYSTEM] You have wasted the last 5+ tool calls on blocked/cached/useless commands. "
                                "STOP using execute_command for local tasks. Instead:\n"
                                "- Use curl_request to interact with the target web app\n"
                                "- Use ffuf_fuzz to discover new endpoints or parameters\n"
                                "- Use gobuster_dir for directory brute-forcing\n"
                                "- Use nmap_scan with different flags (e.g. -p- for all ports, or UDP scan)\n"
                                "- Use query_kb to look up exploits for discovered services\n"
                                "- Check the 'Discovered Web Assets' section for JS/CSS files to fetch\n"
                                "- Call transition_phase if you have exhausted this phase\n"
                                "Your next call MUST use a dedicated tool, NOT execute_command."
                            )
                            self.messages.append({'role': 'user', 'content': waste_nudge, '_iteration': self._iteration_counter})
                            self._consecutive_waste = 0
                            L.log(f"{C_RED}Waste detector: 5+ consecutive wasted calls — injecting corrective prompt{C_RESET}")
                    else:
                        self._consecutive_waste = 0

                    # ── Same-file repetition detection ────────────
                    if name == 'execute_command' and len(result.strip()) < 50:
                        cmd_str = args.get('command', '')
                        tmp_files = re.findall(r'/tmp/\S+', cmd_str)
                        for tf in tmp_files:
                            tf_clean = tf.rstrip("'\"`;|&)")
                            self._file_analysis_count[tf_clean] = self._file_analysis_count.get(tf_clean, 0) + 1
                            if self._file_analysis_count[tf_clean] >= 3:
                                repetition_nudge = (
                                    f"[SYSTEM] You have analyzed '{tf_clean}' {self._file_analysis_count[tf_clean]} times "
                                    f"with no useful results. This file does NOT contain what you're looking for.\n"
                                    f"- Check the 'Discovered Web Assets' section — there may be OTHER JS/CSS files to fetch\n"
                                    f"- Use curl_request to fetch a different resource from the target\n"
                                    f"- Use ffuf_fuzz to discover new endpoints"
                                )
                                self.messages.append({'role': 'user', 'content': repetition_nudge, '_iteration': self._iteration_counter})
                                L.log(f"{C_RED}Repetition detector: {tf_clean} analyzed {self._file_analysis_count[tf_clean]}x with empty results{C_RESET}")
                                break

                    # ── Auto-update graph ────────────────────────
                    parsed = None
                    if name in TOOL_PARSERS and not result.startswith('[ERROR]') and not result.startswith('[TIMEOUT'):
                        parsed = TOOL_PARSERS[name](result, self.target)
                    elif name in ('execute_command', 'download_and_analyze') and not result.startswith('[ERROR]'):
                        parsed = _parse_command_output_for_graph(result, self.target)

                    if parsed and (parsed['nodes'] or parsed['edges']):
                        self.graph.update_from_args(parsed)
                        await self._broadcast_graph()
                        L.log(f"{C_BLUE}Graph: +{len(parsed['nodes'])} nodes, +{len(parsed['edges'])} edges{C_RESET}")

                    # ── Feed state extractors ────────────────────
                    if name in STATE_EXTRACTORS and not result.startswith('[ERROR]'):
                        STATE_EXTRACTORS[name](result, self.target, self.state)

                    # ── Auto-detect and add hostnames to /etc/hosts ──
                    if name in ('nmap_scan', 'curl_request', 'execute_command') and not result.startswith('[ERROR]'):
                        await self._auto_add_hosts(result)

                    # ── Auto-extract web assets from HTML/JS output ──
                    if name in ('curl_request', 'execute_command', 'download_and_analyze') and not result.startswith('[ERROR]'):
                        self._auto_extract_web_assets(result)

                    # ── IDOR pattern detection for numeric URL IDs ──
                    if name in ('curl_request', 'download_and_analyze') and not result.startswith('[ERROR]'):
                        url_arg = args.get('url', '')
                        if url_arg:
                            self._check_idor_pattern(url_arg, result)

                    # ── Check for new shell access ───────────────
                    await self._check_new_access()

                    # ── Adaptive strategy: evaluate after state update
                    await self._evaluate_strategy()
                    if self._done:
                        should_break = True

                    await self.manager.broadcast('tool_result', {'id': call_id, 'result': result, 'error': False})
                    self.messages.append({
                        'role': 'tool',
                        'tool_call_id': call_id,
                        'content': result,
                        '_iteration': self._iteration_counter,
                    })

                    # ── Phase transition ─────────────────────────
                    if name == 'transition_phase':
                        next_phase = args.get('next_phase', '')
                        if not next_phase or next_phase not in PHASES + ['complete']:
                            current_idx = PHASES.index(self.phase) if self.phase in PHASES else -1
                            next_phase = PHASES[current_idx + 1] if current_idx < len(PHASES) - 1 else 'complete'

                        if next_phase == 'complete':
                            self.phase = 'complete'
                            self._done = True
                        elif next_phase in PHASES:
                            self.phase = next_phase

                        self._phase_entry_iteration = self.total_iterations
                        self._phase_entry_node_count = len(self.graph.nodes)

                        L.log(f"\n{C_MAGENTA}{'='*40}{C_RESET}")
                        L.log(f"{C_MAGENTA}Phase: {self.phase.upper()}{C_RESET}")
                        L.log(f"{C_MAGENTA}Reason: {args.get('reason', 'N/A')}{C_RESET}")
                        L.log(f"{C_MAGENTA}{'='*40}{C_RESET}\n")
                        await self.manager.broadcast('phase_change', {'phase': self.phase})
                        await self._broadcast_budget()
                        should_break = True

                if should_break:
                    # Append placeholder results for any remaining tool calls
                    # MiniMax requires every tool_call to have a corresponding tool result
                    processed_ids = {m['tool_call_id'] for m in self.messages
                                     if m.get('role') == 'tool' and m.get('tool_call_id')}
                    for remaining_tc in message.tool_calls:
                        if remaining_tc.id not in processed_ids:
                            self.messages.append({
                                'role': 'tool',
                                'tool_call_id': remaining_tc.id,
                                'content': '[SKIPPED — phase transition or completion in progress]',
                                '_iteration': self._iteration_counter,
                            })
                    break

        # ── Final summary ────────────────────────────────────────
        L.header(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  COMPLETE{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Model: {get_active_model()} ({get_active_backend()}){C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Iterations: {self.total_iterations} | Tool calls: {self._tool_call_count}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Tokens: {self.total_input_tokens} in ({self.total_cached_tokens} cached) / {self.total_output_tokens} out{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Estimated cost: ${self.total_cost:.4f}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Graph: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges{C_RESET}")
        if self.state.loot:
            for loot_name, value in self.state.loot.items():
                L.header(f"{C_BOLD}{C_GREEN}  {loot_name}: {value}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Log: {L.log_path}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}{'='*60}{C_RESET}\n")

        await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
        await self.manager.broadcast('complete', {})
        L.close()

    # ── Tool execution ───────────────────────────────────────────

    async def _execute_tool(self, name: str, args: dict) -> str:
        L = self.logger

        if name == 'update_graph':
            self.graph.update_from_args(args)
            await self._broadcast_graph()
            return "Graph updated."

        if name == 'transition_phase':
            return f"Transitioning to {args.get('next_phase', 'next')}. Reason: {args.get('reason', '')}"

        if name == 'append_report':
            md = args.get('markdown', '')
            if not md:
                md = json.dumps(args, indent=2) if args else ''
            self.report.append(md)
            await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
            L.log(f"{C_CYAN}Report appended ({len(md)} chars){C_RESET}")
            return "Report section appended."

        if name in TOOL_REGISTRY:
            func = TOOL_REGISTRY[name]['function']
            sig = inspect.signature(func)
            valid_args = {}
            for param_name, param in sig.parameters.items():
                if param_name in args:
                    valid_args[param_name] = args[param_name]
                elif param.default is inspect.Parameter.empty:
                    if param_name == 'target':
                        valid_args['target'] = self.target
                        L.log(f"{C_YELLOW}Injected: target={self.target}{C_RESET}")
                    elif param_name == 'lhost' and self.lhost:
                        valid_args['lhost'] = self.lhost
                        L.log(f"{C_YELLOW}Injected: lhost={self.lhost}{C_RESET}")
                    elif param_name == 'url':
                        valid_args['url'] = f'http://{self.target}'
                        L.log(f"{C_YELLOW}Injected: url=http://{self.target}{C_RESET}")
            try:
                result = await func(**valid_args)
                if result.startswith('[ERROR]') or result.startswith('[TIMEOUT'):
                    result = _add_tool_hint(name, args, result)
                return result
            except Exception as e:
                error_msg = f"[ERROR] {name} failed: {str(e)}"
                return _add_tool_hint(name, args, error_msg)

        return f"[ERROR] Unknown tool: {name}. Check available tools for this phase — you may need to transition_phase first."

    async def _broadcast_graph(self):
        await self.manager.broadcast('graph_update', self.graph.get_state())


# ── Graph extraction from command output ─────────────────────────

def _parse_command_output_for_graph(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []

        for m in re.finditer(r'uid=\d+\((\w+)\)', output):
            user = m.group(1)
            if user == 'root':
                nodes.append({'id': 'root-access', 'label': 'ROOT ACCESS', 'type': 'root'})
                edges.append({'source': target, 'target': 'root-access', 'label': 'privesc'})
            elif user != 'nobody':
                node_id = f'user-{user}'
                nodes.append({'id': node_id, 'label': f'User: {user}', 'type': 'user'})
                edges.append({'source': target, 'target': node_id, 'label': 'ssh'})

        if re.search(r'user\.txt', output) and re.search(r'[0-9a-f]{32}', output):
            nodes.append({'id': 'user-flag', 'label': 'user.txt', 'type': 'vulnerability'})

        if re.search(r'root\.txt', output) and re.search(r'[0-9a-f]{32}', output):
            nodes.append({'id': 'root-flag', 'label': 'root.txt', 'type': 'root'})
            edges.append({'source': 'root-access', 'target': 'root-flag', 'label': 'flag'})

        ftp_users = []
        for m in re.finditer(r'USER\s+(\S+)', output):
            user = m.group(1)
            if user and user not in ('anonymous', 'ftp'):
                ftp_users.append(user)
                nodes.append({'id': f'user-{user}', 'label': f'User: {user}', 'type': 'user'})
                edges.append({'source': target, 'target': f'user-{user}', 'label': 'cred found'})
        for i, m in enumerate(re.finditer(r'PASS\s+(\S+)', output)):
            passwd = m.group(1)
            node_id = f'cred-{passwd[:30]}'
            nodes.append({'id': node_id, 'label': f'Password: {passwd}', 'type': 'vulnerability'})
            if i < len(ftp_users):
                edges.append({'source': f'user-{ftp_users[i]}', 'target': node_id, 'label': 'password'})
            else:
                edges.append({'source': target, 'target': node_id, 'label': 'credential'})

        if 'cap_setuid' in output:
            nodes.append({'id': 'vuln-cap-setuid', 'label': 'cap_setuid', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': 'vuln-cap-setuid', 'label': 'capability'})

        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}
