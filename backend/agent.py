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
import shlex
import shutil
import subprocess
import time
import inspect
import asyncio
from pathlib import Path
from datetime import datetime

from backend.llm import get_client, get_active_model, get_active_backend
from backend.analyzer import Analyzer
from backend.graph import GraphManager
from backend.journal import RunJournal
from backend.operator import Operator, OperatorTaskContext
from backend.report import ReportBuilder
from backend.ws_manager import WSManager
from backend.state import StateManager
from backend.knowledge import match_service_to_exploits
from backend.output_processing import OutputProcessor
from backend.planning import Planner, WorkingMemory
from backend.shell_sessions import ShellSessionManager, parse_sshpass_ssh_command
from backend.tools import TOOL_REGISTRY, get_tools_for_phase
from backend.tools.exploitation import set_lhost

LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"

PHASES = ['enumeration', 'exploitation', 'privesc']
PHASE_BASE_BUDGETS = {
    'enumeration': 20,
    'exploitation': 40,
    'privesc': 15,
}
RESERVE_ITERATIONS = 30
MAX_TOTAL_ITERATIONS = sum(PHASE_BASE_BUDGETS.values()) + RESERVE_ITERATIONS

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
    'run_linpeas', 'check_sudo', 'check_suid', 'check_cron', 'check_capabilities',
    'web_request',
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
    'web_request': 'HINT: Use this for stateful web forms, JSON APIs, and login/invite flows. Keep a stable session_name so cookies persist across steps.',
    'download_and_analyze': 'HINT: Verify the download URL is correct and the file exists. Check HTTP response code. Try curl_request first to confirm the URL works.',
    'execute_command': 'HINT: Check command syntax. If running remote commands via SSH, verify credentials and connectivity first.',
    'decode_text': 'HINT: Use this for base64, ROT13, or URL-decoding invite codes, tokens, and obfuscated hints instead of shell commands.',
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
    'check_capabilities': 'HINT: You MUST provide a full sshpass SSH command. Use: sshpass -p \'PASS\' ssh -o StrictHostKeyChecking=no USER@TARGET \'getcap -r / 2>/dev/null\'',
    'sqlmap_scan': 'HINT: Ensure the target URL has a parameter to test (e.g. ?id=1). Try with --level=3 --risk=2 for deeper testing.',
    'hydra_brute': 'HINT: Verify the service is running and accessible. Try fewer credentials or a different protocol.',
    'wpscan': 'HINT: Ensure the target is running WordPress. Check the URL (usually /wp-login.php exists).',
}
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
        if name == 'decode_text' and canonical == 'markdown':
            canonical = 'text'
        normalized[canonical] = value
    if name == 'append_report' and 'title' in args:
        title = args.get('title', '')
        md = normalized.get('markdown', '')
        if title and md:
            normalized['markdown'] = f"## {title}\n\n{md}"
        elif title and not md:
            normalized['markdown'] = f"## {title}"
    return normalized


def sanitize_tool_args(name: str, args: dict, context: dict | None = None) -> tuple[dict, str | None]:
    sanitized = dict(args)
    note = None

    if name == 'nmap_scan':
        flags = str(sanitized.get('flags', '') or '').strip()
        # First nmap call of enumeration: rewrite -p- to fast targeted scan
        if ('-p-' in flags
                and context
                and context.get('nmap_call_count', 99) == 0
                and context.get('phase') == 'enumeration'):
            flags = re.sub(r'-p-', '', flags).strip()
            if '-sV' not in flags:
                flags += ' -sV'
            if '-sC' not in flags:
                flags += ' -sC'
            if '-T4' not in flags and '-T5' not in flags:
                flags += ' -T4'
            sanitized['flags'] = flags.strip()
            note = 'REWRITTEN: First nmap used -p-; rewritten to fast scan. Request -p- again after reviewing results.'
            return sanitized, note
        if '-A' in flags and '-sV' not in flags and '-sC' not in flags:
            sanitized['flags'] = flags.replace('-A', '-sV -sC').strip()
            note = 'Replaced -A with -sV -sC to avoid slow OS/scripts spray.'
        flags = str(sanitized.get('flags', '') or '').strip()
        if '-p-' in flags and '--host-timeout' not in flags:
            sanitized['flags'] = f'{flags} --host-timeout 90s --max-retries 2 --min-rate 2000 -n'.strip()
            note = 'Bounded full-port nmap scan to avoid 5-minute stalls.'

    elif name == 'gobuster_dir':
        flags = str(sanitized.get('flags', '') or '')
        cleaned = flags.replace('-q', ' ').strip()
        if cleaned != flags.strip():
            sanitized['flags'] = cleaned
            note = 'Removed redundant gobuster quiet flag; tool already adds it.'

    elif name == 'execute_command':
        command = str(sanitized.get('command', '') or '').strip()
        if any(token in command for token in ('curl -s http', 'curl -sL http', 'curl -sv http')) and 'grep' in command:
            note = 'Raw curl|grep pipeline detected; prefer curl_request or download_and_analyze unless target execution is required.'

    return sanitized, note


def _add_tool_hint(name: str, args: dict, error_msg: str) -> str:
    hint = TOOL_HINTS.get(name, 'HINT: Try a different approach or tool. Do not repeat the same call.')
    if 'TIMEOUT' in error_msg:
        hint = f'HINT: Command timed out. Try a faster/lighter variant or reduce scope. {hint.replace("HINT: ", "Also: ")}'
    return f"{error_msg} {hint}"


def _should_cache_tool(name: str, args: dict) -> bool:
    if name in _NO_CACHE:
        return False
    if name == 'curl_request':
        flags = f" {str(args.get('flags', '') or '')} "
        if any(token in flags for token in (' -b ', ' --cookie ', ' -c ', ' --cookie-jar ', ' -o ', ' --output ')):
            return False
    return True


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
        self.memory = WorkingMemory()
        self.output_processor = OutputProcessor()
        self.analyzer = Analyzer(target, self.state, self.graph, self.output_processor)
        self.shell_sessions = ShellSessionManager()
        self.client = get_client()
        self.planner = Planner(self.client, target)
        self.operator = Operator(self.client)
        self.phase = 'enumeration'
        self.total_iterations = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.logger = SessionLogger(target)
        self.journal = RunJournal(target, LOGS_DIR)
        self._done = False
        self._tool_cache: dict[str, str] = {}
        self._tool_call_count = 0
        self._nmap_call_count: int = 0
        self._phase_entry_iteration = 0
        self._phase_entry_node_count = 0
        self._knowledge_injected: set[str] = set()
        self.total_cost = 0.0
        self.total_cached_tokens = 0
        self._tool_failures: dict[str, int] = {}
        # Reasoning layer tracking
        self._plan_injected_for_phase: set[str] = set()
        self._current_strategy: str = ''
        # Iteration counter for context windowing
        self._iteration_counter: int = 0
        # Shell session tracking
        self._spawned_sessions: set[str] = set()  # "user@host" keys
        self._terminal = _find_terminal()
        # Track previous access count for detecting new access
        self._prev_access_count: int = 0
        # Track hostnames added to /etc/hosts
        self._hosts_added: set = set()
        # Privesc checklist completion tracker
        self._privesc_checks_done: set[str] = set()
        # Persistent per-phase budgets; do not reset when the outer loop re-enters the same phase
        self._phase_iterations_used: dict[str, int] = {phase: 0 for phase in PHASES}
        self._plan_refresh_required: bool = True
        self._last_state_fingerprint = self._state_fingerprint()
        self._last_progress_fingerprint = self._last_state_fingerprint
        self._last_progress_iteration: int = 0
        self._tracked_task_id: str = ''
        self._active_task_stall_count: int = 0
        self._planner_calls: int = 0

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

    def _get_tools(self) -> list[dict]:
        phase_tools = get_tools_for_phase(self.phase)
        # Circuit breaker: exclude tools that have failed 2+ times consecutively
        blocked = {name for name, count in self._tool_failures.items() if count >= 2}
        if blocked:
            phase_tools = [t for t in phase_tools if t['function']['name'] not in blocked]
        return META_TOOLS + phase_tools

    def _state_fingerprint(self) -> tuple:
        return (
            self.phase,
            tuple(sorted(
                (svc.host, svc.port, svc.protocol, svc.name, svc.version, svc.info)
                for svc in self.state.services.values()
            )),
            tuple(sorted(self.state.credentials.keys())),
            tuple(sorted(
                (access.host, access.user, access.level, access.method)
                for access in self.state.accesses
            )),
            tuple(sorted(
                (finding.title, finding.severity, finding.service)
                for finding in self.state.findings
            )),
            tuple(sorted(self.state.loot.items())),
            tuple(sorted(key for key, value in self.state.workflow_markers.items() if value)),
            tuple(sorted(
                (hyp.key, hyp.status, hyp.evidence)
                for hyp in self.state.hypotheses.values()
            )),
            tuple(sorted(
                (
                    session.name,
                    session.last_url,
                    session.last_status,
                    session.authenticated,
                    tuple(sorted(session.cookies)),
                )
                for session in self.state.web_sessions.values()
            )),
            tuple(
                (category, tuple(sorted(values)))
                for category, values in sorted(self.state.web_assets.items())
            ),
        )

    def _request_plan_refresh(self):
        self._plan_refresh_required = True

    def _phase_budget_limit(self, phase: str) -> int:
        base = PHASE_BASE_BUDGETS.get(phase, 20)
        reserve_used = sum(
            max(0, used - PHASE_BASE_BUDGETS.get(name, 20))
            for name, used in self._phase_iterations_used.items()
        )
        reserve_left = max(0, RESERVE_ITERATIONS - reserve_used)
        active_task = self.memory.current_plan.ensure_single_active() if self.memory.current_plan else None
        if active_task and active_task.status in ('active', 'pending'):
            return base + reserve_left
        return base

    def _build_operator_context(self):
        active_task = self.memory.current_plan.ensure_single_active() if self.memory.current_plan else None
        if not active_task:
            return None
        budget_remaining = max(0, MAX_TOTAL_ITERATIONS - self._tool_call_count)
        return OperatorTaskContext(
            phase=self.phase,
            target=self.target,
            lhost=self.lhost,
            task_id=active_task.id,
            task_title=active_task.title,
            task_description=active_task.description,
            success_criteria=active_task.success_criteria,
            tool_hints=list(active_task.tool_hints),
            budget_remaining=budget_remaining,
            state_summary=self.state.get_prompt_summary(),
            memory_summary=self.memory.get_prompt_summary(),
            graph_summary=self.graph.get_brief_summary(),
            knowledge_hints=self._get_knowledge_hints(),
        )

    def _sync_plan_progress(self):
        plan = self.memory.current_plan
        if not plan:
            return

        if self.state.services:
            plan.set_status('enum-services', 'done', evidence=f"{len(self.state.services)} services identified")
        if self.state.web_assets['api_endpoints'] or self.state.web_assets['scripts'] or self.state.web_sessions:
            plan.set_status('enum-web', 'done', evidence='Web workflow artifacts captured')

        markers = self.state.workflow_markers
        if markers.get('invite_code_obtained'):
            plan.set_status('invite-howto', 'done', evidence=self.state.loot.get('invite_code', 'invite code recovered'))
            if plan.get_task('invite-verify') and plan.get_task('invite-verify').status == 'pending':
                plan.set_status('invite-verify', 'active')
        if markers.get('invite_verified'):
            plan.set_status('invite-verify', 'done', evidence='Invite verification succeeded')
            if plan.get_task('invite-register') and plan.get_task('invite-register').status == 'pending':
                plan.set_status('invite-register', 'active')
        if markers.get('authenticated_session'):
            plan.set_status('invite-register', 'done', evidence='Authenticated session established')

        if self.state.credentials:
            plan.set_status('idor-paths', 'done', evidence='Credentials recovered from web workflow')
            if plan.get_task('test-creds') and plan.get_task('test-creds').status == 'pending':
                plan.set_status('test-creds', 'active')
        if any(cred.verified_for for cred in self.state.credentials.values()):
            plan.set_status('test-creds', 'done', evidence='Credential verified on a service')
        if self.state.accesses:
            plan.set_status('test-creds', 'done', evidence='Shell access obtained')
            plan.set_status('ssh-foothold', 'done', evidence='SSH foothold established')
            if self.phase == 'privesc':
                for task_id in ('privesc-sudo', 'privesc-caps', 'privesc-suid', 'privesc-cron'):
                    task = plan.get_task(task_id)
                    if task and task.status == 'pending':
                        task.status = 'active'
                        break

        if 'check_sudo' in self._privesc_checks_done:
            plan.set_status('privesc-sudo', 'done', evidence='sudo -l executed')
        if 'check_capabilities' in self._privesc_checks_done or any('cap_setuid' in finding.title for finding in self.state.findings):
            plan.set_status('privesc-caps', 'done', evidence='Capabilities checked')
        if 'check_suid' in self._privesc_checks_done:
            plan.set_status('privesc-suid', 'done', evidence='SUID enumeration complete')
        if 'check_cron' in self._privesc_checks_done:
            plan.set_status('privesc-cron', 'done', evidence='Cron enumeration complete')

        if self.state.has_root(self.target):
            plan.set_status('collect-root-flag', 'active', evidence='Root access confirmed')
        if 'root_flag' in self.state.loot:
            plan.set_status('collect-root-flag', 'done', evidence='Root flag collected')

        plan.ensure_single_active()

    async def _refresh_plan(self, reason: str = "", force: bool = False):
        if not force and not self._plan_refresh_required:
            return

        self.memory.sync_from_state(self.state)
        result = await self.planner.build_plan(
            self.phase,
            self.state.to_snapshot(),
            self.memory.to_snapshot(),
        )
        self.memory.set_plan(result.plan, reason or result.source)
        self._sync_plan_progress()
        self._plan_refresh_required = False
        self._last_state_fingerprint = self._state_fingerprint()

        if result.usage:
            self.total_input_tokens += result.usage.get('input', 0)
            self.total_output_tokens += result.usage.get('output', 0)
            self.total_cached_tokens += result.usage.get('cached', 0)
            self.total_cost += result.usage.get('cost', 0.0)
            self._planner_calls += 1

        self._current_strategy = self.memory.current_plan.render_summary(limit=10)
        await self.manager.broadcast('strategy_update', {
            'strategy': self._current_strategy,
            'phase': self.phase,
        })
        self.journal.write('plan_refresh', {
            'phase': self.phase,
            'reason': reason or result.source,
            'source': result.source,
            'error': result.error,
            'plan': self.memory.current_plan.to_dict() if self.memory.current_plan else None,
            'memory': self.memory.to_snapshot(),
        })
        source = result.source
        if result.error:
            source = f"{source} (llm fallback: {result.error})"
        self.logger.log(f"{C_CYAN}Planner refresh [{source}] {reason or 'state update'}{C_RESET}")

    def _guard_plan_drift(self, name: str, args: dict) -> str | None:
        plan = self.memory.current_plan
        if not plan:
            return None
        task = plan.ensure_single_active()
        if not task or not task.tool_hints:
            return None

        if name in {'transition_phase', 'append_report'} or name in task.tool_hints:
            return None

        noisy_tools = {'hydra_brute', 'gobuster_dir', 'ffuf_fuzz', 'nuclei_scan', 'nikto_scan', 'sqlmap_scan'}
        strict_tasks = {
            'invite-howto', 'invite-verify', 'invite-register',
            'privesc-sudo', 'privesc-caps', 'privesc-suid', 'privesc-cron',
        }
        if task.id in strict_tasks and name in noisy_tools:
            return (
                f"[ERROR] Active plan task: {task.title}. "
                f"Preferred tools: {', '.join(task.tool_hints)}. "
                f"Success condition: {task.success_criteria}"
            )
        return None

    def _guard_phase_transition(self, name: str, args: dict) -> str | None:
        if name != 'transition_phase':
            return None
        next_phase = str(args.get('next_phase', '') or '').strip()
        if next_phase == 'privesc' and not any(a.host == self.target for a in self.state.accesses):
            return '[ERROR] Cannot transition to privesc without shell access on the target.'
        return None

    def _guard_execute_command(self, args: dict) -> str | None:
        """Block unsafe or low-signal execute_command patterns before tool execution."""
        command = str(args.get('command', '') or '').lower()
        if not command:
            return None

        if self.phase != 'privesc':
            return None

        checklist_patterns = (
            'sudo -l',
            'getcap -r /',
            'find / -perm -4000',
            '/etc/crontab',
            '/etc/cron.d',
        )
        if any(p in command for p in checklist_patterns):
            return (
                "[ERROR] In privesc phase, checklist commands must use dedicated tools: "
                "check_sudo, check_capabilities, check_suid, check_cron."
            )

        required = {'check_sudo', 'check_capabilities', 'check_suid', 'check_cron'}
        if not required.issubset(self._privesc_checks_done):
            exploit_markers = (
                'pkexec', 'pwnkit', 'cve-2021-4034', '/tmp/exploit',
                'msfconsole', 'os.setuid(0)', 'chmod u+s',
            )
            if any(marker in command for marker in exploit_markers):
                missing = sorted(required - self._privesc_checks_done)
                return (
                    "[ERROR] Exploit attempt blocked: complete privesc checklist first. "
                    f"Missing: {', '.join(missing)}."
                )
        return None

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
            self.journal.write('phase_change', {'phase': 'complete', 'reason': 'root flag obtained'})
            return

        # User access + no root → jump to privesc
        has_user = any(a.level == 'user' and a.host == self.target for a in self.state.accesses)
        has_root = self.state.has_root(self.target)
        if has_user and not has_root and self.phase in ('enumeration',):
            L.log(f"{C_MAGENTA}{C_BOLD}STRATEGY: User access detected — jumping to privesc{C_RESET}")
            self.phase = 'privesc'
            self._request_plan_refresh()
            self._phase_entry_iteration = self.total_iterations
            self._phase_entry_node_count = len(self.graph.nodes)
            self._last_progress_iteration = self.total_iterations
            await self.manager.broadcast('phase_change', {'phase': self.phase})
            self.journal.write('phase_change', {'phase': self.phase, 'reason': 'user access detected'})
            return

        # Verified creds + no access → jump to exploitation
        verified_creds = [c for c in self.state.credentials.values() if c.verified_for]
        unverified_creds = [c for c in self.state.credentials.values()
                           if not c.verified_for and not c.failed_for]
        if (verified_creds or unverified_creds) and not has_user and self.phase == 'enumeration':
            L.log(f"{C_MAGENTA}{C_BOLD}STRATEGY: Credentials found — jumping to exploitation{C_RESET}")
            self.phase = 'exploitation'
            self._request_plan_refresh()
            self._phase_entry_iteration = self.total_iterations
            self._phase_entry_node_count = len(self.graph.nodes)
            self._last_progress_iteration = self.total_iterations
            await self.manager.broadcast('phase_change', {'phase': self.phase})
            self.journal.write('phase_change', {'phase': self.phase, 'reason': 'credentials discovered'})
            return

        # Critical KB exploit match during enumeration → jump to exploitation
        if self.phase == 'enumeration':
            for svc in self.state.services.values():
                matches = match_service_to_exploits(svc.name, svc.version)
                critical_matches = [m for m in matches if m.get('severity') == 'critical']
                if critical_matches:
                    L.log(f"{C_MAGENTA}{C_BOLD}STRATEGY: Critical exploit match for {svc.name} — jumping to exploitation{C_RESET}")
                    self.phase = 'exploitation'
                    self._request_plan_refresh()
                    self._phase_entry_iteration = self.total_iterations
                    self._phase_entry_node_count = len(self.graph.nodes)
                    self._last_progress_iteration = self.total_iterations
                    await self.manager.broadcast('phase_change', {'phase': self.phase})
                    self.journal.write('phase_change', {'phase': self.phase, 'reason': f'critical exploit match for {svc.name}'})
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
            self.journal.write('shell_access', {
                'host': access.host,
                'user': access.user,
                'level': access.level,
                'method': access.method,
                'ssh_command': ssh_cmd,
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

    async def _auto_add_hosts(self, hostnames: list[str]):
        """Add discovered target hostnames to /etc/hosts."""
        L = self.logger
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
        await self._refresh_plan(reason='initial state', force=True)
        self.journal.write('phase_change', {'phase': self.phase, 'reason': 'initial state'})

        L.log(f"{C_MAGENTA}Phase: ENUMERATION{C_RESET}")
        self._phase_entry_iteration = 0
        self._phase_entry_node_count = len(self.graph.nodes)

        while self.phase != 'complete' and self.total_iterations < MAX_TOTAL_ITERATIONS and not self._done:
            phase_iterations = self._phase_iterations_used.get(self.phase, 0)
            phase_budget_limit = self._phase_budget_limit(self.phase)
            if phase_iterations >= phase_budget_limit:
                await self._evaluate_strategy()
                if self.phase == 'complete' or self._done:
                    break
                if self._phase_iterations_used.get(self.phase, 0) >= self._phase_budget_limit(self.phase):
                    exhausted_phase = self.phase
                    next_phase = 'complete'
                    if exhausted_phase == 'enumeration':
                        has_working_path = bool(
                            self.state.credentials
                            or self.state.accesses
                            or self.state.findings
                            or self.state.hypotheses
                            or self.state.loot.get('invite_code')
                        )
                        next_phase = 'exploitation' if has_working_path else 'complete'
                    elif exhausted_phase == 'exploitation':
                        next_phase = 'privesc' if self.state.has_access(self.target) else 'complete'

                    L.log(
                        f"{C_YELLOW}Phase budget exhausted for {exhausted_phase} "
                        f"({phase_iterations}/{phase_budget_limit}) -> {next_phase}{C_RESET}"
                    )
                    self.phase = next_phase
                    if next_phase == 'complete':
                        self._done = True
                        break
                    self._request_plan_refresh()
                    self._phase_entry_iteration = self.total_iterations
                    self._phase_entry_node_count = len(self.graph.nodes)
                    await self.manager.broadcast('phase_change', {'phase': self.phase})
                    await self._broadcast_budget()
                    continue
            consecutive_stops = 0

            if self.phase not in self._plan_injected_for_phase and self.total_iterations > 0:
                self._plan_injected_for_phase.add(self.phase)
                self._request_plan_refresh()
                L.log(f"{C_CYAN}Refreshing task tree for phase entry: {self.phase}{C_RESET}")

            while phase_iterations < self._phase_budget_limit(self.phase) and self.total_iterations < MAX_TOTAL_ITERATIONS:
                self.total_iterations += 1
                self._iteration_counter += 1
                phase_iterations += 1
                self._phase_iterations_used[self.phase] = phase_iterations

                active_task = self.memory.current_plan.ensure_single_active() if self.memory.current_plan else None
                active_task_id = active_task.id if active_task else ''
                if active_task_id != self._tracked_task_id:
                    self._tracked_task_id = active_task_id
                    self._active_task_stall_count = 0

                # ── Stagnation detection ─────────────────────────
                iters_in_phase = self.total_iterations - self._phase_entry_iteration
                iters_since_progress = self.total_iterations - self._last_progress_iteration

                # Hard stagnation: in exploitation/privesc without access for too long → complete
                if iters_since_progress > 15 and self.phase in ('exploitation', 'privesc'):
                    has_access = bool(self.state.accesses)
                    has_creds = bool(self.state.credentials)
                    if not has_access and not has_creds:
                        L.log(f"{C_RED}Hard stagnation: {self.phase} for {iters_since_progress} iterations without state progress — completing{C_RESET}")
                        self.phase = 'complete'
                        self._done = True
                        break

                # Hard stagnation: enumeration spinning without progress → force transition
                if iters_since_progress > 25 and self.phase == 'enumeration':
                    has_creds = bool(self.state.credentials)
                    has_access = bool(self.state.accesses)
                    if not has_creds and not has_access:
                        L.log(f"{C_RED}Hard stagnation: enumeration for {iters_since_progress} iterations without state progress — completing{C_RESET}")
                        self.phase = 'complete'
                        self._done = True
                        break

                # ── Auto-complete if root flag found ─────────────
                if self.state.has_root(self.target) and 'root_flag' in self.state.loot:
                    L.log(f"{C_GREEN}{C_BOLD}ROOT + FLAG DETECTED — auto-completing{C_RESET}")
                    self.phase = 'complete'
                    self._done = True
                    break

                L.log(f"{C_DIM}--- Iteration {self.total_iterations}/{MAX_TOTAL_ITERATIONS} (phase: {phase_iterations}/{self._phase_budget_limit(self.phase)}) ---{C_RESET}")

                await self._refresh_plan(reason='iteration start')
                operator_context = self._build_operator_context()
                if not operator_context:
                    self._request_plan_refresh()
                    self.memory.record_dead_end("Planner returned no active task; requesting replanning.")
                    continue

                tools = self._get_tools()
                if operator_context.task_id != self.operator.current_task_id:
                    self.journal.write('task_activate', {
                        'phase': self.phase,
                        'task_id': operator_context.task_id,
                        'task_title': operator_context.task_title,
                        'success_criteria': operator_context.success_criteria,
                        'tool_hints': operator_context.tool_hints,
                    })

                L.log(f"{C_CYAN}Operator call ({operator_context.task_id}, {len(tools)} tools)...{C_RESET}")
                operator_start = time.time()

                try:
                    turn = await self.operator.next_turn(operator_context, tools)
                except Exception as e:
                    L.log(f"{C_RED}LLM ERROR: {e}{C_RESET}")
                    await self.manager.broadcast('error', {'message': f"LLM error: {str(e)}"})
                    self.journal.write('operator_error', {
                        'phase': self.phase,
                        'task_id': operator_context.task_id,
                        'error': str(e),
                    })
                    await self.shell_sessions.close_all()
                    self.journal.close()
                    L.close()
                    return

                llm_time = time.time() - operator_start
                usage_info = turn.usage
                self.total_input_tokens += usage_info['input']
                self.total_output_tokens += usage_info['output']
                self.total_cached_tokens += usage_info['cached']
                self.total_cost += usage_info['cost']
                if usage_info['input']:
                    cached_pct = f" ({usage_info['cached']} cached)" if usage_info['cached'] else ""
                    L.log(f"{C_DIM}LLM: {llm_time:.1f}s | {usage_info['input']}{cached_pct}/{usage_info['output']} tokens | ${usage_info['cost']:.4f} (total: ${self.total_cost:.4f}){C_RESET}")

                choice = turn.response.choices[0]
                message = choice.message

                if message.content:
                    text = message.content[:200] + ('...' if len(message.content) > 200 else '')
                    L.log(f"{C_YELLOW}Thinking: {text}{C_RESET}")
                    await self.manager.broadcast('agent_thinking', {'text': message.content})
                self.journal.write('operator_turn', {
                    'phase': self.phase,
                    'task_id': operator_context.task_id,
                    'content': message.content or '',
                    'tool_calls': [
                        {
                            'id': tc.id,
                            'name': tc.function.name,
                            'arguments': tc.function.arguments,
                        }
                        for tc in (message.tool_calls or [])
                    ],
                    'usage': usage_info,
                })

                # ── No tool calls → model is done with phase ─────
                if not message.tool_calls:
                    consecutive_stops += 1
                    L.log(f"{C_DIM}No tool calls (stop #{consecutive_stops}){C_RESET}")

                    active_task = self.memory.current_plan.ensure_single_active() if self.memory.current_plan else None
                    if active_task and active_task.status in ('active', 'pending'):
                        active_task.status = 'blocked'
                        self.memory.record_dead_end(
                            f"Operator returned no tool calls while task remained open: {active_task.title}"
                        )
                        self.operator.mark_task_blocked(active_task.title)
                        self._request_plan_refresh()
                        L.log(f"{C_CYAN}Blocked task after no-tool response: {active_task.title}{C_RESET}")
                        continue

                    if consecutive_stops >= 2:
                        current_idx = PHASES.index(self.phase) if self.phase in PHASES else len(PHASES) - 1
                        # Don't auto-advance to exploitation/privesc without actionable intel
                        has_creds = bool(self.state.credentials)
                        has_access = bool(self.state.accesses)
                        has_vulns = bool(self.state.findings)

                        if current_idx == 0 and not has_creds and not has_access and not has_vulns:
                            self.memory.record_dead_end(
                                "Enumeration exhausted without actionable findings; planner must switch surfaces or terminate."
                            )
                            self._request_plan_refresh()
                            L.log(f"{C_YELLOW}Enumeration exhausted without findings — requesting replanning{C_RESET}")
                            consecutive_stops = 0
                            continue

                        if current_idx < len(PHASES) - 1:
                            self.phase = PHASES[current_idx + 1]
                            self._request_plan_refresh()
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
                iteration_progress = False

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

                    _sanitize_ctx = {'phase': self.phase, 'nmap_call_count': self._nmap_call_count}
                    args, sanitize_note = sanitize_tool_args(name, args, context=_sanitize_ctx)
                    if sanitize_note:
                        L.log(f"{C_YELLOW}Args sanitized for {name}: {sanitize_note}{C_RESET}")
                    plan_drift_error = self._guard_plan_drift(name, args)
                    transition_error = self._guard_phase_transition(name, args)

                    call_id = tc.id
                    args_short = json.dumps(args)
                    if len(args_short) > 150:
                        args_short = args_short[:150] + '...'
                    L.log(f"{C_GREEN}Tool: {C_BOLD}{name}{C_RESET}{C_GREEN} | {args_short}{C_RESET}")
                    await self.manager.broadcast('tool_call', {'id': call_id, 'name': name, 'args': args})
                    self.journal.write('tool_call', {
                        'phase': self.phase,
                        'task_id': operator_context.task_id,
                        'tool_name': name,
                        'args': args,
                    })

                    # ── Cache check ──────────────────────────────
                    cache_key = f"{name}|{json.dumps(args, sort_keys=True)}"
                    if _should_cache_tool(name, args) and cache_key in self._tool_cache:
                        result = f"[CACHED - identical call already executed] {self._tool_cache[cache_key][:3000]}"
                        tool_time = 0.0
                        L.log(f"{C_YELLOW}Cache hit: {name}{C_RESET}")
                    else:
                        self._tool_call_count += 1
                        if name == 'nmap_scan':
                            self._nmap_call_count += 1
                        await self._broadcast_budget()
                        tool_start = time.time()
                        # ── curl redirect check ──────────────
                        if plan_drift_error:
                            result = plan_drift_error
                        elif transition_error:
                            result = transition_error
                        elif name == 'execute_command':
                            guard_error = self._guard_execute_command(args)
                            if guard_error:
                                result = guard_error
                            else:
                                web_tool, web_args, web_feedback = self._check_web_redirect(args)
                                if web_tool:
                                    L.log(f"{C_YELLOW}Redirecting execute_command(curl) -> {web_tool}{C_RESET}")
                                    result = await self._execute_tool(web_tool, web_args)
                                    result = f"[REDIRECTED to {web_tool}] {result}"
                                    if web_feedback:
                                        result = f"{web_feedback}\n\n{result}"
                                else:
                                    redirect_tool, redirect_args, curl_feedback = self._check_curl_redirect(args)
                                    if redirect_tool:
                                        L.log(f"{C_YELLOW}Redirecting execute_command(curl) -> {redirect_tool}{C_RESET}")
                                        result = await self._execute_tool(redirect_tool, redirect_args)
                                        result = f"[REDIRECTED to {redirect_tool}] {result}"
                                    elif curl_feedback:
                                        result = await self._execute_tool(name, args)
                                        result = f"{result}\n\n{curl_feedback}"
                                    else:
                                        result = await self._execute_tool(name, args)
                        else:
                            result = await self._execute_tool(name, args)
                        tool_time = time.time() - tool_start
                        if _should_cache_tool(name, args):
                            self._tool_cache[cache_key] = result

                    # Prepend sanitization note so the model sees it
                    if sanitize_note:
                        result = f"[NOTE: {sanitize_note}]\n\n{result}"

                    result_lines = result.count('\n') + 1
                    L.log(f"{C_GREEN}Done: {name} | {tool_time:.1f}s | {len(result)} chars, {result_lines} lines{C_RESET}")
                    self.operator.record_tool_result(call_id, result)
                    self.journal.write('tool_result', {
                        'phase': self.phase,
                        'task_id': operator_context.task_id,
                        'tool_name': name,
                        'result': result[:4000],
                    })

                    # Circuit breaker: track consecutive failures per tool
                    if result.startswith('[ERROR]') or result.startswith('[TIMEOUT'):
                        self._tool_failures[name] = self._tool_failures.get(name, 0) + 1
                        self.memory.record_dead_end(f"{name}: {result.splitlines()[0][:180]}")
                        if self._tool_failures[name] >= 2:
                            L.log(f"{C_RED}Circuit breaker: {name} failed {self._tool_failures[name]}x — temporarily disabled{C_RESET}")
                    else:
                        self._tool_failures.pop(name, None)
                        if name in {'check_sudo', 'check_capabilities', 'check_suid', 'check_cron'}:
                            self._privesc_checks_done.add(name)

                    analysis = self.analyzer.analyze(name, args, result)
                    self.memory.record_observation(analysis.observation)
                    self.memory.sync_from_state(self.state)
                    self._sync_plan_progress()
                    if analysis.graph_nodes_added or analysis.graph_edges_added:
                        await self._broadcast_graph()
                        L.log(f"{C_BLUE}Graph: +{analysis.graph_nodes_added} nodes, +{analysis.graph_edges_added} edges{C_RESET}")
                    if analysis.discovered_hosts:
                        await self._auto_add_hosts(analysis.discovered_hosts)
                    if analysis.web_assets_added:
                        L.log(f"{C_CYAN}Analyzer extracted {analysis.web_assets_added} web asset(s){C_RESET}")
                    new_fingerprint = self._state_fingerprint()
                    if new_fingerprint != self._last_progress_fingerprint:
                        self._last_progress_fingerprint = new_fingerprint
                        self._last_progress_iteration = self.total_iterations
                        self._active_task_stall_count = 0
                        iteration_progress = True
                    if new_fingerprint != self._last_state_fingerprint or analysis.plan_refresh_required:
                        self._request_plan_refresh()
                        self._last_state_fingerprint = new_fingerprint
                    self.journal.write('analysis', {
                        'phase': self.phase,
                        'task_id': operator_context.task_id,
                        'tool_name': name,
                        'observation': analysis.observation.to_dict(),
                        'graph_nodes_added': analysis.graph_nodes_added,
                        'graph_edges_added': analysis.graph_edges_added,
                        'discovered_hosts': analysis.discovered_hosts,
                        'web_assets_added': analysis.web_assets_added,
                        'state_changed': analysis.state_changed,
                        'plan_refresh_required': analysis.plan_refresh_required,
                    })

                    # ── Check for new shell access ───────────────
                    await self._check_new_access()

                    # ── Adaptive strategy: evaluate after state update
                    await self._evaluate_strategy()
                    if self._done:
                        should_break = True

                    await self.manager.broadcast('tool_result', {'id': call_id, 'result': result, 'error': False})

                    # ── Phase transition ─────────────────────────
                    if name == 'transition_phase' and not result.startswith('[ERROR]'):
                        next_phase = args.get('next_phase', '')
                        if not next_phase or next_phase not in PHASES + ['complete']:
                            current_idx = PHASES.index(self.phase) if self.phase in PHASES else -1
                            next_phase = PHASES[current_idx + 1] if current_idx < len(PHASES) - 1 else 'complete'

                        if next_phase == 'complete':
                            self.phase = 'complete'
                            self._done = True
                        elif next_phase in PHASES:
                            self.phase = next_phase
                            if next_phase == 'privesc':
                                self._privesc_checks_done.clear()
                            self._request_plan_refresh()

                        self._phase_entry_iteration = self.total_iterations
                        self._phase_entry_node_count = len(self.graph.nodes)
                        self._last_progress_iteration = self.total_iterations
                        self._tracked_task_id = ''
                        self._active_task_stall_count = 0

                        L.log(f"\n{C_MAGENTA}{'='*40}{C_RESET}")
                        L.log(f"{C_MAGENTA}Phase: {self.phase.upper()}{C_RESET}")
                        L.log(f"{C_MAGENTA}Reason: {args.get('reason', 'N/A')}{C_RESET}")
                        L.log(f"{C_MAGENTA}{'='*40}{C_RESET}\n")
                        await self.manager.broadcast('phase_change', {'phase': self.phase})
                        self.journal.write('phase_change', {
                            'phase': self.phase,
                            'reason': args.get('reason', 'N/A'),
                        })
                        await self._broadcast_budget()
                        should_break = True

                if should_break:
                    for remaining_tc in message.tool_calls:
                        if remaining_tc.id == call_id:
                            continue
                        self.operator.record_placeholder_result(
                            remaining_tc.id,
                            '[SKIPPED — phase transition or completion in progress]',
                        )
                    break

                if message.tool_calls and not should_break and active_task:
                    if iteration_progress:
                        self._active_task_stall_count = 0
                    else:
                        self._active_task_stall_count += 1
                        if self._active_task_stall_count >= 4 and active_task.status in ('active', 'pending'):
                            active_task.status = 'blocked'
                            self.memory.record_dead_end(
                                f"Task stalled without durable state progress: {active_task.title}"
                            )
                            self._request_plan_refresh()
                            L.log(f"{C_YELLOW}Task stall detected: {active_task.title} — requesting replanning{C_RESET}")

        # ── Final summary ────────────────────────────────────────
        L.header(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  COMPLETE{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Model: {get_active_model()} ({get_active_backend()}){C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Iterations: {self.total_iterations} | Tool calls: {self._tool_call_count} | Planner calls: {self._planner_calls}{C_RESET}")
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
        await self.shell_sessions.close_all()
        self.journal.close()
        L.close()

    # ── curl redirect ────────────────────────────────────────────

    def _default_session_name_for_url(self, url: str) -> str:
        host = re.sub(r'^https?://', '', url or '').split('/', 1)[0]
        host = host or self.target
        return re.sub(r'[^a-zA-Z0-9_.-]+', '_', host)

    def _check_web_redirect(self, args: dict) -> tuple[str | None, dict | None, str | None]:
        """Redirect stateful curl usage into web_request."""
        command = str(args.get('command', '') or '').strip()
        if not command.startswith('curl '):
            return None, None, None
        if any(x in command for x in ('|', '&&', ';', 'sshpass', 'ssh ', 'wget')):
            return None, None, None

        try:
            tokens = shlex.split(command)
        except ValueError:
            return None, None, None

        method = 'GET'
        headers: list[str] = []
        data = ''
        json_body = ''
        follow_redirects = False
        url = ''
        saw_stateful_flag = False

        i = 1
        while i < len(tokens):
            token = tokens[i]
            if token in ('-X', '--request') and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                saw_stateful_flag = True
                i += 2
                continue
            if token in ('-H', '--header') and i + 1 < len(tokens):
                header = tokens[i + 1]
                headers.append(header)
                saw_stateful_flag = True
                i += 2
                continue
            if token in ('-d', '--data', '--data-raw', '--data-binary', '--form') and i + 1 < len(tokens):
                payload = tokens[i + 1]
                if any(h.lower().startswith('content-type: application/json') for h in headers):
                    json_body = payload
                else:
                    data = payload
                if method == 'GET':
                    method = 'POST'
                saw_stateful_flag = True
                i += 2
                continue
            if token in ('-L', '--location'):
                follow_redirects = True
                saw_stateful_flag = True
                i += 1
                continue
            if token in ('-b', '--cookie', '-c', '--cookie-jar'):
                saw_stateful_flag = True
                i += 2 if i + 1 < len(tokens) else 1
                continue
            if token.startswith('http://') or token.startswith('https://'):
                url = token
            i += 1

        if not url:
            return None, None, None
        if not saw_stateful_flag and method == 'GET':
            return None, None, None

        return (
            'web_request',
            {
                'url': url,
                'method': method,
                'session_name': self._default_session_name_for_url(url),
                'headers': headers,
                'data': data,
                'json_body': json_body,
                'follow_redirects': follow_redirects,
            },
            '[NOTE] Redirected stateful curl to web_request so cookies, redirects, headers, and body are preserved structurally.',
        )

    def _check_curl_redirect(self, args: dict) -> tuple[str | None, dict | None, str | None]:
        """Check if an execute_command(curl) should redirect to curl_request.

        Returns (redirect_tool, redirect_args, feedback_note) or (None, None, None).
        """
        command = str(args.get('command', '') or '').strip()

        # Never redirect curl inside sshpass/ssh/multi-command chains
        if any(x in command for x in ('sshpass', 'ssh ', '&&', ';', 'python', 'bash -c', 'gcc', 'wget')):
            return None, None, None

        # Simple curl: curl [flags] URL — no pipe/redirect
        m = re.match(r'^curl\s+((?:-[a-zA-Z]+\s+)*)(["\']?https?://\S+["\']?)\s*$', command)
        if m:
            flags = m.group(1).strip()
            url = m.group(2).strip().strip("'\"")
            return 'curl_request', {'url': url, 'flags': flags or '-sS'}, None

        # curl|grep pipeline: allow but inject feedback
        if re.match(r'^curl\s+.*\|\s*(grep|head|tail|awk|sed)', command):
            return None, None, (
                '[NOTE] You used execute_command for a curl pipeline. '
                'Use curl_request for simple URL fetching — it is faster and auto-sanitized. '
                'Reserve execute_command for complex pipelines or target-side execution via SSH.'
            )

        return None, None, None

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

        if name in {'execute_command', 'check_sudo', 'check_suid', 'check_cron', 'check_capabilities', 'run_linpeas'}:
            command = str(args.get('command', '') or '').strip()
            parsed = parse_sshpass_ssh_command(command) if command else None
            if parsed:
                spec, remote_command = parsed
                if remote_command:
                    timeout = 300 if name == 'run_linpeas' else 120
                    result = await self.shell_sessions.execute(spec, remote_command, timeout=timeout)
                    return f"[SESSION {spec.key}] {result}".strip()

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
