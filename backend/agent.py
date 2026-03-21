"""Lacuna Agent — core autonomous penetration testing loop.

Architecture:
  - StateManager tracks all structured findings (creds, services, access, loot)
  - ContextManager compresses old messages to prevent token bloat
  - Knowledge base provides instant exploit recognition
  - Graph + frontend provide real-time visualization
  - Phase model guides but doesn't restrict — agent can skip phases
"""

import json
import re
import time
import inspect
from pathlib import Path
from datetime import datetime

from backend.llm import get_client, chat_completion
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

PHASES = ['enumeration', 'vuln_analysis', 'exploitation', 'privesc']
MAX_ITERATIONS_PER_PHASE = 15
MAX_TOTAL_ITERATIONS = 60

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
                        'enum': ['vuln_analysis', 'exploitation', 'privesc', 'complete'],
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

    # ── System prompt construction ───────────────────────────────

    def _build_system_prompt(self) -> str:
        system = load_prompt("system.md")
        phase_prompt = load_prompt(f"{self.phase}.md")
        state_summary = self.state.get_prompt_summary()
        graph_summary = self.graph.get_summary()
        knowledge_hints = self._get_knowledge_hints()

        remaining = max(0, 30 - self._tool_call_count)
        budget = f"## Tool Budget: {remaining} calls remaining (used {self._tool_call_count}/30)"
        lhost_section = f"\n\n## Attacker IP (LHOST): {self.lhost}" if self.lhost else ""

        parts = [
            system,
            f"## Current Phase: {self.phase}",
            phase_prompt,
            state_summary,
            f"## Attack Graph\n{graph_summary}",
            f"## Target: {self.target}{lhost_section}",
            budget,
        ]
        if knowledge_hints:
            parts.insert(4, knowledge_hints)

        return '\n\n'.join(parts)

    def _get_knowledge_hints(self) -> str:
        """Match discovered services against exploit knowledge base."""
        hints = []
        for svc in self.state.services.values():
            svc_key = f"{svc.name}:{svc.version}"
            if svc_key in self._knowledge_injected:
                continue
            matches = match_service_to_exploits(svc.name, svc.version)
            for exploit in matches:
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
        return META_TOOLS + get_tools_for_phase(self.phase)

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

            while phase_iterations < MAX_ITERATIONS_PER_PHASE and self.total_iterations < MAX_TOTAL_ITERATIONS:
                self.total_iterations += 1
                phase_iterations += 1

                # ── Stagnation detection ─────────────────────────
                iters_in_phase = self.total_iterations - self._phase_entry_iteration
                new_nodes = len(self.graph.nodes) - self._phase_entry_node_count
                iterations_since_nudge = self.total_iterations - self._last_nudge_iteration
                if iters_in_phase > 8 and new_nodes == 0 and iterations_since_nudge >= 5:
                    nudge = (
                        f"[SYSTEM] You have been in the '{self.phase}' phase for {iters_in_phase} iterations "
                        f"without discovering new information. Either transition to the next phase with "
                        f"transition_phase, or explain what specific information you are still looking for."
                    )
                    self.messages.append({'role': 'user', 'content': nudge})
                    self._last_nudge_iteration = self.total_iterations
                    L.log(f"{C_YELLOW}Stagnation nudge (iter {iters_in_phase}, 0 new nodes){C_RESET}")

                # ── Auto-complete if root flag found ─────────────
                if self.state.has_root(self.target) and 'root_flag' in self.state.loot:
                    L.log(f"{C_GREEN}{C_BOLD}ROOT + FLAG DETECTED — auto-completing{C_RESET}")
                    self.phase = 'complete'
                    self._done = True
                    break

                L.log(f"{C_DIM}--- Iteration {self.total_iterations}/{MAX_TOTAL_ITERATIONS} (phase: {phase_iterations}/{MAX_ITERATIONS_PER_PHASE}) ---{C_RESET}")

                # ── Build context-managed message list ───────────
                system_prompt = self._build_system_prompt()
                messages = build_messages(system_prompt, self.messages)
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
                usage = getattr(response, 'usage', None)
                if usage:
                    inp = getattr(usage, 'prompt_tokens', 0) or 0
                    out = getattr(usage, 'completion_tokens', 0) or 0
                    self.total_input_tokens += inp
                    self.total_output_tokens += out
                    L.log(f"{C_DIM}LLM: {llm_time:.1f}s | {inp}/{out} tokens | total: {self.total_input_tokens}/{self.total_output_tokens}{C_RESET}")

                choice = response.choices[0]
                message = choice.message

                if message.content:
                    text = message.content[:200] + ('...' if len(message.content) > 200 else '')
                    L.log(f"{C_YELLOW}Thinking: {text}{C_RESET}")
                    await self.manager.broadcast('agent_thinking', {'text': message.content})

                assistant_msg = {'role': 'assistant', 'content': message.content or ''}
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
                        tool_start = time.time()
                        result = await self._execute_tool(name, args)
                        tool_time = time.time() - tool_start
                        if name not in _NO_CACHE:
                            self._tool_cache[cache_key] = result

                    result_lines = result.count('\n') + 1
                    L.log(f"{C_GREEN}Done: {name} | {tool_time:.1f}s | {len(result)} chars, {result_lines} lines{C_RESET}")

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

                    await self.manager.broadcast('tool_result', {'id': call_id, 'result': result, 'error': False})
                    self.messages.append({
                        'role': 'tool',
                        'tool_call_id': call_id,
                        'content': result,
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
                        should_break = True

                if should_break:
                    break

        # ── Final summary ────────────────────────────────────────
        L.header(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  COMPLETE{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Iterations: {self.total_iterations} | Tool calls: {self._tool_call_count}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Tokens: {self.total_input_tokens} in / {self.total_output_tokens} out{C_RESET}")
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
