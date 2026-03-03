import json
import re
import time
from pathlib import Path
from datetime import datetime

from backend.llm import get_client, chat_completion
from backend.graph import GraphManager
from backend.report import ReportBuilder
from backend.ws_manager import WSManager
from backend.tools import TOOL_REGISTRY, get_tools_for_phase
from backend.tools.exploitation import set_lhost
from backend.parsers import TOOL_PARSERS

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"

PHASES = ['enumeration', 'vuln_analysis', 'exploitation', 'privesc']
MAX_ITERATIONS_PER_PHASE = 15
MAX_TOTAL_ITERATIONS = 50

# Colors for terminal output
C_RESET = '\033[0m'
C_BOLD = '\033[1m'
C_DIM = '\033[2m'
C_BLUE = '\033[94m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_RED = '\033[91m'
C_CYAN = '\033[96m'
C_MAGENTA = '\033[95m'

# Argument name aliases
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

META_TOOLS = [
    {
        'type': 'function',
        'function': {
            'name': 'transition_phase',
            'description': 'Move to the next phase of the pentest. Call this when you have gathered enough information in the current phase.',
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


def load_prompt(filename: str) -> str:
    path = PROMPTS_DIR / filename
    if path.exists():
        return path.read_text()
    return ""


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


def parse_command_output_for_graph(output: str, target: str) -> dict:
    """Extract user/root access from execute_command output for the graph."""
    nodes = []
    edges = []

    # Detect SSH user access (uid=1000(nathan) or similar)
    for m in re.finditer(r'uid=\d+\((\w+)\)', output):
        user = m.group(1)
        if user == 'root':
            nodes.append({'id': 'root-access', 'label': 'ROOT ACCESS', 'type': 'root'})
            edges.append({'source': target, 'target': 'root-access', 'label': 'privesc'})
        elif user != 'nobody':
            node_id = f'user-{user}'
            nodes.append({'id': node_id, 'label': f'User: {user}', 'type': 'user'})
            edges.append({'source': target, 'target': node_id, 'label': 'ssh'})

    # Detect user flag
    if re.search(r'user\.txt', output) and re.search(r'[0-9a-f]{32}', output):
        flag = re.search(r'[0-9a-f]{32}', output).group()
        nodes.append({'id': 'user-flag', 'label': f'user.txt', 'type': 'vulnerability'})

    # Detect root flag
    if re.search(r'root\.txt', output) and re.search(r'[0-9a-f]{32}', output):
        nodes.append({'id': 'root-flag', 'label': f'root.txt', 'type': 'root'})
        edges.append({'source': 'root-access', 'target': 'root-flag', 'label': 'flag'})

    # Detect credentials in output (FTP USER/PASS from pcap strings)
    for m in re.finditer(r'USER\s+(\S+)', output):
        user = m.group(1)
        if user and user not in ('anonymous', 'ftp'):
            nodes.append({'id': f'user-{user}', 'label': f'User: {user}', 'type': 'user'})
            edges.append({'source': target, 'target': f'user-{user}', 'label': 'cred found'})
    for m in re.finditer(r'PASS\s+(\S+)', output):
        nodes.append({'id': 'cred-found', 'label': 'Credentials Found', 'type': 'vulnerability'})

    # Detect cap_setuid or capability escalation
    if 'cap_setuid' in output:
        nodes.append({'id': 'vuln-cap-setuid', 'label': 'cap_setuid (Python)', 'type': 'vulnerability'})
        edges.append({'source': target, 'target': 'vuln-cap-setuid', 'label': 'capability'})

    return {'nodes': nodes, 'edges': edges}


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
    'run_linpeas': 'HINT: Ensure you have shell access on the target first. Try downloading linpeas to /tmp on the target.',
    'check_sudo': 'HINT: Ensure you have a shell on the target. You may need a password — try with credentials found earlier.',
    'check_suid': 'HINT: Ensure you have shell access on the target. This command must run on the remote system, not locally.',
    'check_cron': 'HINT: Ensure you have shell access on the target. Check /etc/crontab and /var/spool/cron/ manually.',
}


def _add_tool_hint(name: str, args: dict, error_msg: str) -> str:
    """Append a tool-specific corrective hint to an error message."""
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
        self.client = get_client()
        self.phase = 'enumeration'
        self.messages: list[dict] = []
        self.total_iterations = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.logger = SessionLogger(target)
        self._done = False  # signals agent should stop entirely
        self._tool_cache: dict[str, str] = {}  # key: "name|args_json" -> cached result
        self._tool_call_count = 0  # total tool calls made (for budget tracking)
        self._phase_entry_iteration = 0  # iteration when current phase started
        self._phase_entry_node_count = 0  # graph node count when current phase started

    def _build_system_prompt(self) -> str:
        system = load_prompt("system.md")
        phase_prompt = load_prompt(f"{self.phase}.md")
        graph_summary = self.graph.get_summary()
        lhost_section = f"\n\n## Attacker IP (LHOST): {self.lhost}" if self.lhost else ""
        return f"{system}\n\n## Current Phase: {self.phase}\n\n{phase_prompt}\n\n## Current Graph State\n{graph_summary}\n\n## Target: {self.target}{lhost_section}"

    def _get_tools(self) -> list[dict]:
        phase_tools = get_tools_for_phase(self.phase)
        return META_TOOLS + phase_tools

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

                # Phase stagnation nudge: if 8+ iterations in same phase with no new graph nodes
                iters_in_phase = self.total_iterations - self._phase_entry_iteration
                new_nodes = len(self.graph.nodes) - self._phase_entry_node_count
                if iters_in_phase > 8 and new_nodes == 0:
                    nudge = (
                        f"[SYSTEM] You have been in the '{self.phase}' phase for {iters_in_phase} iterations "
                        f"without discovering new information (no new graph nodes). Either transition to the next "
                        f"phase with transition_phase, or explain what specific information you are still looking for "
                        f"and why previous attempts failed."
                    )
                    self.messages.append({'role': 'user', 'content': nudge})
                    L.log(f"{C_YELLOW}Phase stagnation nudge injected (iter {iters_in_phase}, 0 new nodes){C_RESET}")

                L.log(f"{C_DIM}--- Iteration {self.total_iterations}/{MAX_TOTAL_ITERATIONS} (phase: {phase_iterations}/{MAX_ITERATIONS_PER_PHASE}) ---{C_RESET}")

                system_prompt = self._build_system_prompt()
                messages = [{'role': 'system', 'content': system_prompt}] + self.messages
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
                    L.log(f"{C_DIM}LLM response in {llm_time:.1f}s | tokens: {inp} in / {out} out | total: {self.total_input_tokens} in / {self.total_output_tokens} out{C_RESET}")
                else:
                    L.log(f"{C_DIM}LLM response in {llm_time:.1f}s{C_RESET}")

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

                # No tool calls = model is done
                if not message.tool_calls:
                    consecutive_stops += 1
                    L.log(f"{C_DIM}No tool calls (stop #{consecutive_stops}), finish_reason={choice.finish_reason}{C_RESET}")

                    # CRITICAL: if model stops without tool calls, it's done with this phase
                    # Don't keep looping — either advance phase or complete
                    if consecutive_stops >= 1:
                        current_idx = PHASES.index(self.phase) if self.phase in PHASES else len(PHASES) - 1
                        if current_idx < len(PHASES) - 1:
                            self.phase = PHASES[current_idx + 1]
                            self._phase_entry_iteration = self.total_iterations
                            self._phase_entry_node_count = len(self.graph.nodes)
                            L.log(f"{C_MAGENTA}Auto-advancing to {self.phase.upper()} (model stopped){C_RESET}")
                            await self.manager.broadcast('phase_change', {'phase': self.phase})
                        else:
                            self.phase = 'complete'
                            self._done = True
                            L.log(f"{C_MAGENTA}All phases complete — finishing{C_RESET}")
                        break
                    continue

                # Reset stop counter on tool calls
                consecutive_stops = 0

                # Process tool calls
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
                    L.log(f"{C_GREEN}Tool call: {C_BOLD}{name}{C_RESET}{C_GREEN} | {args_short}{C_RESET}")

                    await self.manager.broadcast('tool_call', {'id': call_id, 'name': name, 'args': args})

                    # Deduplication: check if exact same call was already made
                    cache_key = f"{name}|{json.dumps(args, sort_keys=True)}"
                    if cache_key in self._tool_cache:
                        result = f"[CACHED - already ran this exact call] {self._tool_cache[cache_key]}"
                        tool_time = 0.0
                        L.log(f"{C_YELLOW}Cache hit for {name} — returning cached result{C_RESET}")
                    else:
                        self._tool_call_count += 1
                        tool_start = time.time()
                        result = await self._execute_tool(name, args)
                        tool_time = time.time() - tool_start
                        # Cache the result (skip meta-tools and errors that might be transient)
                        if name not in ('transition_phase', 'append_report', 'update_graph'):
                            self._tool_cache[cache_key] = result

                    result_lines = result.count('\n') + 1
                    L.log(f"{C_GREEN}Tool done: {name} | {tool_time:.1f}s | {len(result)} chars, {result_lines} lines{C_RESET}")

                    # Auto-update graph from tool output
                    parsed = None
                    if name in TOOL_PARSERS and not result.startswith('[ERROR]') and not result.startswith('[TIMEOUT'):
                        parsed = TOOL_PARSERS[name](result, self.target)
                    elif name in ('execute_command', 'download_and_analyze') and not result.startswith('[ERROR]'):
                        parsed = parse_command_output_for_graph(result, self.target)

                    if parsed and (parsed['nodes'] or parsed['edges']):
                        self.graph.update_from_args(parsed)
                        await self._broadcast_graph()
                        L.log(f"{C_BLUE}Auto-graph: +{len(parsed['nodes'])} nodes, +{len(parsed['edges'])} edges{C_RESET}")

                    await self.manager.broadcast('tool_result', {'id': call_id, 'result': result, 'error': False})

                    self.messages.append({
                        'role': 'tool',
                        'tool_call_id': call_id,
                        'content': result,
                    })

                    if name == 'transition_phase':
                        next_phase = args.get('next_phase', '')
                        if not next_phase or next_phase not in PHASES + ['complete']:
                            current_idx = PHASES.index(self.phase) if self.phase in PHASES else -1
                            if current_idx < len(PHASES) - 1:
                                next_phase = PHASES[current_idx + 1]
                            else:
                                next_phase = 'complete'

                        if next_phase == 'complete':
                            self.phase = 'complete'
                            self._done = True
                        elif next_phase in PHASES:
                            self.phase = next_phase

                        # Reset phase stagnation tracking
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

        # Final summary
        L.header(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  COMPLETE{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Iterations: {self.total_iterations}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Tokens: {self.total_input_tokens} in / {self.total_output_tokens} out{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Graph: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}  Log saved: {L.log_path}{C_RESET}")
        L.header(f"{C_BOLD}{C_BLUE}{'='*60}{C_RESET}\n")

        await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
        await self.manager.broadcast('complete', {})
        L.close()

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
            import inspect
            func = TOOL_REGISTRY[name]['function']
            sig = inspect.signature(func)
            valid_args = {}
            for param_name, param in sig.parameters.items():
                if param_name in args:
                    valid_args[param_name] = args[param_name]
                elif param.default is inspect.Parameter.empty:
                    if param_name == 'target':
                        valid_args['target'] = self.target
                        L.log(f"{C_YELLOW}Injected missing: target={self.target}{C_RESET}")
                    elif param_name == 'lhost' and self.lhost:
                        valid_args['lhost'] = self.lhost
                        L.log(f"{C_YELLOW}Injected missing: lhost={self.lhost}{C_RESET}")
                    elif param_name == 'url':
                        valid_args['url'] = f'http://{self.target}'
                        L.log(f"{C_YELLOW}Injected missing: url=http://{self.target}{C_RESET}")
            try:
                result = await func(**valid_args)
                # Check for tool-level errors in output and add hints
                if result.startswith('[ERROR]') or result.startswith('[TIMEOUT'):
                    result = _add_tool_hint(name, args, result)
                return result
            except Exception as e:
                error_msg = f"[ERROR] {name} failed: {str(e)}"
                return _add_tool_hint(name, args, error_msg)

        return f"[ERROR] Unknown tool: {name}. HINT: Check available tools for this phase — you may need to transition_phase first."

    async def _broadcast_graph(self):
        await self.manager.broadcast('graph_update', self.graph.get_state())
