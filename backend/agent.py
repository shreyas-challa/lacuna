import json
import time
from pathlib import Path

from backend.llm import get_client, chat_completion
from backend.graph import GraphManager
from backend.report import ReportBuilder
from backend.ws_manager import WSManager
from backend.tools import TOOL_REGISTRY, get_tools_for_phase
from backend.parsers import TOOL_PARSERS

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

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

# Meta-tool schemas (always available)
META_TOOLS = [
    {
        'type': 'function',
        'function': {
            'name': 'update_graph',
            'description': 'Update the attack graph with new nodes and edges. The graph is auto-updated from tool outputs, but use this for manual additions like discovered usernames, credentials, or attack paths not captured automatically.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'nodes': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'string', 'description': 'Unique node ID'},
                                'label': {'type': 'string', 'description': 'Display label'},
                                'type': {'type': 'string', 'enum': ['machine', 'service', 'user', 'vulnerability', 'root'], 'description': 'Node type'},
                            },
                            'required': ['id', 'label', 'type'],
                        },
                        'description': 'Nodes to add/update',
                    },
                    'edges': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'source': {'type': 'string'},
                                'target': {'type': 'string'},
                                'label': {'type': 'string', 'description': 'Edge label'},
                            },
                            'required': ['source', 'target'],
                        },
                        'description': 'Edges to add',
                    },
                },
                'required': [],
            },
        },
    },
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
            'description': 'Append a markdown section to the penetration test report. Call this after completing significant findings or actions.',
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


def log(msg: str):
    print(f"{C_DIM}[{time.strftime('%H:%M:%S')}]{C_RESET} {msg}")


class Agent:
    def __init__(self, target: str, manager: WSManager):
        self.target = target
        self.manager = manager
        self.graph = GraphManager()
        self.report = ReportBuilder(target)
        self.client = get_client()
        self.phase = 'enumeration'
        self.messages: list[dict] = []
        self.total_iterations = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def _build_system_prompt(self) -> str:
        system = load_prompt("system.md")
        phase_prompt = load_prompt(f"{self.phase}.md")
        graph_summary = self.graph.get_summary()
        return f"{system}\n\n## Current Phase: {self.phase}\n\n{phase_prompt}\n\n## Current Graph State\n{graph_summary}\n\n## Target: {self.target}"

    def _get_tools(self) -> list[dict]:
        phase_tools = get_tools_for_phase(self.phase)
        return META_TOOLS + phase_tools

    async def run(self):
        """Main agent loop."""
        print(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}  LACUNA — Security Research Agent{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}  Target: {self.target}{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}{'='*60}{C_RESET}\n")

        # Add initial target node and seed the conversation
        self.graph.add_node(self.target, self.target, 'machine')
        await self._broadcast_graph()
        await self.manager.broadcast('phase_change', {'phase': self.phase})

        self.messages.append({
            'role': 'user',
            'content': f'Begin the authorized penetration test against target {self.target}. Start with enumeration.',
        })

        log(f"{C_MAGENTA}Phase: ENUMERATION{C_RESET}")

        while self.phase != 'complete' and self.total_iterations < MAX_TOTAL_ITERATIONS:
            phase_iterations = 0

            while phase_iterations < MAX_ITERATIONS_PER_PHASE and self.total_iterations < MAX_TOTAL_ITERATIONS:
                self.total_iterations += 1
                phase_iterations += 1

                log(f"{C_DIM}--- Iteration {self.total_iterations}/{MAX_TOTAL_ITERATIONS} (phase: {phase_iterations}/{MAX_ITERATIONS_PER_PHASE}) ---{C_RESET}")

                # Build messages with fresh system prompt
                system_prompt = self._build_system_prompt()
                messages = [{'role': 'system', 'content': system_prompt}] + self.messages

                tools = self._get_tools()

                log(f"{C_CYAN}Calling LLM ({len(messages)} messages, {len(tools)} tools)...{C_RESET}")
                llm_start = time.time()

                try:
                    response = await chat_completion(self.client, messages, tools)
                except Exception as e:
                    log(f"{C_RED}LLM ERROR: {e}{C_RESET}")
                    await self.manager.broadcast('error', {'message': f"LLM error: {str(e)}"})
                    return

                llm_time = time.time() - llm_start

                # Token tracking
                usage = getattr(response, 'usage', None)
                if usage:
                    inp = getattr(usage, 'prompt_tokens', 0) or 0
                    out = getattr(usage, 'completion_tokens', 0) or 0
                    self.total_input_tokens += inp
                    self.total_output_tokens += out
                    log(f"{C_DIM}LLM response in {llm_time:.1f}s | tokens: {inp} in / {out} out | total: {self.total_input_tokens} in / {self.total_output_tokens} out{C_RESET}")
                else:
                    log(f"{C_DIM}LLM response in {llm_time:.1f}s | token usage not available{C_RESET}")

                choice = response.choices[0]
                message = choice.message

                # Log + broadcast thinking text
                if message.content:
                    text = message.content[:200] + ('...' if len(message.content) > 200 else '')
                    log(f"{C_YELLOW}Thinking: {text}{C_RESET}")
                    await self.manager.broadcast('agent_thinking', {'text': message.content})

                # Add assistant message to history
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

                # If no tool calls, the model is done thinking for this turn
                if not message.tool_calls:
                    log(f"{C_DIM}No tool calls, finish_reason={choice.finish_reason}{C_RESET}")
                    if choice.finish_reason == 'stop':
                        break
                    continue

                # Process tool calls
                should_break = False
                for tc in message.tool_calls:
                    name = tc.function.name
                    try:
                        args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        args = {}

                    call_id = tc.id

                    # Log the tool call
                    args_short = json.dumps(args)
                    if len(args_short) > 150:
                        args_short = args_short[:150] + '...'
                    log(f"{C_GREEN}Tool call: {C_BOLD}{name}{C_RESET}{C_GREEN} | {args_short}{C_RESET}")

                    await self.manager.broadcast('tool_call', {'id': call_id, 'name': name, 'args': args})

                    tool_start = time.time()
                    result = await self._execute_tool(name, args)
                    tool_time = time.time() - tool_start

                    # Log tool result summary
                    result_lines = result.count('\n') + 1
                    result_len = len(result)
                    log(f"{C_GREEN}Tool done: {name} | {tool_time:.1f}s | {result_len} chars, {result_lines} lines{C_RESET}")

                    # Auto-update graph from tool output
                    if name in TOOL_PARSERS and not result.startswith('[ERROR]') and not result.startswith('[TIMEOUT'):
                        parsed = TOOL_PARSERS[name](result, self.target)
                        if parsed['nodes'] or parsed['edges']:
                            self.graph.update_from_args(parsed)
                            await self._broadcast_graph()
                            node_count = len(parsed['nodes'])
                            edge_count = len(parsed['edges'])
                            log(f"{C_BLUE}Auto-graph: +{node_count} nodes, +{edge_count} edges from {name}{C_RESET}")

                    await self.manager.broadcast('tool_result', {'id': call_id, 'result': result, 'error': False})

                    # Add tool response to messages
                    self.messages.append({
                        'role': 'tool',
                        'tool_call_id': call_id,
                        'content': result,
                    })

                    # Check for phase transition
                    if name == 'transition_phase':
                        next_phase = args.get('next_phase', 'complete')
                        if next_phase == 'complete':
                            self.phase = 'complete'
                        elif next_phase in PHASES:
                            self.phase = next_phase
                        log(f"\n{C_MAGENTA}{'='*40}{C_RESET}")
                        log(f"{C_MAGENTA}Phase: {self.phase.upper()}{C_RESET}")
                        log(f"{C_MAGENTA}Reason: {args.get('reason', 'N/A')}{C_RESET}")
                        log(f"{C_MAGENTA}{'='*40}{C_RESET}\n")
                        await self.manager.broadcast('phase_change', {'phase': self.phase})
                        should_break = True

                if should_break:
                    break

        # Final summary
        print(f"\n{C_BOLD}{C_BLUE}{'='*60}{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}  COMPLETE{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}  Iterations: {self.total_iterations}{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}  Tokens: {self.total_input_tokens} in / {self.total_output_tokens} out{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}  Graph: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}{'='*60}{C_RESET}\n")

        await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
        await self.manager.broadcast('complete', {})

    async def _execute_tool(self, name: str, args: dict) -> str:
        """Execute a tool by name and return the result string."""
        # Meta-tools
        if name == 'update_graph':
            self.graph.update_from_args(args)
            await self._broadcast_graph()
            node_count = len(args.get('nodes', []))
            edge_count = len(args.get('edges', []))
            log(f"{C_BLUE}Manual graph update: +{node_count} nodes, +{edge_count} edges{C_RESET}")
            return "Graph updated successfully."

        if name == 'transition_phase':
            reason = args.get('reason', '')
            return f"Transitioning to {args.get('next_phase', 'complete')}. Reason: {reason}"

        if name == 'append_report':
            md = args.get('markdown', '')
            self.report.append(md)
            await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
            log(f"{C_CYAN}Report appended ({len(md)} chars){C_RESET}")
            return "Report section appended."

        # Phase tools
        if name in TOOL_REGISTRY:
            func = TOOL_REGISTRY[name]['function']
            try:
                result = await func(**args)
                return result
            except Exception as e:
                return f"[ERROR] Tool {name} failed: {str(e)}"

        return f"[ERROR] Unknown tool: {name}"

    async def _broadcast_graph(self):
        await self.manager.broadcast('graph_update', self.graph.get_state())
