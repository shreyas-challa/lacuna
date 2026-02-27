import json
from pathlib import Path

from backend.llm import get_client, chat_completion
from backend.graph import GraphManager
from backend.report import ReportBuilder
from backend.ws_manager import WSManager
from backend.tools import TOOL_REGISTRY, get_tools_for_phase

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

PHASES = ['enumeration', 'vuln_analysis', 'exploitation', 'privesc']
MAX_ITERATIONS_PER_PHASE = 15
MAX_TOTAL_ITERATIONS = 50

# Meta-tool schemas (always available)
META_TOOLS = [
    {
        'type': 'function',
        'function': {
            'name': 'update_graph',
            'description': 'Update the attack graph with new nodes and edges. Call this after discovering hosts, services, users, vulnerabilities, or access paths.',
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
        # Add initial target node
        self.graph.add_node(self.target, self.target, 'machine')
        await self._broadcast_graph()
        await self.manager.broadcast('phase_change', {'phase': self.phase})

        while self.phase != 'complete' and self.total_iterations < MAX_TOTAL_ITERATIONS:
            phase_iterations = 0

            while phase_iterations < MAX_ITERATIONS_PER_PHASE and self.total_iterations < MAX_TOTAL_ITERATIONS:
                self.total_iterations += 1
                phase_iterations += 1

                # Build messages with fresh system prompt
                system_prompt = self._build_system_prompt()
                messages = [{'role': 'system', 'content': system_prompt}] + self.messages

                tools = self._get_tools()

                try:
                    response = await chat_completion(self.client, messages, tools)
                except Exception as e:
                    await self.manager.broadcast('error', {'message': f"LLM error: {str(e)}"})
                    return

                choice = response.choices[0]
                message = choice.message

                # Broadcast thinking text
                if message.content:
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
                    if choice.finish_reason == 'stop':
                        # Model stopped without tool calls — nudge or move on
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
                    await self.manager.broadcast('tool_call', {'id': call_id, 'name': name, 'args': args})

                    result = await self._execute_tool(name, args)

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
                        await self.manager.broadcast('phase_change', {'phase': self.phase})
                        should_break = True

                if should_break:
                    break

        # Send completion
        await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
        await self.manager.broadcast('complete', {})

    async def _execute_tool(self, name: str, args: dict) -> str:
        """Execute a tool by name and return the result string."""
        # Meta-tools
        if name == 'update_graph':
            self.graph.update_from_args(args)
            await self._broadcast_graph()
            return "Graph updated successfully."

        if name == 'transition_phase':
            reason = args.get('reason', '')
            return f"Transitioning to {args.get('next_phase', 'complete')}. Reason: {reason}"

        if name == 'append_report':
            md = args.get('markdown', '')
            self.report.append(md)
            await self.manager.broadcast('report_update', {'markdown': self.report.get_markdown()})
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
