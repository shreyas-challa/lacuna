"""Tactical operator for single-task execution."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from backend.context import build_messages
from backend.llm import chat_completion, extract_usage


PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


@dataclass
class OperatorTaskContext:
    phase: str
    target: str
    lhost: str
    task_id: str
    task_title: str
    task_description: str
    success_criteria: str
    tool_hints: list[str]
    budget_remaining: int
    state_summary: str
    memory_summary: str
    graph_summary: str
    knowledge_hints: str


@dataclass
class OperatorTurn:
    assistant_message: dict
    response: object
    usage: dict


def _load_prompt(filename: str) -> str:
    path = PROMPTS_DIR / filename
    return path.read_text() if path.exists() else ""


class Operator:
    """Executes one active task at a time with narrow context."""

    def __init__(self, client):
        self.client = client
        self.history: list[dict] = []
        self.current_task_id: str = ""
        self._iteration = 0
        self.model_override = os.getenv("LACUNA_OPERATOR_MODEL", "").strip() or None
        self.backend_override = os.getenv("LACUNA_OPERATOR_BACKEND", "").strip().lower() or None

    async def next_turn(self, context: OperatorTaskContext, tools: list[dict]) -> OperatorTurn:
        if context.task_id != self.current_task_id:
            self.current_task_id = context.task_id
            self.history = [{
                'role': 'user',
                'content': (
                    f"Start task {context.task_id}: {context.task_title}. "
                    f"Success condition: {context.success_criteria or 'Advance this task concretely.'}"
                ),
            }]
            self._iteration = 0

        self._iteration += 1
        system_prompt = self._build_system_prompt(context)
        messages = build_messages(system_prompt, self.history, self._iteration)
        response = await chat_completion(
            self.client,
            messages,
            tools,
            backend_override=self.backend_override,
            model_override=self.model_override,
            max_tokens=1800,
        )
        message = response.choices[0].message
        assistant_msg = {'role': 'assistant', 'content': message.content or '', '_iteration': self._iteration}
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
        self.history.append(assistant_msg)
        return OperatorTurn(
            assistant_message=assistant_msg,
            response=response,
            usage=extract_usage(response, model=self.model_override),
        )

    def record_tool_result(self, call_id: str, result: str):
        self.history.append({
            'role': 'tool',
            'tool_call_id': call_id,
            'content': result,
            '_iteration': self._iteration,
        })

    def record_placeholder_result(self, call_id: str, result: str):
        self.record_tool_result(call_id, result)

    def mark_task_blocked(self, reason: str):
        self.history.append({
            'role': 'user',
            'content': f"Task blocked: {reason}",
            '_iteration': self._iteration,
        })

    def _build_system_prompt(self, context: OperatorTaskContext) -> str:
        phase_prompt = _load_prompt(f"{context.phase}.md")
        lhost_line = f"\nLHOST: {context.lhost}" if context.lhost else ""
        parts = [
            "You are Lacuna's tactical operator. Your role is to advance ONE active task.",
            f"Target: {context.target}{lhost_line}",
            f"Phase: {context.phase}",
            f"Current task: {context.task_title}",
        ]
        if context.task_description:
            parts.append(f"Task detail: {context.task_description}")
        if context.success_criteria:
            parts.append(f"Success condition: {context.success_criteria}")
        if context.tool_hints:
            parts.append(f"Preferred tools: {', '.join(context.tool_hints[:5])}")
        parts.extend([
            "Rules:",
            "- Stay within the active task unless transition_phase is the only correct move.",
            "- Prefer one decisive tool call. Use multiple tool calls only if they are a tight sequence for the same task.",
            "- If the task is blocked, return no tool calls and state the blocker briefly.",
            "- Do not invent facts outside the structured context.",
        ])
        if phase_prompt:
            parts.append("Phase guidance:\n" + phase_prompt)
        if context.state_summary:
            parts.append(context.state_summary)
        if context.memory_summary:
            parts.append(context.memory_summary)
        if context.knowledge_hints:
            parts.append(context.knowledge_hints)
        if context.graph_summary:
            parts.append(context.graph_summary)
        parts.append(f"Budget remaining: {context.budget_remaining}")
        return "\n\n".join(parts)
