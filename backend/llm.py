"""LLM client — OpenAI primary, Anthropic backup via Claude Code OAuth.

Token optimization strategy:
  - OpenAI prompt caching: static instruction prefix gets cached at 50% off
  - Model selection: gpt-4.1-mini by default (5x cheaper than gpt-4.1)
  - Cost tracking: every call logs estimated spend so you know your burn rate
  - Auto-fallback to Anthropic when OpenAI credits exhausted or rate limited
"""

import os
import json
import asyncio
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ────────────────────────────────────────────────
BACKEND = os.getenv("LACUNA_BACKEND", "openai").lower()
OPENAI_MODEL = os.getenv("LACUNA_MODEL", "gpt-4.1-mini")
ANTHROPIC_MODEL = os.getenv("LACUNA_ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
FALLBACK_ENABLED = os.getenv("LACUNA_FALLBACK", "true").lower() in ("true", "1", "yes")

# Public MODEL — reflects whichever backend is currently active
MODEL = OPENAI_MODEL if BACKEND == "openai" else ANTHROPIC_MODEL

MAX_RETRIES = 3
RETRY_DELAYS = [2, 5, 15]

# ── Cost tracking ────────────────────────────────────────────────
# Prices per million tokens (USD)
MODEL_PRICING = {
    # OpenAI
    'gpt-4.1':      {'input': 2.00, 'output': 8.00,  'cached_input': 0.50},
    'gpt-4.1-mini': {'input': 0.40, 'output': 1.60,  'cached_input': 0.10},
    'gpt-4.1-nano': {'input': 0.10, 'output': 0.40,  'cached_input': 0.025},
    'gpt-4o':       {'input': 2.50, 'output': 10.00, 'cached_input': 1.25},
    'gpt-4o-mini':  {'input': 0.15, 'output': 0.60,  'cached_input': 0.075},
    'o4-mini':      {'input': 1.10, 'output': 4.40,  'cached_input': 0.275},
    # Anthropic (per-API-key billing; $0 via Pro subscription OAuth)
    'claude-opus-4':   {'input': 15.00, 'output': 75.00, 'cached_input': 1.875},
    'claude-sonnet-4': {'input': 3.00,  'output': 15.00, 'cached_input': 0.375},
    'claude-haiku-4':  {'input': 0.80,  'output': 4.00,  'cached_input': 0.10},
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int,
                  cached_tokens: int = 0) -> float:
    """Estimate cost in USD for a set of tokens."""
    pricing = None
    for key, p in MODEL_PRICING.items():
        if model.startswith(key):
            pricing = p
            break
    if not pricing:
        return 0.0

    non_cached = max(0, input_tokens - cached_tokens)
    return (non_cached * pricing['input'] / 1_000_000 +
            cached_tokens * pricing['cached_input'] / 1_000_000 +
            output_tokens * pricing['output'] / 1_000_000)


# ── Active backend tracking (for auto-fallback) ─────────────────
_active_backend = BACKEND
_anthropic_client = None


def get_active_model() -> str:
    return ANTHROPIC_MODEL if _active_backend == "anthropic" else OPENAI_MODEL


def get_active_backend() -> str:
    return _active_backend


# ── Client creation ──────────────────────────────────────────────

def get_client():
    """Create primary API client based on configured backend."""
    if BACKEND == "openai":
        from openai import AsyncOpenAI
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not set. Add it to .env\n"
                "  OPENAI_API_KEY=sk-..."
            )
        return AsyncOpenAI(api_key=api_key)
    else:
        return _get_anthropic_client()


def _get_anthropic_client():
    """Create Anthropic client — tries API key first, then Claude Code OAuth."""
    import anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        return anthropic.AsyncAnthropic(api_key=api_key)

    # Piggyback off Claude Code session via OAuth token
    creds_path = Path.home() / ".claude" / ".credentials.json"
    if creds_path.exists():
        try:
            data = json.loads(creds_path.read_text())
            token = data.get("claudeAiOauth", {}).get("accessToken")
            if token:
                return anthropic.AsyncAnthropic(auth_token=token)
        except (json.JSONDecodeError, KeyError):
            pass

    raise ValueError(
        "No Anthropic credentials found. Either:\n"
        "  1. Set ANTHROPIC_API_KEY in .env\n"
        "  2. Log in to Claude Code (claude login) to use OAuth"
    )


# ── Chat completion with auto-fallback ───────────────────────────

async def chat_completion(client, messages: list, tools: list | None = None):
    """Call the LLM with retry logic and auto-fallback to Anthropic.

    Returns a response object with OpenAI-compatible structure regardless
    of which backend actually served the request.
    """
    global _active_backend, _anthropic_client

    if _active_backend == "openai":
        try:
            return await _openai_completion(client, messages, tools)
        except Exception as e:
            if FALLBACK_ENABLED and _is_switchable_error(e):
                _active_backend = "anthropic"
                _anthropic_client = _get_anthropic_client()
                return await _anthropic_completion(_anthropic_client, messages, tools)
            raise
    else:
        target_client = _anthropic_client or client
        if not target_client:
            _anthropic_client = _get_anthropic_client()
            target_client = _anthropic_client
        return await _anthropic_completion(target_client, messages, tools)


def _is_switchable_error(e: Exception) -> bool:
    """Return True if this OpenAI error should trigger Anthropic fallback."""
    msg = str(e).lower()
    return any(x in msg for x in (
        'insufficient_quota', 'billing', 'rate_limit',
        '429', 'quota', 'exceeded your current',
    ))


# ── OpenAI backend ──────────────────────────────────────────────

async def _openai_completion(client, messages: list, tools: list | None):
    kwargs = {
        'model': OPENAI_MODEL,
        'messages': messages,
        'max_tokens': 4096,
    }
    if tools:
        kwargs['tools'] = tools
        kwargs['tool_choice'] = 'auto'

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            return await client.chat.completions.create(**kwargs)
        except Exception as e:
            last_error = e
            error_str = str(e).lower()
            if any(x in error_str for x in ('auth', '401', '400', 'invalid_api_key')):
                raise
            if _is_switchable_error(e):
                raise  # let the fallback handler catch it
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_DELAYS[attempt])

    raise last_error


# ── Anthropic backend ───────────────────────────────────────────

async def _anthropic_completion(client, messages: list, tools: list | None):
    """Call Anthropic API, translating OpenAI format in/out."""
    system, translated_msgs = _translate_messages(messages)
    anthropic_tools = _translate_tools(tools) if tools else None

    kwargs = {
        'model': ANTHROPIC_MODEL,
        'max_tokens': 4096,
        'messages': translated_msgs,
    }
    if system:
        kwargs['system'] = system
    if anthropic_tools:
        kwargs['tools'] = anthropic_tools

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            response = await client.messages.create(**kwargs)
            return _wrap_anthropic_response(response)
        except Exception as e:
            last_error = e
            error_str = str(e).lower()
            if any(x in error_str for x in ('auth', '401', '400', 'invalid')):
                raise
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_DELAYS[attempt])

    raise last_error


# ── Format translation: OpenAI → Anthropic ──────────────────────

def _translate_messages(messages: list) -> tuple[str, list]:
    """Convert OpenAI-format messages to Anthropic format.

    Returns (system_prompt, anthropic_messages).
    Handles: system extraction, tool_calls→tool_use, tool→tool_result,
    and merging consecutive same-role messages (Anthropic requirement).
    """
    system = ""
    result = []

    for msg in messages:
        role = msg.get('role', '')

        if role == 'system':
            system = msg.get('content', '')
            continue

        if role == 'assistant':
            content_blocks = []
            text = msg.get('content')
            if text:
                content_blocks.append({"type": "text", "text": text})
            for tc in msg.get('tool_calls', []):
                raw_args = tc['function']['arguments']
                parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc['id'],
                    "name": tc['function']['name'],
                    "input": parsed_args,
                })
            # Anthropic requires content to be non-empty
            if not content_blocks:
                content_blocks.append({"type": "text", "text": "(thinking)"})
            result.append({"role": "assistant", "content": content_blocks})
            continue

        if role == 'tool':
            tool_result = {
                "type": "tool_result",
                "tool_use_id": msg.get('tool_call_id', ''),
                "content": msg.get('content', ''),
            }
            # Group consecutive tool results into one user message
            if result and result[-1]['role'] == 'user' and isinstance(result[-1]['content'], list):
                result[-1]['content'].append(tool_result)
            else:
                result.append({"role": "user", "content": [tool_result]})
            continue

        # Regular user message
        result.append({"role": "user", "content": msg.get('content', '')})

    # Merge consecutive same-role messages (Anthropic requires alternation)
    merged = []
    for msg in result:
        if merged and merged[-1]['role'] == msg['role']:
            prev_content = merged[-1]['content']
            curr_content = msg['content']
            # Normalize both to lists
            if isinstance(prev_content, str):
                prev_content = [{"type": "text", "text": prev_content}]
            if isinstance(curr_content, str):
                curr_content = [{"type": "text", "text": curr_content}]
            merged[-1]['content'] = prev_content + curr_content
        else:
            merged.append(msg)

    return system, merged


def _translate_tools(tools: list) -> list:
    """Convert OpenAI tool schemas to Anthropic format."""
    return [
        {
            "name": t['function']['name'],
            "description": t['function']['description'],
            "input_schema": t['function']['parameters'],
        }
        for t in tools
    ]


# ── Format translation: Anthropic → OpenAI-compatible response ──
# Adapter classes so agent.py can use response.choices[0].message etc.

class _ToolCallFunction:
    __slots__ = ('name', 'arguments')
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments

class _ToolCall:
    __slots__ = ('id', 'type', 'function')
    def __init__(self, tc_id: str, function: _ToolCallFunction):
        self.id = tc_id
        self.type = 'function'
        self.function = function

class _Message:
    __slots__ = ('content', 'tool_calls')
    def __init__(self, content: str | None, tool_calls: list | None):
        self.content = content
        self.tool_calls = tool_calls

class _Choice:
    __slots__ = ('message', 'finish_reason')
    def __init__(self, message: _Message, finish_reason: str):
        self.message = message
        self.finish_reason = finish_reason

class _TokenDetails:
    __slots__ = ('cached_tokens',)
    def __init__(self, cached: int):
        self.cached_tokens = cached

class _Usage:
    __slots__ = ('prompt_tokens', 'completion_tokens', 'prompt_tokens_details')
    def __init__(self, prompt: int, completion: int, cached: int = 0):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.prompt_tokens_details = _TokenDetails(cached) if cached else None

class _Response:
    __slots__ = ('choices', 'usage')
    def __init__(self, choices: list, usage: _Usage):
        self.choices = choices
        self.usage = usage


def _wrap_anthropic_response(response) -> _Response:
    """Wrap an Anthropic response in OpenAI-compatible adapter objects."""
    text_parts = []
    tool_calls = []

    for block in response.content:
        if block.type == "text":
            text_parts.append(block.text)
        elif block.type == "tool_use":
            tool_calls.append(_ToolCall(
                tc_id=block.id,
                function=_ToolCallFunction(
                    name=block.name,
                    arguments=json.dumps(block.input),
                ),
            ))

    content = "\n".join(text_parts) if text_parts else None
    message = _Message(content=content, tool_calls=tool_calls or None)
    choice = _Choice(message=message, finish_reason=response.stop_reason or 'end_turn')

    # Anthropic usage fields
    cached = getattr(response.usage, 'cache_read_input_tokens', 0) or 0
    usage = _Usage(
        prompt=response.usage.input_tokens,
        completion=response.usage.output_tokens,
        cached=cached,
    )

    return _Response(choices=[choice], usage=usage)


# ── Usage extraction ─────────────────────────────────────────────

def extract_usage(response) -> dict:
    """Extract token usage and cost from API response (works for both backends)."""
    usage = getattr(response, 'usage', None)
    if not usage:
        return {'input': 0, 'output': 0, 'cached': 0, 'cost': 0.0}

    inp = getattr(usage, 'prompt_tokens', 0) or 0
    out = getattr(usage, 'completion_tokens', 0) or 0

    cached = 0
    details = getattr(usage, 'prompt_tokens_details', None)
    if details:
        cached = getattr(details, 'cached_tokens', 0) or 0

    model = get_active_model()
    cost = estimate_cost(model, inp, out, cached)
    return {'input': inp, 'output': out, 'cached': cached, 'cost': cost}
