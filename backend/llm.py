"""LLM client — OpenAI API, Codex OAuth, Anthropic OAuth with auto-fallback.

Supports three backends:
  - openai: Standard OpenAI API with API key ($OPENAI_API_KEY)
  - codex: ChatGPT/Codex OAuth — piggybacks off Codex CLI session (~/.codex/auth.json)
  - anthropic: Anthropic API key or Claude Code OAuth (~/.claude/.credentials.json)

Auto-detection picks the first available backend based on credentials.
Auto-fallback transparently switches when a backend hits quota/rate limits.
"""

import os
import json
import asyncio
import base64
import time
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ────────────────────────────────────────────────
OPENAI_MODEL = os.getenv("LACUNA_MODEL", "gpt-4.1-mini")
CODEX_MODEL = os.getenv("LACUNA_CODEX_MODEL", "") or "gpt-5.1-codex-mini"
ANTHROPIC_MODEL = os.getenv("LACUNA_ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
FALLBACK_ENABLED = os.getenv("LACUNA_FALLBACK", "true").lower() in ("true", "1", "yes")

MAX_RETRIES = 3
RETRY_DELAYS = [2, 5, 15]

_MODEL_FOR_BACKEND = {
    "openai": OPENAI_MODEL,
    "codex": CODEX_MODEL,
    "anthropic": ANTHROPIC_MODEL,
}

# ── Backend auto-detection ───────────────────────────────────────

def _codex_creds_exist() -> bool:
    codex_home = os.getenv("CODEX_HOME", "")
    if codex_home and (Path(codex_home) / "auth.json").exists():
        return True
    return (Path.home() / ".codex" / "auth.json").exists()


def _detect_backend() -> str:
    configured = os.getenv("LACUNA_BACKEND", "auto").lower()
    if configured != "auto":
        return configured
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if _codex_creds_exist():
        return "codex"
    if os.getenv("ANTHROPIC_API_KEY") or (Path.home() / ".claude" / ".credentials.json").exists():
        return "anthropic"
    return "openai"  # will fail with helpful error


BACKEND = _detect_backend()
MODEL = _MODEL_FOR_BACKEND.get(BACKEND, OPENAI_MODEL)

# ── Cost tracking ────────────────────────────────────────────────
# Prices per million tokens (USD)
MODEL_PRICING = {
    # OpenAI (applies to both API and Codex OAuth — Codex uses subscription credits)
    'gpt-4.1':      {'input': 2.00, 'output': 8.00,  'cached_input': 0.50},
    'gpt-4.1-mini': {'input': 0.40, 'output': 1.60,  'cached_input': 0.10},
    'gpt-4.1-nano': {'input': 0.10, 'output': 0.40,  'cached_input': 0.025},
    'gpt-4o':       {'input': 2.50, 'output': 10.00, 'cached_input': 1.25},
    'gpt-4o-mini':  {'input': 0.15, 'output': 0.60,  'cached_input': 0.075},
    'o4-mini':      {'input': 1.10, 'output': 4.40,  'cached_input': 0.275},
    'o3-mini':      {'input': 1.10, 'output': 4.40,  'cached_input': 0.275},
    # Anthropic
    'claude-opus-4':   {'input': 15.00, 'output': 75.00, 'cached_input': 1.875},
    'claude-sonnet-4': {'input': 3.00,  'output': 15.00, 'cached_input': 0.375},
    'claude-haiku-4':  {'input': 0.80,  'output': 4.00,  'cached_input': 0.10},
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int,
                  cached_tokens: int = 0) -> float:
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


# ── Active backend tracking ──────────────────────────────────────
_active_backend = BACKEND
_codex_auth = None       # CodexAuth instance (lazy)
_anthropic_client = None  # Anthropic client (lazy)

_FALLBACK_ORDER = {
    "openai": ["codex", "anthropic"],
    "codex": ["anthropic", "openai"],
    "anthropic": ["openai", "codex"],
}


def get_active_model() -> str:
    return _MODEL_FOR_BACKEND.get(_active_backend, OPENAI_MODEL)


def get_active_backend() -> str:
    return _active_backend


# ── Client creation ──────────────────────────────────────────────

def get_client():
    """Create primary API client. Returns None for codex (uses httpx internally)."""
    global _codex_auth
    if BACKEND == "openai":
        from openai import AsyncOpenAI
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set. Add it to .env")
        return AsyncOpenAI(api_key=api_key)
    elif BACKEND == "codex":
        _codex_auth = CodexAuth()
        return None  # codex uses httpx directly
    else:
        return _get_anthropic_client()


def _get_anthropic_client():
    import anthropic
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        return anthropic.AsyncAnthropic(api_key=api_key)
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


# ── Main chat completion with auto-fallback ──────────────────────

async def chat_completion(client, messages: list, tools: list | None = None):
    """Call the LLM with retry logic and auto-fallback.

    Returns a response object with OpenAI-compatible structure regardless
    of which backend actually served the request.
    """
    global _active_backend

    try:
        return await _dispatch(_active_backend, client, messages, tools)
    except Exception as e:
        if not FALLBACK_ENABLED or not _is_switchable_error(e):
            raise
        # Try fallback backends in order
        for fallback in _FALLBACK_ORDER.get(_active_backend, []):
            try:
                _active_backend = fallback
                return await _dispatch(fallback, client, messages, tools)
            except Exception:
                continue
        raise  # all fallbacks failed


async def _dispatch(backend: str, client, messages, tools):
    global _codex_auth, _anthropic_client
    if backend == "openai":
        if client is None:
            from openai import AsyncOpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("No OpenAI API key for fallback")
            client = AsyncOpenAI(api_key=api_key)
        return await _openai_completion(client, messages, tools)
    elif backend == "codex":
        if not _codex_auth:
            _codex_auth = CodexAuth()
        return await _codex_completion(messages, tools)
    else:
        if not _anthropic_client:
            _anthropic_client = _get_anthropic_client()
        return await _anthropic_completion(_anthropic_client, messages, tools)


def _is_switchable_error(e: Exception) -> bool:
    msg = str(e).lower()
    return any(x in msg for x in (
        'insufficient_quota', 'billing', 'rate_limit',
        '429', 'quota', 'exceeded',
        'no codex credentials', 'no anthropic credentials',
        'no openai api key',
    ))


# ═════════════════════════════════════════════════════════════════
#  OpenAI Chat Completions backend
# ═════════════════════════════════════════════════════════════════

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
                raise
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_DELAYS[attempt])
    raise last_error


# ═════════════════════════════════════════════════════════════════
#  Codex OAuth backend (ChatGPT Responses API)
# ═════════════════════════════════════════════════════════════════

CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
CODEX_AUTH_URL = "https://auth.openai.com/oauth/token"
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"


class CodexAuth:
    """Manages Codex OAuth token lifecycle — read, refresh, save."""

    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.expires_at = 0
        self.account_id = None
        self._auth_path = None
        self._load_tokens()

    def _load_tokens(self):
        candidates = []
        codex_home = os.getenv("CODEX_HOME", "")
        if codex_home:
            candidates.append(Path(codex_home) / "auth.json")
        candidates.extend([
            Path.home() / ".codex" / "auth.json",
            Path.home() / ".chatgpt-local" / "auth.json",
        ])

        for p in candidates:
            if p.exists():
                try:
                    data = json.loads(p.read_text())
                    tokens = data.get("tokens", data)  # handle legacy flat format
                    self.access_token = tokens.get("access_token")
                    self.refresh_token = tokens.get("refresh_token")
                    self.id_token = tokens.get("id_token")
                    self.expires_at = tokens.get("expires_at", 0)
                    # expires_at might be in milliseconds
                    if self.expires_at > 1e12:
                        self.expires_at = self.expires_at / 1000
                    self.account_id = self._extract_account_id()
                    self._auth_path = p
                    return
                except (json.JSONDecodeError, KeyError):
                    continue

        raise ValueError(
            "No Codex credentials found. Run 'codex' to authenticate.\n"
            "Expected: ~/.codex/auth.json"
        )

    def _extract_account_id(self) -> str | None:
        """Decode chatgpt_account_id from the JWT id_token (or access_token)."""
        token = self.id_token or self.access_token
        if not token:
            return None
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            return claims.get("https://api.openai.com/auth", {}).get("chatgpt_account_id")
        except Exception:
            return None

    async def ensure_valid_token(self):
        """Refresh the token if it's expired or within 5 min of expiry."""
        if self.access_token and time.time() < self.expires_at - 300:
            return
        await self._refresh()

    async def _refresh(self):
        if not self.refresh_token:
            raise ValueError("No Codex refresh token. Re-authenticate: run 'codex'")
        import httpx
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                CODEX_AUTH_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                    "client_id": CODEX_CLIENT_ID,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                raise ValueError(
                    f"Codex token refresh failed ({resp.status_code}). "
                    "Re-authenticate: run 'codex'"
                )
            data = resp.json()

        self.access_token = data["access_token"]
        if "refresh_token" in data:
            self.refresh_token = data["refresh_token"]
        self.expires_at = time.time() + data.get("expires_in", 3600)
        if "id_token" in data:
            self.id_token = data["id_token"]
            self.account_id = self._extract_account_id()
        self._save_tokens()

    def _save_tokens(self):
        """Persist refreshed tokens back to auth.json."""
        if not self._auth_path or not self._auth_path.exists():
            return
        try:
            data = json.loads(self._auth_path.read_text())
            tokens = data.get("tokens", data)
            tokens["access_token"] = self.access_token
            tokens["refresh_token"] = self.refresh_token
            if self.id_token:
                tokens["id_token"] = self.id_token
            tokens["expires_at"] = int(self.expires_at)
            self._auth_path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass  # non-critical

    def get_headers(self) -> dict:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "accept": "application/json",
            "OpenAI-Beta": "responses=experimental",
            "originator": "codex_cli_rs",
        }
        if self.account_id:
            headers["chatgpt-account-id"] = self.account_id
        return headers


async def _codex_completion(messages: list, tools: list | None):
    """Call Codex endpoint, translating Chat Completions ↔ Responses API."""
    await _codex_auth.ensure_valid_token()

    system, input_items = _translate_messages_for_codex(messages)

    body = {
        "model": CODEX_MODEL,
        "instructions": system or "You are a helpful assistant.",
        "input": input_items,
        "store": False,
        "stream": False,
    }
    if tools:
        body["tools"] = _translate_tools_for_codex(tools)
        body["tool_choice"] = "auto"

    import httpx
    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{CODEX_BASE_URL}/responses",
                    headers=_codex_auth.get_headers(),
                    json=body,
                )
                if resp.status_code == 401:
                    await _codex_auth._refresh()
                    continue
                if resp.status_code == 429:
                    raise Exception("429 rate_limit: Codex rate limit exceeded")
                resp.raise_for_status()
                data = resp.json()
            return _wrap_codex_response(data)
        except Exception as e:
            last_error = e
            if _is_switchable_error(e):
                raise
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_DELAYS[attempt])
    raise last_error


# ── Codex format translation ────────────────────────────────────

def _translate_messages_for_codex(messages: list) -> tuple[str, list]:
    """Chat Completions messages → Responses API input items."""
    system = ""
    items = []

    for msg in messages:
        role = msg.get("role", "")

        if role == "system":
            system = msg.get("content", "")

        elif role == "user":
            items.append({"role": "user", "content": msg.get("content", "")})

        elif role == "assistant":
            text = msg.get("content") or ""
            if text:
                items.append({
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text}],
                })
            for tc in msg.get("tool_calls", []):
                items.append({
                    "type": "function_call",
                    "call_id": tc["id"],
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                })

        elif role == "tool":
            items.append({
                "type": "function_call_output",
                "call_id": msg.get("tool_call_id", ""),
                "output": msg.get("content", ""),
            })

    return system, items


def _translate_tools_for_codex(tools: list) -> list:
    """Chat Completions tools → Responses API tools (flatter nesting)."""
    return [
        {
            "type": "function",
            "name": t["function"]["name"],
            "description": t["function"]["description"],
            "parameters": t["function"]["parameters"],
        }
        for t in tools
    ]


def _wrap_codex_response(data: dict):
    """Wrap Responses API response in Chat Completions-compatible adapter."""
    text_parts = []
    tool_calls = []

    for item in data.get("output", []):
        item_type = item.get("type", "")

        if item_type == "message":
            for block in item.get("content", []):
                if block.get("type") == "output_text":
                    text_parts.append(block.get("text", ""))

        elif item_type == "function_call":
            tc_id = item.get("call_id") or item.get("id", "")
            tool_calls.append(_ToolCall(
                tc_id=tc_id,
                function=_ToolCallFunction(
                    name=item.get("name", ""),
                    arguments=item.get("arguments", "{}"),
                ),
            ))

    content = "\n".join(text_parts) if text_parts else None
    message = _Message(content=content, tool_calls=tool_calls or None)
    choice = _Choice(message=message, finish_reason=data.get("status", "completed"))

    usage_data = data.get("usage", {})
    cached = 0
    details = usage_data.get("input_tokens_details")
    if details:
        cached = details.get("cached_tokens", 0)
    usage = _Usage(
        prompt=usage_data.get("input_tokens", 0),
        completion=usage_data.get("output_tokens", 0),
        cached=cached,
    )
    return _Response(choices=[choice], usage=usage)


# ═════════════════════════════════════════════════════════════════
#  Anthropic backend
# ═════════════════════════════════════════════════════════════════

async def _anthropic_completion(client, messages: list, tools: list | None):
    system, translated_msgs = _translate_messages_for_anthropic(messages)
    anthropic_tools = _translate_tools_for_anthropic(tools) if tools else None

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


# ── Anthropic format translation ────────────────────────────────

def _translate_messages_for_anthropic(messages: list) -> tuple[str, list]:
    """OpenAI messages → Anthropic format with alternation enforcement."""
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
            if result and result[-1]['role'] == 'user' and isinstance(result[-1]['content'], list):
                result[-1]['content'].append(tool_result)
            else:
                result.append({"role": "user", "content": [tool_result]})
            continue

        result.append({"role": "user", "content": msg.get('content', '')})

    # Merge consecutive same-role messages (Anthropic requires alternation)
    merged = []
    for msg in result:
        if merged and merged[-1]['role'] == msg['role']:
            prev = merged[-1]['content']
            curr = msg['content']
            if isinstance(prev, str):
                prev = [{"type": "text", "text": prev}]
            if isinstance(curr, str):
                curr = [{"type": "text", "text": curr}]
            merged[-1]['content'] = prev + curr
        else:
            merged.append(msg)

    return system, merged


def _translate_tools_for_anthropic(tools: list) -> list:
    return [
        {
            "name": t['function']['name'],
            "description": t['function']['description'],
            "input_schema": t['function']['parameters'],
        }
        for t in tools
    ]


def _wrap_anthropic_response(response) -> '_Response':
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

    cached = getattr(response.usage, 'cache_read_input_tokens', 0) or 0
    usage = _Usage(
        prompt=response.usage.input_tokens,
        completion=response.usage.output_tokens,
        cached=cached,
    )
    return _Response(choices=[choice], usage=usage)


# ═════════════════════════════════════════════════════════════════
#  Shared response adapter classes (OpenAI-compatible structure)
# ═════════════════════════════════════════════════════════════════

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


# ═════════════════════════════════════════════════════════════════
#  Usage extraction (works for all backends)
# ═════════════════════════════════════════════════════════════════

def extract_usage(response) -> dict:
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
