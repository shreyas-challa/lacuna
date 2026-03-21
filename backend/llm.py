"""LLM client — OpenAI API with cost tracking.

Token optimization strategy:
  - OpenAI prompt caching: static instruction prefix gets cached at 50% off
  - Model selection: gpt-4.1-mini by default (5x cheaper than gpt-4.1)
  - Cost tracking: every call logs estimated spend so you know your burn rate
"""

import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ────────────────────────────────────────────────
MODEL = os.getenv("LACUNA_MODEL", "gpt-4.1-mini")

MAX_RETRIES = 3
RETRY_DELAYS = [2, 5, 15]

# ── Cost tracking ────────────────────────────────────────────────
# Prices per million tokens (USD, as of early 2025)
MODEL_PRICING = {
    'gpt-4.1':      {'input': 2.00, 'output': 8.00,  'cached_input': 0.50},
    'gpt-4.1-mini': {'input': 0.40, 'output': 1.60,  'cached_input': 0.10},
    'gpt-4.1-nano': {'input': 0.10, 'output': 0.40,  'cached_input': 0.025},
    'gpt-4o':       {'input': 2.50, 'output': 10.00, 'cached_input': 1.25},
    'gpt-4o-mini':  {'input': 0.15, 'output': 0.60,  'cached_input': 0.075},
    'o4-mini':      {'input': 1.10, 'output': 4.40,  'cached_input': 0.275},
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


# ── Client creation ──────────────────────────────────────────────

def get_client():
    """Create an OpenAI API client."""
    from openai import AsyncOpenAI
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY not set. Add it to .env\n"
            "  OPENAI_API_KEY=sk-..."
        )
    return AsyncOpenAI(api_key=api_key)


# ── Chat completion ──────────────────────────────────────────────

async def chat_completion(client, messages: list, tools: list | None = None):
    """Call the LLM with retry logic. Returns raw response object."""
    kwargs = {
        'model': MODEL,
        'messages': messages,
        'max_tokens': 4096,
    }
    if tools:
        kwargs['tools'] = tools
        kwargs['tool_choice'] = 'auto'

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            response = await client.chat.completions.create(**kwargs)
            return response
        except Exception as e:
            last_error = e
            error_str = str(e).lower()
            # Don't retry on auth or client errors
            if any(x in error_str for x in ('auth', '401', '400', 'invalid_api_key')):
                raise
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_DELAYS[attempt])

    raise last_error


def extract_usage(response) -> dict:
    """Extract token usage and cost from API response."""
    usage = getattr(response, 'usage', None)
    if not usage:
        return {'input': 0, 'output': 0, 'cached': 0, 'cost': 0.0}

    inp = getattr(usage, 'prompt_tokens', 0) or 0
    out = getattr(usage, 'completion_tokens', 0) or 0

    # OpenAI includes cached token details
    cached = 0
    details = getattr(usage, 'prompt_tokens_details', None)
    if details:
        cached = getattr(details, 'cached_tokens', 0) or 0

    cost = estimate_cost(MODEL, inp, out, cached)
    return {'input': inp, 'output': out, 'cached': cached, 'cost': cost}
