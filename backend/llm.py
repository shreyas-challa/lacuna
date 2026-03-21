import os
import asyncio
from dotenv import load_dotenv
from dedalus_labs import AsyncDedalus

load_dotenv()

MODEL = "anthropic/claude-opus-4-5-20251101"

MAX_RETRIES = 3
RETRY_DELAYS = [2, 5, 15]  # seconds between retries


def get_client() -> AsyncDedalus:
    """Create a Dedalus Labs API client."""
    api_key = os.getenv("DEDALUS_API_KEY")
    if not api_key:
        raise ValueError("DEDALUS_API_KEY not set. Copy .env.example to .env and fill it in.")
    return AsyncDedalus(api_key=api_key)


async def chat_completion(client: AsyncDedalus, messages: list, tools: list | None = None):
    """Call the LLM with automatic retry on transient failures."""
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
            # Don't retry on auth errors or invalid requests
            if 'auth' in error_str or 'invalid' in error_str or '401' in error_str or '400' in error_str:
                raise
            # Retry on rate limits, server errors, timeouts
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_DELAYS[attempt]
                await asyncio.sleep(delay)

    raise last_error
