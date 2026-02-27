import os
from dotenv import load_dotenv
from openai import AsyncOpenAI

load_dotenv()

MODEL = "anthropic/claude-opus-4-5-20251101"


def get_client() -> AsyncOpenAI:
    """Create a Dedalus Labs API client (OpenAI-compatible)."""
    api_key = os.getenv("DEDALUS_API_KEY")
    if not api_key:
        raise ValueError("DEDALUS_API_KEY not set. Copy .env.example to .env and fill it in.")
    return AsyncOpenAI(
        api_key=api_key,
        base_url="https://api.dedalus-labs.com/v1",
    )


async def chat_completion(client: AsyncOpenAI, messages: list, tools: list | None = None) -> dict:
    """Call the LLM and return the raw response."""
    kwargs = {
        'model': MODEL,
        'messages': messages,
        'max_tokens': 4096,
    }
    if tools:
        kwargs['tools'] = tools
        kwargs['tool_choice'] = 'auto'

    response = await client.chat.completions.create(**kwargs)
    return response
