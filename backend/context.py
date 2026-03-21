"""Context manager — aggressive token optimization.

Every token in the conversation history is re-sent with every LLM call.
With 30+ calls, a 1KB tool result costs 30KB of input tokens total.
Compression is the single biggest lever for reducing spend.

Strategy:
  - Recent iterations (last 12 messages): keep full detail but cap results at 4KB
  - Old iterations: compress tool results to 400 chars (just enough to recall what happened)
  - The StateManager holds all actionable data, so old tool output is reference only
  - First user message always kept (engagement start)
"""

from __future__ import annotations

# Max chars for tool results in recent messages
RESULT_CAP = 4000
# How many recent messages to keep at full detail
RECENT_WINDOW = 12
# Max chars for tool results in compressed old messages
OLD_RESULT_CAP = 400


def build_messages(
    system_prompt: str,
    full_history: list[dict],
) -> list[dict]:
    """Build the message list for an LLM call.

    The system prompt is rebuilt fresh each iteration with current state,
    so the model always has accurate context even with compressed history.
    """
    messages = [{'role': 'system', 'content': system_prompt}]

    if not full_history:
        return messages

    # Always keep the first user message (engagement start)
    messages.append(full_history[0])

    remaining = full_history[1:]
    if not remaining:
        return messages

    # Split into old and recent
    if len(remaining) > RECENT_WINDOW:
        old = remaining[:-RECENT_WINDOW]
        recent = remaining[-RECENT_WINDOW:]
    else:
        old = []
        recent = remaining

    # Compress old messages aggressively
    if old:
        messages.extend(_compress_old(old))

    # Keep recent messages with moderate caps
    for msg in recent:
        if msg.get('role') == 'tool':
            content = msg.get('content', '')
            if len(content) > RESULT_CAP:
                msg = dict(msg)
                msg['content'] = content[:RESULT_CAP] + f"\n[... truncated from {len(content)} chars]"
        messages.append(msg)

    return messages


def _compress_old(messages: list[dict]) -> list[dict]:
    """Compress old messages. Tool results get truncated heavily.
    Assistant messages keep tool_calls but lose verbose thinking."""
    compressed = []
    for msg in messages:
        role = msg.get('role', '')

        if role == 'tool':
            content = msg.get('content', '')
            if len(content) > OLD_RESULT_CAP:
                # Keep just the beginning — enough to recall what this was
                short = content[:OLD_RESULT_CAP] + f"\n[... {len(content)} chars total]"
                compressed.append({**msg, 'content': short})
            else:
                compressed.append(msg)

        elif role == 'assistant':
            cmsg = dict(msg)
            # Truncate verbose thinking
            if cmsg.get('content') and len(cmsg['content']) > 200:
                cmsg['content'] = cmsg['content'][:200] + '...'
            compressed.append(cmsg)

        elif role == 'user':
            # System nudges etc — keep but trim
            cmsg = dict(msg)
            if len(cmsg.get('content', '')) > 300:
                cmsg['content'] = cmsg['content'][:300] + '...'
            compressed.append(cmsg)

        else:
            compressed.append(msg)

    return compressed
