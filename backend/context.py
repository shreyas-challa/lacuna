"""Context manager — keeps the LLM conversation window focused and bounded.

The problem: after 20+ iterations with large tool outputs, the message history
grows to 100k+ tokens. The model loses track of early findings and API costs
explode.

Solution: keep full detail for recent iterations, compress old iterations to
one-line summaries. The StateManager already holds all actionable data, so
old tool output just needs a short "what happened" note.
"""

from __future__ import annotations

# Max tool result characters to keep in recent messages
RESULT_CAP = 8000
# How many recent message exchanges to keep at full detail
RECENT_WINDOW = 20


def compress_tool_result(result: str) -> str:
    """Shorten a tool result to its essential information."""
    lines = result.split('\n')
    if len(result) <= 600:
        return result

    # For very long outputs, keep first and last portions
    kept = []
    kept.extend(lines[:15])
    if len(lines) > 30:
        kept.append(f"\n[... {len(lines) - 30} lines omitted ...]")
        kept.extend(lines[-15:])
    return '\n'.join(kept)[:2000]


def build_messages(
    system_prompt: str,
    full_history: list[dict],
) -> list[dict]:
    """Build the message list for an LLM call.

    Strategy:
    - System prompt is always fresh (rebuilt each iteration with current state).
    - Keep the initial user message (the engagement start).
    - For old iterations (beyond RECENT_WINDOW): compress tool results.
    - For recent iterations: keep full detail.
    """
    messages = [{'role': 'system', 'content': system_prompt}]

    if not full_history:
        return messages

    # Always keep the first user message intact
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

    # Compress old messages
    if old:
        compressed = _compress_old_messages(old)
        messages.extend(compressed)

    # Keep recent messages at full detail (but cap individual results)
    for msg in recent:
        if msg.get('role') == 'tool' and len(msg.get('content', '')) > RESULT_CAP:
            msg = dict(msg)
            msg['content'] = msg['content'][:RESULT_CAP] + f"\n[TRUNCATED — full output was {len(msg['content'])} chars]"
        messages.append(msg)

    return messages


def _compress_old_messages(messages: list[dict]) -> list[dict]:
    """Compress a batch of old messages into a summary block + key assistant messages."""
    compressed = []
    i = 0
    while i < len(messages):
        msg = messages[i]

        if msg.get('role') == 'assistant':
            # Keep assistant messages but strip long content
            cmsg = dict(msg)
            if cmsg.get('content') and len(cmsg['content']) > 300:
                cmsg['content'] = cmsg['content'][:300] + '...'
            compressed.append(cmsg)
        elif msg.get('role') == 'tool':
            # Compress tool results heavily
            cmsg = dict(msg)
            cmsg['content'] = compress_tool_result(msg.get('content', ''))
            compressed.append(cmsg)
        elif msg.get('role') == 'user':
            # Keep user/system injections (nudges, etc.)
            cmsg = dict(msg)
            if len(cmsg.get('content', '')) > 500:
                cmsg['content'] = cmsg['content'][:500] + '...'
            compressed.append(cmsg)
        else:
            compressed.append(msg)
        i += 1

    return compressed
