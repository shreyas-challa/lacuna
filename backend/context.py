"""Context manager — iteration-aware token optimization.

Every token in the conversation history is re-sent with every LLM call.
With 30+ calls, a 1KB tool result costs 30KB of input tokens total.
Compression is the single biggest lever for reducing spend.

Strategy:
  - Group messages by iteration (assistant + tool calls + results)
  - Keep last 4-5 complete iterations at full detail (capped at 4KB per result)
  - Old iterations: compress tool results to 400 chars
  - The StateManager holds all actionable data, so old tool output is reference only
  - First user message always kept (engagement start)
  - Final pass ensures tool results follow their tool calls (MiniMax strict ordering)
"""

from __future__ import annotations
import re

# Max chars for tool results in recent messages
RESULT_CAP = 4000
# How many recent iterations to keep at full detail
RECENT_ITERATIONS = 5
# Max chars for tool results in compressed old messages
OLD_RESULT_CAP = 400


def build_messages(
    system_prompt: str,
    full_history: list[dict],
    current_iteration: int = 0,
) -> list[dict]:
    """Build the message list for an LLM call.

    Uses iteration tags on messages to keep complete iterations together,
    falling back to a flat window if no iteration tags are present.
    """
    messages = [{'role': 'system', 'content': system_prompt}]

    if not full_history:
        return messages

    # Always keep the first user message (engagement start)
    messages.append(full_history[0])

    remaining = full_history[1:]
    if not remaining:
        return messages

    # Check if messages have iteration tags
    has_iterations = any(msg.get('_iteration') for msg in remaining)

    if has_iterations and current_iteration > 0:
        # Iteration-aware windowing
        cutoff_iteration = max(0, current_iteration - RECENT_ITERATIONS)

        old_msgs = []
        recent_msgs = []

        for msg in remaining:
            msg_iter = msg.get('_iteration', 0)
            if msg_iter and msg_iter > cutoff_iteration:
                recent_msgs.append(msg)
            else:
                old_msgs.append(msg)

        # Compress old messages
        if old_msgs:
            messages.extend(_compress_old(old_msgs))

        # Keep recent messages with moderate caps
        for msg in recent_msgs:
            messages.append(_cap_recent(msg))
    else:
        # Fallback: flat window (12 messages)
        RECENT_WINDOW = 12
        if len(remaining) > RECENT_WINDOW:
            old = remaining[:-RECENT_WINDOW]
            recent = remaining[-RECENT_WINDOW:]
        else:
            old = []
            recent = remaining

        if old:
            messages.extend(_compress_old(old))

        for msg in recent:
            messages.append(_cap_recent(msg))

    return _enforce_tool_call_ordering(messages)


def _enforce_tool_call_ordering(messages: list[dict]) -> list[dict]:
    """Ensure tool result messages directly follow their assistant+tool_calls message.

    Some LLM backends (MiniMax) require strict ordering: after an assistant message
    with tool_calls, the next messages MUST be the corresponding tool results.
    System nudges (role=user) injected between tool_calls and results will cause
    a 400 error. This function reorders to fix that.
    """
    result = []
    i = 0
    while i < len(messages):
        msg = messages[i]

        # If this is an assistant message with tool_calls, collect its tool results
        if (msg.get('role') == 'assistant' and msg.get('tool_calls')):
            result.append(msg)
            i += 1

            # Gather the expected tool_call IDs
            expected_ids = {tc['id'] for tc in msg['tool_calls']}
            collected_tool_results = []
            deferred_others = []

            # Scan forward to find all matching tool results, deferring non-tool messages
            while i < len(messages) and expected_ids:
                next_msg = messages[i]
                if next_msg.get('role') == 'tool' and next_msg.get('tool_call_id') in expected_ids:
                    collected_tool_results.append(next_msg)
                    expected_ids.discard(next_msg['tool_call_id'])
                    i += 1
                elif next_msg.get('role') == 'user':
                    # User/system nudge injected mid-stream — defer it
                    deferred_others.append(next_msg)
                    i += 1
                else:
                    # Different assistant msg or unrelated tool — stop scanning
                    break

            # Emit tool results first (strict ordering), then deferred messages
            result.extend(collected_tool_results)
            result.extend(deferred_others)
        else:
            result.append(msg)
            i += 1

    return result


def _cap_recent(msg: dict) -> dict:
    """Cap tool results in recent messages."""
    if msg.get('role') == 'tool':
        content = msg.get('content', '')
        if len(content) > RESULT_CAP:
            # Strip internal iteration tag before sending to LLM
            capped = dict(msg)
            capped['content'] = content[:RESULT_CAP] + f"\n[... truncated from {len(content)} chars]"
            capped.pop('_iteration', None)
            return capped
    # Strip iteration tag
    clean = dict(msg)
    clean.pop('_iteration', None)
    return clean


def _extract_key_refs(content: str) -> str:
    """Extract HTML asset references to preserve during compression."""
    refs = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE):
        refs.append(f'script:{m.group(1)}')
    for m in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', content, re.IGNORECASE):
        if m.group(1) and m.group(1) != '#':
            refs.append(f'form:{m.group(1)}')
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.(?:css|js))["\']', content, re.IGNORECASE):
        refs.append(f'link:{m.group(1)}')
    if refs:
        return '[refs: ' + ', '.join(refs[:10]) + ']'
    return ''


def _compress_old(messages: list[dict]) -> list[dict]:
    """Compress old messages. Tool results get truncated heavily.
    Assistant messages keep tool_calls but lose verbose thinking."""
    compressed = []
    for msg in messages:
        role = msg.get('role', '')
        cmsg = dict(msg)
        cmsg.pop('_iteration', None)  # Strip iteration tag

        if role == 'tool':
            content = cmsg.get('content', '')
            if len(content) > OLD_RESULT_CAP:
                # Preserve HTML asset references before truncating
                preserved = _extract_key_refs(content)
                if preserved:
                    remaining_budget = max(100, OLD_RESULT_CAP - len(preserved) - 20)
                    cmsg['content'] = f"{preserved}\n{content[:remaining_budget]}\n[... {len(content)} chars total]"
                else:
                    cmsg['content'] = content[:OLD_RESULT_CAP] + f"\n[... {len(content)} chars total]"
            compressed.append(cmsg)

        elif role == 'assistant':
            if cmsg.get('content') and len(cmsg['content']) > 200:
                cmsg['content'] = cmsg['content'][:200] + '...'
            compressed.append(cmsg)

        elif role == 'user':
            if len(cmsg.get('content', '')) > 300:
                cmsg['content'] = cmsg['content'][:300] + '...'
            compressed.append(cmsg)

        else:
            compressed.append(cmsg)

    return compressed
