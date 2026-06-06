import asyncio
import inspect
import re
from typing import Callable

# Global tool registry: name -> {function, schema, phases}
TOOL_REGISTRY: dict[str, dict] = {}

OUTPUT_CAP = 8 * 1024  # 8KB max output
TIMEOUT = 120  # seconds


def tool(name: str, description: str, parameters: dict, phases: list[str]):
    """Decorator to register a tool function."""
    def decorator(func: Callable):
        TOOL_REGISTRY[name] = {
            'function': func,
            'description': description,
            'parameters': parameters,
            'phases': phases,
        }
        return func
    return decorator


def validate_tool_registry() -> list[str]:
    """Catch registration bugs where @tool decorated the wrong function (e.g. a
    helper inserted between the decorator and the intended function). Returns a
    list of human-readable problems; empty means healthy."""
    problems = []
    for name, info in TOOL_REGISTRY.items():
        fn = info['function']
        try:
            params = set(inspect.signature(fn).parameters)
        except (TypeError, ValueError):
            problems.append(f"{name}: cannot inspect registered function signature")
            continue
        props = set((info.get('parameters') or {}).get('properties', {}).keys())
        # A correctly-registered tool's function must accept at least one of the
        # parameters its JSON schema advertises. Zero overlap = wrong function.
        if props and not (props & params):
            problems.append(
                f"{name}: registered function '{getattr(fn, '__name__', '?')}' takes {sorted(params)} "
                f"but the schema declares {sorted(props)} — decorator is attached to the wrong function."
            )
    return problems


def get_tools_for_phase(phase: str) -> list[dict]:
    """Get OpenAI-format tool schemas available for a given phase."""
    phase_order = ['enumeration', 'exploitation', 'privesc']
    current_idx = phase_order.index(phase) if phase in phase_order else 0
    available_phases = phase_order[:current_idx + 1]

    tools = []
    for name, info in TOOL_REGISTRY.items():
        if any(p in available_phases for p in info['phases']):
            tools.append({
                'type': 'function',
                'function': {
                    'name': name,
                    'description': info['description'],
                    'parameters': info['parameters'],
                }
            })
    return tools


async def run_command(cmd: str, timeout: int = TIMEOUT) -> str:
    """Execute a shell command, capturing output incrementally so that PARTIAL
    output is preserved on timeout. Long streaming tools (gobuster/ffuf/nmap)
    often print useful hits before they finish — losing that on timeout is the
    'it found things but timed out with nothing' failure. We keep what was
    printed and append a clear timeout marker."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as e:
        return f"[ERROR] {str(e)}"

    buf = bytearray()
    timed_out = False

    async def _drain():
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > OUTPUT_CAP * 4:  # captured plenty; stop reading
                break

    try:
        await asyncio.wait_for(_drain(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
    except Exception as e:
        if not buf:
            return f"[ERROR] {str(e)}"
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass

    output = bytes(buf).decode('utf-8', errors='replace')

    if len(output) > OUTPUT_CAP:
        # For HTML output, extract key links from the FULL output before truncating
        suffix = f"\n\n[TRUNCATED at {OUTPUT_CAP} bytes]"
        if '<html' in output[:500].lower() or '<head' in output[:500].lower():
            links = set()
            for m in re.finditer(r'href=["\']([^"\']+)["\']', output, re.IGNORECASE):
                href = m.group(1)
                if href and href != '#' and not href.startswith(('javascript:', 'mailto:')):
                    links.add(href)
            if links:
                sorted_links = sorted(links)[:30]
                suffix = f"\n\n[TRUNCATED at {OUTPUT_CAP} bytes — all href links: {', '.join(sorted_links)}]"
        output = output[:OUTPUT_CAP] + suffix

    if timed_out:
        marker = (f"\n\n[TIMEOUT after {timeout}s — partial output above; the command was still "
                  f"running. Act on any results already shown; otherwise narrow the scope and retry.]")
        output = (output + marker) if output.strip() else f"[TIMEOUT after {timeout}s — no output produced yet]"

    return output
