import asyncio
from typing import Callable

# Global tool registry: name -> {function, schema, phases}
TOOL_REGISTRY: dict[str, dict] = {}

OUTPUT_CAP = 15 * 1024  # 15KB max output
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


def get_tools_for_phase(phase: str) -> list[dict]:
    """Get OpenAI-format tool schemas available for a given phase."""
    phase_order = ['enumeration', 'vuln_analysis', 'exploitation', 'privesc']
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
    """Execute a shell command string with timeout and output cap."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"[TIMEOUT after {timeout}s]"

        output = stdout.decode('utf-8', errors='replace')
        if len(output) > OUTPUT_CAP:
            output = output[:OUTPUT_CAP] + f"\n\n[OUTPUT TRUNCATED at {OUTPUT_CAP} bytes]"
        return output
    except Exception as e:
        return f"[ERROR] {str(e)}"
