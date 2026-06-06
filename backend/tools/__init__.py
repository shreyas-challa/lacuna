from backend.tools.base import TOOL_REGISTRY, get_tools_for_phase, validate_tool_registry
from backend.tools.enumeration import *
from backend.tools.vuln_analysis import *
from backend.tools.exploitation import *
from backend.tools.privesc import *
from backend.tools.web import *
from backend.tools.web_session import *

# Fail loud at import if any @tool decorator is attached to the wrong function.
_registry_problems = validate_tool_registry()
if _registry_problems:
    raise RuntimeError(
        "Tool registry validation failed:\n  " + "\n  ".join(_registry_problems)
    )
