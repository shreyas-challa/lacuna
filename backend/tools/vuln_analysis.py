from backend.tools.base import tool, run_command


@tool(
    name='nuclei_scan',
    description='Run nuclei vulnerability scanner against a target.',
    parameters={
        'type': 'object',
        'properties': {
            'target': {'type': 'string', 'description': 'Target URL or IP'},
            'flags': {'type': 'string', 'description': 'Additional nuclei flags (e.g. "-severity critical,high")', 'default': ''},
        },
        'required': ['target'],
    },
    phases=['enumeration'],
)
async def nuclei_scan(target: str, flags: str = '') -> str:
    return await run_command(f'nuclei -u {target} -nc {flags}', timeout=300)


@tool(
    name='searchsploit',
    description='Search Exploit-DB for known exploits matching a query.',
    parameters={
        'type': 'object',
        'properties': {
            'query': {'type': 'string', 'description': 'Search query (e.g. "Apache 2.4.49")'},
        },
        'required': ['query'],
    },
    phases=['enumeration'],
)
async def searchsploit(query: str) -> str:
    return await run_command(f'searchsploit {query}')


@tool(
    name='nikto_scan',
    description='Run nikto web server scanner.',
    parameters={
        'type': 'object',
        'properties': {
            'target': {'type': 'string', 'description': 'Target URL or host'},
            'flags': {'type': 'string', 'description': 'Additional nikto flags', 'default': ''},
        },
        'required': ['target'],
    },
    phases=['enumeration'],
)
async def nikto_scan(target: str, flags: str = '') -> str:
    return await run_command(f'nikto -h {target} {flags}', timeout=300)
