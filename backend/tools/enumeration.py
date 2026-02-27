from backend.tools.base import tool, run_command


@tool(
    name='nmap_scan',
    description='Run an nmap scan against a target. Supports custom flags.',
    parameters={
        'type': 'object',
        'properties': {
            'target': {'type': 'string', 'description': 'Target IP or hostname'},
            'flags': {'type': 'string', 'description': 'Additional nmap flags (e.g. "-sV -sC -p-")', 'default': '-sV -sC'},
        },
        'required': ['target'],
    },
    phases=['enumeration'],
)
async def nmap_scan(target: str, flags: str = '-sV -sC') -> str:
    cmd = ['nmap'] + flags.split() + [target]
    return await run_command(cmd, timeout=300)


@tool(
    name='gobuster_dir',
    description='Run gobuster directory brute-force against a target URL.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL (e.g. http://10.10.10.1)'},
            'wordlist': {'type': 'string', 'description': 'Wordlist path', 'default': '/usr/share/wordlists/dirb/common.txt'},
            'flags': {'type': 'string', 'description': 'Additional gobuster flags', 'default': ''},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def gobuster_dir(url: str, wordlist: str = '/usr/share/wordlists/dirb/common.txt', flags: str = '') -> str:
    cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist]
    if flags:
        cmd += flags.split()
    return await run_command(cmd, timeout=300)


@tool(
    name='ffuf_fuzz',
    description='Run ffuf for web fuzzing (directories, parameters, vhosts).',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL with FUZZ keyword (e.g. http://10.10.10.1/FUZZ)'},
            'wordlist': {'type': 'string', 'description': 'Wordlist path', 'default': '/usr/share/wordlists/dirb/common.txt'},
            'flags': {'type': 'string', 'description': 'Additional ffuf flags', 'default': ''},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def ffuf_fuzz(url: str, wordlist: str = '/usr/share/wordlists/dirb/common.txt', flags: str = '') -> str:
    cmd = ['ffuf', '-u', url, '-w', wordlist, '-c']
    if flags:
        cmd += flags.split()
    return await run_command(cmd, timeout=300)


@tool(
    name='whatweb_scan',
    description='Run whatweb to identify technologies on a target.',
    parameters={
        'type': 'object',
        'properties': {
            'target': {'type': 'string', 'description': 'Target URL or IP'},
        },
        'required': ['target'],
    },
    phases=['enumeration'],
)
async def whatweb_scan(target: str) -> str:
    return await run_command(['whatweb', '-a', '3', target])


@tool(
    name='curl_request',
    description='Make an HTTP request using curl.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL'},
            'flags': {'type': 'string', 'description': 'Additional curl flags (e.g. "-I" for headers only)', 'default': '-s'},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def curl_request(url: str, flags: str = '-s') -> str:
    cmd = ['curl'] + flags.split() + [url]
    return await run_command(cmd, timeout=30)
