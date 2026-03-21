import os
from backend.tools.base import tool, run_command

WORDLIST = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'common.txt')


@tool(
    name='nmap_scan',
    description='Run an nmap scan against a target. Supports custom flags.',
    parameters={
        'type': 'object',
        'properties': {
            'target': {'type': 'string', 'description': 'Target IP or hostname'},
            'flags': {'type': 'string', 'description': 'Additional nmap flags (e.g. "-sV -sC -T4 -p-")', 'default': '-sV -sC'},
        },
        'required': ['target'],
    },
    phases=['enumeration'],
)
async def nmap_scan(target: str, flags: str = '-sV -sC') -> str:
    return await run_command(f'nmap {flags} {target}', timeout=300)


@tool(
    name='gobuster_dir',
    description='Run gobuster directory brute-force against a target URL.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL (e.g. http://10.10.10.1)'},
            'wordlist': {'type': 'string', 'description': 'Wordlist path (default: bundled common.txt)', 'default': ''},
            'flags': {'type': 'string', 'description': 'Additional gobuster flags', 'default': ''},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def gobuster_dir(url: str, wordlist: str = '', flags: str = '') -> str:
    wl = _resolve_wordlist(wordlist)
    return await run_command(f'gobuster dir -u {url} -w {wl} {flags}', timeout=300)


@tool(
    name='ffuf_fuzz',
    description='Run ffuf for web fuzzing (directories, parameters, vhosts).',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL with FUZZ keyword (e.g. http://10.10.10.1/FUZZ)'},
            'wordlist': {'type': 'string', 'description': 'Wordlist path (default: bundled common.txt)', 'default': ''},
            'flags': {'type': 'string', 'description': 'Additional ffuf flags', 'default': ''},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def ffuf_fuzz(url: str, wordlist: str = '', flags: str = '') -> str:
    wl = _resolve_wordlist(wordlist)
    return await run_command(f'ffuf -u {url} -w {wl} -c {flags}', timeout=300)


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
    return await run_command(f'whatweb -a 3 {target}')


@tool(
    name='curl_request',
    description='Make an HTTP request using curl. For downloading files use "-o /tmp/filename" in flags.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL'},
            'flags': {'type': 'string', 'description': 'Additional curl flags (e.g. "-I" for headers, "-o /tmp/file.pcap" to save)', 'default': '-s'},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def curl_request(url: str, flags: str = '-s') -> str:
    return await run_command(f'curl {flags} {url}', timeout=120)


@tool(
    name='download_and_analyze',
    description='Download a file and analyze its contents. Supports pcap files (analyzed with tshark), text files, and binary files (analyzed with strings). Use this to examine pcap captures, config files, etc.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'URL to download the file from'},
            'filename': {'type': 'string', 'description': 'Filename to save as (e.g. "capture.pcap", "config.txt")'},
        },
        'required': ['url', 'filename'],
    },
    phases=['enumeration'],
)
async def download_and_analyze(url: str, filename: str) -> str:
    filepath = f'/tmp/{filename}'
    # Download
    dl_result = await run_command(f'curl -s -o {filepath} -w "%{{http_code}}" {url}', timeout=120)

    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext == 'pcap' or ext == 'pcapng':
        # Targeted credential extraction — tshark -V is far too verbose and hits the output cap
        ftp_creds = await run_command(
            f'tshark -r {filepath} -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null',
            timeout=30,
        )
        http_auth = await run_command(
            f'tshark -r {filepath} -Y "http.authorization or http.request.uri" -T fields '
            f'-e http.request.method -e http.request.uri -e http.authorization 2>/dev/null',
            timeout=30,
        )
        tcp_stream = await run_command(
            f'tshark -r {filepath} -q -z follow,tcp,ascii,0 2>/dev/null | head -n 150',
            timeout=30,
        )
        cred_strings = await run_command(
            f'strings {filepath} | grep -iE "(USER|PASS|password|login|auth|username|secret)" | head -n 60',
            timeout=15,
        )
        parts = [f"Downloaded {filename} (HTTP {dl_result.strip()})"]
        if ftp_creds.strip():
            parts.append(f"=== FTP Commands ===\n{ftp_creds}")
        if http_auth.strip():
            parts.append(f"=== HTTP Auth/Requests ===\n{http_auth}")
        if tcp_stream.strip():
            parts.append(f"=== TCP Stream 0 ===\n{tcp_stream}")
        if cred_strings.strip():
            parts.append(f"=== Credential Strings ===\n{cred_strings}")
        if len(parts) == 1:
            # Nothing found via targeted queries — fall back to strings
            fallback = await run_command(f'strings {filepath} | head -n 200', timeout=30)
            parts.append(f"=== Strings (fallback) ===\n{fallback}")
        return '\n\n'.join(parts)
    elif ext in ('txt', 'conf', 'cfg', 'xml', 'json', 'html', 'php', 'py', 'sh', 'log'):
        content = await run_command(f'cat {filepath}', timeout=10)
        return f"Downloaded {filename} (HTTP {dl_result.strip()})\n\n=== File Contents ===\n{content}"
    else:
        # Binary - use strings and file
        file_info = await run_command(f'file {filepath}', timeout=10)
        strings_out = await run_command(f'strings {filepath}', timeout=30)
        return f"Downloaded {filename} (HTTP {dl_result.strip()})\n{file_info}\n=== Strings ===\n{strings_out}"


@tool(
    name='execute_command',
    description='Execute an arbitrary shell command. Use this for ad-hoc tasks like analyzing files, chaining commands, or anything the specialized tools cannot do.',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Shell command to execute'},
        },
        'required': ['command'],
    },
    phases=['enumeration'],
)
async def execute_command_enum(command: str) -> str:
    return await run_command(command)


def _resolve_wordlist(wordlist: str) -> str:
    """Resolve wordlist path, falling back to bundled common.txt."""
    if wordlist and os.path.isfile(wordlist):
        return wordlist
    # Fall back to bundled wordlist
    bundled = os.path.abspath(WORDLIST)
    if os.path.isfile(bundled):
        return bundled
    return '/usr/share/wordlists/dirb/common.txt'
