import os
from backend.tools.base import tool, run_command
from backend.knowledge import query_knowledge_base

# ── Wordlist paths (order of preference) ──────────────────────
_WORDLIST_SEARCH_PATHS = {
    'common': [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/common.txt',
        '/usr/share/dirb/wordlists/common.txt',
    ],
    'medium': [
        '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
        '/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt',
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    ],
    'big': [
        '/usr/share/seclists/Discovery/Web-Content/big.txt',
        '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt',
    ],
    'raft': [
        '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
        '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt',
    ],
    'subdomains': [
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
    ],
}

def _find_wordlist(name: str = 'common') -> str | None:
    """Find the first existing wordlist file for a given category."""
    for path in _WORDLIST_SEARCH_PATHS.get(name, []):
        if os.path.isfile(path):
            return path
    return None

DEFAULT_WORDLIST = _find_wordlist('common') or '/usr/share/seclists/Discovery/Web-Content/common.txt'


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
    description='Run gobuster directory brute-force against a target URL. '
                'Available wordlists: "common" (4750 words, default), "medium" (220k words), '
                '"big" (227k words), "raft" (raft-medium-directories). '
                'Pass the keyword or leave empty for common.txt. Custom paths also accepted.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL (e.g. http://10.10.10.1)'},
            'wordlist': {'type': 'string', 'description': 'Wordlist: "common", "medium", "big", "raft", or full path. Default: common', 'default': ''},
            'flags': {'type': 'string', 'description': 'Additional gobuster flags', 'default': ''},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def gobuster_dir(url: str, wordlist: str = '', flags: str = '') -> str:
    wl = _resolve_wordlist(wordlist)
    # Auto-add --wildcard and --no-error to handle wildcard responses gracefully
    base_flags = '--no-error -q'
    # If user didn't specify status codes, exclude 301 redirects to avoid wildcard noise
    if '-s ' not in flags and '--status-codes' not in flags:
        base_flags += ' -b 404'
    result = await run_command(f'gobuster dir -u {url} -w {wl} {base_flags} {flags}', timeout=300)
    # Detect gobuster wildcard/error abort
    if 'the server returns a status code that matches' in result or 'Wildcard response found' in result.lower():
        return (
            f"[ERROR] Gobuster detected wildcard responses — the server returns the same status code "
            f"for non-existent URLs, making directory brute-forcing unreliable. "
            f"Try ffuf_fuzz with filter flags (e.g. -fs to filter by response size) or "
            f"use curl_request to manually probe specific paths instead."
        )
    return result


@tool(
    name='ffuf_fuzz',
    description='Run ffuf for web fuzzing (directories, parameters, vhosts). '
                'Available wordlists: "common" (4750 words, default), "medium" (220k words), '
                '"big", "raft", "subdomains". Pass keyword or full path.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL with FUZZ keyword (e.g. http://10.10.10.1/FUZZ)'},
            'wordlist': {'type': 'string', 'description': 'Wordlist: "common", "medium", "big", "raft", "subdomains", or full path. Default: common', 'default': ''},
            'flags': {'type': 'string', 'description': 'Additional ffuf flags', 'default': ''},
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def ffuf_fuzz(url: str, wordlist: str = '', flags: str = '') -> str:
    wl = _resolve_wordlist(wordlist)
    # Auto-calibrate to filter wildcard responses unless user specified filters
    auto_flags = '-c -noninteractive'
    if '-fc' not in flags and '-fs' not in flags and '-ac' not in flags:
        auto_flags += ' -ac'  # auto-calibrate: ffuf detects and filters wildcard sizes
    return await run_command(f'ffuf -u {url} -w {wl} {auto_flags} {flags}', timeout=300)


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
    # Reject hallucinated non-commands (LLM sometimes outputs text instead of a real command)
    cmd_stripped = command.strip()
    if not cmd_stripped or cmd_stripped.startswith('[') or cmd_stripped.startswith('{'):
        return "[ERROR] Invalid command — this is not a shell command. Use a real shell command or a dedicated tool."
    return await run_command(command)


@tool(
    name='query_kb',
    description='Query the built-in knowledge base for GTFOBins privesc techniques, known exploits/CVEs, default credentials, or reverse shell one-liners. Zero-cost — no subprocess or network call.',
    parameters={
        'type': 'object',
        'properties': {
            'query': {'type': 'string', 'description': 'Search query (e.g. "python3", "tomcat", "vsftpd 2.3.4", "bash reverse shell")'},
            'category': {
                'type': 'string',
                'enum': ['all', 'gtfobins', 'exploits', 'creds', 'shells'],
                'description': 'Category to search (default: all)',
                'default': 'all',
            },
        },
        'required': ['query'],
    },
    phases=['enumeration'],
)
async def query_kb(query: str, category: str = 'all') -> str:
    return query_knowledge_base(query, category)


def _resolve_wordlist(wordlist: str) -> str:
    """Resolve wordlist path with intelligent fallback.

    1. If the exact path exists, use it.
    2. If the path looks like a known category name, find the best match.
    3. If the path doesn't exist, try common SecLists locations.
    4. Fall back to the default common.txt.
    """
    # Exact path exists
    if wordlist and os.path.isfile(wordlist):
        return wordlist

    if wordlist:
        # Direct category keyword (e.g. "common", "medium", "big")
        wl_lower = wordlist.strip().lower()
        if wl_lower in _WORDLIST_SEARCH_PATHS:
            found = _find_wordlist(wl_lower)
            if found:
                return found

        # Try to match against known category keywords in path
        for category in ('medium', 'big', 'raft', 'subdomains', 'common'):
            if category in wl_lower:
                found = _find_wordlist(category)
                if found:
                    return found

        # Try common SecLists base path corrections
        # e.g. LLM asks for /usr/share/seclists/Discovery/Web-Content/common.txt
        # but actual file is at a slightly different path
        basename = os.path.basename(wordlist)
        seclists_web = '/usr/share/seclists/Discovery/Web-Content'
        candidate = os.path.join(seclists_web, basename)
        if os.path.isfile(candidate):
            return candidate

    return DEFAULT_WORDLIST
