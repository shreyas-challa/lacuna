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
            # Nothing found via targeted queries — check if file is essentially empty
            filesize = await run_command(f'wc -c < {filepath}', timeout=5)
            size = int(filesize.strip()) if filesize.strip().isdigit() else 0
            pkt_count = await run_command(f'tshark -r {filepath} -T fields -e frame.number 2>/dev/null | wc -l', timeout=10)
            pkts = int(pkt_count.strip()) if pkt_count.strip().isdigit() else 0

            if pkts == 0 or size < 100:
                parts.append(
                    f"=== EMPTY CAPTURE ===\n"
                    f"This pcap has {pkts} packets ({size} bytes) — it contains NO useful data.\n"
                    f"IMPORTANT: If the URL contains a numeric ID (e.g. /download/1), "
                    f"try other IDs — especially /download/0 which often contains "
                    f"pre-existing captures from other users with credentials."
                )
            else:
                # Has some data but no creds found — fall back to strings
                fallback = await run_command(f'strings {filepath} | head -n 200', timeout=30)
                parts.append(f"=== Strings (fallback) ===\n{fallback}")
        return '\n\n'.join(parts)
    elif ext in ('js', 'jsx', 'ts'):
        # Smart JS analysis: extract security-relevant patterns
        parts = [f"Downloaded {filename} (HTTP {dl_result.strip()})"]

        # Extract URL/API paths
        api_hits = await run_command(
            f"grep -oE '[\"\\x27](/[a-zA-Z0-9_/]{{3,}})[\"\\x27]' {filepath} | sort -u | head -30",
            timeout=10,
        )
        if api_hits.strip():
            parts.append(f"=== URL/API Paths ===\n{api_hits}")

        # Extract security-relevant strings
        interesting = await run_command(
            f'grep -i -oE ".{{0,40}}(invite|token|secret|password|admin|auth|key|register|generate|verify|code|flag|credentials|session|cookie).{{0,40}}" {filepath} | head -30',
            timeout=10,
        )
        if interesting.strip():
            parts.append(f"=== Interesting References ===\n{interesting}")

        # Extract HTTP call patterns
        http_calls = await run_command(
            f'grep -i -oE ".{{0,30}}(fetch\\(|\\$\\.ajax|\\$\\.post|\\$\\.get|XMLHttpRequest|axios\\.).{{0,60}}" {filepath} | head -20',
            timeout=10,
        )
        if http_calls.strip():
            parts.append(f"=== HTTP/API Calls ===\n{http_calls}")

        # Include first 2KB of raw content for context
        content = await run_command(f'head -c 2048 {filepath}', timeout=10)
        parts.append(f"=== File Contents (first 2KB) ===\n{content}")

        return '\n\n'.join(parts)
    elif ext in ('txt', 'conf', 'cfg', 'xml', 'json', 'html', 'php', 'py', 'sh', 'log', 'css'):
        content = await run_command(f'cat {filepath}', timeout=10)
        return f"Downloaded {filename} (HTTP {dl_result.strip()})\n\n=== File Contents ===\n{content}"
    else:
        # Binary - use strings and file
        file_info = await run_command(f'file {filepath}', timeout=10)
        strings_out = await run_command(f'strings {filepath}', timeout=30)
        return f"Downloaded {filename} (HTTP {dl_result.strip()})\n{file_info}\n=== Strings ===\n{strings_out}"


@tool(
    name='execute_command',
    description='Execute a shell command for TARGET interaction: curl to target, sshpass SSH, '
                'file analysis, exploit compilation. Do NOT use for local system admin '
                '(apt/dnf/pip), echo messages, or local recon (whoami/uname/ls without target context).',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Shell command to execute against or about the target'},
        },
        'required': ['command'],
    },
    phases=['enumeration'],
)
async def execute_command_enum(command: str) -> str:
    cmd_stripped = command.strip()

    # Reject hallucinated non-commands
    if not cmd_stripped or cmd_stripped.startswith('[') or cmd_stripped.startswith('{'):
        return "[ERROR] Invalid command — this is not a shell command. Use a real shell command or a dedicated tool."

    # Block dangerous local system commands that should never run during a pentest
    _BLOCKED_COMMANDS = (
        'apt-get update', 'apt-get upgrade', 'apt-get install',
        'apt update', 'apt upgrade', 'apt install',
        'dnf update', 'dnf upgrade', 'dnf install',
        'yum update', 'yum upgrade', 'yum install',
        'pacman -S', 'pip install', 'npm install',
        'rm -rf /', 'mkfs', 'dd if=',
        'shutdown', 'reboot', 'poweroff', 'init 0', 'init 6',
    )
    cmd_lower = cmd_stripped.lower()
    for blocked in _BLOCKED_COMMANDS:
        if blocked in cmd_lower:
            return f"[ERROR] Blocked — '{blocked}' modifies the LOCAL system, not the target. Focus on the target machine."

    # Reject ALL echo commands that aren't piped/redirected to a target
    # (status messages like "echo Preparing...", "echo Analysis ready", etc.)
    if cmd_lower.startswith('echo ') and '|' not in cmd_stripped and '>>' not in cmd_stripped and 'tee' not in cmd_lower:
        return "[ERROR] Do not echo status messages — call a tool that advances the engagement."

    # Block purely local recon commands (not SSH'd to target)
    _LOCAL_ONLY = ('whoami', 'uname -a', 'uname', 'uptime', 'hostname', 'id',
                   'date', 'pwd', 'w', 'last', 'ps', 'ps aux', 'env')
    if cmd_stripped in _LOCAL_ONLY:
        return (
            f"[ERROR] '{cmd_stripped}' runs on YOUR local machine, not the target. "
            f"Use sshpass to run on the target, or use a dedicated tool (nmap_scan, curl_request, etc.)."
        )

    # Block local filesystem browsing that isn't target-related
    # Allowed: ls /tmp/*.pcap, ls with target paths. Blocked: ls, ls /tmp, ls backend/, etc.
    _LOCAL_LS_PATTERNS = (
        'ls', 'ls -l', 'ls -la', 'ls -a', 'ls -al',
        'ls /tmp', 'ls -l /tmp', 'ls -a /tmp', 'ls -la /tmp',
        'ls backend', 'ls frontend', 'ls -l backend', 'ls -l frontend',
    )
    if cmd_stripped in _LOCAL_LS_PATTERNS or cmd_stripped.startswith('ls backend/') or cmd_stripped.startswith('ls frontend/'):
        return (
            "[ERROR] Browsing the local filesystem wastes iterations. "
            "Use a dedicated tool: nmap_scan, curl_request, gobuster_dir, ffuf_fuzz, or query_kb."
        )

    # Block find/locate on the local system (wordlist hunting etc.)
    if cmd_stripped.startswith('find /') and 'tmp/' not in cmd_stripped:
        return "[ERROR] Searching the local filesystem wastes iterations. Use dedicated tools with keyword wordlists (e.g. gobuster_dir with wordlist='common')."

    # Block cat/head/tail on local project files (not /tmp or target-downloaded files)
    for reader in ('cat ', 'head ', 'tail ', 'sed ', 'less ', 'more '):
        if cmd_stripped.startswith(reader):
            target_path = cmd_stripped[len(reader):].strip().split()[0] if cmd_stripped[len(reader):].strip() else ''
            if target_path and not target_path.startswith('/tmp') and not target_path.startswith('/dev'):
                # Allow reading /etc/hosts and similar system files needed for pentest
                if not target_path.startswith('/etc/'):
                    return f"[ERROR] Reading local project files wastes iterations. Focus on the target."

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
