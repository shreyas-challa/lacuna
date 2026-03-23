import os
import re
import ipaddress
import base64
import codecs
from urllib.parse import unquote
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


def _dedupe_flags(flags: str) -> str:
    seen = []
    for part in flags.split():
        if part not in seen:
            seen.append(part)
    return ' '.join(seen)


def _sanitize_nmap_flags(flags: str) -> str:
    flags = re.sub(r'\s+', ' ', (flags or '').strip())
    if not flags:
        flags = '-sV -sC'

    # Full-port scans are often worthwhile on HTB, but they should be bounded.
    is_full_scan = '-p-' in flags or '--top-ports' in flags or '-A' in flags
    if is_full_scan:
        if '--host-timeout' not in flags:
            flags += ' --host-timeout 90s'
        if '--max-retries' not in flags:
            flags += ' --max-retries 2'
        if '--min-rate' not in flags:
            flags += ' --min-rate 2000'
        if '-n' not in flags:
            flags += ' -n'

    return _dedupe_flags(flags)


def _sanitize_gobuster_flags(flags: str) -> str:
    flags = re.sub(r'\s+', ' ', (flags or '').strip())
    if '--timeout' not in flags:
        flags += ' --timeout 5s'
    if '-t ' not in f'{flags} ' and '--threads' not in flags:
        flags += ' -t 20'
    return _dedupe_flags(flags.strip())


def _sanitize_ffuf_flags(flags: str) -> str:
    flags = re.sub(r'\s+', ' ', (flags or '').strip())
    if '-timeout' not in flags:
        flags += ' -timeout 5'
    if '-maxtime' not in flags:
        flags += ' -maxtime 60'
    return _dedupe_flags(flags.strip())


def _sanitize_curl_flags(flags: str) -> str:
    flags = re.sub(r'\s+', ' ', (flags or '').strip())
    if not flags:
        flags = '-sS'
    if '--max-time' not in flags and '-m ' not in f'{flags} ':
        flags += ' --max-time 20'
    return flags.strip()


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
    safe_flags = _sanitize_nmap_flags(flags)
    timeout = 120 if '-p-' in safe_flags or '--top-ports' in safe_flags or '-A' in safe_flags else 60
    return await run_command(f'nmap {safe_flags} {target}', timeout=timeout)


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
    safe_flags = _sanitize_gobuster_flags(flags)
    result = await run_command(f'gobuster dir -u {url} -w {wl} {base_flags} {safe_flags}', timeout=90)
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
    safe_flags = _sanitize_ffuf_flags(flags)
    return await run_command(f'ffuf -u {url} -w {wl} {auto_flags} {safe_flags}', timeout=90)


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
    safe_flags = _sanitize_curl_flags(flags)
    return await run_command(f'curl {safe_flags} {url}', timeout=30)


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
    name='decode_text',
    description='Decode or transform text without shell execution. Supports base64, rot13, URL decoding, and auto-detection. Use this instead of execute_command for invite codes, tokens, or obfuscated hints.',
    parameters={
        'type': 'object',
        'properties': {
            'text': {'type': 'string', 'description': 'Text to decode or transform'},
            'mode': {
                'type': 'string',
                'enum': ['auto', 'base64', 'rot13', 'url'],
                'description': 'Decode mode (default: auto)',
                'default': 'auto',
            },
        },
        'required': ['text'],
    },
    phases=['enumeration'],
)
async def decode_text(text: str, mode: str = 'auto') -> str:
    raw = (text or '').strip()
    if not raw:
        return '[ERROR] No text provided to decode.'

    attempts: list[tuple[str, str]] = []
    chosen = (mode or 'auto').strip().lower()

    if chosen in ('auto', 'base64'):
        try:
            padded = raw + '=' * (-len(raw) % 4)
            decoded = base64.b64decode(padded, validate=False).decode('utf-8', errors='replace').strip()
            if decoded:
                attempts.append(('base64', decoded))
        except Exception:
            pass

    if chosen in ('auto', 'rot13'):
        decoded = codecs.decode(raw, 'rot_13')
        if decoded and decoded != raw and (chosen == 'rot13' or _looks_like_meaningful_text(decoded)):
            attempts.append(('rot13', decoded))

    if chosen in ('auto', 'url'):
        decoded = unquote(raw)
        if decoded and decoded != raw and (chosen == 'url' or _looks_like_meaningful_text(decoded)):
            attempts.append(('url', decoded))

    if not attempts:
        return '[ERROR] Could not decode text with the selected mode(s).'

    lines = [f'{kind}: {decoded}' for kind, decoded in attempts]
    return '\n'.join(lines)


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
async def execute_command_enum(command: str, target: str) -> str:
    return await _execute_command_guarded(command, target)


async def _execute_command_guarded(command: str, target: str = '') -> str:
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

    # Redirect decode attempts to the dedicated transform tool.
    if (
        'base64 -d' in cmd_lower
        or "import base64" in cmd_lower
        or "codecs.decode" in cmd_lower
        or ("tr 'a-za-z'" in cmd_lower and "'n-za-mn-za-m'" in cmd_lower)
    ):
        return "[ERROR] Use decode_text for base64/ROT13 decoding instead of execute_command."

    # Disallow external internet payload fetching inside execute_command.
    # execute_command is for target interaction, not downloading random exploit PoCs locally.
    for url_host in _extract_url_hosts(cmd_stripped):
        if not _is_allowed_target_host(url_host, target):
            return (
                f"[ERROR] External URL '{url_host}' blocked in execute_command. "
                "Only target/lab hosts are allowed here. Use query_kb or target-native checks instead."
            )

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

    # execute_command must be target-context unless this is a read-only /tmp artifact inspection.
    has_remote_context = (
        'sshpass ' in cmd_lower
        or _command_mentions_target_url(cmd_stripped, target)
        or (' scp ' in f' {cmd_lower} ' and '@' in cmd_stripped)
    )
    if not has_remote_context:
        if _looks_like_local_mutation(cmd_lower):
            return (
                "[ERROR] Local mutation/exec command blocked. "
                "Run commands on the target via sshpass or use dedicated tools."
            )
        if not _is_safe_local_tmp_read(cmd_stripped):
            return (
                "[ERROR] execute_command requires target context (sshpass/target URL). "
                "Only read-only inspection of /tmp artifacts is allowed locally."
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


_URL_RE = re.compile(r'https?://([^/\s\'":]+)')
_SAFE_LOCAL_READ_PREFIXES = (
    'file ', 'strings ', 'xxd ', 'hexdump ', 'stat ', 'wc ',
    'head ', 'tail ', 'cat ', 'grep ', 'sed ', 'awk ',
    'tshark ', 'tcpdump ',
)
_LOCAL_MUTATION_TOKENS = (
    'gcc ', 'clang ', 'make ', 'cmake ', 'python ', 'python3 ', 'perl ', 'ruby ',
    'bash ', 'sh ', './', 'chmod ', 'chown ', 'chgrp ', 'tee ', '>>', ' >', '<<',
    'wget ', 'curl ', 'msfconsole', 'pkexec', 'pwnkit',
)


def _extract_url_hosts(command: str) -> list[str]:
    hosts = []
    for m in _URL_RE.finditer(command):
        host = m.group(1).strip().lower()
        if host:
            hosts.append(host)
    return hosts


def _is_allowed_target_host(host: str, target: str) -> bool:
    clean = host.split('@')[-1].split(':')[0].strip().lower()
    target_clean = (target or '').strip().lower()
    if target_clean and clean == target_clean:
        return True
    if clean.endswith('.htb'):
        return True
    try:
        return ipaddress.ip_address(clean).is_private
    except ValueError:
        return False


def _command_mentions_target_url(command: str, target: str) -> bool:
    for host in _extract_url_hosts(command):
        if _is_allowed_target_host(host, target):
            return True
    return False


def _looks_like_local_mutation(cmd_lower: str) -> bool:
    return any(tok in cmd_lower for tok in _LOCAL_MUTATION_TOKENS)


def _is_safe_local_tmp_read(command: str) -> bool:
    cmd = command.strip()
    cmd_lower = cmd.lower()
    if not cmd_lower.startswith(_SAFE_LOCAL_READ_PREFIXES):
        return False
    if '/tmp/' not in cmd and '/tmp ' not in cmd:
        return False
    if any(tok in cmd_lower for tok in (' >', '>>', '<<', 'chmod ', './', 'bash ', 'python ', 'python3 ')):
        return False
    return True


def _looks_like_meaningful_text(text: str) -> bool:
    return (
        '/api/' in text
        or 'http' in text
        or bool(re.search(r'\b(?:the|and|order|request|generate|invite|code|post)\b', text, re.IGNORECASE))
    )


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
