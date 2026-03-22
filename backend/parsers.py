"""Auto-parsers for tool outputs.

Two responsibilities:
1. Extract graph nodes/edges for visualization
2. Extract structured data for StateManager (credentials, services, access)
"""

from __future__ import annotations

import re
import base64
import codecs
import json

from backend.state import StateManager


# ── Graph parsers (return {nodes, edges} for GraphManager) ───────

def parse_nmap(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        for m in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', output):
            port, proto, service, version = m.groups()
            version = version.strip()
            node_id = f'{target}:{port}'
            label = f'{service}/{port}' + (f' ({version})' if version else '')
            nodes.append({'id': node_id, 'label': label, 'type': 'service'})
            edges.append({'source': target, 'target': node_id, 'label': proto})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_gobuster(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        # Standard format: /path  (Status: 200) [Size: 1234]
        for m in re.finditer(r'(/\S+)\s+\(Status:\s*(\d+)\)', output):
            path, status = m.groups()
            if status == '404':
                continue
            node_id = f'{target}{path}'
            if not any(n['id'] == node_id for n in nodes):
                nodes.append({'id': node_id, 'label': f'{path} [{status}]', 'type': 'service'})
                edges.append({'source': target, 'target': node_id, 'label': 'path'})
        # Cap at 15 nodes
        if len(nodes) > 15:
            nodes = nodes[:15]
            edges = edges[:15]
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_ffuf(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        # Only parse actual ffuf result lines: "path  [Status: NNN, Size: NNN, ...]"
        for m in re.finditer(r'^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)', output, re.MULTILINE):
            path, status, size = m.groups()
            # Skip noise: ffuf banner lines, stats, or very short generic paths
            if path.startswith('[') or path.startswith('::') or len(path) < 1:
                continue
            # Only add interesting status codes (not 404s or generic redirects)
            if status in ('404',):
                continue
            node_id = f'{target}/{path}'
            # Deduplicate
            if any(n['id'] == node_id for n in nodes):
                continue
            nodes.append({'id': node_id, 'label': f'/{path} [{status}]', 'type': 'service'})
            edges.append({'source': target, 'target': node_id, 'label': 'path'})
        # Cap at 15 nodes to prevent graph flooding
        if len(nodes) > 15:
            nodes = nodes[:15]
            edges = edges[:15]
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_nuclei(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        for m in re.finditer(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)', output):
            vuln_id, severity, proto, url = m.groups()
            node_id = f'vuln-{vuln_id}'
            nodes.append({'id': node_id, 'label': f'{vuln_id} ({severity})', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': node_id, 'label': severity})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_searchsploit(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        for m in re.finditer(r'(\S.*\S)\s+\|\s+(exploits/\S+|shellcodes/\S+)', output):
            title, path = m.groups()
            title = title.strip()[:60]
            node_id = f'exploit-{path.replace("/", "-")}'
            nodes.append({'id': node_id, 'label': title, 'type': 'vulnerability'})
            edges.append({'source': target, 'target': node_id, 'label': 'exploit'})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_pcap_analysis(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        ftp_users = [m.group(1) for m in re.finditer(r'(?:^|\s)USER\s+(\S+)', output, re.MULTILINE)
                     if m.group(1).lower() not in ('anonymous', 'ftp', '')]
        ftp_passes = [m.group(1) for m in re.finditer(r'(?:^|\s)PASS\s+(\S+)', output, re.MULTILINE)
                      if m.group(1)]

        for user in ftp_users:
            node_id = f'user-{user}'
            nodes.append({'id': node_id, 'label': f'User: {user}', 'type': 'user'})
            edges.append({'source': target, 'target': node_id, 'label': 'cred found'})

        for i, passwd in enumerate(ftp_passes):
            node_id = f'cred-{passwd[:30]}'
            nodes.append({'id': node_id, 'label': f'Password: {passwd}', 'type': 'vulnerability'})
            if i < len(ftp_users):
                edges.append({'source': f'user-{ftp_users[i]}', 'target': node_id, 'label': 'password'})
            else:
                edges.append({'source': target, 'target': node_id, 'label': 'credential'})

        for m in re.finditer(r'Authorization:\s*Basic\s+(\S+)', output):
            nodes.append({'id': 'vuln-basic-auth', 'label': 'Basic Auth Creds', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': 'vuln-basic-auth', 'label': 'credential'})

        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_sqlmap(output: str, target: str) -> dict:
    """Extract injection points and databases from sqlmap output."""
    try:
        nodes, edges = [], []
        # Detect injectable parameters
        for m in re.finditer(r"Parameter:\s*(\S+)\s.*is\s+(.*vulnerable)", output, re.IGNORECASE):
            param = m.group(1)
            node_id = f'vuln-sqli-{param}'
            nodes.append({'id': node_id, 'label': f'SQLi: {param}', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': node_id, 'label': 'sqli'})
        # Detect databases
        for m in re.finditer(r'\[\*\]\s+(\w+)', output):
            db = m.group(1)
            if db not in ('information_schema', 'performance_schema', 'mysql', 'sys', 'starting', 'testing', 'shutting'):
                node_id = f'db-{db}'
                nodes.append({'id': node_id, 'label': f'DB: {db}', 'type': 'service'})
                edges.append({'source': target, 'target': node_id, 'label': 'database'})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_hydra(output: str, target: str) -> dict:
    """Extract cracked credentials from hydra output."""
    try:
        nodes, edges = [], []
        for m in re.finditer(r'\[(\d+)\]\[(\w+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)', output):
            port, service, user, passwd = m.groups()
            node_id = f'cred-{user}-{passwd[:20]}'
            nodes.append({'id': node_id, 'label': f'Cred: {user}:{passwd}', 'type': 'user'})
            edges.append({'source': target, 'target': node_id, 'label': f'{service} brute'})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_wpscan(output: str, target: str) -> dict:
    """Extract WordPress users, plugins, and vulnerabilities from wpscan output."""
    try:
        nodes, edges = [], []
        # Users
        for m in re.finditer(r'\|\s+(\w+)\s+\|.*Author', output):
            user = m.group(1)
            node_id = f'wp-user-{user}'
            nodes.append({'id': node_id, 'label': f'WP User: {user}', 'type': 'user'})
            edges.append({'source': target, 'target': node_id, 'label': 'wordpress'})
        # Also catch user enumeration format
        for m in re.finditer(r'(?:Identified|Found).*user.*?:\s*(\w+)', output, re.IGNORECASE):
            user = m.group(1)
            node_id = f'wp-user-{user}'
            nodes.append({'id': node_id, 'label': f'WP User: {user}', 'type': 'user'})
            edges.append({'source': target, 'target': node_id, 'label': 'wordpress'})
        # Vulnerabilities
        for m in re.finditer(r'Title:\s*(.+)', output):
            title = m.group(1).strip()[:60]
            node_id = f'wp-vuln-{title[:30].replace(" ", "-").lower()}'
            nodes.append({'id': node_id, 'label': title, 'type': 'vulnerability'})
            edges.append({'source': target, 'target': node_id, 'label': 'wp-vuln'})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


# Graph parser registry
TOOL_PARSERS = {
    'nmap_scan': parse_nmap,
    'gobuster_dir': parse_gobuster,
    'ffuf_fuzz': parse_ffuf,
    'nuclei_scan': parse_nuclei,
    'searchsploit': parse_searchsploit,
    'download_and_analyze': parse_pcap_analysis,
    'sqlmap_scan': parse_sqlmap,
    'hydra_brute': parse_hydra,
    'wpscan': parse_wpscan,
}


# ── State extractors (feed into StateManager) ───────────────────

def extract_state_from_nmap(output: str, target: str, state: StateManager):
    """Extract services from nmap output into state."""
    try:
        for m in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', output):
            port, proto, name, version = m.groups()
            state.add_service(target, int(port), proto, name, version.strip())

        if 'Anonymous FTP login allowed' in output:
            state.add_credential('anonymous', '', source='nmap_script')
            state.mark_credential_verified('anonymous', '', 'ftp')

        title_match = re.search(r'http-title:\s*(.+)', output)
        if title_match:
            title = title_match.group(1).strip()
            for svc in state.services.values():
                if svc.host == target and svc.name in ('http', 'https'):
                    svc.info = f"title: {title}"
    except Exception:
        pass


def extract_state_from_command(output: str, target: str, state: StateManager):
    """Extract access info, credentials, flags from command output."""
    try:
        # Detect user/root access
        for m in re.finditer(r'uid=(\d+)\((\w+)\)', output):
            uid, user = m.groups()
            level = 'root' if user == 'root' or uid == '0' else 'user'
            if user not in ('nobody',):
                state.add_access(target, user, level)

        # Detect flags
        if re.search(r'user\.txt', output):
            flag = re.search(r'[0-9a-f]{32}', output)
            if flag:
                state.add_loot('user_flag', flag.group())

        if re.search(r'root\.txt', output):
            flag = re.search(r'[0-9a-f]{32}', output)
            if flag:
                state.add_loot('root_flag', flag.group())

        # FTP credentials
        ftp_users = [m.group(1) for m in re.finditer(r'USER\s+(\S+)', output)
                     if m.group(1).lower() not in ('anonymous', 'ftp')]
        ftp_passes = [m.group(1) for m in re.finditer(r'PASS\s+(\S+)', output)]
        for i, user in enumerate(ftp_users):
            passwd = ftp_passes[i] if i < len(ftp_passes) else ''
            if passwd:
                state.add_credential(user, passwd, source='pcap/output')

        # SSH login success
        if 'Welcome to' in output or 'Last login' in output:
            uid_match = re.search(r'uid=\d+\((\w+)\)', output)
            if uid_match:
                state.add_access(target, uid_match.group(1), 'user', 'ssh')

        # Capabilities
        if 'cap_setuid' in output:
            cap_match = re.search(r'(\S+)\s.*cap_setuid', output)
            if cap_match:
                state.add_finding(
                    title=f'cap_setuid on {cap_match.group(1)}',
                    severity='critical', service=target,
                    description=f'{cap_match.group(1)} has cap_setuid — instant root',
                )

        # Sudo
        if '(ALL)' in output or '(root)' in output or 'NOPASSWD' in output:
            for line in output.split('\n'):
                if '(ALL)' in line or '(root)' in line or 'NOPASSWD' in line:
                    state.add_finding(
                        title=f'Sudo: {line.strip()[:80]}',
                        severity='critical', service=target,
                        description=line.strip(),
                    )

        # Interesting SUID binaries
        suid_interesting = {'python', 'python3', 'vim', 'nmap', 'find', 'bash',
                            'perl', 'ruby', 'php', 'docker', 'pkexec', 'env',
                            'awk', 'node', 'screen', 'systemctl'}
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('/') and any(b in line.split('/')[-1] for b in suid_interesting):
                state.add_finding(
                    title=f'SUID: {line}',
                    severity='high', service=target,
                    description=f'{line.split("/")[-1]} has SUID bit set',
                )

        _extract_web_workflow_artifacts(output, target, state)
    except Exception:
        pass


def _extract_web_workflow_artifacts(output: str, target: str, state: StateManager):
    """Extract app-specific workflow artifacts from HTTP/JS/API responses."""
    session_name = re.search(r'(?m)^Session:\s*(\S+)', output)
    last_url = re.search(r'(?m)^URL:\s*(\S+)', output)
    status = re.search(r'(?m)^HTTP Status:\s*(\d+)', output)
    content_type = re.search(r'(?m)^Content-Type:\s*(.+)', output)
    redirect = re.search(r'(?m)^Redirect:\s*(\S+)', output)
    cookie_line = re.search(r'(?m)^Cookies:\s*(.+)', output)
    if session_name:
        cookies = []
        if cookie_line:
            cookies = [c.strip() for c in cookie_line.group(1).split(',') if c.strip()]
        state.upsert_web_session(
            session_name.group(1),
            last_url=last_url.group(1) if last_url else '',
            last_status=int(status.group(1)) if status else 0,
            last_content_type=content_type.group(1).strip() if content_type else '',
            cookies=cookies,
            authenticated=bool(cookies),
        )
        if redirect:
            state.add_note(f'Session redirect: {redirect.group(1)}')

    lower_output = output.lower()
    if 'invite code decoded:' in lower_output or 'invite_code' in lower_output:
        state.set_workflow_marker('invite_code_obtained')

    invite_paths = (
        '/invite',
        '/api/v1/invite/how/to/generate',
        '/api/v1/invite/generate',
        '/api/v1/invite/verify',
        '/api/v1/user/register',
        '/api/v1/user/login',
    )
    for path in invite_paths:
        if path in output:
            state.add_note(f'Invite workflow endpoint seen: {path}')

    if '/api/v1/invite/how/to/generate' in output or '/api/v1/invite/generate' in output:
        state.upsert_hypothesis(
            'invite_workflow',
            'This target likely requires an invite-code workflow before account creation.',
            status='active',
            evidence='Invite endpoints were observed in app responses or JS.',
        )

    # Scan embedded JSON objects or bare JSON responses.
    for candidate in re.findall(r'\{.*?\}', output, re.DOTALL):
        try:
            payload = json.loads(candidate)
        except Exception:
            continue
        _extract_from_json_payload(payload, state)

    # Some responses are just quoted/inline encoded values.
    for encoded in re.findall(r'([A-Za-z0-9+/]{16,}={0,2})', output):
        decoded = _safe_b64decode(encoded)
        if not decoded:
            continue
        if _looks_like_invite_code(decoded):
            state.add_loot('invite_code', decoded)
            state.set_workflow_marker('invite_code_obtained')
            state.add_note(f'Invite code decoded: {decoded}')
            state.add_note(f'Next step: POST code={decoded} to /api/v1/invite/verify')
            state.upsert_hypothesis(
                'invite_workflow',
                'Decoded invite code is available; the next valid action is invite verification followed by registration.',
                status='validated',
                evidence=decoded,
            )
        elif '/api/v1/invite/generate' in decoded:
            state.add_note(f'Decoded invite hint: {decoded}')

    # ROT13 hints appear in 2million-like flows.
    for text in re.findall(r'([A-Za-z0-9 /:._-]{20,})', output):
        decoded = codecs.decode(text, 'rot_13')
        if '/api/v1/invite/generate' in decoded and decoded != text:
            state.add_note(f'Decoded ROT13 hint: {decoded}')

    current_url = last_url.group(1) if last_url else ''
    status_code = int(status.group(1)) if status else 0
    if current_url.endswith('/api/v1/invite/verify') and status_code in (200, 201):
        if '"status":"success"' in lower_output or 'invite is valid' in lower_output or '"success":true' in lower_output:
            state.set_workflow_marker('invite_verified')
            state.add_note('Invite verification succeeded.')
    if current_url.endswith('/api/v1/user/register') and status_code in (200, 201):
        if '"status":"success"' in lower_output or 'registration successful' in lower_output or '"success":true' in lower_output:
            state.set_workflow_marker('account_registered')
            state.add_note('Account registration succeeded.')
    if current_url.endswith('/api/v1/user/login') and status_code in (200, 201, 302):
        if '"status":"success"' in lower_output or 'login successful' in lower_output or redirect or cookie_line:
            state.set_workflow_marker('authenticated_session')
            state.add_note('Authenticated web session established.')


def _extract_from_json_payload(payload: object, state: StateManager):
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lower = str(key).lower()
            if isinstance(value, str):
                decoded = _safe_b64decode(value)
                if key_lower in {'data', 'code', 'invite', 'invitecode'} and decoded and _looks_like_invite_code(decoded):
                    state.add_loot('invite_code', decoded)
                    state.add_loot('invite_code_b64', value)
                    state.set_workflow_marker('invite_code_obtained')
                    state.add_note(f'Invite code decoded: {decoded}')
                    state.add_note('Verify the invite, then register and log in.')
                elif 'how/to/generate' in value or '/api/v1/invite/' in value:
                    state.add_note(f'Invite API hint: {value}')

                rot_decoded = codecs.decode(value, 'rot_13')
                if '/api/v1/invite/generate' in rot_decoded and rot_decoded != value:
                    state.add_note(f'Decoded ROT13 hint: {rot_decoded}')
            else:
                _extract_from_json_payload(value, state)
    elif isinstance(payload, list):
        for item in payload:
            _extract_from_json_payload(item, state)


def _safe_b64decode(value: str) -> str | None:
    raw = (value or '').strip()
    if len(raw) < 8 or len(raw) % 4 not in (0, 2, 3):
        return None
    try:
        decoded = base64.b64decode(raw + '=' * (-len(raw) % 4), validate=False).decode('utf-8', errors='ignore').strip()
    except Exception:
        return None
    if not decoded:
        return None
    if any(ord(ch) < 9 for ch in decoded):
        return None
    return decoded


def _looks_like_invite_code(value: str) -> bool:
    return bool(re.fullmatch(r'[A-Z0-9]{4,}(?:-[A-Z0-9]{4,}){2,}', value.strip()))


def extract_state_from_pcap(output: str, target: str, state: StateManager):
    """Extract credentials from pcap analysis output."""
    try:
        ftp_users = [m.group(1) for m in re.finditer(r'(?:^|\s)USER\s+(\S+)', output, re.MULTILINE)
                     if m.group(1).lower() not in ('anonymous', 'ftp', '')]
        ftp_passes = [m.group(1) for m in re.finditer(r'(?:^|\s)PASS\s+(\S+)', output, re.MULTILINE)
                      if m.group(1)]

        for i, user in enumerate(ftp_users):
            passwd = ftp_passes[i] if i < len(ftp_passes) else ''
            if passwd:
                state.add_credential(user, passwd, source='pcap')

        for m in re.finditer(r'Authorization:\s*Basic\s+(\S+)', output):
            try:
                decoded = base64.b64decode(m.group(1)).decode()
                if ':' in decoded:
                    user, passwd = decoded.split(':', 1)
                    state.add_credential(user, passwd, source='http_basic_auth')
            except Exception:
                pass
    except Exception:
        pass


def extract_state_from_sqlmap(output: str, target: str, state: StateManager):
    """Extract injection points and databases from sqlmap output."""
    try:
        for m in re.finditer(r"Parameter:\s*(\S+)", output):
            state.add_finding(
                title=f'SQL Injection: {m.group(1)}',
                severity='critical', service=target,
                description=f'Injectable parameter: {m.group(1)}',
            )
        # Extract credentials if --dump was used
        for m in re.finditer(r'\|\s+(\S+)\s+\|\s+(\S{4,})\s+\|', output):
            user, passwd = m.groups()
            if user.lower() not in ('username', 'user', 'name', 'id', 'email', '---'):
                state.add_credential(user, passwd, source='sqlmap_dump')
    except Exception:
        pass


def extract_state_from_hydra(output: str, target: str, state: StateManager):
    """Extract cracked credentials from hydra output."""
    try:
        for m in re.finditer(r'\[(\d+)\]\[(\w+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)', output):
            port, service, user, passwd = m.groups()
            state.add_credential(user, passwd, source=f'hydra_{service}')
            state.mark_credential_verified(user, passwd, service)
    except Exception:
        pass


def extract_state_from_wpscan(output: str, target: str, state: StateManager):
    """Extract WordPress findings from wpscan output."""
    try:
        for m in re.finditer(r'(?:Identified|Found).*user.*?:\s*(\w+)', output, re.IGNORECASE):
            user = m.group(1)
            state.add_credential(user, '', source='wpscan_enum')
        for m in re.finditer(r'Title:\s*(.+)', output):
            title = m.group(1).strip()
            state.add_finding(
                title=f'WP: {title[:60]}',
                severity='high', service=target,
                description=title,
            )
    except Exception:
        pass


# State extractor registry
STATE_EXTRACTORS = {
    'nmap_scan': extract_state_from_nmap,
    'execute_command': extract_state_from_command,
    'download_and_analyze': extract_state_from_pcap,
    'check_sudo': extract_state_from_command,
    'check_suid': extract_state_from_command,
    'check_cron': extract_state_from_command,
    'check_capabilities': extract_state_from_command,
    'run_linpeas': extract_state_from_command,
    'curl_request': extract_state_from_command,
    'web_request': extract_state_from_command,
    'send_payload': extract_state_from_command,
    'sqlmap_scan': extract_state_from_sqlmap,
    'hydra_brute': extract_state_from_hydra,
    'wpscan': extract_state_from_wpscan,
    'msfconsole_run': extract_state_from_command,
}
