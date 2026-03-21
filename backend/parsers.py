"""Auto-parsers for tool outputs.

Two responsibilities:
1. Extract graph nodes/edges for visualization
2. Extract structured data for StateManager (credentials, services, access)
"""

from __future__ import annotations

import re
import base64

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
    except Exception:
        pass


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
    'run_linpeas': extract_state_from_command,
    'curl_request': extract_state_from_command,
    'send_payload': extract_state_from_command,
    'sqlmap_scan': extract_state_from_sqlmap,
    'hydra_brute': extract_state_from_hydra,
    'wpscan': extract_state_from_wpscan,
    'msfconsole_run': extract_state_from_command,
}
