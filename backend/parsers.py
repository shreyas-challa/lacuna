"""Auto-parsers for tool outputs. Extract graph nodes/edges without an LLM round-trip."""

import re


def parse_nmap(output: str, target: str) -> dict:
    """Parse nmap output for open ports and services."""
    try:
        nodes = []
        edges = []
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
    """Parse gobuster output for discovered directories."""
    try:
        nodes = []
        edges = []
        for m in re.finditer(r'(/\S+)\s+\(Status:\s*(\d+)\)', output):
            path, status = m.groups()
            node_id = f'{target}{path}'
            nodes.append({'id': node_id, 'label': f'{path} [{status}]', 'type': 'service'})
            edges.append({'source': target, 'target': node_id, 'label': 'path'})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_ffuf(output: str, target: str) -> dict:
    """Parse ffuf output for discovered endpoints."""
    try:
        nodes = []
        edges = []
        for m in re.finditer(r'(\S+)\s+\[Status:\s*(\d+)', output):
            path, status = m.groups()
            node_id = f'{target}/{path}'
            nodes.append({'id': node_id, 'label': f'/{path} [{status}]', 'type': 'service'})
            edges.append({'source': target, 'target': node_id, 'label': 'path'})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_nuclei(output: str, target: str) -> dict:
    """Parse nuclei output for vulnerabilities."""
    try:
        nodes = []
        edges = []
        for m in re.finditer(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)', output):
            vuln_id, severity, proto, url = m.groups()
            node_id = f'vuln-{vuln_id}'
            nodes.append({'id': node_id, 'label': f'{vuln_id} ({severity})', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': node_id, 'label': severity})
        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


def parse_searchsploit(output: str, target: str) -> dict:
    """Parse searchsploit for found exploits."""
    try:
        nodes = []
        edges = []
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
    """Parse pcap/tshark output for credentials and interesting data."""
    try:
        nodes = []
        edges = []

        # Extract FTP USER/PASS in order so we can pair them
        ftp_users = [m.group(1) for m in re.finditer(r'(?:^|\s)USER\s+(\S+)', output, re.MULTILINE)
                     if m.group(1).lower() not in ('anonymous', 'ftp', '')]
        ftp_passes = [m.group(1) for m in re.finditer(r'(?:^|\s)PASS\s+(\S+)', output, re.MULTILINE)
                      if m.group(1) != '']

        for user in ftp_users:
            node_id = f'user-{user}'
            nodes.append({'id': node_id, 'label': f'User: {user}', 'type': 'user'})
            edges.append({'source': target, 'target': node_id, 'label': 'cred found'})

        for i, passwd in enumerate(ftp_passes):
            node_id = f'cred-{passwd[:30]}'
            # Store the ACTUAL password in the label so it's visible in graph summary
            nodes.append({'id': node_id, 'label': f'Password: {passwd}', 'type': 'vulnerability'})
            # Link to the corresponding user if we can pair them
            if i < len(ftp_users):
                edges.append({'source': f'user-{ftp_users[i]}', 'target': node_id, 'label': 'password'})
            else:
                edges.append({'source': target, 'target': node_id, 'label': 'credential'})

        # HTTP Basic Auth
        for m in re.finditer(r'Authorization:\s*Basic\s+(\S+)', output):
            node_id = 'vuln-basic-auth'
            nodes.append({'id': node_id, 'label': 'Basic Auth Creds', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': node_id, 'label': 'credential'})

        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}


# Map tool names to their parsers
TOOL_PARSERS = {
    'nmap_scan': parse_nmap,
    'gobuster_dir': parse_gobuster,
    'ffuf_fuzz': parse_ffuf,
    'nuclei_scan': parse_nuclei,
    'searchsploit': parse_searchsploit,
    'download_and_analyze': parse_pcap_analysis,
}
