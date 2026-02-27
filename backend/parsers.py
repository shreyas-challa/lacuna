"""Auto-parsers for tool outputs. Extract graph nodes/edges without an LLM round-trip."""

import re


def parse_nmap(output: str, target: str) -> dict:
    """Parse nmap output for open ports and services."""
    nodes = []
    edges = []

    # Match lines like: 22/tcp   open  ssh     OpenSSH 8.2p1
    for m in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', output):
        port, proto, service, version = m.groups()
        version = version.strip()
        node_id = f'{target}:{port}'
        label = f'{service}/{port}' + (f' ({version})' if version else '')
        nodes.append({'id': node_id, 'label': label, 'type': 'service'})
        edges.append({'source': target, 'target': node_id, 'label': proto})

    return {'nodes': nodes, 'edges': edges}


def parse_gobuster(output: str, target: str) -> dict:
    """Parse gobuster output for discovered directories."""
    nodes = []
    edges = []

    # Match lines like: /admin                (Status: 200) [Size: 1234]
    for m in re.finditer(r'(/\S+)\s+\(Status:\s*(\d+)\)', output):
        path, status = m.groups()
        node_id = f'{target}{path}'
        nodes.append({'id': node_id, 'label': f'{path} [{status}]', 'type': 'service'})
        # Find the web service node to connect to, or fallback to target
        edges.append({'source': target, 'target': node_id, 'label': 'path'})

    return {'nodes': nodes, 'edges': edges}


def parse_ffuf(output: str, target: str) -> dict:
    """Parse ffuf output for discovered endpoints."""
    nodes = []
    edges = []

    # ffuf output: path  [Status: 200, Size: 1234, ...]
    for m in re.finditer(r'(\S+)\s+\[Status:\s*(\d+)', output):
        path, status = m.groups()
        node_id = f'{target}/{path}'
        nodes.append({'id': node_id, 'label': f'/{path} [{status}]', 'type': 'service'})
        edges.append({'source': target, 'target': node_id, 'label': 'path'})

    return {'nodes': nodes, 'edges': edges}


def parse_nuclei(output: str, target: str) -> dict:
    """Parse nuclei output for vulnerabilities."""
    nodes = []
    edges = []

    # nuclei output: [vuln-id] [severity] [proto] url info
    for m in re.finditer(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)', output):
        vuln_id, severity, proto, url = m.groups()
        node_id = f'vuln-{vuln_id}'
        nodes.append({'id': node_id, 'label': f'{vuln_id} ({severity})', 'type': 'vulnerability'})
        edges.append({'source': target, 'target': node_id, 'label': severity})

    return {'nodes': nodes, 'edges': edges}


def parse_searchsploit(output: str, target: str) -> dict:
    """Parse searchsploit for found exploits."""
    nodes = []
    edges = []

    # searchsploit table rows with exploit titles and paths
    for m in re.finditer(r'(\S.*\S)\s+\|\s+(exploits/\S+|shellcodes/\S+)', output):
        title, path = m.groups()
        title = title.strip()[:60]
        node_id = f'exploit-{path.replace("/", "-")}'
        nodes.append({'id': node_id, 'label': title, 'type': 'vulnerability'})
        edges.append({'source': target, 'target': node_id, 'label': 'exploit'})

    return {'nodes': nodes, 'edges': edges}


# Map tool names to their parsers
TOOL_PARSERS = {
    'nmap_scan': parse_nmap,
    'gobuster_dir': parse_gobuster,
    'ffuf_fuzz': parse_ffuf,
    'nuclei_scan': parse_nuclei,
    'searchsploit': parse_searchsploit,
}
