"""Output analyzer: parse raw tool output into structured state and observations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from backend.output_processing import OutputProcessor
from backend.parsers import STATE_EXTRACTORS, TOOL_PARSERS
from backend.planning import Observation
from backend.state import StateManager


@dataclass
class AnalysisOutcome:
    observation: Observation
    discovered_hosts: list[str] = field(default_factory=list)
    graph_nodes_added: int = 0
    graph_edges_added: int = 0
    plan_refresh_required: bool = False
    web_assets_added: int = 0


class Analyzer:
    def __init__(self, target: str, state: StateManager, graph, output_processor: OutputProcessor):
        self.target = target
        self.state = state
        self.graph = graph
        self.output_processor = output_processor
        self._seen_idor_paths: set[str] = set()

    def analyze(self, name: str, args: dict, result: str) -> AnalysisOutcome:
        refresh_required = False
        graph_nodes_added = 0
        graph_edges_added = 0
        web_assets_added = 0

        if name in STATE_EXTRACTORS and not result.startswith('[ERROR]'):
            before = self.state.to_snapshot()
            STATE_EXTRACTORS[name](result, self.target, self.state)
            after = self.state.to_snapshot()
            refresh_required = before != after

        parsed = None
        if name in TOOL_PARSERS and not result.startswith('[ERROR]') and not result.startswith('[TIMEOUT'):
            parsed = TOOL_PARSERS[name](result, self.target)
        elif name in ('execute_command', 'download_and_analyze') and not result.startswith('[ERROR]'):
            parsed = _parse_command_output_for_graph(result, self.target)
        if parsed and (parsed['nodes'] or parsed['edges']):
            before_nodes = len(self.graph.nodes)
            before_edges = len(self.graph.edges)
            self.graph.update_from_args(parsed)
            graph_nodes_added = max(0, len(self.graph.nodes) - before_nodes)
            graph_edges_added = max(0, len(self.graph.edges) - before_edges)

        if name in ('curl_request', 'execute_command', 'download_and_analyze') and not result.startswith('[ERROR]'):
            web_assets_added = self._extract_web_assets(result)
            if web_assets_added:
                refresh_required = True

        if name in ('curl_request', 'download_and_analyze') and not result.startswith('[ERROR]'):
            url_arg = args.get('url', '')
            if url_arg and self._persist_idor_signal(url_arg, result):
                refresh_required = True

        discovered_hosts = []
        if name in ('nmap_scan', 'curl_request', 'execute_command') and not result.startswith('[ERROR]'):
            discovered_hosts = self._extract_hostnames(result)

        processed = self.output_processor.process(name, args, result, self.target)
        summary = processed.summary
        if processed.notable:
            summary += " " + " ".join(processed.notable[:2])
        observation = Observation(
            tool_name=name,
            summary=summary,
            significance=processed.significance,
            notable=processed.notable,
            follow_up=processed.follow_up,
            raw_ref=f"{name}:{args.get('url', args.get('command', ''))[:120]}",
        )

        if processed.significance in {'high', 'critical'}:
            refresh_required = True

        return AnalysisOutcome(
            observation=observation,
            discovered_hosts=discovered_hosts,
            graph_nodes_added=graph_nodes_added,
            graph_edges_added=graph_edges_added,
            plan_refresh_required=refresh_required,
            web_assets_added=web_assets_added,
        )

    def _extract_hostnames(self, output: str) -> list[str]:
        hostnames = set()
        for match in re.finditer(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', output):
            hostname = match.group(1).lower()
            if any(hostname.endswith(skip) for skip in ('.com', '.org', '.net', '.io', '.dev', '.gov')):
                continue
            hostnames.add(hostname)
        return sorted(hostnames)

    def _extract_web_assets(self, result: str) -> int:
        added = 0
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', result, re.IGNORECASE):
            if self.state.add_web_asset('scripts', match.group(1)):
                added += 1
        for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', result, re.IGNORECASE):
            href = match.group(1)
            if href.endswith(('.css', '.js')):
                category = 'stylesheets' if href.endswith('.css') else 'scripts'
                if self.state.add_web_asset(category, href):
                    added += 1
        for match in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', result, re.IGNORECASE):
            action = match.group(1)
            if action and action != '#' and self.state.add_web_asset('forms', action):
                added += 1
        for match in re.finditer(r'["\'](/api/[^"\'?\s]{3,})["\']', result):
            if self.state.add_web_asset('api_endpoints', match.group(1)):
                added += 1
        for match in re.finditer(r'(?:fetch|ajax|post|get|put|delete)\s*\(\s*["\'](/[^"\'?\s]{3,})["\']', result, re.IGNORECASE):
            if self.state.add_web_asset('api_endpoints', match.group(1)):
                added += 1
        for match in re.finditer(r'href=["\']([^"\']*(?:/download/|/file/|/export/|/raw/|/pcap/|\.pcap)[^"\']*)["\']', result, re.IGNORECASE):
            link = match.group(1)
            if link and link != '#' and self.state.add_web_asset('api_endpoints', link):
                added += 1
        return added

    def _persist_idor_signal(self, url: str, result: str) -> bool:
        match = re.search(r'(https?://[^/]+)?(/[^?#\s]*?/)(\d+)(?:[?#\s]|$)', url)
        if not match:
            return False
        base_path = match.group(2)
        if base_path in self._seen_idor_paths:
            return False
        self._seen_idor_paths.add(base_path)

        host_prefix = match.group(1) or ''
        current_id = int(match.group(3))
        try_ids = {current_id + 1}
        if current_id != 0:
            try_ids.add(0)
        if current_id > 1:
            try_ids.add(current_id - 1)

        sibling_paths = {
            '/data/': ['/download/', '/export/', '/file/', '/raw/'],
            '/download/': ['/data/', '/view/', '/file/'],
            '/view/': ['/download/', '/data/', '/raw/'],
            '/file/': ['/download/', '/data/'],
            '/capture/': ['/download/', '/data/', '/pcap/'],
        }
        sibling_suggestions = []
        for sibling in sibling_paths.get(base_path, []):
            sibling_suggestions.append(f"{host_prefix}{sibling}{current_id}")
            if current_id != 0:
                sibling_suggestions.append(f"{host_prefix}{sibling}0")

        notes = [f"Potential IDOR observed at {url} with numeric object id {current_id}."]
        if try_ids:
            id_urls = ', '.join(f'{host_prefix}{base_path}{i}' for i in sorted(try_ids))
            notes.append(f"Candidate adjacent object IDs: {id_urls}.")
        if sibling_suggestions:
            notes.append(f"Sibling endpoints worth testing: {', '.join(sibling_suggestions[:6])}.")

        download_links = set()
        for match_download in re.finditer(r'href=["\']([^"\']*(?:download|file|export|raw|pcap)[^"\']*)["\']', result, re.IGNORECASE):
            link = match_download.group(1)
            if link and link != '#':
                download_links.add(link)
        if download_links:
            notes.append(f"Download links seen: {', '.join(sorted(download_links)[:5])}.")

        for note in notes:
            self.state.add_note(note)
        self.state.upsert_hypothesis(
            f'idor:{base_path}',
            f'Numeric endpoint family {base_path}<id> may expose insecure direct object references.',
            status='active',
            evidence=', '.join(sorted(download_links)[:3]) or f'Observed {url}',
        )
        return True


def _parse_command_output_for_graph(output: str, target: str) -> dict:
    try:
        nodes, edges = [], []
        for match in re.finditer(r'uid=\d+\((\w+)\)', output):
            user = match.group(1)
            if user == 'root':
                nodes.append({'id': 'root-access', 'label': 'ROOT ACCESS', 'type': 'root'})
                edges.append({'source': target, 'target': 'root-access', 'label': 'privesc'})
            elif user != 'nobody':
                node_id = f'user-{user}'
                nodes.append({'id': node_id, 'label': f'User: {user}', 'type': 'user'})
                edges.append({'source': target, 'target': node_id, 'label': 'ssh'})

        if re.search(r'user\.txt', output) and re.search(r'[0-9a-f]{32}', output):
            nodes.append({'id': 'user-flag', 'label': 'user.txt', 'type': 'vulnerability'})
        if re.search(r'root\.txt', output) and re.search(r'[0-9a-f]{32}', output):
            nodes.append({'id': 'root-flag', 'label': 'root.txt', 'type': 'root'})
            edges.append({'source': 'root-access', 'target': 'root-flag', 'label': 'flag'})

        ftp_users = []
        for match in re.finditer(r'USER\s+(\S+)', output):
            user = match.group(1)
            if user and user not in ('anonymous', 'ftp'):
                ftp_users.append(user)
                nodes.append({'id': f'user-{user}', 'label': f'User: {user}', 'type': 'user'})
                edges.append({'source': target, 'target': f'user-{user}', 'label': 'cred found'})
        for index, match in enumerate(re.finditer(r'PASS\s+(\S+)', output)):
            passwd = match.group(1)
            node_id = f'cred-{passwd[:30]}'
            nodes.append({'id': node_id, 'label': f'Password: {passwd}', 'type': 'vulnerability'})
            if index < len(ftp_users):
                edges.append({'source': f'user-{ftp_users[index]}', 'target': node_id, 'label': 'password'})
            else:
                edges.append({'source': target, 'target': node_id, 'label': 'credential'})

        if 'cap_setuid' in output:
            nodes.append({'id': 'vuln-cap-setuid', 'label': 'cap_setuid', 'type': 'vulnerability'})
            edges.append({'source': target, 'target': 'vuln-cap-setuid', 'label': 'capability'})

        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}
