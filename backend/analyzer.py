"""Output analyzer: parse raw tool output into structured state and observations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from backend.output_processing import OutputProcessor
from backend.parsers import (
    STATE_EXTRACTORS,
    TOOL_PARSERS,
    _extract_json_payloads,
    _payload_indicates_success,
    _payload_messages,
)
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
    state_changed: bool = False


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
        state_changed = False

        before = self.state.to_snapshot() if not result.startswith('[ERROR]') else None
        if name in STATE_EXTRACTORS and not result.startswith('[ERROR]'):
            STATE_EXTRACTORS[name](result, self.target, self.state)
        if not result.startswith('[ERROR]'):
            self._apply_semantic_state_updates(name, args, result)
        if before is not None:
            after = self.state.to_snapshot()
            state_changed = before != after
            refresh_required = refresh_required or state_changed

        parsed = None
        ctx = self._graph_context(name, args)
        if name in TOOL_PARSERS and not result.startswith('[ERROR]') and not result.startswith('[TIMEOUT'):
            parsed = TOOL_PARSERS[name](result, self.target, ctx)
        elif name in ('execute_command', 'download_and_analyze') and not result.startswith('[ERROR]'):
            parsed = _parse_command_output_for_graph(result, self.target, ctx)
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
            state_changed=state_changed,
        )

    def _graph_context(self, name: str, args: dict) -> dict:
        """Compute provenance for graph edges so findings chain off the artifact
        that produced them, not the machine node. Builds the web spine
        (machine → service → endpoint → downloaded file) and identifies the
        foothold user/credential for privesc chaining."""
        ctx: dict = {'source_id': self.target, 'foothold_user_id': None, 'foothold_cred_id': None}

        url = str(args.get('url', '') or '')
        if url.startswith(('http://', 'https://')):
            spine = self._ensure_web_spine(name, url, args)
            if spine:
                ctx['source_id'] = spine

        # Foothold: a credential already verified for a shell service lets us
        # chain privesc findings (root, cap_setuid) off the user we logged in as.
        for cred in self.state.credentials.values():
            if any(svc in cred.verified_for for svc in ('ssh', 'winrm', 'rdp')):
                ctx['foothold_cred_id'] = f'cred-{cred.password[:30]}'
                ctx['foothold_user_id'] = f'user-{cred.username}'
                break

        # If a privesc vector node already exists in the graph (e.g. cap_setuid
        # found a turn earlier), let root chain through it for a complete path.
        for node_id in self.graph.nodes:
            if 'cap-setuid' in node_id or node_id.startswith('vuln-suid') or node_id.startswith('vuln-sudo'):
                ctx['privesc_vector_id'] = node_id
                break

        return ctx

    def _ensure_web_spine(self, name: str, url: str, args: dict) -> str | None:
        """Ensure machine → service:port → endpoint(path) [→ file] nodes exist.
        Returns the deepest node id, which becomes the provenance anchor."""
        m = re.match(r'(https?)://([^/:]+)(?::(\d+))?(/[^?#\s]*)?', url)
        if not m:
            return None
        scheme, host, port, path = m.groups()
        port = port or ('443' if scheme == 'https' else '80')

        svc_id = f'{host}:{port}'
        if svc_id not in self.graph.nodes:
            self.graph.add_node(svc_id, f'http/{port}', 'service')
        self.graph.add_edge(self.target, svc_id, scheme)
        deepest = svc_id

        path = (path or '/').rstrip('/') or '/'
        if path != '/':
            ep_id = f'{host}:{port}{path}'
            if ep_id not in self.graph.nodes:
                self.graph.add_node(ep_id, path, 'service')
            self.graph.add_edge(svc_id, ep_id, 'path')
            deepest = ep_id

        # download_and_analyze pulls a file off an endpoint — represent it so
        # creds recovered from the file chain: endpoint → file → cred.
        if name == 'download_and_analyze':
            filename = str(args.get('filename', '') or '').strip()
            if filename:
                file_id = f'file-{filename}'
                if file_id not in self.graph.nodes:
                    self.graph.add_node(file_id, filename, 'vulnerability')
                self.graph.add_edge(deepest, file_id, 'download')
                deepest = file_id

        return deepest

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

    def _apply_semantic_state_updates(self, name: str, args: dict, result: str):
        if name not in {'curl_request', 'web_request'}:
            return

        url = str(args.get('url', '') or '')
        if not url:
            return
        lower = result.lower()
        status_code = self._extract_status_code(result)
        response_body = self._extract_response_body(result)
        payloads = self._extract_payloads(result)
        success_payload = any(_payload_indicates_success(payload) for payload in payloads)
        message_fragments = " ".join(_payload_messages(payloads)).lower()
        combined = f"{response_body.lower()}\n{message_fragments}\n{lower}"

        # Generic auth-success: any login/auth endpoint returning 2xx/302 with a
        # success payload or session evidence implies an authenticated session.
        auth_url = any(token in url.lower() for token in ('login', 'signin', 'sign-in', 'authenticate', 'auth'))
        if auth_url and (
            success_payload
            or (status_code in (200, 201, 302)
                and any(token in combined for token in ('authenticated', 'dashboard', 'phpsessid', 'set-cookie', 'welcome', 'success')))
        ):
            self.state.set_workflow_marker('authenticated_session')
            self.state.add_note('Authenticated web session established.')

    @staticmethod
    def _extract_status_code(result: str) -> int:
        patterns = (
            r'(?m)^HTTP Status:\s*(\d+)',
            r'(?m)^HTTP/\S+\s+(\d+)',
            r'(?m)^< HTTP/\S+\s+(\d+)',
            r'(?m)^__LACUNA_HTTP_STATUS__:(\d+)',
        )
        for pattern in patterns:
            match = re.search(pattern, result)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    return 0
        return 0

    @staticmethod
    def _extract_response_body(result: str) -> str:
        body_match = re.search(r'Response Body:\n(.*)', result, re.DOTALL)
        if body_match:
            return body_match.group(1).strip()
        return result.strip()

    @staticmethod
    def _extract_payloads(result: str) -> list[object]:
        payloads = _extract_json_payloads(result)
        if payloads:
            return payloads
        body = Analyzer._extract_response_body(result)
        try:
            return [json.loads(body)]
        except Exception:
            return []


def _parse_command_output_for_graph(output: str, target: str, ctx: dict | None = None) -> dict:
    try:
        ctx = ctx or {}
        src = ctx.get('source_id') or target
        foothold_user = ctx.get('foothold_user_id')
        privesc_vector = ctx.get('privesc_vector_id')
        nodes, edges = [], []

        # Privesc capability node — surfaced before the uid check so root can
        # chain through it: user → cap_setuid → root.
        cap_node = None
        if 'cap_setuid' in output:
            cap_node = 'vuln-cap-setuid'
            nodes.append({'id': cap_node, 'label': 'cap_setuid', 'type': 'vulnerability'})
            edges.append({'source': foothold_user or target, 'target': cap_node, 'label': 'capability'})

        for match in re.finditer(r'uid=\d+\((\w+)\)', output):
            user = match.group(1)
            if user == 'root':
                nodes.append({'id': 'root-access', 'label': 'ROOT ACCESS', 'type': 'root'})
                # Chain root through the privesc vector (cap_setuid found this
                # turn or earlier) → foothold user → machine, in that preference.
                root_src = cap_node or privesc_vector or foothold_user or target
                edges.append({'source': root_src, 'target': 'root-access', 'label': 'privesc'})
            elif user != 'nobody':
                # The user node already exists in the chain (discovered via the
                # credential it came from), so just ensure it's present — no
                # extra edge, which would only create a cred↔user cycle.
                node_id = f'user-{user}'
                nodes.append({'id': node_id, 'label': f'User: {user}', 'type': 'user'})

        if re.search(r'user\.txt', output) and re.search(r'[0-9a-f]{32}', output):
            nodes.append({'id': 'user-flag', 'label': 'user.txt', 'type': 'vulnerability'})
            if foothold_user:
                edges.append({'source': foothold_user, 'target': 'user-flag', 'label': 'flag'})
        if re.search(r'root\.txt', output) and re.search(r'[0-9a-f]{32}', output):
            nodes.append({'id': 'root-flag', 'label': 'root.txt', 'type': 'root'})
            edges.append({'source': 'root-access', 'target': 'root-flag', 'label': 'flag'})

        ftp_users = []
        for match in re.finditer(r'USER\s+(\S+)', output):
            user = match.group(1)
            if user and user not in ('anonymous', 'ftp'):
                ftp_users.append(user)
                nodes.append({'id': f'user-{user}', 'label': f'User: {user}', 'type': 'user'})
                edges.append({'source': src, 'target': f'user-{user}', 'label': 'cred found'})
        for index, match in enumerate(re.finditer(r'PASS\s+(\S+)', output)):
            passwd = match.group(1)
            node_id = f'cred-{passwd[:30]}'
            nodes.append({'id': node_id, 'label': f'Password: {passwd}', 'type': 'vulnerability'})
            if index < len(ftp_users):
                edges.append({'source': f'user-{ftp_users[index]}', 'target': node_id, 'label': 'password'})
            else:
                edges.append({'source': src, 'target': node_id, 'label': 'credential'})

        return {'nodes': nodes, 'edges': edges}
    except Exception:
        return {'nodes': [], 'edges': []}
