import json


class GraphManager:
    """Manages the attack graph state (nodes and edges)."""

    def __init__(self):
        self.nodes: dict[str, dict] = {}  # id -> {id, label, type}
        self.edges: list[dict] = []  # [{source, target, label}]

    def add_node(self, node_id: str, label: str, node_type: str = 'service'):
        """Add or update a node."""
        self.nodes[node_id] = {
            'id': node_id,
            'label': label,
            'type': node_type,  # machine, service, user, vulnerability, root
        }

    def add_edge(self, source: str, target: str, label: str = ''):
        """Add an edge (skip duplicates)."""
        for e in self.edges:
            if e['source'] == source and e['target'] == target:
                return
        self.edges.append({'source': source, 'target': target, 'label': label})

    def get_state(self) -> dict:
        """Return full graph state for broadcast."""
        return {
            'nodes': list(self.nodes.values()),
            'edges': list(self.edges),
        }

    def get_summary(self) -> str:
        """Return a text summary for inclusion in LLM prompts."""
        if not self.nodes:
            return "Graph is empty. No nodes discovered yet."
        lines = ["Current attack graph:"]
        lines.append(f"  Nodes ({len(self.nodes)}):")
        for n in self.nodes.values():
            lines.append(f"    - [{n['type']}] {n['id']}: {n['label']}")
        lines.append(f"  Edges ({len(self.edges)}):")
        for e in self.edges:
            label = f" ({e['label']})" if e.get('label') else ''
            lines.append(f"    - {e['source']} -> {e['target']}{label}")
        return '\n'.join(lines)

    def update_from_args(self, args: dict):
        """Process an update_graph call. Tolerant of various key names."""
        for node in args.get('nodes', []):
            node_id = node.get('id') or node.get('name', '')
            label = node.get('label') or node.get('name') or node_id
            ntype = node.get('type', 'service')
            if node_id:
                self.add_node(node_id, label, ntype)
        for edge in args.get('edges', []):
            src = edge.get('source') or edge.get('from') or edge.get('src', '')
            tgt = edge.get('target') or edge.get('to') or edge.get('dst', '')
            label = edge.get('label') or edge.get('relation', '')
            if src and tgt:
                self.add_edge(src, tgt, label)
