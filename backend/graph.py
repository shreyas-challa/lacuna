class GraphManager:
    """Manages the attack graph state (nodes and edges)."""

    def __init__(self):
        self.nodes: dict[str, dict] = {}  # id -> {id, label, type}
        self.edges: list[dict] = []
        self._edge_keys: set[tuple[str, str]] = set()  # O(1) dedup

    def add_node(self, node_id: str, label: str, node_type: str = 'service'):
        self.nodes[node_id] = {
            'id': node_id,
            'label': label,
            'type': node_type,
        }

    def add_edge(self, source: str, target: str, label: str = ''):
        key = (source, target)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({'source': source, 'target': target, 'label': label})

    def get_state(self) -> dict:
        return {
            'nodes': list(self.nodes.values()),
            'edges': list(self.edges),
        }

    def get_summary(self) -> str:
        """Text summary for LLM prompt. Groups by node type for readability."""
        if not self.nodes:
            return "Graph is empty. No nodes discovered yet."

        # Group nodes by type
        by_type: dict[str, list[dict]] = {}
        for n in self.nodes.values():
            by_type.setdefault(n['type'], []).append(n)

        # Order: machine > service > user > vulnerability > root
        type_order = ['machine', 'service', 'user', 'vulnerability', 'root']
        lines = [f"Nodes ({len(self.nodes)}):"]
        for ntype in type_order:
            group = by_type.pop(ntype, [])
            for n in group:
                lines.append(f"  [{ntype}] {n['id']}: {n['label']}")
        # Any remaining types
        for ntype, group in by_type.items():
            for n in group:
                lines.append(f"  [{ntype}] {n['id']}: {n['label']}")

        lines.append(f"Edges ({len(self.edges)}):")
        for e in self.edges:
            label = f" ({e['label']})" if e.get('label') else ''
            lines.append(f"  {e['source']} -> {e['target']}{label}")

        return '\n'.join(lines)

    def update_from_args(self, args: dict):
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
